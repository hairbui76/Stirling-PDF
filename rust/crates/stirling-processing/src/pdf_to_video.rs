//! PDF slideshow video conversion through `ffmpeg`.
//!
//! The Java controller has this endpoint commented out while `ffmpeg` CVEs are assessed. This
//! adapter keeps the route available for a Rust-only deployment, but still requires an explicitly
//! installed `ffmpeg` executable and never invokes a shell.

use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, ErrorKind, copy},
    path::{Path, PathBuf},
    process::Command,
};

use ab_glyph::{FontArc, PxScale};
use image::{ImageReader, Rgba, RgbaImage, imageops};
use imageproc::{
    drawing::{draw_text_mut, text_size},
    geometric_transformations::{Interpolation, rotate_about_center},
};
use tempfile::TempDir;
use thiserror::Error;
use zip::ZipArchive;

use crate::{
    pdf_flatten::configured_max_render_dpi,
    pdf_to_image::{PdfToImageError, PdfToImageOptions, PdfToImageOutput, convert_pdf_to_images},
};

const FFMPEG_COMMAND_ENV: &str = "STIRLING_PROCESSING_FFMPEG_COMMAND";
const MAX_VIDEO_FRAMES: usize = 10_000;
const MAX_WATERMARK_CHARACTERS: usize = 4_096;
const MAX_WATERMARK_PIXELS: u64 = 32 * 1024 * 1024;
const DEJAVU_SANS_BOLD: &[u8] =
    include_bytes!("../../../../app/core/src/main/resources/static/fonts/DejaVuSans-Bold.ttf");

/// The two output containers supported by the Java request contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VideoFormat {
    Mp4,
    Webm,
}

impl VideoFormat {
    #[must_use]
    pub fn from_requested(value: &str) -> Self {
        if value.trim().eq_ignore_ascii_case("webm") {
            Self::Webm
        } else {
            Self::Mp4
        }
    }

    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Mp4 => "mp4",
            Self::Webm => "webm",
        }
    }

    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Mp4 => "video/mp4",
            Self::Webm => "video/webm",
        }
    }
}

/// Form options accepted by `POST /api/v1/convert/pdf/video`.
#[derive(Clone, Debug, PartialEq)]
pub struct PdfToVideoOptions {
    pub video_format: String,
    pub seconds_per_page: i32,
    pub resolution: String,
    pub dpi: i32,
    pub opacity: f32,
    pub watermark_text: Option<String>,
}

impl Default for PdfToVideoOptions {
    fn default() -> Self {
        Self {
            video_format: "mp4".to_owned(),
            seconds_per_page: 3,
            resolution: "ORIGINAL".to_owned(),
            dpi: 150,
            opacity: 0.1,
            watermark_text: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum PdfToVideoError {
    #[error("secondsPerPage must be greater than zero")]
    InvalidSecondsPerPage,
    #[error("dpi must be at least 72")]
    InvalidDpi,
    #[error("DPI value {requested} exceeds maximum safe limit of {maximum}")]
    DpiExceedsLimit { requested: i32, maximum: i32 },
    #[error("opacity must be a finite number between 0.0 and 1.0")]
    InvalidOpacity,
    #[error("watermarkText exceeds the {MAX_WATERMARK_CHARACTERS}-character safety limit")]
    WatermarkTextTooLong,
    #[error("watermark text requires too many pixels to render safely")]
    WatermarkTooLarge,
    #[error("the embedded DejaVu Sans Bold font is invalid")]
    EmbeddedFont,
    #[error("PDF rendering failed: {0}")]
    PdfRender(#[from] PdfToImageError),
    #[error("could not read the rendered frame archive: {0}")]
    FrameArchive(#[from] zip::result::ZipError),
    #[error("the rendered PDF has no pages")]
    NoFrames,
    #[error("the PDF exceeds the {MAX_VIDEO_FRAMES}-page video safety limit")]
    TooManyFrames,
    #[error("could not prepare video frames: {0}")]
    Io(#[from] io::Error),
    #[error("could not decode or write rendered frame '{path}': {source}")]
    FrameImage {
        path: PathBuf,
        #[source]
        source: image::ImageError,
    },
    #[error("ffmpeg executable is not available")]
    FfmpegUnavailable { explicitly_configured: bool },
    #[error("could not start ffmpeg command '{command}': {source}")]
    FfmpegStart {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("ffmpeg command '{command}' failed with status {status}: {details}")]
    FfmpegFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("ffmpeg reported success without producing a video")]
    FfmpegNoOutput,
}

/// Renders every PDF page as a slideshow frame and encodes an MP4 or `WebM` video with `ffmpeg`.
///
/// # Errors
///
/// Returns [`PdfToVideoError`] for invalid options, unavailable `PDFium` or `ffmpeg`, malformed
/// PDFs, frame rendering failures, or failed video encoding.
pub fn convert_pdf_to_video(
    input_path: &Path,
    filename: &str,
    options: &PdfToVideoOptions,
    output_path: &Path,
) -> Result<VideoFormat, PdfToVideoError> {
    validate_options(options)?;
    let format = VideoFormat::from_requested(&options.video_format);
    let workspace = TempDir::new()?;
    let rendered_frames = workspace.path().join("rendered-pages.zip");
    let frame_directory = workspace.path().join("frames");
    fs::create_dir(&frame_directory)?;
    let image_options = PdfToImageOptions {
        image_format: "png".to_owned(),
        single_or_multiple: "multiple".to_owned(),
        color_type: "color".to_owned(),
        dpi: options.dpi,
        page_numbers: "all".to_owned(),
        include_annotations: true,
    };
    match convert_pdf_to_images(input_path, filename, &image_options, &rendered_frames)? {
        PdfToImageOutput::Multiple => {}
        PdfToImageOutput::Single { .. } => return Err(PdfToVideoError::NoFrames),
    }
    let frame_paths = extract_frames(&rendered_frames, &frame_directory)?;
    if let Some(watermark_text) = options
        .watermark_text
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        apply_watermark_to_frames(&frame_paths, watermark_text, options.opacity)?;
    }
    run_ffmpeg(
        &frame_directory,
        output_path,
        format,
        options.seconds_per_page,
        &options.resolution,
    )?;
    Ok(format)
}

fn validate_options(options: &PdfToVideoOptions) -> Result<(), PdfToVideoError> {
    if options.seconds_per_page <= 0 {
        return Err(PdfToVideoError::InvalidSecondsPerPage);
    }
    if options.dpi < 72 {
        return Err(PdfToVideoError::InvalidDpi);
    }
    let maximum = configured_max_render_dpi();
    if options.dpi > maximum {
        return Err(PdfToVideoError::DpiExceedsLimit {
            requested: options.dpi,
            maximum,
        });
    }
    if !options.opacity.is_finite() || !(0.0..=1.0).contains(&options.opacity) {
        return Err(PdfToVideoError::InvalidOpacity);
    }
    if options
        .watermark_text
        .as_deref()
        .is_some_and(|value| value.chars().count() > MAX_WATERMARK_CHARACTERS)
    {
        return Err(PdfToVideoError::WatermarkTextTooLong);
    }
    Ok(())
}

fn extract_frames(
    archive_path: &Path,
    frame_directory: &Path,
) -> Result<Vec<PathBuf>, PdfToVideoError> {
    let archive_file = File::open(archive_path)?;
    let mut archive = ZipArchive::new(archive_file)?;
    let mut frames = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() {
            continue;
        }
        if frames.len() == MAX_VIDEO_FRAMES {
            return Err(PdfToVideoError::TooManyFrames);
        }
        let frame = frame_directory.join(format!("frame_{:05}.png", frames.len() + 1));
        let mut output = File::create(&frame)?;
        copy(&mut entry, &mut output)?;
        frames.push(frame);
    }
    if frames.is_empty() {
        return Err(PdfToVideoError::NoFrames);
    }
    Ok(frames)
}

fn apply_watermark_to_frames(
    frame_paths: &[PathBuf],
    watermark_text: &str,
    opacity: f32,
) -> Result<(), PdfToVideoError> {
    let font =
        FontArc::try_from_slice(DEJAVU_SANS_BOLD).map_err(|_| PdfToVideoError::EmbeddedFont)?;
    for path in frame_paths {
        let mut frame = ImageReader::open(path)?
            .decode()
            .map_err(|source| PdfToVideoError::FrameImage {
                path: path.clone(),
                source,
            })?
            .to_rgba8();
        apply_watermark(&mut frame, watermark_text, opacity, &font)?;
        frame
            .save(path)
            .map_err(|source| PdfToVideoError::FrameImage {
                path: path.clone(),
                source,
            })?;
    }
    Ok(())
}

fn apply_watermark(
    frame: &mut RgbaImage,
    watermark_text: &str,
    opacity: f32,
    font: &FontArc,
) -> Result<(), PdfToVideoError> {
    let frame_width =
        u16::try_from(frame.width()).map_err(|_| PdfToVideoError::WatermarkTooLarge)?;
    let frame_height =
        u16::try_from(frame.height()).map_err(|_| PdfToVideoError::WatermarkTooLarge)?;
    let font_size = frame_width.min(frame_height).saturating_div(5).max(32);
    let scale = PxScale::from(f32::from(font_size));
    let (text_width, text_height) = text_size(scale, font, watermark_text);
    let padding = 6_u32;
    let width = text_width
        .checked_add(padding.saturating_mul(2))
        .ok_or(PdfToVideoError::WatermarkTooLarge)?;
    let height = text_height
        .checked_add(padding.saturating_mul(2))
        .ok_or(PdfToVideoError::WatermarkTooLarge)?;
    if u64::from(width).saturating_mul(u64::from(height)) > MAX_WATERMARK_PIXELS {
        return Err(PdfToVideoError::WatermarkTooLarge);
    }
    let mut watermark = RgbaImage::from_pixel(width, height, Rgba([0, 0, 0, 0]));
    let alpha = opacity_to_alpha(opacity);
    let shadow_alpha = alpha.saturating_div(2);
    let text_x = i32::try_from(padding).map_err(|_| PdfToVideoError::WatermarkTooLarge)?;
    draw_text_mut(
        &mut watermark,
        Rgba([0, 0, 0, shadow_alpha]),
        text_x.saturating_add(3),
        text_x.saturating_add(3),
        scale,
        font,
        watermark_text,
    );
    draw_text_mut(
        &mut watermark,
        Rgba([255, 255, 255, alpha]),
        text_x,
        text_x,
        scale,
        font,
        watermark_text,
    );
    let angle = -f32::from(frame_height).atan2(f32::from(frame_width));
    let rotated = rotate_about_center(
        &watermark,
        angle,
        Interpolation::Bilinear,
        Rgba([0, 0, 0, 0]),
    );
    let position_x = (i64::from(frame.width()) - i64::from(rotated.width())) / 2;
    let position_y = (i64::from(frame.height()) - i64::from(rotated.height())) / 2;
    imageops::overlay(frame, &rotated, position_x, position_y);
    Ok(())
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn opacity_to_alpha(opacity: f32) -> u8 {
    // `validate_options()` accepts only finite 0.0–1.0 values before a watermark is rendered.
    (opacity * 255.0).round() as u8
}

fn run_ffmpeg(
    frame_directory: &Path,
    output_path: &Path,
    format: VideoFormat,
    seconds_per_page: i32,
    resolution: &str,
) -> Result<(), PdfToVideoError> {
    let arguments = ffmpeg_arguments(output_path, format, seconds_per_page, resolution);
    let commands = ffmpeg_commands();
    for command in commands.candidates {
        match Command::new(&command)
            .args(&arguments)
            .current_dir(frame_directory)
            .output()
        {
            Ok(output) if output.status.success() => {
                if output_path
                    .metadata()
                    .is_ok_and(|metadata| metadata.len() > 0)
                {
                    return Ok(());
                }
                return Err(PdfToVideoError::FfmpegNoOutput);
            }
            Ok(output) => {
                return Err(PdfToVideoError::FfmpegFailed {
                    command,
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(PdfToVideoError::FfmpegStart { command, source }),
        }
    }
    Err(PdfToVideoError::FfmpegUnavailable {
        explicitly_configured: commands.explicitly_configured,
    })
}

fn ffmpeg_arguments(
    output_path: &Path,
    format: VideoFormat,
    seconds_per_page: i32,
    resolution: &str,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("-y"),
        OsString::from("-framerate"),
        OsString::from(frame_rate(seconds_per_page)),
        OsString::from("-i"),
        OsString::from("frame_%05d.png"),
        OsString::from("-vf"),
        OsString::from(resolution_filter(resolution)),
    ];
    match format {
        VideoFormat::Mp4 => arguments.extend([
            OsString::from("-c:v"),
            OsString::from("libx264"),
            OsString::from("-pix_fmt"),
            OsString::from("yuv420p"),
            OsString::from("-movflags"),
            OsString::from("+faststart"),
        ]),
        VideoFormat::Webm => arguments.extend([
            OsString::from("-c:v"),
            OsString::from("libvpx-vp9"),
            OsString::from("-b:v"),
            OsString::from("0"),
            OsString::from("-crf"),
            OsString::from("30"),
        ]),
    }
    arguments.push(output_path.as_os_str().to_owned());
    arguments
}

fn frame_rate(seconds_per_page: i32) -> String {
    let rendered = format!("{:.6}", 1.0 / f64::from(seconds_per_page));
    rendered
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_owned()
}

fn resolution_filter(resolution: &str) -> &'static str {
    match resolution.trim().to_ascii_uppercase().as_str() {
        "1080P" => "scale=-2:1080,setsar=1",
        "720P" => "scale=-2:720,setsar=1",
        "480P" => "scale=-2:480,setsar=1",
        _ => "scale=trunc(iw/2)*2:trunc(ih/2)*2,setsar=1",
    }
}

fn ffmpeg_commands() -> FfmpegCommands {
    if let Ok(command) = env::var(FFMPEG_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return FfmpegCommands {
            candidates: vec![command],
            explicitly_configured: true,
        };
    }
    let candidates = if cfg!(windows) {
        vec!["ffmpeg.exe".to_owned(), "ffmpeg".to_owned()]
    } else {
        vec!["ffmpeg".to_owned(), "/usr/bin/ffmpeg".to_owned()]
    };
    FfmpegCommands {
        candidates,
        explicitly_configured: false,
    }
}

fn exit_status(status: std::process::ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
}

fn process_details(stdout: &[u8], stderr: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    let details = String::from_utf8_lossy(bytes);
    let mut characters = details.trim().chars();
    let result = characters.by_ref().take(2_048).collect::<String>();
    if characters.next().is_some() {
        format!("{result}…")
    } else if result.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        result
    }
}

struct FfmpegCommands {
    candidates: Vec<String>,
    explicitly_configured: bool,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{
        PdfToVideoError, PdfToVideoOptions, VideoFormat, ffmpeg_arguments, frame_rate,
        resolution_filter, validate_options,
    };

    #[test]
    fn keeps_java_video_defaults_and_fallbacks() {
        let options = PdfToVideoOptions::default();
        assert_eq!(
            VideoFormat::from_requested(&options.video_format),
            VideoFormat::Mp4
        );
        assert_eq!(VideoFormat::from_requested("unexpected"), VideoFormat::Mp4);
        assert_eq!(VideoFormat::from_requested("WEBM"), VideoFormat::Webm);
        assert_eq!(
            resolution_filter("unexpected"),
            resolution_filter("ORIGINAL")
        );
        assert_eq!(frame_rate(3), "0.333333");
    }

    #[test]
    fn validates_before_loading_pdfium_or_starting_ffmpeg() {
        let mut options = PdfToVideoOptions {
            seconds_per_page: 0,
            ..PdfToVideoOptions::default()
        };
        assert!(matches!(
            validate_options(&options),
            Err(PdfToVideoError::InvalidSecondsPerPage)
        ));

        options = PdfToVideoOptions {
            dpi: 71,
            ..PdfToVideoOptions::default()
        };
        assert!(matches!(
            validate_options(&options),
            Err(PdfToVideoError::InvalidDpi)
        ));

        options = PdfToVideoOptions {
            opacity: f32::NAN,
            ..PdfToVideoOptions::default()
        };
        assert!(matches!(
            validate_options(&options),
            Err(PdfToVideoError::InvalidOpacity)
        ));
    }

    #[test]
    fn passes_only_fixed_ffmpeg_filters_and_codecs() {
        let arguments = ffmpeg_arguments(
            std::path::Path::new("video.mp4"),
            VideoFormat::Mp4,
            3,
            "1080p",
        );
        assert!(arguments.contains(&OsStr::new("scale=-2:1080,setsar=1").to_owned()));
        assert!(arguments.contains(&OsStr::new("libx264").to_owned()));
        assert!(arguments.contains(&OsStr::new("+faststart").to_owned()));
    }
}
