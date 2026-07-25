use std::{
    env,
    ffi::OsString,
    fs,
    io::{Cursor, ErrorKind},
    path::Path,
    process::Command,
};

use image::{
    DynamicImage, GrayImage, ImageReader, RgbImage, codecs::jpeg::JpegEncoder, imageops::FilterType,
};
use lopdf::{Document, Object, Stream, dictionary};
use tempfile::tempdir;
use thiserror::Error;

use crate::ghostscript::{exit_status, ghostscript_commands};

const QPDF_COMMAND_ENV: &str = "STIRLING_PROCESSING_QPDF_COMMAND";
const MAX_IMAGE_BYTES: usize = 512 * 1024 * 1024;
const MAX_IMAGE_PIXELS: u64 = 100_000_000;
const MAX_JAVA_SIZE: f64 = 9_223_372_036_854_775_807.0;

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)] // These booleans are independent fields in the public API.
pub struct CompressOptions {
    pub optimize_level: i32,
    pub expected_output_size: Option<String>,
    pub linearize: bool,
    pub normalize: bool,
    pub grayscale: bool,
    pub line_art: bool,
    pub line_art_threshold: f64,
    pub line_art_edge_level: i32,
}

#[derive(Debug, Error)]
pub enum CompressError {
    #[error("optimizeLevel must be between 1 and 9")]
    InvalidOptimizeLevel,
    #[error("expectedOutputSize is invalid")]
    InvalidExpectedOutputSize,
    #[error("lineArtThreshold must be a finite number between 0 and 100")]
    InvalidLineArtThreshold,
    #[error("lineArtEdgeLevel must be between 1 and 3")]
    InvalidLineArtEdgeLevel,
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("input PDF '{filename}' has no pages")]
    EmptyPdf { filename: String },
    #[error("QPDF is required for linearize or normalize")]
    QpdfUnavailable { explicitly_configured: bool },
    #[error("external command '{command}' failed with status {status}: {details}")]
    ExternalFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("external command '{command}' could not start: {source}")]
    ExternalStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("image processing failed: {0}")]
    Image(#[from] image::ImageError),
    #[error("compression I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Optimizes a PDF with native stream/image rewriting and optional Ghostscript/QPDF adapters.
///
/// The native path recompresses structure, downscales common embedded RGB/gray images, converts
/// images to gray when requested, and implements line-art conversion as 1-bit embedded images.
/// Target-size mode escalates the Java-compatible optimization level through level 9.
///
/// # Errors
///
/// Returns [`CompressError`] for invalid request values, malformed PDFs/images, configured tool
/// failures, or output I/O errors.
pub fn compress_pdf_to_file(
    input_path: &Path,
    input_filename: &str,
    options: &CompressOptions,
    output_path: &Path,
) -> Result<(), CompressError> {
    validate_options(options)?;
    let original_size = fs::metadata(input_path)?.len();
    let target_size = options
        .expected_output_size
        .as_deref()
        .map(parse_size_bytes)
        .transpose()?;
    let mut level = target_size.map_or(options.optimize_level, |target| {
        determine_optimize_level(target, original_size)
    });

    let mut source = load_document(input_path, input_filename)?;
    if source.get_pages().is_empty() {
        return Err(CompressError::EmptyPdf {
            filename: input_filename.to_owned(),
        });
    }
    source.compress();
    let work = tempdir()?;
    let mut current_path = work.path().join("current.pdf");
    source.save(&current_path)?;
    drop(source);

    if options.line_art {
        let line_art_path = work.path().join("line-art.pdf");
        transform_images(
            &current_path,
            input_filename,
            ImageTransform::LineArt {
                threshold: options.line_art_threshold,
                edge_level: options.line_art_edge_level,
            },
            &line_art_path,
        )?;
        current_path = line_art_path;
    }

    let mut iteration = 0_u8;
    loop {
        iteration = iteration.saturating_add(1);
        let ghostscript_path = work.path().join(format!("ghostscript-{iteration}.pdf"));
        let ghostscript_applied = if level >= 6 {
            try_ghostscript_compression(&current_path, &ghostscript_path, level, options.grayscale)?
        } else {
            false
        };
        if ghostscript_applied {
            current_path = ghostscript_path;
        }

        let qpdf_path = work.path().join(format!("qpdf-{iteration}.pdf"));
        let qpdf_applied = try_qpdf_compression(
            &current_path,
            &qpdf_path,
            level,
            options.linearize,
            options.normalize,
        )?;
        if qpdf_applied {
            current_path = qpdf_path;
        } else if options.linearize || options.normalize {
            return Err(CompressError::QpdfUnavailable {
                explicitly_configured: env::var_os(QPDF_COMMAND_ENV).is_some(),
            });
        }

        if (level >= 4 || options.grayscale) && !ghostscript_applied {
            let images_path = work.path().join(format!("images-{iteration}.pdf"));
            transform_images(
                &current_path,
                input_filename,
                ImageTransform::Compress {
                    level,
                    grayscale: options.grayscale,
                },
                &images_path,
            )?;
            current_path = images_path;
        }

        let structural_path = work.path().join(format!("structural-{iteration}.pdf"));
        rewrite_pdf(&current_path, input_filename, &structural_path)?;
        current_path = structural_path;
        let current_size = fs::metadata(&current_path)?.len();
        let Some(target) = target_size else {
            break;
        };
        if current_size <= target || level >= 9 {
            break;
        }
        level = increment_optimize_level(level, current_size, target);
    }

    let selected = if fs::metadata(&current_path)?.len() < original_size {
        current_path.as_path()
    } else {
        input_path
    };
    rewrite_pdf(selected, input_filename, output_path)
}

fn validate_options(options: &CompressOptions) -> Result<(), CompressError> {
    if !(1..=9).contains(&options.optimize_level) {
        return Err(CompressError::InvalidOptimizeLevel);
    }
    if !options.line_art_threshold.is_finite()
        || !(0.0..=100.0).contains(&options.line_art_threshold)
    {
        return Err(CompressError::InvalidLineArtThreshold);
    }
    if !(1..=3).contains(&options.line_art_edge_level) {
        return Err(CompressError::InvalidLineArtEdgeLevel);
    }
    Ok(())
}

fn load_document(path: &Path, filename: &str) -> Result<Document, CompressError> {
    Document::load(path).map_err(|source| CompressError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}

fn rewrite_pdf(input_path: &Path, filename: &str, output_path: &Path) -> Result<(), CompressError> {
    let mut document = load_document(input_path, filename)?;
    document.prune_objects();
    document.renumber_objects();
    document.compress();
    document.save(output_path)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ImageTransform {
    Compress { level: i32, grayscale: bool },
    LineArt { threshold: f64, edge_level: i32 },
}

fn transform_images(
    input_path: &Path,
    filename: &str,
    transform: ImageTransform,
    output_path: &Path,
) -> Result<(), CompressError> {
    let mut document = load_document(input_path, filename)?;
    let image_ids = document
        .objects
        .iter()
        .filter_map(|(&id, object)| {
            let stream = object.as_stream().ok()?;
            stream
                .dict
                .get(b"Subtype")
                .ok()
                .and_then(|value| value.as_name().ok())
                .is_some_and(|name| name == b"Image")
                .then_some(id)
        })
        .collect::<Vec<_>>();
    for image_id in image_ids {
        let Some(Object::Stream(stream)) = document.objects.get(&image_id).cloned() else {
            continue;
        };
        let Some(image) = decode_pdf_image(&document, &stream)? else {
            continue;
        };
        let replacement = match transform {
            ImageTransform::Compress { level, grayscale } => {
                compress_image_stream(&stream, image, level, grayscale)?
            }
            ImageTransform::LineArt {
                threshold,
                edge_level,
            } => Some(line_art_stream(&image, threshold, edge_level)?),
        };
        if let Some(replacement) = replacement {
            document
                .objects
                .insert(image_id, Object::Stream(replacement));
        }
    }
    document.prune_objects();
    document.renumber_objects();
    document.compress();
    document.save(output_path)?;
    Ok(())
}

fn decode_pdf_image(
    document: &Document,
    stream: &Stream,
) -> Result<Option<DynamicImage>, CompressError> {
    if stream.dict.has(b"SMask")
        || stream.dict.has(b"Mask")
        || stream
            .dict
            .get(b"ImageMask")
            .ok()
            .and_then(|value| value.as_bool().ok())
            .unwrap_or(false)
    {
        return Ok(None);
    }
    let width = image_dimension(stream, b"Width")?;
    let height = image_dimension(stream, b"Height")?;
    if u64::from(width).saturating_mul(u64::from(height)) > MAX_IMAGE_PIXELS {
        return Ok(None);
    }
    if filter_names(stream)
        .iter()
        .any(|name| *name == b"DCTDecode")
    {
        let reader = ImageReader::new(Cursor::new(&stream.content)).with_guessed_format()?;
        return reader.decode().map(Some).map_err(CompressError::Image);
    }
    if !filter_names(stream)
        .iter()
        .all(|name| matches!(*name, b"FlateDecode" | b"ASCII85Decode" | b"LZWDecode"))
    {
        return Ok(None);
    }
    if stream
        .dict
        .get(b"BitsPerComponent")
        .ok()
        .and_then(|value| value.as_i64().ok())
        != Some(8)
    {
        return Ok(None);
    }
    let data = stream
        .decompressed_content_with_limit(MAX_IMAGE_BYTES)
        .map_err(CompressError::Pdf)?;
    let color_space = resolved_color_space_name(document, stream);
    match color_space.as_deref() {
        Some(b"DeviceRGB") => {
            Ok(RgbImage::from_raw(width, height, data).map(DynamicImage::ImageRgb8))
        }
        Some(b"DeviceGray") => {
            Ok(GrayImage::from_raw(width, height, data).map(DynamicImage::ImageLuma8))
        }
        _ => Ok(None),
    }
}

fn image_dimension(stream: &Stream, key: &[u8]) -> Result<u32, CompressError> {
    stream
        .dict
        .get(key)?
        .as_i64()
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            CompressError::Pdf(lopdf::Error::Syntax(format!(
                "image {} is invalid",
                String::from_utf8_lossy(key)
            )))
        })
}

fn filter_names(stream: &Stream) -> Vec<&[u8]> {
    match stream.dict.get(b"Filter") {
        Ok(Object::Name(name)) => vec![name.as_slice()],
        Ok(Object::Array(filters)) => filters
            .iter()
            .filter_map(|value| value.as_name().ok())
            .collect(),
        _ => Vec::new(),
    }
}

fn resolved_color_space_name(document: &Document, stream: &Stream) -> Option<Vec<u8>> {
    let value = stream.dict.get(b"ColorSpace").ok()?;
    let (_, value) = document.dereference(value).ok()?;
    match value {
        Object::Name(name) => Some(name.clone()),
        Object::Array(values) => values
            .first()
            .and_then(|value| value.as_name().ok())
            .map(ToOwned::to_owned),
        _ => None,
    }
}

fn compress_image_stream(
    original: &Stream,
    mut image: DynamicImage,
    level: i32,
    grayscale: bool,
) -> Result<Option<Stream>, CompressError> {
    let width = image.width();
    let height = image.height();
    if (width <= 400 || height <= 400) && !grayscale {
        return Ok(None);
    }
    if grayscale {
        image = DynamicImage::ImageLuma8(image.to_luma8());
    }
    let factor = adjusted_scale_factor(level, width, height);
    let new_width = scaled_dimension(width, factor).max(400);
    let new_height = scaled_dimension(height, factor).max(400);
    if f64::from(new_width) / f64::from(width) > 0.95
        && f64::from(new_height) / f64::from(height) > 0.95
        && !grayscale
    {
        return Ok(None);
    }
    let resized = image.resize_exact(new_width, new_height, FilterType::CatmullRom);
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, jpeg_quality(level)).encode_image(&resized)?;
    if jpeg.len() >= original.content.len() && !grayscale {
        return Ok(None);
    }
    let color_space = if grayscale { "DeviceGray" } else { "DeviceRGB" };
    Ok(Some(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => i64::from(new_width),
            "Height" => i64::from(new_height),
            "ColorSpace" => color_space,
            "BitsPerComponent" => 8,
            "Filter" => "DCTDecode",
        },
        jpeg,
    )))
}

fn line_art_stream(
    image: &DynamicImage,
    threshold: f64,
    edge_level: i32,
) -> Result<Stream, CompressError> {
    let grayscale = image.to_luma8();
    let width = grayscale.width();
    let height = grayscale.height();
    let radius = u32::try_from(edge_level).map_err(|_| CompressError::InvalidLineArtEdgeLevel)?;
    let gradients = sobel_gradients(&grayscale, radius);
    let maximum = gradients.iter().copied().max().unwrap_or(0);
    let row_bytes = width.div_ceil(8);
    let capacity = u64::from(row_bytes).saturating_mul(u64::from(height));
    let capacity = usize::try_from(capacity).map_err(|_| CompressError::InvalidLineArtThreshold)?;
    let mut packed = vec![0_u8; capacity];
    let threshold_value = threshold / 100.0;
    for y in 0..height {
        for x in 0..width {
            let index = usize::try_from(u64::from(y) * u64::from(width) + u64::from(x))
                .map_err(|_| CompressError::InvalidLineArtThreshold)?;
            let normalized = if maximum == 0 {
                0.0
            } else {
                f64::from(gradients[index]) / f64::from(maximum)
            };
            let negated = 1.0 - normalized;
            if negated >= threshold_value {
                let byte_index =
                    usize::try_from(u64::from(y) * u64::from(row_bytes) + u64::from(x / 8))
                        .map_err(|_| CompressError::InvalidLineArtThreshold)?;
                packed[byte_index] |= 1 << (7 - (x % 8));
            }
        }
    }
    Ok(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => i64::from(width),
            "Height" => i64::from(height),
            "ColorSpace" => "DeviceGray",
            "BitsPerComponent" => 1,
        },
        packed,
    ))
}

fn sobel_gradients(image: &GrayImage, radius: u32) -> Vec<u32> {
    let width = image.width();
    let height = image.height();
    let count = usize::try_from(u64::from(width) * u64::from(height)).unwrap_or(0);
    let mut output = vec![0_u32; count];
    if width <= radius.saturating_mul(2) || height <= radius.saturating_mul(2) {
        return output;
    }
    for y in radius..height - radius {
        for x in radius..width - radius {
            let top_left = i32::from(image.get_pixel(x - radius, y - radius)[0]);
            let top = i32::from(image.get_pixel(x, y - radius)[0]);
            let top_right = i32::from(image.get_pixel(x + radius, y - radius)[0]);
            let left = i32::from(image.get_pixel(x - radius, y)[0]);
            let right = i32::from(image.get_pixel(x + radius, y)[0]);
            let bottom_left = i32::from(image.get_pixel(x - radius, y + radius)[0]);
            let bottom = i32::from(image.get_pixel(x, y + radius)[0]);
            let bottom_right = i32::from(image.get_pixel(x + radius, y + radius)[0]);
            let gradient_x =
                -top_left + top_right - 2 * left + 2 * right - bottom_left + bottom_right;
            let gradient_y =
                -top_left - 2 * top - top_right + bottom_left + 2 * bottom + bottom_right;
            let magnitude = gradient_x
                .unsigned_abs()
                .saturating_add(gradient_y.unsigned_abs());
            let index =
                usize::try_from(u64::from(y) * u64::from(width) + u64::from(x)).unwrap_or(0);
            output[index] = magnitude;
        }
    }
    output
}

fn adjusted_scale_factor(level: i32, width: u32, height: u32) -> f64 {
    let base: f64 = match level {
        1 => 0.98,
        2 => 0.95,
        3 => 0.88,
        4 => 0.78,
        5 => 0.68,
        6 => 0.58,
        7 => 0.48,
        8 => 0.38,
        9 => 0.28,
        _ => 1.0,
    };
    if width > 3_000 || height > 3_000 {
        base.min(0.75)
    } else if width < 1_000 || height < 1_000 {
        base.max(0.9)
    } else {
        base
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn scaled_dimension(value: u32, factor: f64) -> u32 {
    (f64::from(value) * factor)
        .floor()
        .clamp(1.0, f64::from(u32::MAX)) as u32
}

const fn jpeg_quality(level: i32) -> u8 {
    match level {
        1 => 92,
        2 => 88,
        3 => 85,
        4 => 80,
        5 => 72,
        6 => 65,
        7 => 55,
        8 => 45,
        9 => 35,
        _ => 75,
    }
}

fn try_ghostscript_compression(
    input_path: &Path,
    output_path: &Path,
    level: i32,
    grayscale: bool,
) -> Result<bool, CompressError> {
    let commands = ghostscript_commands();
    let mut arguments = vec![
        OsString::from("-sDEVICE=pdfwrite"),
        OsString::from("-dCompatibilityLevel=1.5"),
        OsString::from("-dNOPAUSE"),
        OsString::from("-dQUIET"),
        OsString::from("-dBATCH"),
        OsString::from("-dSAFER"),
        OsString::from("-dDetectDuplicateImages=true"),
        OsString::from("-dDownsampleColorImages=true"),
        OsString::from("-dCompressFonts=true"),
        OsString::from("-dSubsetFonts=true"),
    ];
    arguments.extend(
        ghostscript_level_arguments(level)
            .into_iter()
            .map(OsString::from),
    );
    if grayscale {
        arguments.push(OsString::from("-dColorConversionStrategy=/Gray"));
        arguments.push(OsString::from("-dProcessColorModel=/DeviceGray"));
    } else if level >= 7 {
        arguments.push(OsString::from("-dConvertCMYKImagesToRGB=true"));
    }
    arguments.push(output_argument(output_path));
    arguments.push(input_path.as_os_str().to_owned());
    run_optional_command(
        &commands.candidates,
        commands.explicitly_configured,
        &arguments,
        output_path,
    )
}

fn ghostscript_level_arguments(level: i32) -> Vec<&'static str> {
    match level {
        1 => vec!["-dPDFSETTINGS=/prepress"],
        2 => vec!["-dPDFSETTINGS=/printer"],
        3 => vec!["-dPDFSETTINGS=/ebook"],
        4 | 5 => vec!["-dPDFSETTINGS=/screen"],
        6 | 7 => vec![
            "-dPDFSETTINGS=/screen",
            "-dColorImageResolution=150",
            "-dGrayImageResolution=150",
            "-dMonoImageResolution=300",
        ],
        8 => vec![
            "-dPDFSETTINGS=/screen",
            "-dColorImageResolution=100",
            "-dGrayImageResolution=100",
            "-dMonoImageResolution=200",
        ],
        _ => vec![
            "-dPDFSETTINGS=/screen",
            "-dColorImageResolution=72",
            "-dGrayImageResolution=72",
            "-dMonoImageResolution=150",
        ],
    }
}

fn try_qpdf_compression(
    input_path: &Path,
    output_path: &Path,
    level: i32,
    linearize: bool,
    normalize: bool,
) -> Result<bool, CompressError> {
    let (commands, explicitly_configured) = qpdf_commands();
    let mut arguments = Vec::new();
    if normalize {
        arguments.push(OsString::from("--normalize-content=y"));
    }
    if linearize {
        arguments.push(OsString::from("--linearize"));
    }
    arguments.extend([
        OsString::from("--decode-level=generalized"),
        OsString::from("--recompress-flate"),
        OsString::from(format!(
            "--compression-level={}",
            qpdf_compression_level(level)
        )),
        OsString::from("--compress-streams=y"),
        OsString::from("--stream-data=compress"),
    ]);
    if level <= 3 {
        arguments.push(OsString::from("--preserve-unreferenced"));
    }
    if level >= 5 {
        arguments.push(OsString::from("--optimize-images"));
        arguments.push(OsString::from(format!(
            "--jpeg-quality={}",
            qpdf_jpeg_quality(level)
        )));
    }
    arguments.push(OsString::from("--object-streams=generate"));
    arguments.push(input_path.as_os_str().to_owned());
    arguments.push(output_path.as_os_str().to_owned());
    run_optional_command(&commands, explicitly_configured, &arguments, output_path)
}

const fn qpdf_compression_level(level: i32) -> i32 {
    match level {
        1 => 3,
        2 => 5,
        3..=5 => 7,
        _ => 9,
    }
}

const fn qpdf_jpeg_quality(level: i32) -> i32 {
    match level {
        5 => 78,
        6 => 68,
        7 => 58,
        8 => 46,
        _ => 34,
    }
}

fn qpdf_commands() -> (Vec<String>, bool) {
    if let Ok(command) = env::var(QPDF_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return (vec![command], true);
    }
    if cfg!(windows) {
        (vec!["qpdf.exe".to_owned(), "qpdf".to_owned()], false)
    } else {
        (vec!["qpdf".to_owned()], false)
    }
}

fn output_argument(output_path: &Path) -> OsString {
    let mut argument = OsString::from("-sOutputFile=");
    argument.push(output_path.as_os_str());
    argument
}

fn run_optional_command(
    commands: &[String],
    explicitly_configured: bool,
    arguments: &[OsString],
    output_path: &Path,
) -> Result<bool, CompressError> {
    for command in commands {
        let result = Command::new(command).args(arguments).output();
        match result {
            Ok(output) if output.status.success() => {
                return Ok(output_path
                    .metadata()
                    .is_ok_and(|metadata| metadata.len() > 0));
            }
            Ok(output) if explicitly_configured => {
                return Err(CompressError::ExternalFailed {
                    command: command.clone(),
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) if explicitly_configured => {
                return Err(CompressError::ExternalStart {
                    command: command.clone(),
                    source,
                });
            }
            Ok(_) | Err(_) => return Ok(false),
        }
    }
    Ok(false)
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

fn parse_size_bytes(value: &str) -> Result<u64, CompressError> {
    let normalized = value
        .trim()
        .to_ascii_uppercase()
        .replace(',', ".")
        .replace(' ', "");
    let (number, multiplier) = [
        ("TB", 1_099_511_627_776_f64),
        ("GB", 1_073_741_824_f64),
        ("MB", 1_048_576_f64),
        ("KB", 1_024_f64),
        ("B", 1_f64),
    ]
    .into_iter()
    .find_map(|(suffix, multiplier)| {
        normalized
            .strip_suffix(suffix)
            .map(|number| (number, multiplier))
    })
    .unwrap_or((normalized.as_str(), 1_048_576_f64));
    let number = number
        .parse::<f64>()
        .map_err(|_| CompressError::InvalidExpectedOutputSize)?;
    let bytes = number * multiplier;
    if !bytes.is_finite() || !(0.0..=MAX_JAVA_SIZE).contains(&bytes) {
        return Err(CompressError::InvalidExpectedOutputSize);
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bytes = bytes.floor() as u64;
    Ok(bytes)
}

fn determine_optimize_level(target_size: u64, input_size: u64) -> i32 {
    if input_size == 0 {
        return 9;
    }
    let target = u128::from(target_size);
    let input = u128::from(input_size);
    if target * 10 > input * 9 {
        1
    } else if target * 10 > input * 8 {
        2
    } else if target * 10 > input * 7 {
        3
    } else if target * 10 > input * 6 {
        4
    } else if target * 10 > input * 3 {
        5
    } else if target * 10 > input * 2 {
        6
    } else if target * 20 > input * 3 {
        7
    } else if target * 10 > input {
        8
    } else {
        9
    }
}

fn increment_optimize_level(level: i32, current_size: u64, target_size: u64) -> i32 {
    if target_size == 0 {
        return 9;
    }
    let current = u128::from(current_size);
    let target = u128::from(target_size);
    let increment = if current > target * 2 {
        3
    } else if current * 2 > target * 3 {
        2
    } else {
        1
    };
    (level + increment).min(9)
}

#[cfg(test)]
mod tests {
    use super::{determine_optimize_level, increment_optimize_level, parse_size_bytes};

    #[test]
    fn parses_java_compatible_target_sizes() -> Result<(), super::CompressError> {
        assert_eq!(parse_size_bytes("25KB")?, 25 * 1_024);
        assert_eq!(parse_size_bytes("1,5 MB")?, 1_572_864);
        assert_eq!(parse_size_bytes("2")?, 2 * 1_048_576);
        assert!(parse_size_bytes("not-a-size").is_err());
        Ok(())
    }

    #[test]
    fn escalates_java_compatible_optimization_levels() {
        assert_eq!(determine_optimize_level(95, 100), 1);
        assert_eq!(determine_optimize_level(50, 100), 5);
        assert_eq!(determine_optimize_level(5, 100), 9);
        assert_eq!(increment_optimize_level(5, 250, 100), 8);
        assert_eq!(increment_optimize_level(8, 160, 100), 9);
    }
}
