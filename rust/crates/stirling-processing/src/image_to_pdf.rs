use std::{
    fs::File,
    io::BufReader,
    path::{Path, PathBuf},
};

use image::{
    DynamicImage, GrayAlphaImage, GrayImage, ImageDecoder, ImageReader, RgbImage, RgbaImage,
};
use lopdf::{Document, Object, Stream, dictionary};
use thiserror::Error;
use tiff::{
    ColorType as TiffColorType,
    decoder::{Decoder as TiffDecoder, DecodingResult},
};

use crate::pdf_metadata::apply_default_new_document_metadata;

const A4_WIDTH: f32 = 595.275_63;
const A4_HEIGHT: f32 = 841.889_8;

#[derive(Debug, Clone)]
pub struct ImageInput {
    pub filename: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ImageToPdfOptions {
    pub fit_option: String,
    pub color_type: String,
    pub auto_rotate: bool,
}

#[derive(Debug, Clone, Copy)]
enum FitOption {
    FillPage,
    FitDocumentToImage,
    MaintainAspectRatio,
}

#[derive(Debug, Clone, Copy)]
enum OutputColor {
    Color,
    Greyscale,
    BlackWhite,
}

#[derive(Debug, Error)]
pub enum ImageToPdfError {
    #[error("at least one fileInput image is required")]
    NoImages,
    #[error("fitOption must be fillPage, fitDocumentToImage, or maintainAspectRatio")]
    InvalidFitOption,
    #[error("colorType must be color, greyscale, grayscale, or blackwhite")]
    InvalidColorType,
    #[error("could not open image '{filename}': {source}")]
    OpenImage {
        filename: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not decode image '{filename}': {source}")]
    DecodeImage {
        filename: String,
        #[source]
        source: image::ImageError,
    },
    #[error("could not decode TIFF image '{filename}': {source}")]
    DecodeTiff {
        filename: String,
        #[source]
        source: tiff::TiffError,
    },
    #[error("TIFF image '{filename}' uses an unsupported {details}")]
    UnsupportedTiff { filename: String, details: String },
    #[error("image '{filename}' has invalid or unsafe dimensions {width}x{height}")]
    UnsafeDimensions {
        filename: String,
        width: u32,
        height: u32,
    },
    #[error("could not build the output PDF: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write the output PDF: {0}")]
    Write(#[from] std::io::Error),
}

/// Converts one or more raster images into one PDF page per image frame.
///
/// # Errors
///
/// Returns [`ImageToPdfError`] for invalid options, unsupported or unsafe
/// images, malformed image data, or PDF output failures.
pub fn images_to_pdf_file(
    inputs: &[ImageInput],
    options: &ImageToPdfOptions,
    output_path: &Path,
) -> Result<(), ImageToPdfError> {
    images_to_pdf_file_with_policy(inputs, options, false, output_path)
}

pub(crate) fn images_to_pdf_file_skipping_invalid_images(
    inputs: &[ImageInput],
    options: &ImageToPdfOptions,
    output_path: &Path,
) -> Result<(), ImageToPdfError> {
    images_to_pdf_file_with_policy(inputs, options, true, output_path)
}

fn images_to_pdf_file_with_policy(
    inputs: &[ImageInput],
    options: &ImageToPdfOptions,
    skip_invalid_images: bool,
    output_path: &Path,
) -> Result<(), ImageToPdfError> {
    if inputs.is_empty() {
        return Err(ImageToPdfError::NoImages);
    }
    let fit = match options.fit_option.trim() {
        "fillPage" | "" => FitOption::FillPage,
        "fitDocumentToImage" => FitOption::FitDocumentToImage,
        "maintainAspectRatio" => FitOption::MaintainAspectRatio,
        _ => return Err(ImageToPdfError::InvalidFitOption),
    };
    let color = match options.color_type.trim().to_ascii_lowercase().as_str() {
        "color" | "" => OutputColor::Color,
        "greyscale" | "grayscale" => OutputColor::Greyscale,
        "blackwhite" => OutputColor::BlackWhite,
        _ => return Err(ImageToPdfError::InvalidColorType),
    };

    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut page_ids = Vec::new();
    for input in inputs {
        let frames = match decode_input_frames(input) {
            Ok(frames) => frames,
            Err(_) if skip_invalid_images => continue,
            Err(error) => return Err(error),
        };
        for image in frames {
            if let Err(error) = validate_dimensions(&image, &input.filename) {
                if skip_invalid_images {
                    continue;
                }
                return Err(error);
            }
            add_image_page(
                &mut document,
                pages_id,
                &image,
                fit,
                color,
                options.auto_rotate,
                &mut page_ids,
            )?;
        }
    }
    if page_ids.is_empty() {
        return Err(ImageToPdfError::NoImages);
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids.iter().copied().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(page_ids.len()).map_err(|_| ImageToPdfError::NoImages)?,
        }),
    );
    let catalog_id = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog_id);
    apply_default_new_document_metadata(&mut document);
    document.compress();
    document.save(output_path)?;
    Ok(())
}

fn decode_input_frames(input: &ImageInput) -> Result<Vec<DynamicImage>, ImageToPdfError> {
    let extension = Path::new(&input.filename)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("tif") || extension.eq_ignore_ascii_case("tiff") {
        return decode_tiff_frames(input);
    }
    let file = File::open(&input.path).map_err(|source| ImageToPdfError::OpenImage {
        filename: input.filename.clone(),
        source,
    })?;
    let reader = ImageReader::new(BufReader::new(file))
        .with_guessed_format()
        .map_err(|source| ImageToPdfError::OpenImage {
            filename: input.filename.clone(),
            source,
        })?;
    let mut decoder = reader
        .into_decoder()
        .map_err(|source| ImageToPdfError::DecodeImage {
            filename: input.filename.clone(),
            source,
        })?;
    let orientation = decoder
        .orientation()
        .map_err(|source| ImageToPdfError::DecodeImage {
            filename: input.filename.clone(),
            source,
        })?;
    let mut image =
        DynamicImage::from_decoder(decoder).map_err(|source| ImageToPdfError::DecodeImage {
            filename: input.filename.clone(),
            source,
        })?;
    image.apply_orientation(orientation);
    Ok(vec![image])
}

fn decode_tiff_frames(input: &ImageInput) -> Result<Vec<DynamicImage>, ImageToPdfError> {
    let file = File::open(&input.path).map_err(|source| ImageToPdfError::OpenImage {
        filename: input.filename.clone(),
        source,
    })?;
    let mut decoder =
        TiffDecoder::new(BufReader::new(file)).map_err(|source| ImageToPdfError::DecodeTiff {
            filename: input.filename.clone(),
            source,
        })?;
    let mut images = Vec::new();
    loop {
        let dimensions = decoder
            .dimensions()
            .map_err(|source| ImageToPdfError::DecodeTiff {
                filename: input.filename.clone(),
                source,
            })?;
        let color_type = decoder
            .colortype()
            .map_err(|source| ImageToPdfError::DecodeTiff {
                filename: input.filename.clone(),
                source,
            })?;
        let samples = decoder
            .read_image()
            .map_err(|source| ImageToPdfError::DecodeTiff {
                filename: input.filename.clone(),
                source,
            })?;
        images.push(tiff_frame_to_image(
            dimensions,
            color_type,
            samples,
            &input.filename,
        )?);
        if !decoder.more_images() {
            break;
        }
        decoder
            .next_image()
            .map_err(|source| ImageToPdfError::DecodeTiff {
                filename: input.filename.clone(),
                source,
            })?;
    }
    Ok(images)
}

fn tiff_frame_to_image(
    (width, height): (u32, u32),
    color_type: TiffColorType,
    samples: DecodingResult,
    filename: &str,
) -> Result<DynamicImage, ImageToPdfError> {
    let samples = tiff_samples_to_u8(samples, filename)?;
    let invalid = || ImageToPdfError::UnsupportedTiff {
        filename: filename.to_owned(),
        details: format!("color type {color_type:?}"),
    };
    match color_type {
        TiffColorType::Gray(bits) if bits == 1 || bits == 8 || bits == 16 => {
            let samples = if bits == 1 {
                samples
                    .into_iter()
                    .map(|sample| if sample == 0 { 0 } else { 255 })
                    .collect()
            } else {
                samples
            };
            GrayImage::from_raw(width, height, samples)
                .map(DynamicImage::ImageLuma8)
                .ok_or_else(invalid)
        }
        TiffColorType::GrayA(8 | 16) => GrayAlphaImage::from_raw(width, height, samples)
            .map(DynamicImage::ImageLumaA8)
            .ok_or_else(invalid),
        TiffColorType::RGB(8 | 16) => RgbImage::from_raw(width, height, samples)
            .map(DynamicImage::ImageRgb8)
            .ok_or_else(invalid),
        TiffColorType::RGBA(8 | 16) => RgbaImage::from_raw(width, height, samples)
            .map(DynamicImage::ImageRgba8)
            .ok_or_else(invalid),
        TiffColorType::CMYK(8 | 16) => cmyk_to_rgb(width, height, &samples)
            .map(DynamicImage::ImageRgb8)
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

fn tiff_samples_to_u8(samples: DecodingResult, filename: &str) -> Result<Vec<u8>, ImageToPdfError> {
    match samples {
        DecodingResult::U8(samples) => Ok(samples),
        DecodingResult::U16(samples) => Ok(samples
            .into_iter()
            .map(|sample| u8::try_from(sample >> 8).unwrap_or(u8::MAX))
            .collect()),
        _ => Err(ImageToPdfError::UnsupportedTiff {
            filename: filename.to_owned(),
            details: "sample representation".to_owned(),
        }),
    }
}

fn cmyk_to_rgb(width: u32, height: u32, samples: &[u8]) -> Option<RgbImage> {
    let pixel_count = usize::try_from(width)
        .ok()?
        .checked_mul(usize::try_from(height).ok()?)?;
    if samples.len() != pixel_count.checked_mul(4)? {
        return None;
    }
    let mut rgb = Vec::with_capacity(pixel_count.checked_mul(3)?);
    for pixel in samples.chunks_exact(4) {
        let black = u16::from(pixel[3]);
        rgb.push(255_u8.saturating_sub(u8::try_from((u16::from(pixel[0]) + black).min(255)).ok()?));
        rgb.push(255_u8.saturating_sub(u8::try_from((u16::from(pixel[1]) + black).min(255)).ok()?));
        rgb.push(255_u8.saturating_sub(u8::try_from((u16::from(pixel[2]) + black).min(255)).ok()?));
    }
    RgbImage::from_raw(width, height, rgb)
}

fn validate_dimensions(image: &DynamicImage, filename: &str) -> Result<(), ImageToPdfError> {
    let width = image.width();
    let height = image.height();
    if width == 0
        || height == 0
        || u64::from(width).saturating_mul(u64::from(height)) > u64::from(i32::MAX.unsigned_abs())
    {
        return Err(ImageToPdfError::UnsafeDimensions {
            filename: filename.to_owned(),
            width,
            height,
        });
    }
    Ok(())
}

#[allow(clippy::cast_precision_loss, clippy::too_many_arguments)]
fn add_image_page(
    document: &mut Document,
    pages_id: lopdf::ObjectId,
    image: &DynamicImage,
    fit: FitOption,
    color: OutputColor,
    auto_rotate: bool,
    page_ids: &mut Vec<lopdf::ObjectId>,
) -> Result<(), ImageToPdfError> {
    let width = image.width();
    let height = image.height();
    let (image_id, image_width, image_height) = add_image_xobject(document, image, color)?;
    let (page_width, page_height) = match fit {
        FitOption::FitDocumentToImage => (width as f32, height as f32),
        FitOption::FillPage | FitOption::MaintainAspectRatio if auto_rotate && width > height => {
            (A4_HEIGHT, A4_WIDTH)
        }
        FitOption::FillPage | FitOption::MaintainAspectRatio => (A4_WIDTH, A4_HEIGHT),
    };
    let (draw_width, draw_height, x, y) = match fit {
        FitOption::FillPage | FitOption::FitDocumentToImage => (page_width, page_height, 0.0, 0.0),
        FitOption::MaintainAspectRatio => {
            let scale = (page_width / image_width).min(page_height / image_height);
            let draw_width = image_width * scale;
            let draw_height = image_height * scale;
            (
                draw_width,
                draw_height,
                (page_width - draw_width) / 2.0,
                (page_height - draw_height) / 2.0,
            )
        }
    };
    let content = format!(
        "q\n{} 0 0 {} {} {} cm\n/Im0 Do\nQ\n",
        pdf_number(draw_width),
        pdf_number(draw_height),
        pdf_number(x),
        pdf_number(y)
    );
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let output_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), f64::from(page_width).into(), f64::from(page_height).into()],
        "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => image_id } },
        "Contents" => content_id,
    });
    page_ids.push(output_page_id);
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn add_image_xobject(
    document: &mut Document,
    image: &DynamicImage,
    color: OutputColor,
) -> Result<(lopdf::ObjectId, f32, f32), ImageToPdfError> {
    let width = image.width();
    let height = image.height();
    let (color_space, pixels, alpha) = match color {
        OutputColor::Color => {
            let rgba = image.to_rgba8();
            let mut rgb = Vec::with_capacity(rgba.len() / 4 * 3);
            let mut alpha = Vec::with_capacity(rgba.len() / 4);
            let mut has_transparency = false;
            for pixel in rgba.pixels() {
                rgb.extend_from_slice(&pixel.0[..3]);
                alpha.push(pixel.0[3]);
                has_transparency |= pixel.0[3] != 255;
            }
            ("DeviceRGB", rgb, has_transparency.then_some(alpha))
        }
        OutputColor::Greyscale => ("DeviceGray", image.to_luma8().into_raw(), None),
        OutputColor::BlackWhite => {
            let mut pixels = image.to_luma8().into_raw();
            for pixel in &mut pixels {
                *pixel = if *pixel < 128 { 0 } else { 255 };
            }
            ("DeviceGray", pixels, None)
        }
    };
    let mut image_dictionary = dictionary! {
        "Type" => "XObject",
        "Subtype" => "Image",
        "Width" => i64::from(width),
        "Height" => i64::from(height),
        "ColorSpace" => color_space,
        "BitsPerComponent" => 8,
    };
    if let Some(alpha) = alpha {
        let mut mask = Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Image",
                "Width" => i64::from(width),
                "Height" => i64::from(height),
                "ColorSpace" => "DeviceGray",
                "BitsPerComponent" => 8,
            },
            alpha,
        );
        mask.compress()?;
        let mask_id = document.add_object(mask);
        image_dictionary.set("SMask", mask_id);
    }
    let mut stream = Stream::new(image_dictionary, pixels);
    stream.compress()?;
    let image_id = document.add_object(stream);
    Ok((image_id, width as f32, height as f32))
}

pub(crate) fn add_color_image_xobject(
    document: &mut Document,
    image: &DynamicImage,
) -> Result<(lopdf::ObjectId, f32, f32), ImageToPdfError> {
    add_image_xobject(document, image, OutputColor::Color)
}

fn pdf_number(value: f32) -> String {
    let mut output = format!("{value:.5}");
    while output.contains('.') && output.ends_with('0') {
        output.pop();
    }
    if output.ends_with('.') {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use super::pdf_number;

    #[test]
    fn writes_compact_locale_independent_pdf_numbers() {
        assert_eq!(pdf_number(10.0), "10");
        assert_eq!(pdf_number(10.125), "10.125");
    }
}
