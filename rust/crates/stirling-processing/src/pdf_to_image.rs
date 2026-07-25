use std::path::Path;

use thiserror::Error;

use crate::{
    pdf_flatten::configured_max_render_dpi,
    pdfium_backend::{
        PdfToImageColor, PdfToImageFormat, PdfToImageMode, PdfiumToImageAttempt,
        PdfiumToImageError, try_convert_pdf_to_images,
    },
};

#[derive(Debug, Clone)]
pub struct PdfToImageOptions {
    pub image_format: String,
    pub single_or_multiple: String,
    pub color_type: String,
    pub dpi: i32,
    pub page_numbers: String,
    pub include_annotations: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfToImageOutput {
    Single {
        extension: &'static str,
        content_type: &'static str,
    },
    Multiple,
}

#[derive(Debug, Error)]
pub enum PdfToImageError {
    #[error("imageFormat must be png, jpeg, jpg, gif, or webp")]
    InvalidFormat,
    #[error("singleOrMultiple must be single or multiple")]
    InvalidMode,
    #[error("colorType must be color, greyscale, grayscale, or blackwhite")]
    InvalidColorType,
    #[error("dpi must be greater than zero")]
    InvalidDpi,
    #[error("DPI value {requested} exceeds maximum safe limit of {maximum}")]
    DpiExceedsLimit { requested: i32, maximum: i32 },
    #[error("PDFium is required to convert PDFs to images: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumToImageError),
}

/// Converts selected PDF pages into one vertically combined image or a ZIP of images.
///
/// # Errors
///
/// Returns [`PdfToImageError`] when options are invalid, `PDFium` is unavailable,
/// the PDF cannot be rendered safely, or an output image cannot be encoded.
pub fn convert_pdf_to_images(
    input_path: &Path,
    filename: &str,
    options: &PdfToImageOptions,
    output_path: &Path,
) -> Result<PdfToImageOutput, PdfToImageError> {
    let (format, single_output) = parse_format(&options.image_format)?;
    let mode = match options
        .single_or_multiple
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "single" => PdfToImageMode::Single,
        "multiple" => PdfToImageMode::Multiple,
        _ => return Err(PdfToImageError::InvalidMode),
    };
    let color = match options.color_type.trim().to_ascii_lowercase().as_str() {
        "color" => PdfToImageColor::Color,
        "greyscale" | "grayscale" => PdfToImageColor::Greyscale,
        "blackwhite" => PdfToImageColor::BlackWhite,
        _ => return Err(PdfToImageError::InvalidColorType),
    };
    let output = if mode == PdfToImageMode::Single {
        single_output
    } else {
        PdfToImageOutput::Multiple
    };
    if options.dpi <= 0 {
        return Err(PdfToImageError::InvalidDpi);
    }
    let maximum = configured_max_render_dpi();
    if options.dpi > maximum {
        return Err(PdfToImageError::DpiExceedsLimit {
            requested: options.dpi,
            maximum,
        });
    }
    let page_numbers = if options.page_numbers.trim().is_empty() {
        "all"
    } else {
        options.page_numbers.trim()
    };
    match try_convert_pdf_to_images(
        input_path,
        filename,
        page_numbers,
        format,
        mode,
        color,
        options.dpi,
        options.include_annotations,
        output_path,
    )? {
        PdfiumToImageAttempt::Converted => Ok(output),
        PdfiumToImageAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(PdfToImageError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}

fn parse_format(value: &str) -> Result<(PdfToImageFormat, PdfToImageOutput), PdfToImageError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "png" => Ok((
            PdfToImageFormat::Png,
            PdfToImageOutput::Single {
                extension: "png",
                content_type: "image/png",
            },
        )),
        "jpeg" => Ok((
            PdfToImageFormat::Jpeg { extension: "jpeg" },
            PdfToImageOutput::Single {
                extension: "jpeg",
                content_type: "image/jpeg",
            },
        )),
        "jpg" => Ok((
            PdfToImageFormat::Jpeg { extension: "jpg" },
            PdfToImageOutput::Single {
                extension: "jpg",
                content_type: "image/jpeg",
            },
        )),
        "gif" => Ok((
            PdfToImageFormat::Gif,
            PdfToImageOutput::Single {
                extension: "gif",
                content_type: "image/gif",
            },
        )),
        "webp" => Ok((
            PdfToImageFormat::WebP,
            PdfToImageOutput::Single {
                extension: "webp",
                content_type: "image/webp",
            },
        )),
        _ => Err(PdfToImageError::InvalidFormat),
    }
}

#[cfg(test)]
mod tests {
    use super::{PdfToImageError, PdfToImageOptions, convert_pdf_to_images};
    use tempfile::tempdir;

    fn options() -> PdfToImageOptions {
        PdfToImageOptions {
            image_format: "png".to_owned(),
            single_or_multiple: "single".to_owned(),
            color_type: "color".to_owned(),
            dpi: 72,
            page_numbers: "all".to_owned(),
            include_annotations: false,
        }
    }

    #[test]
    fn validates_options_before_loading_pdfium() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output");

        let mut request = options();
        request.image_format = "bmp".to_owned();
        assert!(matches!(
            convert_pdf_to_images(&input, "input.pdf", &request, &output),
            Err(PdfToImageError::InvalidFormat)
        ));

        request = options();
        request.single_or_multiple = "archive".to_owned();
        assert!(matches!(
            convert_pdf_to_images(&input, "input.pdf", &request, &output),
            Err(PdfToImageError::InvalidMode)
        ));

        request = options();
        request.color_type = "sepia".to_owned();
        assert!(matches!(
            convert_pdf_to_images(&input, "input.pdf", &request, &output),
            Err(PdfToImageError::InvalidColorType)
        ));

        request = options();
        request.dpi = 0;
        assert!(matches!(
            convert_pdf_to_images(&input, "input.pdf", &request, &output),
            Err(PdfToImageError::InvalidDpi)
        ));
        Ok(())
    }
}
