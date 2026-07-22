use std::path::Path;

use thiserror::Error;

use crate::pdfium_backend::{
    ExtractImageFormat, PdfiumExtractImagesAttempt, PdfiumExtractImagesError,
    try_extract_page_images_to_zip,
};

#[derive(Debug, Error)]
pub enum ExtractImagesError {
    #[error("format must be png, jpg, jpeg, or gif")]
    InvalidFormat,
    #[error("PDFium is required to decode embedded images: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumExtractImagesError),
}

/// Extracts unique top-level page image objects into a ZIP archive.
///
/// # Errors
///
/// Returns [`ExtractImagesError`] for invalid formats, unavailable `PDFium`,
/// PDF/image decode failures, or archive I/O failures.
pub fn extract_images_to_zip(
    input_path: &Path,
    filename: &str,
    format: &str,
    output_path: &Path,
) -> Result<(), ExtractImagesError> {
    let normalized = format.trim().to_ascii_lowercase();
    let (format, extension) = match normalized.as_str() {
        "png" => (ExtractImageFormat::Png, "png"),
        "jpg" => (ExtractImageFormat::Jpeg, "jpg"),
        "jpeg" => (ExtractImageFormat::Jpeg, "jpeg"),
        "gif" => (ExtractImageFormat::Gif, "gif"),
        _ => return Err(ExtractImagesError::InvalidFormat),
    };
    let base_filename = filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem);
    match try_extract_page_images_to_zip(
        input_path,
        filename,
        base_filename,
        format,
        extension,
        output_path,
    )? {
        PdfiumExtractImagesAttempt::Extracted => Ok(()),
        PdfiumExtractImagesAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(ExtractImagesError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}
