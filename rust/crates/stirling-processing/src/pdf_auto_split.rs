use std::path::Path;

use thiserror::Error;

use crate::{
    pdf_flatten::configured_max_render_dpi,
    pdfium_backend::{PdfiumAutoSplitAttempt, PdfiumAutoSplitError, try_auto_split_pdf_to_zip},
};

#[derive(Debug, Error)]
pub enum AutoSplitError {
    #[error("PDFium is required to detect auto-split QR dividers: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumAutoSplitError),
}

/// Splits a PDF at Stirling QR divider pages and writes the results to a ZIP.
///
/// # Errors
///
/// Returns [`AutoSplitError`] when `PDFium` is unavailable, QR rendering or page
/// copying fails, or the output archive cannot be written.
pub fn auto_split_pdf_to_zip(
    input_path: &Path,
    filename: &str,
    duplex_mode: bool,
    output_path: &Path,
) -> Result<(), AutoSplitError> {
    match try_auto_split_pdf_to_zip(
        input_path,
        filename,
        duplex_mode,
        configured_max_render_dpi(),
        output_path,
    )? {
        PdfiumAutoSplitAttempt::Split => Ok(()),
        PdfiumAutoSplitAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(AutoSplitError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}
