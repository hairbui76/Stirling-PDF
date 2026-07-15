use std::{env, path::Path};

use thiserror::Error;

use crate::pdfium_backend::{PdfiumFlattenAttempt, PdfiumFlattenError, try_flatten_pdf_to_file};

const DEFAULT_MAX_RENDER_DPI: i32 = 500;

#[derive(Debug, Error)]
pub enum FlattenError {
    #[error("PDFium is required to flatten PDFs: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumFlattenError),
}

/// Flattens form fields or rasterizes every page using the Java-compatible DPI limits.
///
/// # Errors
///
/// Returns [`FlattenError`] when `PDFium` is unavailable, the PDF cannot be
/// read, a page is unsafe to render, or the output cannot be written.
pub fn flatten_pdf_to_file(
    input_path: &Path,
    filename: &str,
    flatten_only_forms: bool,
    requested_dpi: Option<i32>,
    output_path: &Path,
) -> Result<(), FlattenError> {
    let max_dpi = configured_max_render_dpi();
    let render_dpi = requested_dpi.map_or(max_dpi, |dpi| dpi.min(max_dpi).max(72));
    match try_flatten_pdf_to_file(
        input_path,
        filename,
        flatten_only_forms,
        render_dpi,
        output_path,
    )? {
        PdfiumFlattenAttempt::Flattened => Ok(()),
        PdfiumFlattenAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(FlattenError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}

pub(crate) fn configured_max_render_dpi() -> i32 {
    env::var("SYSTEM_MAXDPI")
        .ok()
        .and_then(|value| value.trim().parse::<i32>().ok())
        .filter(|dpi| *dpi > 0)
        .unwrap_or(DEFAULT_MAX_RENDER_DPI)
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_MAX_RENDER_DPI;

    #[test]
    fn default_maximum_matches_the_application_configuration() {
        assert_eq!(DEFAULT_MAX_RENDER_DPI, 500);
    }
}
