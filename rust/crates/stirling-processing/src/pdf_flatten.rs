use std::{env, path::Path};

use lopdf::Document;
use thiserror::Error;

use crate::{
    pdf_metadata::{
        apply_default_loaded_document_metadata, normalize_rebuilt_document_metadata_from_source,
    },
    pdfium_backend::{PdfiumFlattenAttempt, PdfiumFlattenError, try_flatten_pdf_to_file},
};

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
    #[error("could not read flattened PDF metadata: {0}")]
    Metadata(#[from] lopdf::Error),
    #[error("could not write flattened PDF metadata: {0}")]
    Write(#[from] std::io::Error),
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
        PdfiumFlattenAttempt::Flattened => {
            normalize_flattened_metadata(input_path, flatten_only_forms, output_path)
        }
        PdfiumFlattenAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(FlattenError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}

fn normalize_flattened_metadata(
    input_path: &Path,
    flatten_only_forms: bool,
    output_path: &Path,
) -> Result<(), FlattenError> {
    let source = Document::load(input_path)?;
    let mut output = Document::load(output_path)?;
    if flatten_only_forms {
        apply_default_loaded_document_metadata(&mut output);
    } else {
        normalize_rebuilt_document_metadata_from_source(&mut output, &source);
    }
    output.prune_objects();
    output.save(output_path)?;
    Ok(())
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
