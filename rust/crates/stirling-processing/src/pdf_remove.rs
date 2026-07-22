use std::path::Path;

use lopdf::Document;
use thiserror::Error;

use crate::{
    page_selection::{PageSelectionError, parse_page_list},
    pdf_forms::{prune_orphaned_form_fields, prune_orphaned_form_fields_in_file},
    pdfium_backend::{PdfiumRemoveAttempt, PdfiumRemoveError, try_remove_pdf_pages_to_file},
};

#[derive(Debug, Error)]
pub enum RemovePagesError {
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not update PDF pages or form fields: {0}")]
    Update(#[from] lopdf::Error),
    #[error("could not write the PDF with removed pages: {0}")]
    Write(#[from] std::io::Error),
    #[error("the configured PDFium runtime is unavailable: {details}")]
    PdfiumRuntime { details: String },
    #[error(transparent)]
    Pdfium(#[from] PdfiumRemoveError),
}

/// Removes selected pages and prunes form fields whose widgets became orphaned.
///
/// # Errors
///
/// Returns an error for unsafe page expressions, unreadable PDFs, `PDFium`
/// failures, form pruning failures, or output write failures.
pub fn remove_pdf_pages_to_file(
    input_path: &Path,
    filename: &str,
    page_numbers: &str,
    output_path: &Path,
) -> Result<(), RemovePagesError> {
    match try_remove_pdf_pages_to_file(input_path, filename, page_numbers, output_path)? {
        PdfiumRemoveAttempt::Removed => {
            prune_orphaned_form_fields_in_file(output_path)?;
            return Ok(());
        }
        PdfiumRemoveAttempt::Unavailable {
            explicitly_configured: false,
            ..
        } => {}
        PdfiumRemoveAttempt::Unavailable {
            explicitly_configured: true,
            details,
        } => return Err(RemovePagesError::PdfiumRuntime { details }),
    }

    let mut document = Document::load(input_path).map_err(|source| RemovePagesError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let pages = parse_page_list(page_numbers, document.get_pages().len())?;
    let one_based_pages: Vec<u32> = pages
        .into_iter()
        .filter_map(|index| u32::try_from(index + 1).ok())
        .collect();
    document.delete_pages(&one_based_pages);
    prune_orphaned_form_fields(&mut document)?;
    document.save(output_path)?;
    Ok(())
}
