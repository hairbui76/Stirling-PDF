use std::path::Path;

use lopdf::Document;
use thiserror::Error;

use crate::pdfium_backend::{PdfiumTextError, PdfiumTitleAttempt, try_detect_largest_text_title};

#[derive(Debug, Error)]
pub enum AutoRenameError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("the configured PDFium runtime is unavailable: {details}")]
    PdfiumRuntime { details: String },
    #[error("could not inspect PDF text with PDFium: {0}")]
    Pdfium(#[from] PdfiumTextError),
    #[error("could not write the renamed PDF: {0}")]
    Write(std::io::Error),
}

/// Chooses the Java-compatible title-derived filename and normalizes the PDF.
///
/// # Errors
///
/// Returns [`AutoRenameError`] for unreadable PDFs, an explicitly configured
/// but unavailable `PDFium` runtime, text inspection failures, or output I/O.
pub fn auto_rename_to_file(
    input_path: &Path,
    filename: &str,
    _use_first_text_as_fallback: bool,
    output_path: &Path,
) -> Result<String, AutoRenameError> {
    let title_attempt = try_detect_largest_text_title(input_path, filename)?;
    let mut document = Document::load(input_path).map_err(|source| AutoRenameError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let title = match title_attempt {
        PdfiumTitleAttempt::Detected(title) => title,
        PdfiumTitleAttempt::Unavailable {
            explicitly_configured: false,
            ..
        } => first_extracted_line(&document),
        PdfiumTitleAttempt::Unavailable {
            explicitly_configured: true,
            details,
        } => return Err(AutoRenameError::PdfiumRuntime { details }),
    };
    let output_filename = title
        .filter(|title| title.encode_utf16().count() < 255)
        .map(|title| sanitize_title(&title))
        .map_or_else(|| filename.to_owned(), |title| format!("{title}.pdf"));
    document.save(output_path).map_err(AutoRenameError::Write)?;
    Ok(output_filename)
}

fn first_extracted_line(document: &Document) -> Option<String> {
    let pages: Vec<u32> = document.get_pages().into_keys().collect();
    document.extract_text(&pages).ok().and_then(|text| {
        text.lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned)
    })
}

fn sanitize_title(title: &str) -> String {
    title
        .chars()
        .filter(|character| {
            !matches!(
                character,
                '/' | '\\' | '?' | '%' | '*' | ':' | '|' | '"' | '<' | '>'
            )
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::sanitize_title;

    #[test]
    fn removes_only_the_java_safe_filename_characters() {
        assert_eq!(sanitize_title("  Report:/2026?  "), "Report2026");
        assert_eq!(sanitize_title("Résumé 😀"), "Résumé 😀");
    }
}
