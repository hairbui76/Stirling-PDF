use std::{fmt::Write as _, path::Path};

use lopdf::Document;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextOutputFormat {
    Text,
    RichText,
}

impl TextOutputFormat {
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Text => "txt",
            Self::RichText => "rtf",
        }
    }

    #[must_use]
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain; charset=utf-8",
            Self::RichText => "application/octet-stream",
        }
    }
}

#[derive(Debug, Error)]
pub enum PdfTextError {
    #[error("outputFormat must be txt or rtf")]
    InvalidFormat,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not extract text from '{filename}': {source}")]
    ExtractText {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not write converted text: {0}")]
    Write(#[from] std::io::Error),
}

/// Extracts PDF text into UTF-8 plain text or a text-only Unicode RTF document.
///
/// # Errors
///
/// Returns [`PdfTextError`] for unsupported formats, malformed PDFs, text
/// extraction failures, or output I/O failures.
pub fn pdf_to_text_file(
    input_path: &Path,
    filename: &str,
    output_format: &str,
    output_path: &Path,
) -> Result<TextOutputFormat, PdfTextError> {
    let output_format = match output_format.trim().to_ascii_lowercase().as_str() {
        "txt" => TextOutputFormat::Text,
        "rtf" => TextOutputFormat::RichText,
        _ => return Err(PdfTextError::InvalidFormat),
    };
    let document = Document::load(input_path).map_err(|source| PdfTextError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let pages = document.get_pages().keys().copied().collect::<Vec<_>>();
    let text = document
        .extract_text(&pages)
        .map_err(|source| PdfTextError::ExtractText {
            filename: filename.to_owned(),
            source,
        })?;
    let output = match output_format {
        TextOutputFormat::Text => text,
        TextOutputFormat::RichText => encode_rtf(&text),
    };
    std::fs::write(output_path, output.as_bytes())?;
    Ok(output_format)
}

fn encode_rtf(text: &str) -> String {
    let mut output = String::from("{\\rtf1\\ansi\\deff0\\uc1{\\fonttbl{\\f0\\fnil Arial;}}\\f0 ");
    for character in text.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '{' => output.push_str("\\{"),
            '}' => output.push_str("\\}"),
            '\r' => {}
            '\n' => output.push_str("\\par\n"),
            '\t' => output.push_str("\\tab "),
            ' '..='~' => output.push(character),
            _ => push_rtf_unicode(&mut output, character),
        }
    }
    output.push('}');
    output
}

fn push_rtf_unicode(output: &mut String, character: char) {
    let mut utf16 = [0_u16; 2];
    for code_unit in character.encode_utf16(&mut utf16) {
        let signed = i16::from_ne_bytes(code_unit.to_ne_bytes());
        let _ = write!(output, "\\u{signed}?");
    }
}

#[cfg(test)]
mod tests {
    use super::encode_rtf;

    #[test]
    fn escapes_rtf_control_text_and_unicode() {
        let rtf = encode_rtf("A\\{B}\nViệt 😀");
        assert!(rtf.starts_with("{\\rtf1"));
        assert!(rtf.contains("A\\\\\\{B\\}"));
        assert!(rtf.contains("\\par\n"));
        assert!(rtf.contains("\\u"));
        assert!(rtf.ends_with('}'));
    }
}
