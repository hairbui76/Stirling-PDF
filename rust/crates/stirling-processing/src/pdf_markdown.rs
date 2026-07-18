//! PDF to Markdown conversion.
//!
//! The Java implementation uses `PDFium` text geometry to infer headings, columns,
//! tables, and image placement. This native baseline intentionally keeps the
//! conversion deterministic and safe: it extracts each page in document order,
//! rebuilds paragraphs, and escapes Markdown control characters so source PDF text
//! is preserved as literal content.

use std::{fs, path::Path};

use lopdf::Document;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PdfMarkdownError {
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
    #[error("could not write converted Markdown: {0}")]
    Write(#[from] std::io::Error),
}

/// Converts a PDF to UTF-8 Markdown and writes it to `output_path`.
///
/// # Errors
///
/// Returns [`PdfMarkdownError`] when the source is not a readable PDF, text cannot
/// be extracted, or the output cannot be written.
pub fn pdf_to_markdown_file(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), PdfMarkdownError> {
    let document = Document::load(input_path).map_err(|source| PdfMarkdownError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let mut pages = Vec::new();
    for page_number in document.get_pages().keys().copied() {
        let text = document.extract_text(&[page_number]).map_err(|source| {
            PdfMarkdownError::ExtractText {
                filename: filename.to_owned(),
                source,
            }
        })?;
        let markdown = text_to_markdown(&text);
        if !markdown.is_empty() {
            pages.push(markdown);
        }
    }
    fs::write(output_path, pages.join("\n\n"))?;
    Ok(())
}

fn text_to_markdown(text: &str) -> String {
    let mut blocks = Vec::new();
    let mut paragraph = String::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            flush_paragraph(&mut paragraph, &mut blocks);
            continue;
        }

        if let Some(item) = line
            .chars()
            .next()
            .filter(|character| matches!(character, '•' | '▪' | '◦'))
            .map(|character| &line[character.len_utf8()..])
        {
            flush_paragraph(&mut paragraph, &mut blocks);
            blocks.push(format!("- {}", escape_markdown(item.trim_start())));
            continue;
        }

        let line = escape_markdown(line);
        if paragraph.ends_with('-') && line.chars().next().is_some_and(char::is_lowercase) {
            paragraph.pop();
            paragraph.push_str(&line);
        } else {
            if !paragraph.is_empty() {
                paragraph.push(' ');
            }
            paragraph.push_str(&line);
        }
    }
    flush_paragraph(&mut paragraph, &mut blocks);
    blocks.join("\n\n")
}

fn flush_paragraph(paragraph: &mut String, blocks: &mut Vec<String>) {
    if !paragraph.is_empty() {
        blocks.push(std::mem::take(paragraph));
    }
}

fn escape_markdown(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '*' | '_' | '`' | '[' | ']' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    if matches!(escaped.chars().next(), Some('#' | '>' | '+' | '-')) {
        escaped.insert(0, '\\');
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{escape_markdown, text_to_markdown};

    #[test]
    fn keeps_text_literal_and_rebuilds_paragraphs() {
        assert_eq!(
            text_to_markdown("First *line*\ncontinues\n\nSecond paragraph"),
            "First \\*line\\* continues\n\nSecond paragraph"
        );
    }

    #[test]
    fn preserves_bullets_and_repairs_soft_hyphenation() {
        assert_eq!(
            text_to_markdown("• Alpha\n▪ Beta\ninter-\nnational"),
            "- Alpha\n\n- Beta\n\ninternational"
        );
    }

    #[test]
    fn escapes_block_prefixes_and_inline_markdown() {
        assert_eq!(escape_markdown("# [link]"), "\\# \\[link\\]");
    }
}
