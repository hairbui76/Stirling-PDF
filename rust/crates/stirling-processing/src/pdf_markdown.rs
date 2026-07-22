//! PDF to Markdown conversion.
//!
//! When the `PDFium` runtime is available, text is reconstructed with per-line and
//! per-glyph geometry so headings can be inferred from font size exactly as Java's
//! `HeadingDetector` does (size-ratio thresholds, brevity, and not-a-sentence signals).
//! Tables, columns, image placement, and bold-label emphasis remain documented parity
//! gaps. When `PDFium` is unavailable this falls back to a deterministic lopdf
//! text-only baseline that rebuilds paragraphs without heading inference. Both paths
//! escape Markdown control characters so source PDF text is preserved as literal content.

use std::{fs, path::Path};

use lopdf::Document;
use thiserror::Error;

use crate::pdfium_backend::{MarkdownTextLine, PdfiumMarkdownAttempt, try_extract_markdown_lines};

/// A heading is at most this many words; longer lines are treated as body text.
const MAX_HEADING_WORDS: usize = 12;

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
    // Prefer the geometry-aware PDFium path so headings can be inferred. Fall back to
    // the text-only lopdf baseline whenever PDFium is unavailable or errors reading.
    match try_extract_markdown_lines(input_path, filename) {
        Ok(PdfiumMarkdownAttempt::Extracted {
            lines,
            median_font_size,
            median_line_height,
        }) => {
            let markdown = build_markdown_from_lines(&lines, median_font_size, median_line_height);
            fs::write(output_path, markdown)?;
            Ok(())
        }
        Ok(PdfiumMarkdownAttempt::Unavailable {
            explicitly_configured,
            details,
        }) => {
            tracing::debug!(
                explicitly_configured,
                %details,
                "PDFium unavailable for Markdown conversion; using the text-only fallback"
            );
            convert_with_lopdf(input_path, filename, output_path)
        }
        Err(error) => {
            tracing::debug!(%error, "PDFium Markdown extraction failed; using the text-only fallback");
            convert_with_lopdf(input_path, filename, output_path)
        }
    }
}

fn convert_with_lopdf(
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

/// Assembles Markdown from geometry-bearing lines, inferring headings from font size.
///
/// Non-heading lines are rebuilt into paragraphs (broken at vertical gaps and page
/// boundaries), preserving the bullet, soft-hyphen, and escaping rules of the
/// text-only path. Table, column, and image inference remain deferred.
fn build_markdown_from_lines(
    lines: &[MarkdownTextLine],
    median_font_size: f32,
    median_line_height: f32,
) -> String {
    let mut blocks: Vec<String> = Vec::new();
    let mut paragraph = String::new();
    let mut current_page: Option<usize> = None;
    for line in lines {
        if current_page != Some(line.page) {
            flush_paragraph(&mut paragraph, &mut blocks);
            current_page = Some(line.page);
        }
        let text = line.text.trim();
        if text.is_empty() {
            continue;
        }
        let prefix = heading_prefix(
            text,
            line.dominant_font_size,
            line.height,
            median_font_size,
            median_line_height,
        );
        if !prefix.is_empty() {
            flush_paragraph(&mut paragraph, &mut blocks);
            blocks.push(format!("{prefix}{}", escape_markdown(text)));
            continue;
        }
        if let Some(item) = text
            .chars()
            .next()
            .filter(|character| matches!(character, '•' | '▪' | '◦'))
            .map(|character| &text[character.len_utf8()..])
        {
            flush_paragraph(&mut paragraph, &mut blocks);
            blocks.push(format!("- {}", escape_markdown(item.trim_start())));
            continue;
        }
        if line.paragraph_break_before {
            flush_paragraph(&mut paragraph, &mut blocks);
        }
        let escaped = escape_markdown(text);
        if paragraph.ends_with('-') && escaped.chars().next().is_some_and(char::is_lowercase) {
            paragraph.pop();
            paragraph.push_str(&escaped);
        } else {
            if !paragraph.is_empty() {
                paragraph.push(' ');
            }
            paragraph.push_str(&escaped);
        }
    }
    flush_paragraph(&mut paragraph, &mut blocks);
    blocks.join("\n\n")
}

/// Returns the Markdown heading prefix for a line, porting Java's `HeadingDetector`.
///
/// The decision combines font-size ratio (dominant glyph size vs. the document body
/// median, or line height when sizes are degenerate), brevity, and a not-a-sentence
/// check — never text matching. `size > baseline * 1.4` yields `"# "`, `> 1.2` yields
/// `"## "`, otherwise `""`.
fn heading_prefix(
    text: &str,
    dominant_font_size: f32,
    line_height: f32,
    median_font_size: f32,
    median_line_height: f32,
) -> &'static str {
    let text = text.trim();
    if text.is_empty() || word_count(text) > MAX_HEADING_WORDS || ends_like_sentence(text) {
        return "";
    }
    let (value, baseline) = if dominant_font_size > 2.0 && median_font_size > 2.0 {
        (dominant_font_size, median_font_size)
    } else {
        (line_height, median_line_height)
    };
    if baseline <= 0.0 {
        return "";
    }
    let ratio = value / baseline;
    if ratio > 1.4 {
        "# "
    } else if ratio > 1.2 {
        "## "
    } else {
        ""
    }
}

fn word_count(text: &str) -> usize {
    text.split_whitespace().count()
}

fn ends_like_sentence(text: &str) -> bool {
    matches!(text.chars().last(), Some('.' | '!' | '?'))
}

/// Computes the median of the samples, returning `fallback` when there are none.
pub(crate) fn median(values: &[f32], fallback: f32) -> f32 {
    let mut values: Vec<f32> = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect();
    if values.is_empty() {
        return fallback;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        f32::midpoint(values[middle - 1], values[middle])
    } else {
        values[middle]
    }
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
    use super::{
        MarkdownTextLine, build_markdown_from_lines, escape_markdown, heading_prefix, median,
        text_to_markdown,
    };

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

    #[test]
    fn heading_prefix_uses_font_size_ratio_thresholds() {
        // Body median 10 → ratio 1.5 (# ), 1.3 (## ), 1.1 ("").
        assert_eq!(heading_prefix("Title", 15.0, 12.0, 10.0, 12.0), "# ");
        assert_eq!(heading_prefix("Subtitle", 13.0, 12.0, 10.0, 12.0), "## ");
        assert_eq!(heading_prefix("Body-ish", 11.0, 12.0, 10.0, 12.0), "");
        // Exactly on a threshold is not a heading (strict >).
        assert_eq!(heading_prefix("Edge", 14.0, 12.0, 10.0, 12.0), "## ");
        assert_eq!(heading_prefix("Edge", 12.0, 12.0, 10.0, 12.0), "");
    }

    #[test]
    fn heading_prefix_rejects_long_lines_and_sentences() {
        let long = "one two three four five six seven eight nine ten eleven twelve thirteen";
        assert_eq!(heading_prefix(long, 20.0, 20.0, 10.0, 10.0), "");
        assert_eq!(
            heading_prefix("A full sentence.", 20.0, 20.0, 10.0, 10.0),
            ""
        );
        assert_eq!(heading_prefix("Really?", 20.0, 20.0, 10.0, 10.0), "");
        assert_eq!(heading_prefix("   ", 20.0, 20.0, 10.0, 10.0), "");
    }

    #[test]
    fn heading_prefix_falls_back_to_line_height_when_sizes_are_degenerate() {
        // dominant <= 2 → use line height vs median line height (18/12 = 1.5 → "# ").
        assert_eq!(heading_prefix("Scaled title", 1.0, 18.0, 1.0, 12.0), "# ");
        // Degenerate height baseline yields no heading.
        assert_eq!(heading_prefix("No baseline", 1.0, 18.0, 1.0, 0.0), "");
    }

    #[test]
    fn median_handles_even_odd_and_empty() {
        assert!((median(&[1.0, 2.0, 3.0], 12.0) - 2.0).abs() < 1e-6);
        assert!((median(&[1.0, 2.0, 3.0, 4.0], 12.0) - 2.5).abs() < 1e-6);
        assert!((median(&[], 12.0) - 12.0).abs() < 1e-6);
    }

    #[test]
    fn build_markdown_emits_headings_bullets_and_paragraphs() {
        let lines = vec![
            line(0, "Big Title", 18.0, false),
            line(0, "First body line", 10.0, false),
            line(0, "continues here", 10.0, false),
            line(0, "New paragraph", 10.0, true),
            line(0, "• A bullet", 10.0, false),
            line(1, "Second Page", 10.0, false),
        ];
        assert_eq!(
            build_markdown_from_lines(&lines, 10.0, 12.0),
            "# Big Title\n\nFirst body line continues here\n\nNew paragraph\n\n- A bullet\n\nSecond Page"
        );
    }

    fn line(
        page: usize,
        text: &str,
        dominant_font_size: f32,
        paragraph_break_before: bool,
    ) -> MarkdownTextLine {
        MarkdownTextLine {
            page,
            text: text.to_owned(),
            dominant_font_size,
            height: 12.0,
            paragraph_break_before,
        }
    }

    #[test]
    fn infers_heading_from_font_size_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
        use lopdf::{Document, Object, Stream, dictionary};
        use std::io::Write;

        let mut document = Document::with_version("1.7");
        let font_id = document.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let content = b"BT /F1 24 Tf 72 720 Td (Big Heading) Tj ET\n\
            BT /F1 10 Tf 72 690 Td (This is ordinary body text on the page) Tj ET"
            .to_vec();
        let content_id = document.add_object(Stream::new(dictionary! {}, content));
        let pages_id = document.new_object_id();
        let page_object_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_object_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;

        let mut input = tempfile::NamedTempFile::new()?;
        input.write_all(&bytes)?;
        let output = tempfile::NamedTempFile::new()?;
        super::pdf_to_markdown_file(input.path(), "sized.pdf", output.path())?;
        let markdown = std::fs::read_to_string(output.path())?;

        // The 24pt line is ~2.4x the body median → promoted to a level-1 heading;
        // the 10pt line stays body text. Requires the pinned PDFium runtime.
        assert!(
            markdown.contains("# Big Heading"),
            "expected an inferred heading, got:\n{markdown}"
        );
        assert!(
            markdown.contains("ordinary body text"),
            "expected body text, got:\n{markdown}"
        );
        assert!(
            !markdown.contains("# This is"),
            "body text must not be promoted, got:\n{markdown}"
        );
        Ok(())
    }
}
