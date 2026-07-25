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

/// Assembles Markdown from geometry-bearing lines, inferring headings from font size
/// and two-column reading order from line geometry.
///
/// Each page is processed independently. A genuine two-column page (see
/// [`detects_two_columns`]) is split into left and right columns
/// ([`split_into_columns`]) and emitted left-column-first in top-to-bottom order;
/// otherwise lines keep their extraction order. Within each column/page, headings,
/// bullets, paragraph breaks, soft-hyphen repair, and escaping are applied. Table and
/// image inference remain deferred.
fn build_markdown_from_lines(
    lines: &[MarkdownTextLine],
    median_font_size: f32,
    median_line_height: f32,
) -> String {
    let mut blocks: Vec<String> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let page = lines[index].page;
        let start = index;
        while index < lines.len() && lines[index].page == page {
            index += 1;
        }
        let page_lines: Vec<&MarkdownTextLine> = lines[start..index].iter().collect();
        if detects_two_columns(&page_lines) {
            // Read top-to-bottom before partitioning so each column stays in reading
            // order regardless of the raw extraction order across the gutter.
            let mut ordered = page_lines;
            ordered.sort_by(|a, b| b.y.partial_cmp(&a.y).unwrap_or(std::cmp::Ordering::Equal));
            for column in split_into_columns(&ordered) {
                emit_lines(&column, median_font_size, median_line_height, &mut blocks);
            }
        } else {
            emit_lines(
                &page_lines,
                median_font_size,
                median_line_height,
                &mut blocks,
            );
        }
    }
    blocks.join("\n\n")
}

/// Emits one page or column of lines into `blocks`, applying heading, bullet,
/// paragraph-break, soft-hyphen, and escaping rules. The paragraph buffer is local, so
/// paragraphs never span a column or page boundary.
fn emit_lines(
    lines: &[&MarkdownTextLine],
    median_font_size: f32,
    median_line_height: f32,
    blocks: &mut Vec<String>,
) {
    let mut paragraph = String::new();
    for line in lines {
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
            flush_paragraph(&mut paragraph, blocks);
            blocks.push(format!("{prefix}{}", escape_markdown(text)));
            continue;
        }
        if let Some(item) = text
            .chars()
            .next()
            .filter(|character| matches!(character, '•' | '▪' | '◦'))
            .map(|character| &text[character.len_utf8()..])
        {
            flush_paragraph(&mut paragraph, blocks);
            blocks.push(format!("- {}", escape_markdown(item.trim_start())));
            continue;
        }
        if line.paragraph_break_before {
            flush_paragraph(&mut paragraph, blocks);
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
    flush_paragraph(&mut paragraph, blocks);
}

/// Returns true when a page is a genuine two-column layout, porting Java's
/// `detectsTwoColumns`. It scans candidate gutter positions across the central band
/// (35%–65% of the used width) and picks the one crossed by the fewest lines; a real
/// two-column page has a gutter populated on both sides that few full-width lines
/// cross, whereas a table's rows span every candidate gutter.
fn detects_two_columns(lines: &[&MarkdownTextLine]) -> bool {
    if lines.len() < 8 {
        return false;
    }
    let mut min_x = f32::MAX;
    let mut max_x = f32::MIN;
    for line in lines {
        min_x = min_x.min(line.x);
        max_x = max_x.max(line.x + line.width);
    }
    if max_x - min_x < 200.0 {
        return false;
    }
    let centre_lo = min_x + (max_x - min_x) * 0.35;
    let centre_hi = min_x + (max_x - min_x) * 0.65;
    let mut best_crossing = usize::MAX;
    let mut best_left = 0_usize;
    let mut best_right = 0_usize;
    let mut gutter = centre_lo;
    while gutter <= centre_hi {
        let mut crossing = 0_usize;
        let mut left_only = 0_usize;
        let mut right_only = 0_usize;
        for line in lines {
            let lx = line.x;
            let rx = line.x + line.width;
            if lx < gutter - 5.0 && rx > gutter + 5.0 {
                crossing += 1;
            } else if rx <= gutter {
                left_only += 1;
            } else {
                right_only += 1;
            }
        }
        if crossing < best_crossing {
            best_crossing = crossing;
            best_left = left_only;
            best_right = right_only;
        }
        gutter += 2.0;
    }
    best_left >= 4 && best_right >= 4 && best_crossing <= crossing_limit(lines.len())
}

/// Java uses `(int)(lines.size() * 0.25f)`; reproduce the truncating cast exactly.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn crossing_limit(line_count: usize) -> usize {
    (line_count as f32 * 0.25) as usize
}

/// Splits lines into up to two columns at the widest horizontal gap between the left
/// edges of body-width lines, porting Java's `splitIntoColumns`. Input order is
/// preserved within each column.
fn split_into_columns<'a>(lines: &[&'a MarkdownTextLine]) -> Vec<Vec<&'a MarkdownTextLine>> {
    let mut xs: Vec<f32> = lines
        .iter()
        .filter(|line| line.width >= 40.0)
        .map(|line| line.x)
        .collect();
    if xs.is_empty() {
        return vec![lines.to_vec()];
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mut split_at = f32::midpoint(xs[0], xs[xs.len() - 1]);
    let mut biggest_gap = 0.0_f32;
    for window in xs.windows(2) {
        let gap = window[1] - window[0];
        if gap > biggest_gap {
            biggest_gap = gap;
            split_at = f32::midpoint(window[0], window[1]);
        }
    }
    let mut left = Vec::new();
    let mut right = Vec::new();
    for line in lines {
        if line.x < split_at {
            left.push(*line);
        } else {
            right.push(*line);
        }
    }
    if left.is_empty() {
        return vec![right];
    }
    if right.is_empty() {
        return vec![left];
    }
    vec![left, right]
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
            x: 0.0,
            width: 500.0,
            y: 0.0,
            paragraph_break_before,
        }
    }

    fn positioned_line(text: &str, x: f32, width: f32, y: f32) -> MarkdownTextLine {
        MarkdownTextLine {
            page: 0,
            text: text.to_owned(),
            dominant_font_size: 10.0,
            height: 12.0,
            x,
            width,
            y,
            paragraph_break_before: false,
        }
    }

    fn two_column_layout() -> Vec<MarkdownTextLine> {
        // Four left-column lines (x 50, right edge 150) and four right-column lines
        // (x 300, right edge 400), added out of reading order to prove the sort.
        vec![
            positioned_line("Left one", 50.0, 100.0, 700.0),
            positioned_line("Right one", 300.0, 100.0, 690.0),
            positioned_line("Left three", 50.0, 100.0, 660.0),
            positioned_line("Right two", 300.0, 100.0, 670.0),
            positioned_line("Left two", 50.0, 100.0, 680.0),
            positioned_line("Right four", 300.0, 100.0, 630.0),
            positioned_line("Left four", 50.0, 100.0, 640.0),
            positioned_line("Right three", 300.0, 100.0, 650.0),
        ]
    }

    #[test]
    fn detects_two_columns_on_a_gutter_layout() {
        let lines = two_column_layout();
        let refs: Vec<&MarkdownTextLine> = lines.iter().collect();
        assert!(super::detects_two_columns(&refs));
    }

    #[test]
    fn rejects_two_columns_for_full_width_narrow_and_short_pages() {
        // Full-width rows (every line spans the gutter) → not two columns.
        let full_width: Vec<MarkdownTextLine> = (0..10_u8)
            .map(|i| positioned_line("row", 50.0, 350.0, 700.0 - f32::from(i) * 10.0))
            .collect();
        let refs: Vec<&MarkdownTextLine> = full_width.iter().collect();
        assert!(!super::detects_two_columns(&refs));

        // Fewer than eight lines → not two columns.
        let short = two_column_layout();
        let short_refs: Vec<&MarkdownTextLine> = short.iter().take(6).collect();
        assert!(!super::detects_two_columns(&short_refs));

        // Narrow used width (< 200) → not two columns.
        let narrow: Vec<MarkdownTextLine> = (0..8_u8)
            .map(|i| positioned_line("x", 10.0, 50.0, 700.0 - f32::from(i) * 10.0))
            .collect();
        let narrow_refs: Vec<&MarkdownTextLine> = narrow.iter().collect();
        assert!(!super::detects_two_columns(&narrow_refs));
    }

    #[test]
    fn splits_columns_at_the_widest_gap() {
        let lines = two_column_layout();
        let refs: Vec<&MarkdownTextLine> = lines.iter().collect();
        let columns = super::split_into_columns(&refs);
        assert_eq!(columns.len(), 2);
        assert!(columns[0].iter().all(|line| line.x < 175.0));
        assert!(columns[1].iter().all(|line| line.x >= 175.0));

        // A single cluster stays one column.
        let single: Vec<MarkdownTextLine> = (0..4_u8)
            .map(|i| positioned_line("x", 50.0, 100.0, 700.0 - f32::from(i) * 10.0))
            .collect();
        let single_refs: Vec<&MarkdownTextLine> = single.iter().collect();
        assert_eq!(super::split_into_columns(&single_refs).len(), 1);

        // No body-width lines → one column.
        let thin = [positioned_line("i", 50.0, 5.0, 700.0)];
        let thin_refs: Vec<&MarkdownTextLine> = thin.iter().collect();
        assert_eq!(super::split_into_columns(&thin_refs).len(), 1);
    }

    #[test]
    fn build_markdown_emits_left_column_before_right() {
        let lines = two_column_layout();
        assert_eq!(
            build_markdown_from_lines(&lines, 10.0, 12.0),
            "Left one Left two Left three Left four\n\nRight one Right two Right three Right four"
        );
    }

    #[test]
    fn build_markdown_single_column_keeps_extraction_order() {
        let lines = vec![
            line(0, "First body line", 10.0, false),
            line(0, "second line", 10.0, false),
        ];
        assert_eq!(
            build_markdown_from_lines(&lines, 10.0, 12.0),
            "First body line second line"
        );
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
