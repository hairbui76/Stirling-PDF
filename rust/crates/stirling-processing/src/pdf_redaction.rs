//! Secure raster redaction primitives.
//!
//! The source PDF is never copied into the output. Every page is rendered, redaction rectangles
//! are painted directly into the raster, and a new image-only PDF is written. This deliberately
//! avoids the unsafe "overlay only" behaviour present in legacy Java fallback paths.

use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
};

use image::{DynamicImage, Rgb, RgbImage};
use pdfium_render::prelude::*;
use regex::Regex;
use thiserror::Error;

use crate::{
    page_selection::{PageSelectionError, parse_page_list},
    pdf_flatten::configured_max_render_dpi,
    pdfium_runtime::shared_pdfium_runtime,
};

const MAX_RENDER_PIXELS: f64 = 100_000_000.0;
const MAX_AUTO_REDACTION_PATTERNS: usize = 256;
const MAX_AUTO_REDACTION_MATCHES: usize = 10_000;
const MAX_EXECUTE_REDACTION_RANGES: usize = 128;
const MAX_EXECUTE_REDACTION_IMAGE_BOXES: usize = 10_000;
const MAX_EXECUTE_REDACTION_BOXES: usize = 20_000;
const MAX_IMAGE_XOBJECT_DEPTH: usize = 32;
const LINE_TOLERANCE: f32 = 2.0;
const RANGE_LINE_Y_TOLERANCE: f32 = 3.0;
const RANGE_COLUMN_GAP: f32 = 14.0;
const RANGE_MIDPOINT_SLACK: f32 = 30.0;
const RANGE_MIN_COLUMN_LINE_WIDTH: f32 = 100.0;
const RANGE_MIN_SIDE_LINES: usize = 3;
const RANGE_COLUMN_OVERLAP_SLACK: f32 = 2.0;

/// A manually specified redaction rectangle, with top-left page coordinates in PDF points.
#[derive(Debug, Clone, PartialEq)]
pub struct RedactionBox {
    pub page_number: usize,
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub color: [u8; 3],
}

/// Search options for `POST /api/v1/security/auto-redact`.
#[derive(Debug, Clone, PartialEq)]
pub struct AutoRedactionOptions {
    pub terms: Vec<String>,
    pub use_regex: bool,
    pub whole_word: bool,
    pub color: [u8; 3],
    pub custom_padding: f32,
}

/// A text range from the unified `redact-execute` contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionTextRange {
    pub start_string: String,
    pub end_string: String,
}

/// A rectangle from the unified `redact-execute` contract.
///
/// Coordinates use PDF user space (bottom-left origin), matching the legacy Java route.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecuteRedactionImageBox {
    pub page_index: usize,
    pub x1: f32,
    pub y1: f32,
    pub x2: f32,
    pub y2: f32,
}

/// All supported targets for `POST /api/v1/security/redact-execute`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecuteRedactionOptions {
    pub text_values: Vec<String>,
    pub regex_patterns: Vec<String>,
    pub wipe_pages: Vec<usize>,
    pub ranges: Vec<RedactionTextRange>,
    pub image_boxes: Vec<ExecuteRedactionImageBox>,
    /// `None` skips automatic image redaction; `Some(vec![])` selects every page.
    pub redact_image_pages: Option<Vec<usize>>,
    pub color: [u8; 3],
    pub custom_padding: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfRedactionAttempt {
    Redacted,
    Unavailable { explicitly_configured: bool },
}

#[derive(Debug, Error)]
pub enum PdfRedactionError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not process page {page_number} while redacting: {source}")]
    Page {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("page {page_number} would exceed the {MAX_RENDER_PIXELS}-pixel redaction limit")]
    UnsafeRenderDimensions { page_number: usize },
    #[error("could not select page {page_number} for redaction")]
    InvalidPageNumber { page_number: usize },
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("could not inspect text on page {page_number}: {source}")]
    ReadText {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("automatic redaction requires at least one non-empty search term")]
    NoSearchTerms,
    #[error("automatic redaction accepts at most {MAX_AUTO_REDACTION_PATTERNS} search terms")]
    TooManySearchTerms,
    #[error("automatic redaction regex is invalid: {0}")]
    InvalidPattern(String),
    #[error("custom redaction padding must be finite and non-negative")]
    InvalidPadding,
    #[error("automatic redaction exceeded the {MAX_AUTO_REDACTION_MATCHES}-match safety limit")]
    TooManyMatches,
    #[error("redaction execution requires at least one target")]
    NoExecutionTargets,
    #[error("redaction execution accepts at most {MAX_EXECUTE_REDACTION_RANGES} text ranges")]
    TooManyRanges,
    #[error("redaction execution accepts at most {MAX_EXECUTE_REDACTION_IMAGE_BOXES} image boxes")]
    TooManyImageBoxes,
    #[error("redaction execution produced more than {MAX_EXECUTE_REDACTION_BOXES} paint boxes")]
    TooManyExecutionBoxes,
    #[error("redaction text ranges require a non-empty start string")]
    EmptyRangeStart,
    #[error("redaction image boxes require finite coordinates")]
    InvalidImageBox,
}

/// Securely redacts page rectangles and writes an image-only PDF.
///
/// `page_numbers` uses Stirling's one-based page-selection syntax. Selected pages are replaced
/// by `page_redaction_color` even if they have no rectangles. Out-of-range ordinary page
/// numbers are ignored to preserve Java's manual-redaction behaviour.
///
/// # Errors
///
/// Returns [`PdfRedactionError`] for malformed PDFs, unavailable rendering resources, or unsafe
/// raster dimensions. The output never retains the original page content.
pub fn redact_pdf_to_raster_file(
    input_path: &Path,
    filename: &str,
    boxes: &[RedactionBox],
    page_numbers: &str,
    page_redaction_color: [u8; 3],
    output_path: &Path,
) -> Result<PdfRedactionAttempt, PdfRedactionError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfRedactionError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfRedactionAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
            });
        }
    };
    let source = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfRedactionError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count = usize::try_from(source.pages().len())
        .map_err(|_| PdfRedactionError::InvalidPageNumber { page_number: 0 })?;
    let wiped_pages: HashSet<usize> = if page_numbers.trim().is_empty() {
        HashSet::new()
    } else {
        parse_page_list(page_numbers, page_count)?
            .into_iter()
            .collect()
    };
    let mut output = pdfium
        .create_new_pdf()
        .map_err(|source| PdfRedactionError::Page {
            page_number: 0,
            source,
        })?;
    let dpi = configured_max_render_dpi();
    for pdfium_page_index in source.pages().as_range() {
        let page_index = usize::try_from(pdfium_page_index)
            .map_err(|_| PdfRedactionError::InvalidPageNumber { page_number: 0 })?;
        let page_number = page_index.saturating_add(1);
        let page =
            source
                .pages()
                .get(pdfium_page_index)
                .map_err(|source| PdfRedactionError::Page {
                    page_number,
                    source,
                })?;
        let width = page.width();
        let height = page.height();
        let (pixel_width, pixel_height) = render_dimensions(width, height, dpi, page_number)?;
        let config = PdfRenderConfig::new()
            .set_fixed_size(pixel_width, pixel_height)
            .render_annotations(true)
            .render_form_data(true);
        let mut image = page
            .render_with_config(&config)
            .and_then(|bitmap| bitmap.as_image())
            .map_err(|source| PdfRedactionError::Page {
                page_number,
                source,
            })?
            .to_rgb8();
        if wiped_pages.contains(&page_index) {
            image
                .pixels_mut()
                .for_each(|pixel| *pixel = Rgb(page_redaction_color));
        } else {
            for redaction in boxes.iter().filter(|box_| box_.page_number == page_number) {
                paint_redaction_box(&mut image, width.value, height.value, redaction);
            }
        }
        let mut output_page = output
            .pages_mut()
            .create_page_at_end(PdfPagePaperSize::new_custom(width, height))
            .map_err(|source| PdfRedactionError::Page {
                page_number,
                source,
            })?;
        output_page
            .objects_mut()
            .create_image_object(
                PdfPoints::ZERO,
                PdfPoints::ZERO,
                &DynamicImage::ImageRgb8(image),
                Some(width),
                Some(height),
            )
            .map_err(|source| PdfRedactionError::Page {
                page_number,
                source,
            })?;
    }
    output
        .save_to_file(output_path)
        .map_err(|source| PdfRedactionError::Page {
            page_number: 0,
            source,
        })?;
    Ok(PdfRedactionAttempt::Redacted)
}

/// Finds text matches, securely paints their bounds, and writes an image-only PDF.
///
/// # Errors
///
/// Returns [`PdfRedactionError`] if the PDF cannot be read, a pattern is invalid, text bounds are
/// unavailable, or rendering exceeds a safety limit. No source page objects are copied to output.
pub fn redact_matching_text_to_raster_file(
    input_path: &Path,
    filename: &str,
    options: &AutoRedactionOptions,
    output_path: &Path,
) -> Result<PdfRedactionAttempt, PdfRedactionError> {
    let patterns = automatic_patterns(options)?;
    let boxes = match automatic_redaction_boxes(input_path, filename, &patterns, options) {
        Ok(PdfiumSearch::Found(boxes)) => boxes,
        Ok(PdfiumSearch::Unavailable {
            explicitly_configured,
        }) => {
            return Ok(PdfRedactionAttempt::Unavailable {
                explicitly_configured,
            });
        }
        Err(error) => return Err(error),
    };
    redact_pdf_to_raster_file(input_path, filename, &boxes, "", options.color, output_path)
}

/// Executes a combined redaction plan and writes an image-only PDF.
///
/// This intentionally ignores legacy overlay-only strategy requests. A response that merely paints
/// over source objects is not a safe redaction result, so every supported target is converted to
/// raster paint boxes before writing the output.
///
/// # Errors
///
/// Returns [`PdfRedactionError`] when a request is invalid, `PDFium` cannot inspect the source, or
/// the input cannot be safely rasterized.
pub fn execute_redaction_to_raster_file(
    input_path: &Path,
    filename: &str,
    options: &ExecuteRedactionOptions,
    output_path: &Path,
) -> Result<PdfRedactionAttempt, PdfRedactionError> {
    validate_execute_options(options)?;
    let dimensions = match document_page_dimensions(input_path, filename)? {
        PdfiumSearch::Found(dimensions) => dimensions,
        PdfiumSearch::Unavailable {
            explicitly_configured,
        } => {
            return Ok(PdfRedactionAttempt::Unavailable {
                explicitly_configured,
            });
        }
    };

    let mut boxes = execute_manual_image_boxes(options, &dimensions);
    let wiped_pages = selected_wipe_pages(&options.wipe_pages, dimensions.len());

    if let Some(explicitly_configured) = append_execute_text_matches(
        &mut boxes,
        input_path,
        filename,
        &options.text_values,
        false,
        options,
    )? {
        return Ok(PdfRedactionAttempt::Unavailable {
            explicitly_configured,
        });
    }
    if let Some(explicitly_configured) = append_execute_text_matches(
        &mut boxes,
        input_path,
        filename,
        &options.regex_patterns,
        true,
        options,
    )? {
        return Ok(PdfRedactionAttempt::Unavailable {
            explicitly_configured,
        });
    }
    if let Some(explicitly_configured) =
        append_execute_ranges(&mut boxes, input_path, filename, options)?
    {
        return Ok(PdfRedactionAttempt::Unavailable {
            explicitly_configured,
        });
    }
    if let Some(redact_image_pages) = &options.redact_image_pages {
        let selected_pages = (!redact_image_pages.is_empty()).then(|| {
            redact_image_pages
                .iter()
                .filter(|page_number| **page_number > 0)
                .map(|page_number| page_number - 1)
                .collect::<BTreeSet<_>>()
        });
        match detected_image_redaction_boxes(
            input_path,
            filename,
            selected_pages.as_ref(),
            options.color,
        )? {
            PdfiumSearch::Found(image_boxes) => boxes.extend(image_boxes),
            PdfiumSearch::Unavailable {
                explicitly_configured,
            } => {
                return Ok(PdfRedactionAttempt::Unavailable {
                    explicitly_configured,
                });
            }
        }
    }
    ensure_execution_box_limit(boxes.len())?;

    let page_numbers = wiped_pages
        .into_iter()
        .map(|page_index| page_index.saturating_add(1).to_string())
        .collect::<Vec<_>>()
        .join(",");
    redact_pdf_to_raster_file(
        input_path,
        filename,
        &boxes,
        &page_numbers,
        options.color,
        output_path,
    )
}

enum PdfiumSearch<T> {
    Found(T),
    Unavailable { explicitly_configured: bool },
}

#[derive(Debug, Clone, Copy)]
struct PageDimensions {
    width: f32,
    height: f32,
}

#[derive(Debug, Clone, Copy)]
struct TextGlyph {
    start: usize,
    end: usize,
    left: f32,
    right: f32,
    bottom: f32,
    top: f32,
    visible: bool,
}

#[derive(Debug, Clone, Copy)]
struct GlyphGroup {
    left: f32,
    right: f32,
    bottom: f32,
    top: f32,
}

#[derive(Debug, Clone)]
struct RangePageGeometry {
    layout: PageColumnLayout,
    elements: Vec<RedactionBox>,
}

#[derive(Debug, Clone)]
struct PageColumnLayout {
    columns: Vec<(f32, f32)>,
}

#[derive(Debug, Clone)]
struct RangeAnchor {
    box_: RedactionBox,
    column: usize,
}

fn automatic_patterns(options: &AutoRedactionOptions) -> Result<Vec<Regex>, PdfRedactionError> {
    if !options.custom_padding.is_finite() || options.custom_padding < 0.0 {
        return Err(PdfRedactionError::InvalidPadding);
    }
    let terms: BTreeSet<String> = options
        .terms
        .iter()
        .map(|term| term.trim())
        .filter(|term| !term.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if terms.is_empty() {
        return Err(PdfRedactionError::NoSearchTerms);
    }
    if terms.len() > MAX_AUTO_REDACTION_PATTERNS {
        return Err(PdfRedactionError::TooManySearchTerms);
    }
    terms
        .into_iter()
        .map(|term| {
            let expression = if options.use_regex {
                term
            } else {
                regex::escape(&term)
            };
            let expression = if options.whole_word {
                format!(r"\b(?:{expression})\b")
            } else {
                expression
            };
            Regex::new(&format!("(?i:{expression})"))
                .map_err(|error| PdfRedactionError::InvalidPattern(error.to_string()))
        })
        .collect()
}

fn range_boundary_patterns(raw: &str) -> Result<Vec<Regex>, PdfRedactionError> {
    let trimmed = raw.trim();
    let collapsed = collapse_letter_spacing(trimmed);
    let mut candidates = vec![(trimmed.to_owned(), true), (trimmed.to_owned(), false)];
    if collapsed != trimmed {
        candidates.push((collapsed.clone(), true));
        candidates.push((collapsed, false));
    }
    if let Some(tolerant) = punctuation_tolerant_expression(trimmed) {
        candidates.push((tolerant, true));
    }
    if trimmed.contains('\n')
        && let Some(first_line) = trimmed.lines().map(str::trim).find(|line| !line.is_empty())
        && first_line.len() >= 4
    {
        candidates.push((first_line.to_owned(), false));
        let first_collapsed = collapse_letter_spacing(first_line);
        if first_collapsed != first_line {
            candidates.push((first_collapsed, false));
        }
        if let Some(tolerant) = punctuation_tolerant_expression(first_line) {
            candidates.push((tolerant, true));
        }
    }

    let mut expressions = BTreeSet::new();
    let mut patterns = Vec::new();
    for (candidate, use_regex) in candidates {
        let expression = if use_regex {
            candidate
        } else {
            regex::escape(&candidate)
        };
        let wrapped = format!("(?i:{expression})");
        if !expressions.insert(wrapped.clone()) {
            continue;
        }
        match Regex::new(&wrapped) {
            Ok(pattern) => patterns.push(pattern),
            Err(error) if !use_regex => {
                return Err(PdfRedactionError::InvalidPattern(error.to_string()));
            }
            Err(_) => {}
        }
    }
    Ok(patterns)
}

fn collapse_letter_spacing(text: &str) -> String {
    let mut result = String::new();
    let mut current = String::new();
    for token in text.split(' ') {
        if token.is_empty() {
            append_collapsed_word(&mut result, &mut current);
        } else if token.chars().count() == 1 {
            current.push_str(token);
        } else {
            append_collapsed_word(&mut result, &mut current);
            append_word(&mut result, token);
        }
    }
    append_collapsed_word(&mut result, &mut current);
    result
}

fn append_collapsed_word(result: &mut String, current: &mut String) {
    if !current.is_empty() {
        append_word(result, current);
        current.clear();
    }
}

fn append_word(result: &mut String, word: &str) {
    if !result.is_empty() {
        result.push(' ');
    }
    result.push_str(word);
}

fn punctuation_tolerant_expression(raw: &str) -> Option<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for character in raw.chars() {
        if character.is_alphanumeric() {
            current.push(character);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    (tokens.len() >= 2).then(|| {
        tokens
            .into_iter()
            .map(|token| regex::escape(&token))
            .collect::<Vec<_>>()
            .join(r"\W*")
    })
}

fn automatic_redaction_boxes(
    input_path: &Path,
    filename: &str,
    patterns: &[Regex],
    options: &AutoRedactionOptions,
) -> Result<PdfiumSearch<Vec<RedactionBox>>, PdfRedactionError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfRedactionError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfiumSearch::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfRedactionError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut boxes = Vec::new();
    for pdfium_page_index in document.pages().as_range() {
        let page_index = usize::try_from(pdfium_page_index)
            .map_err(|_| PdfRedactionError::InvalidPageNumber { page_number: 0 })?;
        let page_number = page_index.saturating_add(1);
        let page =
            document
                .pages()
                .get(pdfium_page_index)
                .map_err(|source| PdfRedactionError::Page {
                    page_number,
                    source,
                })?;
        let (text, glyphs) = page_text_glyphs(&page, page_number)?;
        for pattern in patterns {
            for found in pattern.find_iter(&text) {
                boxes.extend(match_redaction_boxes(
                    &glyphs,
                    found.start(),
                    found.end(),
                    page_number,
                    page.height().value,
                    options,
                ));
                if boxes.len() > MAX_AUTO_REDACTION_MATCHES {
                    return Err(PdfRedactionError::TooManyMatches);
                }
            }
        }
    }
    Ok(PdfiumSearch::Found(boxes))
}

fn validate_execute_options(options: &ExecuteRedactionOptions) -> Result<(), PdfRedactionError> {
    if !options.custom_padding.is_finite() || options.custom_padding < 0.0 {
        return Err(PdfRedactionError::InvalidPadding);
    }
    if options.ranges.len() > MAX_EXECUTE_REDACTION_RANGES {
        return Err(PdfRedactionError::TooManyRanges);
    }
    if options.image_boxes.len() > MAX_EXECUTE_REDACTION_IMAGE_BOXES {
        return Err(PdfRedactionError::TooManyImageBoxes);
    }
    if options
        .ranges
        .iter()
        .any(|range| range.start_string.trim().is_empty())
    {
        return Err(PdfRedactionError::EmptyRangeStart);
    }
    if options.image_boxes.iter().any(|box_| {
        !box_.x1.is_finite() || !box_.y1.is_finite() || !box_.x2.is_finite() || !box_.y2.is_finite()
    }) {
        return Err(PdfRedactionError::InvalidImageBox);
    }
    let has_text = options
        .text_values
        .iter()
        .chain(&options.regex_patterns)
        .any(|value| !value.trim().is_empty());
    if !has_text
        && options.wipe_pages.is_empty()
        && options.ranges.is_empty()
        && options.image_boxes.is_empty()
        && options.redact_image_pages.is_none()
    {
        return Err(PdfRedactionError::NoExecutionTargets);
    }
    Ok(())
}

fn execute_manual_image_boxes(
    options: &ExecuteRedactionOptions,
    dimensions: &[PageDimensions],
) -> Vec<RedactionBox> {
    let mut boxes = Vec::with_capacity(options.image_boxes.len());
    for box_ in &options.image_boxes {
        let Some(dimensions) = dimensions.get(box_.page_index) else {
            continue;
        };
        let left = box_.x1.min(box_.x2).clamp(0.0, dimensions.width);
        let right = box_.x1.max(box_.x2).clamp(0.0, dimensions.width);
        let bottom = box_.y1.min(box_.y2).clamp(0.0, dimensions.height);
        let top = box_.y1.max(box_.y2).clamp(0.0, dimensions.height);
        if right <= left || top <= bottom {
            continue;
        }
        boxes.push(RedactionBox {
            page_number: box_.page_index.saturating_add(1),
            x: left,
            y: dimensions.height - top,
            width: right - left,
            height: top - bottom,
            color: options.color,
        });
    }
    boxes
}

fn selected_wipe_pages(wipe_pages: &[usize], page_count: usize) -> BTreeSet<usize> {
    wipe_pages
        .iter()
        .filter(|page_number| **page_number > 0)
        .map(|page_number| page_number - 1)
        .filter(|page_index| *page_index < page_count)
        .collect()
}

fn append_execute_text_matches(
    boxes: &mut Vec<RedactionBox>,
    input_path: &Path,
    filename: &str,
    terms: &[String],
    use_regex: bool,
    execute_options: &ExecuteRedactionOptions,
) -> Result<Option<bool>, PdfRedactionError> {
    if !terms.iter().any(|term| !term.trim().is_empty()) {
        return Ok(None);
    }
    let options = AutoRedactionOptions {
        terms: terms.to_vec(),
        use_regex,
        whole_word: false,
        color: execute_options.color,
        custom_padding: execute_options.custom_padding,
    };
    let patterns = automatic_patterns(&options)?;
    match automatic_redaction_boxes(input_path, filename, &patterns, &options)? {
        PdfiumSearch::Found(found) => {
            boxes.extend(found);
            ensure_execution_box_limit(boxes.len())?;
            Ok(None)
        }
        PdfiumSearch::Unavailable {
            explicitly_configured,
        } => Ok(Some(explicitly_configured)),
    }
}

fn append_execute_ranges(
    boxes: &mut Vec<RedactionBox>,
    input_path: &Path,
    filename: &str,
    options: &ExecuteRedactionOptions,
) -> Result<Option<bool>, PdfRedactionError> {
    if options.ranges.is_empty() {
        return Ok(None);
    }
    let pages = match range_document_geometry(input_path, filename, options.color)? {
        PdfiumSearch::Found(pages) => pages,
        PdfiumSearch::Unavailable {
            explicitly_configured,
        } => return Ok(Some(explicitly_configured)),
    };
    for range in &options.ranges {
        let start_options = AutoRedactionOptions {
            terms: vec![range.start_string.clone()],
            use_regex: false,
            whole_word: false,
            color: options.color,
            custom_padding: options.custom_padding,
        };
        let start_patterns = range_boundary_patterns(&range.start_string)?;
        let starts =
            match automatic_redaction_boxes(input_path, filename, &start_patterns, &start_options)?
            {
                PdfiumSearch::Found(found) => found,
                PdfiumSearch::Unavailable {
                    explicitly_configured,
                } => return Ok(Some(explicitly_configured)),
            };
        if starts.is_empty() {
            continue;
        }
        let ends = if range.end_string.trim().is_empty() {
            Vec::new()
        } else {
            let end_options = AutoRedactionOptions {
                terms: vec![range.end_string.clone()],
                use_regex: false,
                whole_word: false,
                color: options.color,
                custom_padding: options.custom_padding,
            };
            let end_patterns = range_boundary_patterns(&range.end_string)?;
            match automatic_redaction_boxes(input_path, filename, &end_patterns, &end_options)? {
                PdfiumSearch::Found(found) => found,
                PdfiumSearch::Unavailable {
                    explicitly_configured,
                } => return Ok(Some(explicitly_configured)),
            }
        };
        append_range_geometry_boxes(boxes, &starts, &ends, range, &pages);
        ensure_execution_box_limit(boxes.len())?;
    }
    Ok(None)
}

fn append_range_geometry_boxes(
    boxes: &mut Vec<RedactionBox>,
    starts: &[RedactionBox],
    ends: &[RedactionBox],
    range: &RedactionTextRange,
    pages: &[RangePageGeometry],
) {
    let mut starts = range_anchors(starts, pages);
    let mut ends = range_anchors(ends, pages);
    starts.sort_by(range_anchor_reading_order);
    ends.sort_by(range_anchor_reading_order);
    for start in starts {
        let end = if range.end_string.trim().is_empty() {
            None
        } else {
            ends.iter()
                .find(|end| range_anchor_reading_order(end, &start).is_gt())
                .cloned()
        };
        if !range.end_string.trim().is_empty() && end.is_none() {
            continue;
        }
        let start_index = start.box_.page_number.saturating_sub(1);
        let end_index = end.as_ref().map_or_else(
            || pages.len().saturating_sub(1),
            |anchor| anchor.box_.page_number.saturating_sub(1),
        );
        let end_column = end.as_ref().map_or_else(
            || {
                pages
                    .get(end_index)
                    .map_or(0, |page| page.layout.columns.len().saturating_sub(1))
            },
            |anchor| anchor.column,
        );
        let end_bottom = end
            .as_ref()
            .map_or(f32::INFINITY, |anchor| anchor.box_.y + anchor.box_.height);
        for page_index in start_index..=end_index {
            let Some(page) = pages.get(page_index) else {
                continue;
            };
            boxes.extend(
                page.elements
                    .iter()
                    .filter(|element| {
                        range_element_selected(
                            element,
                            page_index,
                            &page.layout,
                            start_index,
                            start.column,
                            start.box_.y,
                            end_index,
                            end_column,
                            end_bottom,
                        )
                    })
                    .cloned(),
            );
        }
    }
}

fn range_anchors(boxes: &[RedactionBox], pages: &[RangePageGeometry]) -> Vec<RangeAnchor> {
    boxes
        .iter()
        .filter_map(|box_| {
            let page = pages.get(box_.page_number.checked_sub(1)?)?;
            Some(RangeAnchor {
                column: page.layout.column_of(box_.x, box_.x + box_.width),
                box_: box_.clone(),
            })
        })
        .collect()
}

fn range_anchor_reading_order(left: &RangeAnchor, right: &RangeAnchor) -> std::cmp::Ordering {
    left.box_
        .page_number
        .cmp(&right.box_.page_number)
        .then_with(|| left.column.cmp(&right.column))
        .then_with(|| left.box_.y.total_cmp(&right.box_.y))
        .then_with(|| left.box_.x.total_cmp(&right.box_.x))
}

#[allow(clippy::too_many_arguments)]
fn range_element_selected(
    element: &RedactionBox,
    page_index: usize,
    layout: &PageColumnLayout,
    start_page: usize,
    start_column: usize,
    start_y: f32,
    end_page: usize,
    end_column: usize,
    end_y: f32,
) -> bool {
    let y_bottom = element.y + element.height;
    layout
        .columns_crossing(element.x, element.x + element.width)
        .into_iter()
        .all(|column| {
            in_range_column_zone(
                page_index,
                column,
                y_bottom,
                start_page,
                start_column,
                start_y,
                end_page,
                end_column,
                end_y,
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn in_range_column_zone(
    page_index: usize,
    column: usize,
    y_bottom: f32,
    start_page: usize,
    start_column: usize,
    start_y: f32,
    end_page: usize,
    end_column: usize,
    end_y: f32,
) -> bool {
    if page_index > start_page && page_index < end_page {
        return true;
    }
    if page_index == start_page && page_index == end_page {
        if start_column == end_column {
            return column == start_column && y_bottom >= start_y && y_bottom <= end_y;
        }
        if start_column < end_column {
            if column < start_column || column > end_column {
                return false;
            }
            if column == start_column {
                return y_bottom >= start_y;
            }
            if column == end_column {
                return y_bottom <= end_y;
            }
            return true;
        }
        return column == start_column && y_bottom >= start_y;
    }
    if page_index == start_page {
        return if column == start_column {
            y_bottom >= start_y
        } else {
            column > start_column
        };
    }
    if page_index == end_page {
        return if column == end_column {
            y_bottom <= end_y
        } else {
            column < end_column
        };
    }
    false
}

impl PageColumnLayout {
    fn from_line_boxes(lines: &[RedactionBox], page_width: f32) -> Self {
        let midpoint = page_width / 2.0;
        let mut left = 0;
        let mut right = 0;
        for line in lines
            .iter()
            .filter(|line| line.width >= RANGE_MIN_COLUMN_LINE_WIDTH)
        {
            let line_midpoint = line.x + line.width / 2.0;
            if line_midpoint < midpoint - RANGE_MIDPOINT_SLACK {
                left += 1;
            } else if line_midpoint > midpoint + RANGE_MIDPOINT_SLACK {
                right += 1;
            }
        }
        let columns = if left >= RANGE_MIN_SIDE_LINES && right >= RANGE_MIN_SIDE_LINES {
            vec![
                (0.0, midpoint - RANGE_MIDPOINT_SLACK),
                (midpoint + RANGE_MIDPOINT_SLACK, page_width),
            ]
        } else {
            vec![(0.0, page_width)]
        };
        Self { columns }
    }

    fn column_of(&self, left: f32, right: f32) -> usize {
        let midpoint = f32::midpoint(left, right);
        self.columns
            .iter()
            .enumerate()
            .min_by(|(_, left_column), (_, right_column)| {
                distance_to_column(midpoint, **left_column)
                    .total_cmp(&distance_to_column(midpoint, **right_column))
            })
            .map_or(0, |(index, _)| index)
    }

    fn columns_crossing(&self, left: f32, right: f32) -> Vec<usize> {
        let crossed = self
            .columns
            .iter()
            .enumerate()
            .filter_map(|(index, column)| {
                let overlap = right.min(column.1) - left.max(column.0);
                (overlap > RANGE_COLUMN_OVERLAP_SLACK).then_some(index)
            })
            .collect::<Vec<_>>();
        if crossed.is_empty() {
            vec![self.column_of(left, right)]
        } else {
            crossed
        }
    }
}

fn distance_to_column(value: f32, column: (f32, f32)) -> f32 {
    if value < column.0 {
        column.0 - value
    } else if value > column.1 {
        value - column.1
    } else {
        0.0
    }
}

fn range_document_geometry(
    input_path: &Path,
    filename: &str,
    color: [u8; 3],
) -> Result<PdfiumSearch<Vec<RangePageGeometry>>, PdfRedactionError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfRedactionError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfiumSearch::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfRedactionError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut pages = Vec::new();
    let mut total_elements = 0_usize;
    for pdfium_page_index in document.pages().as_range() {
        let page_index = usize::try_from(pdfium_page_index)
            .map_err(|_| PdfRedactionError::InvalidPageNumber { page_number: 0 })?;
        let page_number = page_index.saturating_add(1);
        let page =
            document
                .pages()
                .get(pdfium_page_index)
                .map_err(|source| PdfRedactionError::Page {
                    page_number,
                    source,
                })?;
        let dimensions = PageDimensions {
            width: page.width().value,
            height: page.height().value,
        };
        let (_, glyphs) = page_text_glyphs(&page, page_number)?;
        let mut elements = page_text_line_boxes(&glyphs, page_number, dimensions.height, color);
        let layout = PageColumnLayout::from_line_boxes(&elements, dimensions.width);
        for object in page.objects().iter() {
            collect_image_object_boxes(
                &object,
                PdfMatrix::IDENTITY,
                page_number,
                dimensions.height,
                color,
                0,
                &mut elements,
            )?;
        }
        total_elements = total_elements
            .checked_add(elements.len())
            .ok_or(PdfRedactionError::TooManyExecutionBoxes)?;
        ensure_execution_box_limit(total_elements)?;
        pages.push(RangePageGeometry { layout, elements });
    }
    Ok(PdfiumSearch::Found(pages))
}

fn page_text_line_boxes(
    glyphs: &[TextGlyph],
    page_number: usize,
    page_height: f32,
    color: [u8; 3],
) -> Vec<RedactionBox> {
    let mut boxes = Vec::new();
    let mut group = None;
    let mut last_bottom = f32::NAN;
    let mut last_right = f32::NAN;
    for glyph in glyphs.iter().filter(|glyph| glyph.visible) {
        let y_jump =
            last_bottom.is_finite() && (glyph.bottom - last_bottom).abs() > RANGE_LINE_Y_TOLERANCE;
        let x_jump = last_right.is_finite() && glyph.left - last_right > RANGE_COLUMN_GAP;
        if y_jump || x_jump {
            flush_line_group(&mut boxes, group.take(), page_number, page_height, color);
        }
        let current = group.get_or_insert(GlyphGroup {
            left: glyph.left,
            right: glyph.right,
            bottom: glyph.bottom,
            top: glyph.top,
        });
        current.left = current.left.min(glyph.left);
        current.right = current.right.max(glyph.right);
        current.bottom = current.bottom.min(glyph.bottom);
        current.top = current.top.max(glyph.top);
        last_bottom = glyph.bottom;
        last_right = glyph.right;
    }
    flush_line_group(&mut boxes, group, page_number, page_height, color);
    boxes
}

fn flush_line_group(
    boxes: &mut Vec<RedactionBox>,
    group: Option<GlyphGroup>,
    page_number: usize,
    page_height: f32,
    color: [u8; 3],
) {
    let Some(group) = group else {
        return;
    };
    let width = group.right - group.left;
    let height = group.top - group.bottom;
    if width > 0.0 && height > 0.0 {
        boxes.push(RedactionBox {
            page_number,
            x: group.left,
            y: page_height - group.top,
            width,
            height,
            color,
        });
    }
}

fn ensure_execution_box_limit(box_count: usize) -> Result<(), PdfRedactionError> {
    if box_count > MAX_EXECUTE_REDACTION_BOXES {
        return Err(PdfRedactionError::TooManyExecutionBoxes);
    }
    Ok(())
}

fn document_page_dimensions(
    input_path: &Path,
    filename: &str,
) -> Result<PdfiumSearch<Vec<PageDimensions>>, PdfRedactionError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfRedactionError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfiumSearch::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfRedactionError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut dimensions = Vec::new();
    for pdfium_page_index in document.pages().as_range() {
        let page_index = usize::try_from(pdfium_page_index)
            .map_err(|_| PdfRedactionError::InvalidPageNumber { page_number: 0 })?;
        let page_number = page_index.saturating_add(1);
        let page =
            document
                .pages()
                .get(pdfium_page_index)
                .map_err(|source| PdfRedactionError::Page {
                    page_number,
                    source,
                })?;
        dimensions.push(PageDimensions {
            width: page.width().value,
            height: page.height().value,
        });
    }
    Ok(PdfiumSearch::Found(dimensions))
}

fn detected_image_redaction_boxes(
    input_path: &Path,
    filename: &str,
    selected_pages: Option<&BTreeSet<usize>>,
    color: [u8; 3],
) -> Result<PdfiumSearch<Vec<RedactionBox>>, PdfRedactionError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfRedactionError::RuntimePoisoned)?,
        Err(_) => {
            return Ok(PdfiumSearch::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfRedactionError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut boxes = Vec::new();
    for pdfium_page_index in document.pages().as_range() {
        let page_index = usize::try_from(pdfium_page_index)
            .map_err(|_| PdfRedactionError::InvalidPageNumber { page_number: 0 })?;
        if selected_pages.is_some_and(|selected| !selected.contains(&page_index)) {
            continue;
        }
        let page_number = page_index.saturating_add(1);
        let page =
            document
                .pages()
                .get(pdfium_page_index)
                .map_err(|source| PdfRedactionError::Page {
                    page_number,
                    source,
                })?;
        let page_height = page.height().value;
        for object in page.objects().iter() {
            collect_image_object_boxes(
                &object,
                PdfMatrix::IDENTITY,
                page_number,
                page_height,
                color,
                0,
                &mut boxes,
            )?;
        }
    }
    Ok(PdfiumSearch::Found(boxes))
}

fn collect_image_object_boxes(
    object: &PdfPageObject<'_>,
    parent_transform: PdfMatrix,
    page_number: usize,
    page_height: f32,
    color: [u8; 3],
    depth: usize,
    boxes: &mut Vec<RedactionBox>,
) -> Result<(), PdfRedactionError> {
    match object.object_type() {
        PdfPageObjectType::Image => append_transformed_object_box(
            object,
            parent_transform,
            page_number,
            page_height,
            color,
            boxes,
        ),
        PdfPageObjectType::XObjectForm => {
            let Some(form) = object.as_x_object_form_object() else {
                return Ok(());
            };
            if depth >= MAX_IMAGE_XOBJECT_DEPTH {
                return append_transformed_object_box(
                    object,
                    parent_transform,
                    page_number,
                    page_height,
                    color,
                    boxes,
                );
            }
            let transform = form
                .matrix()
                .map_err(|source| PdfRedactionError::Page {
                    page_number,
                    source,
                })?
                .multiply(parent_transform);
            for child in form.iter() {
                collect_image_object_boxes(
                    &child,
                    transform,
                    page_number,
                    page_height,
                    color,
                    depth.saturating_add(1),
                    boxes,
                )?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn append_transformed_object_box(
    object: &PdfPageObject<'_>,
    transform: PdfMatrix,
    page_number: usize,
    page_height: f32,
    color: [u8; 3],
    boxes: &mut Vec<RedactionBox>,
) -> Result<(), PdfRedactionError> {
    let bounds = object.bounds().map_err(|source| PdfRedactionError::Page {
        page_number,
        source,
    })?;
    let corners = [
        (bounds.left(), bounds.bottom()),
        (bounds.right(), bounds.bottom()),
        (bounds.left(), bounds.top()),
        (bounds.right(), bounds.top()),
    ];
    let mut left = f32::INFINITY;
    let mut right = f32::NEG_INFINITY;
    let mut bottom = f32::INFINITY;
    let mut top = f32::NEG_INFINITY;
    for (x, y) in corners {
        let (x, y) = transform.apply_to_points(x, y);
        left = left.min(x.value);
        right = right.max(x.value);
        bottom = bottom.min(y.value);
        top = top.max(y.value);
    }
    if !left.is_finite()
        || !right.is_finite()
        || !bottom.is_finite()
        || !top.is_finite()
        || right <= left
        || top <= bottom
    {
        return Ok(());
    }
    boxes.push(RedactionBox {
        page_number,
        x: left.max(0.0),
        y: (page_height - top).max(0.0),
        width: right - left,
        height: top - bottom,
        color,
    });
    ensure_execution_box_limit(boxes.len())
}

fn page_text_glyphs(
    page: &PdfPage<'_>,
    page_number: usize,
) -> Result<(String, Vec<TextGlyph>), PdfRedactionError> {
    let text = page.text().map_err(|source| PdfRedactionError::ReadText {
        page_number,
        source,
    })?;
    let mut content = String::new();
    let mut glyphs = Vec::new();
    for character in text.chars().iter() {
        let Some(value) = character.unicode_string() else {
            continue;
        };
        let start = content.len();
        content.push_str(&value);
        let end = content.len();
        let Ok(bounds) = character.loose_bounds() else {
            continue;
        };
        glyphs.push(TextGlyph {
            start,
            end,
            left: bounds.left().value,
            right: bounds.right().value,
            bottom: bounds.bottom().value,
            top: bounds.top().value,
            visible: value.chars().any(|character| !character.is_whitespace()),
        });
    }
    Ok((content, glyphs))
}

fn match_redaction_boxes(
    glyphs: &[TextGlyph],
    start: usize,
    end: usize,
    page_number: usize,
    page_height: f32,
    options: &AutoRedactionOptions,
) -> Vec<RedactionBox> {
    let mut groups: Vec<GlyphGroup> = Vec::new();
    for glyph in glyphs
        .iter()
        .filter(|glyph| glyph.start < end && glyph.end > start)
    {
        let center = f32::midpoint(glyph.bottom, glyph.top);
        if let Some(group) = groups.last_mut()
            && (f32::midpoint(group.bottom, group.top) - center).abs() <= LINE_TOLERANCE
        {
            group.left = group.left.min(glyph.left);
            group.right = group.right.max(glyph.right);
            group.bottom = group.bottom.min(glyph.bottom);
            group.top = group.top.max(glyph.top);
        } else {
            groups.push(GlyphGroup {
                left: glyph.left,
                right: glyph.right,
                bottom: glyph.bottom,
                top: glyph.top,
            });
        }
    }
    groups
        .into_iter()
        .filter_map(|group| {
            let height = group.top - group.bottom;
            let width = group.right - group.left;
            if !height.is_finite() || !width.is_finite() || height <= 0.0 || width <= 0.0 {
                return None;
            }
            let padding = height.mul_add(0.6, options.custom_padding);
            let bottom = (group.bottom - padding).max(0.0);
            let top = (group.top + padding).min(page_height);
            let redaction_height = top - bottom;
            (redaction_height > 0.0).then_some(RedactionBox {
                page_number,
                x: group.left.max(0.0),
                y: page_height - top,
                width,
                height: redaction_height,
                color: options.color,
            })
        })
        .collect()
}

fn paint_redaction_box(
    image: &mut RgbImage,
    page_width: f32,
    page_height: f32,
    box_: &RedactionBox,
) {
    if box_.width <= 0.0 || box_.height <= 0.0 || page_width <= 0.0 || page_height <= 0.0 {
        return;
    }
    let x_scale = f64::from(image.width()) / f64::from(page_width);
    let y_scale = f64::from(image.height()) / f64::from(page_height);
    let left = f64::from(box_.x) * x_scale;
    let top = f64::from(box_.y) * y_scale;
    let right = f64::from(box_.x + box_.width) * x_scale;
    let bottom = f64::from(box_.y + box_.height) * y_scale;
    let x_start = bounded_pixel_start(left, image.width());
    let x_end = bounded_pixel_end(right, image.width());
    let y_start = bounded_pixel_start(top, image.height());
    let y_end = bounded_pixel_end(bottom, image.height());
    for y in y_start..y_end {
        for x in x_start..x_end {
            image.put_pixel(x, y, Rgb(box_.color));
        }
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn bounded_pixel_start(value: f64, limit: u32) -> u32 {
    value.floor().clamp(0.0, f64::from(limit)) as u32
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn bounded_pixel_end(value: f64, limit: u32) -> u32 {
    value.ceil().clamp(0.0, f64::from(limit)) as u32
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn render_dimensions(
    width: PdfPoints,
    height: PdfPoints,
    dpi: i32,
    page_number: usize,
) -> Result<(i32, i32), PdfRedactionError> {
    let pixel_width = ((f64::from(width.value) / 72.0) * f64::from(dpi)).round();
    let pixel_height = ((f64::from(height.value) / 72.0) * f64::from(dpi)).round();
    let valid = pixel_width.is_finite()
        && pixel_height.is_finite()
        && pixel_width > 0.0
        && pixel_height > 0.0
        && pixel_width * pixel_height <= MAX_RENDER_PIXELS
        && pixel_width <= f64::from(i32::MAX)
        && pixel_height <= f64::from(i32::MAX);
    if !valid {
        return Err(PdfRedactionError::UnsafeRenderDimensions { page_number });
    }
    Ok((pixel_width as i32, pixel_height as i32))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use image::{Rgb, RgbImage};
    use lopdf::{Document, Object, Stream, dictionary};
    use tempfile::tempdir;

    use super::{
        AutoRedactionOptions, PageColumnLayout, PdfRedactionError, PdfiumSearch, RangePageGeometry,
        RedactionBox, RedactionTextRange, TextGlyph, append_range_geometry_boxes,
        automatic_patterns, automatic_redaction_boxes, collapse_letter_spacing,
        detected_image_redaction_boxes, match_redaction_boxes, page_text_line_boxes,
        paint_redaction_box, range_boundary_patterns,
    };

    #[test]
    fn paints_top_left_pdf_coordinates_into_the_raster() {
        let mut image = RgbImage::from_pixel(100, 100, Rgb([255, 255, 255]));
        paint_redaction_box(
            &mut image,
            100.0,
            100.0,
            &RedactionBox {
                page_number: 1,
                x: 10.0,
                y: 20.0,
                width: 30.0,
                height: 40.0,
                color: [1, 2, 3],
            },
        );
        assert_eq!(image.get_pixel(10, 20), &Rgb([1, 2, 3]));
        assert_eq!(image.get_pixel(39, 59), &Rgb([1, 2, 3]));
        assert_eq!(image.get_pixel(40, 60), &Rgb([255, 255, 255]));
    }

    #[test]
    fn automatic_search_is_case_insensitive_and_respects_whole_words()
    -> Result<(), PdfRedactionError> {
        let patterns = automatic_patterns(&AutoRedactionOptions {
            terms: vec!["secret".to_owned()],
            use_regex: false,
            whole_word: true,
            color: [0, 0, 0],
            custom_padding: 0.0,
        })?;
        let matches: Vec<_> = patterns[0].find_iter("SECRET secrets").collect();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches.first().map(regex::Match::as_str), Some("SECRET"));
        Ok(())
    }

    #[test]
    fn range_boundaries_include_java_compatible_fallbacks() -> Result<(), PdfRedactionError> {
        assert_eq!(collapse_letter_spacing("T a b l e  o f"), "Table of");
        let patterns = range_boundary_patterns("Section 1.2 — Results")?;
        assert!(
            patterns
                .iter()
                .any(|pattern| pattern.is_match("section 1 2 results"))
        );
        let multiline = range_boundary_patterns("First anchor\nignored continuation")?;
        assert!(
            multiline
                .iter()
                .any(|pattern| pattern.is_match("FIRST ANCHOR"))
        );
        Ok(())
    }

    #[test]
    fn automatic_match_uses_top_left_coordinates_and_vertical_padding() {
        let options = AutoRedactionOptions {
            terms: vec!["secret".to_owned()],
            use_regex: false,
            whole_word: false,
            color: [1, 2, 3],
            custom_padding: 1.0,
        };
        let boxes = match_redaction_boxes(
            &[
                TextGlyph {
                    start: 0,
                    end: 1,
                    left: 10.0,
                    right: 16.0,
                    bottom: 40.0,
                    top: 50.0,
                    visible: true,
                },
                TextGlyph {
                    start: 1,
                    end: 2,
                    left: 16.0,
                    right: 22.0,
                    bottom: 40.0,
                    top: 50.0,
                    visible: true,
                },
            ],
            0,
            2,
            1,
            100.0,
            &options,
        );
        assert_eq!(boxes.len(), 1);
        assert!((boxes[0].x - 10.0).abs() < f32::EPSILON);
        assert!((boxes[0].y - 43.0).abs() < f32::EPSILON);
        assert!((boxes[0].width - 12.0).abs() < f32::EPSILON);
        assert!((boxes[0].height - 24.0).abs() < f32::EPSILON);
        assert_eq!(boxes[0].color, [1, 2, 3]);
    }

    #[test]
    fn range_planner_selects_line_boxes_in_two_column_reading_order() {
        let element = |x, y| RedactionBox {
            page_number: 1,
            x,
            y,
            width: 100.0,
            height: 10.0,
            color: [1, 2, 3],
        };
        let pages = vec![RangePageGeometry {
            layout: PageColumnLayout {
                columns: vec![(0.0, 270.0), (330.0, 600.0)],
            },
            elements: vec![
                element(20.0, 10.0),
                element(20.0, 60.0),
                element(360.0, 10.0),
                element(360.0, 40.0),
            ],
        }];
        let starts = vec![element(20.0, 50.0)];
        let ends = vec![element(360.0, 20.0)];
        let mut selected = Vec::new();
        append_range_geometry_boxes(
            &mut selected,
            &starts,
            &ends,
            &RedactionTextRange {
                start_string: "start".to_owned(),
                end_string: "end".to_owned(),
            },
            &pages,
        );
        assert_eq!(selected, vec![element(20.0, 60.0), element(360.0, 10.0)]);
    }

    #[test]
    fn range_line_extraction_splits_large_same_baseline_gaps() {
        let glyph = |left, right| TextGlyph {
            start: 0,
            end: 1,
            left,
            right,
            bottom: 40.0,
            top: 50.0,
            visible: true,
        };
        let boxes = page_text_line_boxes(
            &[glyph(10.0, 20.0), glyph(21.0, 30.0), glyph(100.0, 110.0)],
            1,
            100.0,
            [1, 2, 3],
        );
        assert_eq!(boxes.len(), 2);
        assert!((boxes[0].x - 10.0).abs() < f32::EPSILON);
        assert!((boxes[0].width - 20.0).abs() < f32::EPSILON);
        assert!((boxes[1].x - 100.0).abs() < f32::EPSILON);
    }

    #[test]
    fn automatic_search_finds_pdfium_glyph_bounds_when_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input_path = directory.path().join("searchable.pdf");
        fs::write(&input_path, searchable_pdf()?)?;
        let options = AutoRedactionOptions {
            terms: vec!["confidential".to_owned()],
            use_regex: false,
            whole_word: true,
            color: [0, 0, 0],
            custom_padding: 0.0,
        };
        let patterns = automatic_patterns(&options)?;
        match automatic_redaction_boxes(&input_path, "searchable.pdf", &patterns, &options)? {
            PdfiumSearch::Unavailable { .. } => {}
            PdfiumSearch::Found(boxes) => {
                assert!(!boxes.is_empty());
                assert!(boxes.iter().all(|box_| box_.page_number == 1));
            }
        }
        Ok(())
    }

    #[test]
    fn image_detection_finds_pdfium_page_images_when_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input_path = directory.path().join("image.pdf");
        fs::write(&input_path, searchable_image_pdf()?)?;
        match detected_image_redaction_boxes(&input_path, "image.pdf", None, [1, 2, 3])? {
            PdfiumSearch::Unavailable { .. } => {}
            PdfiumSearch::Found(boxes) => {
                assert_eq!(boxes.len(), 1);
                assert_eq!(boxes[0].page_number, 1);
                assert!((boxes[0].x - 10.0).abs() < f32::EPSILON);
                assert!((boxes[0].y - 50.0).abs() < f32::EPSILON);
                assert!((boxes[0].width - 70.0).abs() < f32::EPSILON);
                assert!((boxes[0].height - 30.0).abs() < f32::EPSILON);
                assert_eq!(boxes[0].color, [1, 2, 3]);
            }
        }
        Ok(())
    }

    #[test]
    fn image_detection_descends_nested_form_xobjects_when_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input_path = directory.path().join("nested-image.pdf");
        fs::write(&input_path, nested_image_form_pdf()?)?;
        match detected_image_redaction_boxes(&input_path, "nested-image.pdf", None, [1, 2, 3])? {
            PdfiumSearch::Unavailable { .. } => {}
            PdfiumSearch::Found(boxes) => {
                assert_eq!(boxes.len(), 1);
                assert!((boxes[0].x - 35.0).abs() < 0.01);
                assert!((boxes[0].y - 54.0).abs() < 0.01);
                assert!((boxes[0].width - 40.0).abs() < 0.01);
                assert!((boxes[0].height - 30.0).abs() < 0.01);
            }
        }
        Ok(())
    }

    fn searchable_pdf() -> Result<Vec<u8>, lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let font_id = document.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            b"BT /F1 16 Tf 10 50 Td (Highly Confidential) Tj ET".to_vec(),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 160.into(), 80.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    fn searchable_image_pdf() -> Result<Vec<u8>, lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let image_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image", "Width" => 1,
                "Height" => 1, "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8,
            },
            vec![255, 255, 255],
        ));
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            b"q 70 0 0 30 10 20 cm /I1 Do Q".to_vec(),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page", "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 160.into(), 100.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "I1" => image_id } },
            "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    fn nested_image_form_pdf() -> Result<Vec<u8>, lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let image_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Image", "Width" => 1,
                "Height" => 1, "ColorSpace" => "DeviceRGB", "BitsPerComponent" => 8,
            },
            vec![255, 255, 255],
        ));
        let inner_form_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Form",
                "BBox" => vec![0.into(), 0.into(), 30.into(), 20.into()],
                "Resources" => dictionary! { "XObject" => dictionary! { "I1" => image_id } },
            },
            b"q 20 0 0 10 5 7 cm /I1 Do Q".to_vec(),
        ));
        let outer_form_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject", "Subtype" => "Form",
                "BBox" => vec![0.into(), 0.into(), 70.into(), 80.into()],
                "Resources" => dictionary! {
                    "XObject" => dictionary! { "FmInner" => inner_form_id }
                },
            },
            b"q 2 0 0 3 10 20 cm /FmInner Do Q".to_vec(),
        ));
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            b"q 1 0 0 1 15 25 cm /FmOuter Do Q".to_vec(),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page", "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 160.into(), 150.into()],
            "Resources" => dictionary! {
                "XObject" => dictionary! { "FmOuter" => outer_form_id }
            },
            "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }
}
