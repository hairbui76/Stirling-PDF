use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    fs::File,
    hash::{Hash, Hasher},
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
};

use image::{DynamicImage, ImageFormat, Rgba, RgbaImage, imageops};
use pdfium_render::prelude::{
    PdfDocument, PdfPage, PdfPageObjectCommon, PdfPageObjectsCommon, PdfPagePaperSize,
    PdfPageRenderRotation, PdfPageText, PdfPoints, PdfRenderConfig, Pdfium, PdfiumError,
};
use rxing::{
    BarcodeFormat, BinaryBitmap, DecodeHintValue, DecodeHints, Luma8LuminanceSource,
    MultiFormatReader, Reader,
    common::{GlobalHistogramBinarizer, HybridBinarizer},
};
use serde::Serialize;
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    page_selection::{PageSelectionError, parse_page_list},
    pdf_bookmarks::{BookmarkEntry, append_bookmarks},
    pdf_merge::MergeInput,
    pdf_scanner_effect::{ScannerEffectParams, calculate_safe_resolution, process_page},
    pdfium_runtime::shared_pdfium_runtime,
};

const MAX_BOOKMARKS_PER_DOCUMENT: usize = 100_000;
const QR_DETECTION_DPI: i32 = 150;
const MAX_QR_IMAGE_PIXELS: u64 = 100_000_000;
const BLANK_QR_CHECK_SAMPLES: usize = 20;

#[derive(Debug)]
pub enum PdfiumMergeAttempt {
    Merged {
        has_signatures: bool,
    },
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumRotateAttempt {
    Rotated,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumRemoveAttempt {
    Removed,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumAutoCropAttempt {
    Detected(Vec<DetectedCropBounds>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumTextLocationAttempt {
    Located(Vec<Option<DetectedTextBounds>>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedTextChunk {
    pub id: String,
    pub page: usize,
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub text: String,
}

#[derive(Debug)]
pub enum PdfiumTextChunksAttempt {
    Extracted(Vec<DetectedTextChunk>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

/// Bounded text and image-presence data needed by the math-audit orchestrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfiumAiPageContent {
    pub text: String,
    pub has_images: bool,
}

/// A successful AI-content scan or a clean indication that `PDFium` is absent.
#[derive(Debug)]
pub enum PdfiumAiPageContentAttempt {
    Extracted(Vec<PdfiumAiPageContent>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

/// Bounded AI page content paired with its one-based source page number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfiumAiPageWindowContent {
    pub page_number: usize,
    pub content: PdfiumAiPageContent,
}

/// A successful edge-window scan or a clean indication that `PDFium` is absent.
#[derive(Debug)]
pub enum PdfiumAiPageWindowAttempt {
    Extracted(Vec<PdfiumAiPageWindowContent>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdfiumWorkflowPageText {
    pub page_number: usize,
    pub text: String,
}

#[derive(Debug)]
pub enum PdfiumWorkflowTextAttempt {
    Extracted(Vec<PdfiumWorkflowPageText>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumTitleAttempt {
    Detected(Option<String>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

/// A single reconstructed visual line of page text with the geometry the Markdown
/// converter needs for heading inference.
#[derive(Debug, Clone, PartialEq)]
pub struct MarkdownTextLine {
    /// Zero-based source page index, used to separate pages in the output.
    pub page: usize,
    pub text: String,
    /// Most frequent glyph font size on the line (ties resolved toward the larger size).
    pub dominant_font_size: f32,
    /// Line bounding-box height, the fallback heading signal when font sizes are degenerate.
    pub height: f32,
    /// Left edge of the line bounding box, used for two-column gutter detection.
    pub x: f32,
    /// Width of the line bounding box, used for two-column gutter detection.
    pub width: f32,
    /// Top edge of the line bounding box; the top-to-bottom reading-order key
    /// (PDF user space grows upward, so larger `y` is higher on the page).
    pub y: f32,
    /// True when a vertical gap before this line suggests a paragraph break.
    pub paragraph_break_before: bool,
}

#[derive(Debug)]
pub enum PdfiumMarkdownAttempt {
    Extracted {
        lines: Vec<MarkdownTextLine>,
        median_font_size: f32,
        median_line_height: f32,
    },
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumExtractImagesAttempt {
    Extracted,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumFlattenAttempt {
    Flattened,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumInvertAttempt {
    Inverted,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumScannerAttempt {
    Processed,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumBlankDetectionAttempt {
    Detected(Vec<bool>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumAutoSplitAttempt {
    Split,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumToImageAttempt {
    Converted,
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug)]
pub enum PdfiumOcrPrepareAttempt {
    Prepared(Vec<PdfiumOcrPageArtifact>),
    Unavailable {
        explicitly_configured: bool,
        details: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfiumOcrMode {
    AllPages,
    SkipTextPages,
}

#[derive(Debug)]
pub struct PdfiumOcrPageArtifact {
    pub page_number: usize,
    pub original_pdf_path: PathBuf,
    pub image_path: Option<PathBuf>,
    pub ocr_output_base: PathBuf,
    pub expected_ocr_pdf_path: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub enum PdfToImageFormat {
    Png,
    Jpeg { extension: &'static str },
    Gif,
    WebP,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdfToImageMode {
    Single,
    Multiple,
}

#[derive(Debug, Clone, Copy)]
pub enum PdfToImageColor {
    Color,
    Greyscale,
    BlackWhite,
}

#[derive(Debug, Clone, Copy)]
pub enum ExtractImageFormat {
    Png,
    Jpeg,
    Gif,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectedCropBounds {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectedTextBounds {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumMergeError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not import pages from '{filename}' with PDFium: {source}")]
    ImportPages {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not write the merged PDF with PDFium: {0}")]
    Save(#[source] PdfiumError),
    #[error("could not append bookmarks to the merged PDF: {0}")]
    WriteBookmarks(#[source] std::io::Error),
    #[error("the merged PDF page count exceeds PDFium's signed 32-bit page index")]
    TooManyPages,
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumRotateError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not read a page rotation with PDFium: {0}")]
    ReadRotation(#[source] PdfiumError),
    #[error("could not write the rotated PDF with PDFium: {0}")]
    Save(#[source] PdfiumError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumRemoveError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("the PDF page count exceeds this platform's addressable memory")]
    PageCount,
    #[error("could not delete a page with PDFium: {0}")]
    DeletePage(#[source] PdfiumError),
    #[error("could not write the PDF with removed pages using PDFium: {0}")]
    Save(#[source] PdfiumError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumToImageError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("the selected page list is empty")]
    NoPages,
    #[error("the PDF page count exceeds this platform's addressable memory")]
    PageCount,
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(
        "page {page_number} would render to unsafe dimensions {width}x{height} pixels at {dpi} DPI"
    )]
    UnsafeRenderDimensions {
        page_number: usize,
        width: u64,
        height: u64,
        dpi: i32,
    },
    #[error("the combined image would have unsafe dimensions {width}x{height} pixels")]
    UnsafeCombinedDimensions { width: u64, height: u64 },
    #[error("could not encode output image {image_number}: {source}")]
    Encode {
        image_number: usize,
        #[source]
        source: image::ImageError,
    },
    #[error("could not write converted image output: {0}")]
    Io(#[from] io::Error),
    #[error("could not build converted image archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumOcrError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("the PDF has no pages to OCR")]
    NoPages,
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not create the retained PDF for page {page_number}: {source}")]
    CreatePageDocument {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not retain original page {page_number}: {source}")]
    ImportPage {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not write retained original page {page_number}: {source}")]
    SavePage {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(transparent)]
    Render(#[from] PdfiumToImageError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumFlattenError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not create the flattened PDF with PDFium: {0}")]
    CreateDocument(#[source] PdfiumError),
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(
        "page {page_number} would render to unsafe dimensions {width}x{height} pixels at {dpi} DPI"
    )]
    UnsafeRenderDimensions {
        page_number: usize,
        width: u64,
        height: u64,
        dpi: i32,
    },
    #[error("could not write the flattened PDF with PDFium: {0}")]
    Save(#[source] PdfiumError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumInvertError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not create the inverted PDF with PDFium: {0}")]
    CreateDocument(#[source] PdfiumError),
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(
        "page {page_number} would render to unsafe dimensions {width}x{height} pixels at {dpi} DPI"
    )]
    UnsafeRenderDimensions {
        page_number: usize,
        width: u64,
        height: u64,
        dpi: i32,
    },
    #[error("could not write the inverted PDF with PDFium: {0}")]
    Save(#[source] PdfiumError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumScannerError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not create the scanner-effect PDF with PDFium: {0}")]
    CreateDocument(#[source] PdfiumError),
    #[error("the provided PDF contains no pages to process")]
    EmptyDocument,
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(
        "page {page_number} would render to unsafe dimensions {width}x{height} pixels at {dpi} DPI"
    )]
    UnsafeRenderDimensions {
        page_number: usize,
        width: u64,
        height: u64,
        dpi: i32,
    },
    #[error("could not write the scanner-effect PDF with PDFium: {0}")]
    Save(#[source] PdfiumError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumBlankDetectionError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("page {page_number} exceeds PDFium's signed page-index range")]
    PageIndex { page_number: usize },
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(
        "page {page_number} would render to unsafe dimensions {width}x{height} pixels at {dpi} DPI"
    )]
    UnsafeRenderDimensions {
        page_number: usize,
        width: u64,
        height: u64,
        dpi: i32,
    },
    #[error("page {page_number} produced an invalid RGBA bitmap")]
    InvalidBitmap { page_number: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumAutoSplitError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not {operation} page {page_number} with PDFium: {source}")]
    Page {
        operation: &'static str,
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error(
        "page {page_number} would render to unsafe dimensions {width}x{height} pixels at {dpi} DPI"
    )]
    UnsafeRenderDimensions {
        page_number: usize,
        width: u64,
        height: u64,
        dpi: i32,
    },
    #[error("page {page_number} produced an invalid RGBA bitmap")]
    InvalidBitmap { page_number: usize },
    #[error("could not create auto-split document {document_number} with PDFium: {source}")]
    CreateDocument {
        document_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not import pages into auto-split document {document_number}: {source}")]
    ImportPages {
        document_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not write auto-split document {document_number}: {source}")]
    Save {
        document_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("the auto-split page count exceeds the supported range")]
    PageCount,
    #[error("could not read or write the auto-split archive: {0}")]
    Io(#[from] io::Error),
    #[error("could not build the auto-split ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumAutoCropError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not render page {page_number} for automatic crop detection: {source}")]
    Render {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("rendered page {page_number} has invalid bitmap dimensions")]
    InvalidBitmap { page_number: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumTextError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not read page {page_number} with PDFium: {source}")]
    ReadPage {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not extract text from page {page_number} with PDFium: {source}")]
    ReadText {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("the requested page index exceeds PDFium's signed 32-bit page index")]
    PageIndex,
    #[error("requested page number {page_number} is outside the PDF page range 1-{page_count}")]
    InvalidPage {
        page_number: usize,
        page_count: usize,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum PdfiumExtractImagesError {
    #[error("could not lock the PDFium runtime because another operation panicked")]
    RuntimePoisoned,
    #[error("could not read '{filename}' as a PDF with PDFium: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: PdfiumError,
    },
    #[error("could not read page {page_number} with PDFium: {source}")]
    ReadPage {
        page_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not decode image {image_number} on page {page_number}: {source}")]
    DecodeImage {
        page_number: usize,
        image_number: usize,
        #[source]
        source: PdfiumError,
    },
    #[error("could not encode image {image_number} on page {page_number}: {source}")]
    EncodeImage {
        page_number: usize,
        image_number: usize,
        #[source]
        source: image::ImageError,
    },
    #[error("could not create the extracted-images ZIP: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not create the extracted-images ZIP: {0}")]
    Zip(#[from] zip::result::ZipError),
}

pub fn try_flatten_pdf_to_file(
    input_path: &Path,
    filename: &str,
    flatten_only_forms: bool,
    render_dpi: i32,
    output_path: &Path,
) -> Result<PdfiumFlattenAttempt, PdfiumFlattenError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfiumFlattenError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumFlattenAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let source = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumFlattenError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;

    if flatten_only_forms {
        flatten_forms(&source, output_path)?;
    } else {
        rasterize_pdf(&pdfium, &source, render_dpi, output_path)?;
    }
    Ok(PdfiumFlattenAttempt::Flattened)
}

fn flatten_forms(document: &PdfDocument<'_>, output_path: &Path) -> Result<(), PdfiumFlattenError> {
    for page_index in document.pages().as_range() {
        let page_number = page_number(page_index);
        let mut page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumFlattenError::Page {
                    operation: "read",
                    page_number,
                    source,
                })?;
        page.flatten().map_err(|source| PdfiumFlattenError::Page {
            operation: "flatten form fields on",
            page_number,
            source,
        })?;
    }
    document
        .save_to_file(output_path)
        .map_err(PdfiumFlattenError::Save)
}

fn rasterize_pdf(
    pdfium: &Pdfium,
    source: &PdfDocument<'_>,
    render_dpi: i32,
    output_path: &Path,
) -> Result<(), PdfiumFlattenError> {
    let mut output = pdfium
        .create_new_pdf()
        .map_err(PdfiumFlattenError::CreateDocument)?;
    for page_index in source.pages().as_range() {
        let page_number = page_number(page_index);
        let page = source
            .pages()
            .get(page_index)
            .map_err(|source| PdfiumFlattenError::Page {
                operation: "read",
                page_number,
                source,
            })?;
        let width = page.width();
        let height = page.height();
        let (pixel_width, pixel_height) =
            checked_render_dimensions(width, height, render_dpi, page_number)?;
        let render_config = PdfRenderConfig::new()
            .set_fixed_size(pixel_width, pixel_height)
            .render_annotations(true)
            .render_form_data(true);
        let rendered = page
            .render_with_config(&render_config)
            .and_then(|bitmap| bitmap.as_image())
            .map_err(|source| PdfiumFlattenError::Page {
                operation: "render",
                page_number,
                source,
            })?;
        let rendered = DynamicImage::ImageRgb8(rendered.to_rgb8());
        let mut output_page = output
            .pages_mut()
            .create_page_at_end(PdfPagePaperSize::new_custom(width, height))
            .map_err(|source| PdfiumFlattenError::Page {
                operation: "create output for",
                page_number,
                source,
            })?;
        output_page
            .objects_mut()
            .create_image_object(
                PdfPoints::ZERO,
                PdfPoints::ZERO,
                &rendered,
                Some(width),
                Some(height),
            )
            .map_err(|source| PdfiumFlattenError::Page {
                operation: "add the rendered image for",
                page_number,
                source,
            })?;
    }
    output
        .save_to_file(output_path)
        .map_err(PdfiumFlattenError::Save)
}

fn checked_render_dimensions(
    width: PdfPoints,
    height: PdfPoints,
    dpi: i32,
    page_number: usize,
) -> Result<(i32, i32), PdfiumFlattenError> {
    let width = render_dimension(width.value, dpi);
    let height = render_dimension(height.value, dpi);
    let max_dimension = u64::from(i32::MAX.unsigned_abs());
    if width == 0
        || height == 0
        || width > max_dimension
        || height > max_dimension
        || width.saturating_mul(height) > max_dimension
    {
        return Err(PdfiumFlattenError::UnsafeRenderDimensions {
            page_number,
            width,
            height,
            dpi,
        });
    }
    let pixel_width =
        i32::try_from(width).map_err(|_| PdfiumFlattenError::UnsafeRenderDimensions {
            page_number,
            width,
            height,
            dpi,
        })?;
    let pixel_height =
        i32::try_from(height).map_err(|_| PdfiumFlattenError::UnsafeRenderDimensions {
            page_number,
            width,
            height,
            dpi,
        })?;
    Ok((pixel_width, pixel_height))
}

/// Renders every page to a raster image, inverts its colors, and rebuilds the
/// PDF with one full-page inverted image per page.
///
/// # Errors
///
/// Returns [`PdfiumInvertError`] when the runtime is poisoned, the PDF cannot be
/// read, a page renders to unsafe dimensions, or the output cannot be written.
pub fn try_invert_pdf_to_file(
    input_path: &Path,
    filename: &str,
    render_dpi: i32,
    output_path: &Path,
) -> Result<PdfiumInvertAttempt, PdfiumInvertError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfiumInvertError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumInvertAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let source = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumInvertError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;

    let mut output = pdfium
        .create_new_pdf()
        .map_err(PdfiumInvertError::CreateDocument)?;
    for page_index in source.pages().as_range() {
        let page_number = page_number(page_index);
        let page = source
            .pages()
            .get(page_index)
            .map_err(|source| PdfiumInvertError::Page {
                operation: "read",
                page_number,
                source,
            })?;
        let width = page.width();
        let height = page.height();
        let (pixel_width, pixel_height) =
            checked_invert_render_dimensions(width, height, render_dpi, page_number)?;
        let render_config = PdfRenderConfig::new()
            .set_fixed_size(pixel_width, pixel_height)
            .render_annotations(true)
            .render_form_data(true);
        let mut rendered = DynamicImage::ImageRgb8(
            page.render_with_config(&render_config)
                .and_then(|bitmap| bitmap.as_image())
                .map_err(|source| PdfiumInvertError::Page {
                    operation: "render",
                    page_number,
                    source,
                })?
                .to_rgb8(),
        );
        rendered.invert();
        let mut output_page = output
            .pages_mut()
            .create_page_at_end(PdfPagePaperSize::new_custom(width, height))
            .map_err(|source| PdfiumInvertError::Page {
                operation: "create output for",
                page_number,
                source,
            })?;
        output_page
            .objects_mut()
            .create_image_object(
                PdfPoints::ZERO,
                PdfPoints::ZERO,
                &rendered,
                Some(width),
                Some(height),
            )
            .map_err(|source| PdfiumInvertError::Page {
                operation: "add the inverted image for",
                page_number,
                source,
            })?;
    }
    output
        .save_to_file(output_path)
        .map_err(PdfiumInvertError::Save)?;
    Ok(PdfiumInvertAttempt::Inverted)
}

fn checked_invert_render_dimensions(
    width: PdfPoints,
    height: PdfPoints,
    dpi: i32,
    page_number: usize,
) -> Result<(i32, i32), PdfiumInvertError> {
    let width = render_dimension(width.value, dpi);
    let height = render_dimension(height.value, dpi);
    let max_dimension = u64::from(i32::MAX.unsigned_abs());
    let unsafe_dimensions = || PdfiumInvertError::UnsafeRenderDimensions {
        page_number,
        width,
        height,
        dpi,
    };
    if width == 0
        || height == 0
        || width > max_dimension
        || height > max_dimension
        || width.saturating_mul(height) > max_dimension
    {
        return Err(unsafe_dimensions());
    }
    let pixel_width = i32::try_from(width).map_err(|_| unsafe_dimensions())?;
    let pixel_height = i32::try_from(height).map_err(|_| unsafe_dimensions())?;
    Ok((pixel_width, pixel_height))
}

/// Rasterizes each page, runs the scanner-effect pipeline, and rebuilds the PDF
/// with one processed image per page placed on a same-sized output page.
///
/// # Errors
///
/// Returns [`PdfiumScannerError`] when the runtime is poisoned, the PDF cannot be
/// read, it has no pages, a page renders to unsafe dimensions, or the output
/// cannot be written.
pub fn try_scanner_effect_to_file(
    input_path: &Path,
    filename: &str,
    params: &ScannerEffectParams,
    output_path: &Path,
) -> Result<PdfiumScannerAttempt, PdfiumScannerError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfiumScannerError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumScannerAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let source = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumScannerError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    if source.pages().is_empty() {
        return Err(PdfiumScannerError::EmptyDocument);
    }

    let mut output = pdfium
        .create_new_pdf()
        .map_err(PdfiumScannerError::CreateDocument)?;
    for page_index in source.pages().as_range() {
        let page_number = page_number(page_index);
        let page = source
            .pages()
            .get(page_index)
            .map_err(|source| PdfiumScannerError::Page {
                operation: "read",
                page_number,
                source,
            })?;
        let width = page.width();
        let height = page.height();
        let safe_dpi = calculate_safe_resolution(width.value, height.value, params.resolution);
        let (pixel_width, pixel_height) =
            checked_scanner_render_dimensions(width, height, safe_dpi, page_number)?;
        let render_config = PdfRenderConfig::new()
            .set_fixed_size(pixel_width, pixel_height)
            .render_annotations(true)
            .render_form_data(true);
        let rendered = page
            .render_with_config(&render_config)
            .and_then(|bitmap| bitmap.as_image())
            .map_err(|source| PdfiumScannerError::Page {
                operation: "render",
                page_number,
                source,
            })?
            .to_rgb8();
        let processed = process_page(rendered, width.value, height.value, params);
        let mut output_page = output
            .pages_mut()
            .create_page_at_end(PdfPagePaperSize::new_custom(width, height))
            .map_err(|source| PdfiumScannerError::Page {
                operation: "create output for",
                page_number,
                source,
            })?;
        output_page
            .objects_mut()
            .create_image_object(
                PdfPoints::new(processed.offset_x),
                PdfPoints::new(processed.offset_y),
                &DynamicImage::ImageRgb8(processed.image),
                Some(PdfPoints::new(processed.draw_width)),
                Some(PdfPoints::new(processed.draw_height)),
            )
            .map_err(|source| PdfiumScannerError::Page {
                operation: "add the scanned image for",
                page_number,
                source,
            })?;
    }
    output
        .save_to_file(output_path)
        .map_err(PdfiumScannerError::Save)?;
    Ok(PdfiumScannerAttempt::Processed)
}

fn checked_scanner_render_dimensions(
    width: PdfPoints,
    height: PdfPoints,
    dpi: i32,
    page_number: usize,
) -> Result<(i32, i32), PdfiumScannerError> {
    let width = render_dimension(width.value, dpi);
    let height = render_dimension(height.value, dpi);
    let max_dimension = u64::from(i32::MAX.unsigned_abs());
    let unsafe_dimensions = || PdfiumScannerError::UnsafeRenderDimensions {
        page_number,
        width,
        height,
        dpi,
    };
    if width == 0
        || height == 0
        || width > max_dimension
        || height > max_dimension
        || width.saturating_mul(height) > max_dimension
    {
        return Err(unsafe_dimensions());
    }
    let pixel_width = i32::try_from(width).map_err(|_| unsafe_dimensions())?;
    let pixel_height = i32::try_from(height).map_err(|_| unsafe_dimensions())?;
    Ok((pixel_width, pixel_height))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn render_dimension(points: f32, dpi: i32) -> u64 {
    if !points.is_finite() || points <= 0.0 || dpi <= 0 {
        return 0;
    }
    ((f64::from(points) / 72.0) * f64::from(dpi)).round() as u64
}

fn page_number(page_index: i32) -> usize {
    usize::try_from(page_index).map_or(usize::MAX, |index| index.saturating_add(1))
}

/// Creates the bounded per-page artifacts needed by the Tesseract OCR fallback.
///
/// The source PDF is loaded once. Every page is retained as a one-page PDF, and
/// pages selected for OCR are additionally rendered to PNG without retaining a
/// full-document raster set in memory.
pub fn try_prepare_tesseract_pages(
    input_path: &Path,
    filename: &str,
    mode: PdfiumOcrMode,
    render_dpi: i32,
    images_dir: &Path,
    pages_dir: &Path,
) -> Result<PdfiumOcrPrepareAttempt, PdfiumOcrError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium.lock().map_err(|_| PdfiumOcrError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumOcrPrepareAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumOcrError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    if document.pages().is_empty() {
        return Err(PdfiumOcrError::NoPages);
    }

    let mut artifacts = Vec::new();
    for page_index in document.pages().as_range() {
        let page_number = page_number(page_index);
        let page = document
            .pages()
            .get(page_index)
            .map_err(|source| PdfiumOcrError::Page {
                operation: "read",
                page_number,
                source,
            })?;
        let has_text = if mode == PdfiumOcrMode::SkipTextPages {
            let text = page.text().map_err(|source| PdfiumOcrError::Page {
                operation: "extract text from",
                page_number,
                source,
            })?;
            text.segments()
                .iter()
                .any(|segment| !segment.text().trim().is_empty())
        } else {
            false
        };

        let original_pdf_path = pages_dir.join(format!("original-page-{page_index}.pdf"));
        let mut original =
            pdfium
                .create_new_pdf()
                .map_err(|source| PdfiumOcrError::CreatePageDocument {
                    page_number,
                    source,
                })?;
        original
            .pages_mut()
            .copy_pages_from_document(&document, &page_number.to_string(), 0)
            .map_err(|source| PdfiumOcrError::ImportPage {
                page_number,
                source,
            })?;
        original
            .save_to_file(&original_pdf_path)
            .map_err(|source| PdfiumOcrError::SavePage {
                page_number,
                source,
            })?;

        let should_ocr = mode == PdfiumOcrMode::AllPages || !has_text;
        let image_path = if should_ocr {
            let page_index = usize::try_from(page_index)
                .map_err(|_| PdfiumOcrError::Render(PdfiumToImageError::PageCount))?;
            let (width, height) = selected_page_dimensions(&document, page_index, render_dpi)?;
            let rendered = render_pdf_page(
                &document,
                page_index,
                width,
                height,
                PdfToImageColor::Color,
                render_dpi,
                true,
            )?;
            let encoded = encode_pdf_image(rendered, PdfToImageFormat::Png).map_err(|source| {
                PdfiumToImageError::Encode {
                    image_number: page_number,
                    source,
                }
            })?;
            let image_path = images_dir.join(format!("page_{page_index}.png"));
            std::fs::write(&image_path, encoded).map_err(PdfiumToImageError::Io)?;
            Some(image_path)
        } else {
            None
        };
        let ocr_output_base = pages_dir.join(format!("page_{page_index}"));
        let expected_ocr_pdf_path = ocr_output_base.with_extension("pdf");
        artifacts.push(PdfiumOcrPageArtifact {
            page_number,
            original_pdf_path,
            image_path,
            ocr_output_base,
            expected_ocr_pdf_path,
        });
    }
    Ok(PdfiumOcrPrepareAttempt::Prepared(artifacts))
}

pub fn try_auto_split_pdf_to_zip(
    input_path: &Path,
    filename: &str,
    duplex_mode: bool,
    maximum_dpi: i32,
    output_path: &Path,
) -> Result<PdfiumAutoSplitAttempt, PdfiumAutoSplitError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfiumAutoSplitError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumAutoSplitAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumAutoSplitError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count = document.pages().len();
    let mut groups = Vec::<Vec<i32>>::new();
    let mut page_index = 0;
    while page_index < page_count {
        let page_number = page_number(page_index);
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumAutoSplitError::Page {
                    operation: "read",
                    page_number,
                    source,
                })?;
        let qr_content = decode_page_qr(&page, maximum_dpi, page_number)?;
        let is_divider = qr_content.as_deref().is_some_and(valid_split_qr);
        add_page_to_auto_split_groups(&mut groups, page_index, is_divider);
        page_index = page_index.saturating_add(if duplex_mode && is_divider { 2 } else { 1 });
    }
    groups.retain(|group| !group.is_empty());

    let directory = tempdir()?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let zip_options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let base = filename_stem(filename);
    for (group_index, group) in groups.iter().enumerate() {
        let document_number = group_index.saturating_add(1);
        let mut split =
            pdfium
                .create_new_pdf()
                .map_err(|source| PdfiumAutoSplitError::CreateDocument {
                    document_number,
                    source,
                })?;
        let pages = group
            .iter()
            .map(|page| page.saturating_add(1).to_string())
            .collect::<Vec<_>>()
            .join(",");
        split
            .pages_mut()
            .copy_pages_from_document(&document, &pages, 0)
            .map_err(|source| PdfiumAutoSplitError::ImportPages {
                document_number,
                source,
            })?;
        let split_path = directory.path().join(format!("split-{group_index}.pdf"));
        split
            .save_to_file(&split_path)
            .map_err(|source| PdfiumAutoSplitError::Save {
                document_number,
                source,
            })?;
        archive.start_file(format!("{base}_{document_number}.pdf"), zip_options)?;
        io::copy(&mut File::open(split_path)?, &mut archive)?;
    }
    archive.finish()?;
    Ok(PdfiumAutoSplitAttempt::Split)
}

#[allow(clippy::too_many_arguments)]
pub fn try_convert_pdf_to_images(
    input_path: &Path,
    filename: &str,
    page_numbers: &str,
    format: PdfToImageFormat,
    mode: PdfToImageMode,
    color: PdfToImageColor,
    dpi: i32,
    include_annotations: bool,
    output_path: &Path,
) -> Result<PdfiumToImageAttempt, PdfiumToImageError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfiumToImageError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumToImageAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumToImageError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count =
        usize::try_from(document.pages().len()).map_err(|_| PdfiumToImageError::PageCount)?;
    let selected_pages = parse_page_list(page_numbers, page_count)?;
    if selected_pages.is_empty() {
        return Err(PdfiumToImageError::NoPages);
    }

    match mode {
        PdfToImageMode::Single => convert_pdf_to_single_image(
            &document,
            &selected_pages,
            format,
            color,
            dpi,
            include_annotations,
            output_path,
        )?,
        PdfToImageMode::Multiple => convert_pdf_to_image_archive(
            &document,
            &selected_pages,
            filename,
            format,
            color,
            dpi,
            include_annotations,
            output_path,
        )?,
    }
    Ok(PdfiumToImageAttempt::Converted)
}

fn convert_pdf_to_single_image(
    document: &PdfDocument<'_>,
    selected_pages: &[usize],
    format: PdfToImageFormat,
    color: PdfToImageColor,
    dpi: i32,
    include_annotations: bool,
    output_path: &Path,
) -> Result<(), PdfiumToImageError> {
    let dimensions = selected_pages
        .iter()
        .map(|page_index| selected_page_dimensions(document, *page_index, dpi))
        .collect::<Result<Vec<_>, _>>()?;
    let maximum_width = dimensions
        .iter()
        .map(|(width, _)| *width)
        .max()
        .ok_or(PdfiumToImageError::NoPages)?;
    let total_height = dimensions.iter().try_fold(0_u64, |total, (_, height)| {
        total
            .checked_add(*height)
            .ok_or(PdfiumToImageError::UnsafeCombinedDimensions {
                width: maximum_width,
                height: u64::MAX,
            })
    })?;
    let total_pixels = maximum_width.saturating_mul(total_height);
    if maximum_width == 0
        || total_height == 0
        || maximum_width > u64::from(u32::MAX)
        || total_height > u64::from(u32::MAX)
        || total_pixels > u64::from(i32::MAX.unsigned_abs())
    {
        return Err(PdfiumToImageError::UnsafeCombinedDimensions {
            width: maximum_width,
            height: total_height,
        });
    }
    let width =
        u32::try_from(maximum_width).map_err(|_| PdfiumToImageError::UnsafeCombinedDimensions {
            width: maximum_width,
            height: total_height,
        })?;
    let height =
        u32::try_from(total_height).map_err(|_| PdfiumToImageError::UnsafeCombinedDimensions {
            width: maximum_width,
            height: total_height,
        })?;
    let background = if matches!(format, PdfToImageFormat::Png | PdfToImageFormat::WebP) {
        Rgba([0, 0, 0, 0])
    } else {
        Rgba([255, 255, 255, 255])
    };
    let mut combined = DynamicImage::ImageRgba8(RgbaImage::from_pixel(width, height, background));
    let mut current_y = 0_i64;
    for (page_index, (page_width, page_height)) in selected_pages.iter().zip(dimensions.iter()) {
        let rendered = render_pdf_page(
            document,
            *page_index,
            *page_width,
            *page_height,
            color,
            dpi,
            include_annotations,
        )?;
        let x = i64::try_from(maximum_width.saturating_sub(*page_width) / 2).map_err(|_| {
            PdfiumToImageError::UnsafeCombinedDimensions {
                width: maximum_width,
                height: total_height,
            }
        })?;
        imageops::overlay(&mut combined, &rendered, x, current_y);
        current_y = current_y
            .checked_add(i64::try_from(*page_height).map_err(|_| {
                PdfiumToImageError::UnsafeCombinedDimensions {
                    width: maximum_width,
                    height: total_height,
                }
            })?)
            .ok_or(PdfiumToImageError::UnsafeCombinedDimensions {
                width: maximum_width,
                height: total_height,
            })?;
    }
    let encoded =
        encode_pdf_image(combined, format).map_err(|source| PdfiumToImageError::Encode {
            image_number: 1,
            source,
        })?;
    std::fs::write(output_path, encoded)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn convert_pdf_to_image_archive(
    document: &PdfDocument<'_>,
    selected_pages: &[usize],
    filename: &str,
    format: PdfToImageFormat,
    color: PdfToImageColor,
    dpi: i32,
    include_annotations: bool,
    output_path: &Path,
) -> Result<(), PdfiumToImageError> {
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let zip_options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let base = filename_stem(filename);
    for (output_index, page_index) in selected_pages.iter().enumerate() {
        let image_number = output_index.saturating_add(1);
        let (width, height) = selected_page_dimensions(document, *page_index, dpi)?;
        let rendered = render_pdf_page(
            document,
            *page_index,
            width,
            height,
            color,
            dpi,
            include_annotations,
        )?;
        let encoded =
            encode_pdf_image(rendered, format).map_err(|source| PdfiumToImageError::Encode {
                image_number,
                source,
            })?;
        let entry_name = if matches!(format, PdfToImageFormat::WebP) {
            format!("page_{image_number}.webp")
        } else {
            format!("{base}_{image_number}.{}", format.extension())
        };
        archive.start_file(entry_name, zip_options)?;
        archive.write_all(&encoded)?;
    }
    archive.finish()?;
    Ok(())
}

fn selected_page_dimensions(
    document: &PdfDocument<'_>,
    page_index: usize,
    dpi: i32,
) -> Result<(u64, u64), PdfiumToImageError> {
    let page_number = page_index.saturating_add(1);
    let page_index = i32::try_from(page_index).map_err(|_| PdfiumToImageError::PageCount)?;
    let page = document
        .pages()
        .get(page_index)
        .map_err(|source| PdfiumToImageError::Page {
            operation: "read",
            page_number,
            source,
        })?;
    let width = render_dimension(page.width().value, dpi);
    let height = render_dimension(page.height().value, dpi);
    let maximum_dimension = u64::from(i32::MAX.unsigned_abs());
    if width == 0
        || height == 0
        || width > maximum_dimension
        || height > maximum_dimension
        || width.saturating_mul(height) > maximum_dimension
    {
        return Err(PdfiumToImageError::UnsafeRenderDimensions {
            page_number,
            width,
            height,
            dpi,
        });
    }
    Ok((width, height))
}

#[allow(clippy::too_many_arguments)]
fn render_pdf_page(
    document: &PdfDocument<'_>,
    page_index: usize,
    width: u64,
    height: u64,
    color: PdfToImageColor,
    dpi: i32,
    include_annotations: bool,
) -> Result<DynamicImage, PdfiumToImageError> {
    let page_number = page_index.saturating_add(1);
    let invalid = || PdfiumToImageError::UnsafeRenderDimensions {
        page_number,
        width,
        height,
        dpi,
    };
    let page_index = i32::try_from(page_index).map_err(|_| PdfiumToImageError::PageCount)?;
    let page = document
        .pages()
        .get(page_index)
        .map_err(|source| PdfiumToImageError::Page {
            operation: "read",
            page_number,
            source,
        })?;
    let config = PdfRenderConfig::new()
        .set_fixed_size(
            i32::try_from(width).map_err(|_| invalid())?,
            i32::try_from(height).map_err(|_| invalid())?,
        )
        .render_annotations(include_annotations)
        .render_form_data(include_annotations);
    let rendered = page
        .render_with_config(&config)
        .and_then(|bitmap| bitmap.as_image())
        .map_err(|source| PdfiumToImageError::Page {
            operation: "render",
            page_number,
            source,
        })?;
    Ok(apply_pdf_image_color(&rendered, color))
}

fn apply_pdf_image_color(image: &DynamicImage, color: PdfToImageColor) -> DynamicImage {
    match color {
        PdfToImageColor::Color => DynamicImage::ImageRgb8(image.to_rgb8()),
        PdfToImageColor::Greyscale => DynamicImage::ImageLuma8(image.to_luma8()),
        PdfToImageColor::BlackWhite => {
            let mut image = image.to_luma8();
            for pixel in image.pixels_mut() {
                pixel.0[0] = if pixel.0[0] < 128 { 0 } else { 255 };
            }
            DynamicImage::ImageLuma8(image)
        }
    }
}

fn encode_pdf_image(
    image: DynamicImage,
    format: PdfToImageFormat,
) -> Result<Vec<u8>, image::ImageError> {
    const WEBP_MAX_DIMENSION: u32 = 16_383;
    let image = if matches!(format, PdfToImageFormat::WebP)
        && (image.width() > WEBP_MAX_DIMENSION || image.height() > WEBP_MAX_DIMENSION)
    {
        image.resize(
            WEBP_MAX_DIMENSION,
            WEBP_MAX_DIMENSION,
            imageops::FilterType::Lanczos3,
        )
    } else {
        image
    };
    let (image, image_format) = match format {
        PdfToImageFormat::Png => (image, ImageFormat::Png),
        PdfToImageFormat::Jpeg { .. } => {
            (DynamicImage::ImageRgb8(image.to_rgb8()), ImageFormat::Jpeg)
        }
        PdfToImageFormat::Gif => (DynamicImage::ImageRgba8(image.to_rgba8()), ImageFormat::Gif),
        PdfToImageFormat::WebP => (image, ImageFormat::WebP),
    };
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, image_format)?;
    Ok(output.into_inner())
}

impl PdfToImageFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg { extension } => extension,
            Self::Gif => "gif",
            Self::WebP => "webp",
        }
    }
}

fn decode_page_qr(
    page: &PdfPage<'_>,
    maximum_dpi: i32,
    page_number: usize,
) -> Result<Option<String>, PdfiumAutoSplitError> {
    let content = render_and_decode_qr(page, QR_DETECTION_DPI, page_number)?;
    if content.is_some() || maximum_dpi <= QR_DETECTION_DPI {
        return Ok(content);
    }
    render_and_decode_qr(page, maximum_dpi, page_number)
}

fn render_and_decode_qr(
    page: &PdfPage<'_>,
    dpi: i32,
    page_number: usize,
) -> Result<Option<String>, PdfiumAutoSplitError> {
    let (pixel_width, pixel_height) =
        checked_qr_render_dimensions(page.width(), page.height(), dpi, page_number)?;
    let config = PdfRenderConfig::new()
        .set_fixed_size(pixel_width, pixel_height)
        .render_annotations(true)
        .render_form_data(true);
    let bitmap = page
        .render_with_config(&config)
        .map_err(|source| PdfiumAutoSplitError::Page {
            operation: "render",
            page_number,
            source,
        })?;
    let rgba = bitmap.as_rgba_bytes();
    let expected_bytes = usize::try_from(pixel_width)
        .ok()
        .and_then(|width| {
            usize::try_from(pixel_height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(PdfiumAutoSplitError::InvalidBitmap { page_number })?;
    if rgba.len() != expected_bytes {
        return Err(PdfiumAutoSplitError::InvalidBitmap { page_number });
    }
    Ok(decode_qr_rgba(
        &rgba,
        u32::try_from(pixel_width)
            .map_err(|_| PdfiumAutoSplitError::InvalidBitmap { page_number })?,
        u32::try_from(pixel_height)
            .map_err(|_| PdfiumAutoSplitError::InvalidBitmap { page_number })?,
    ))
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
fn checked_qr_render_dimensions(
    width: PdfPoints,
    height: PdfPoints,
    dpi: i32,
    page_number: usize,
) -> Result<(i32, i32), PdfiumAutoSplitError> {
    let mut pixel_width = render_dimension(width.value, dpi);
    let mut pixel_height = render_dimension(height.value, dpi);
    let total_pixels = pixel_width.saturating_mul(pixel_height);
    if total_pixels > MAX_QR_IMAGE_PIXELS {
        let scale = (MAX_QR_IMAGE_PIXELS as f64 / total_pixels as f64).sqrt();
        pixel_width = ((pixel_width as f64 * scale).floor() as u64).max(1);
        pixel_height = ((pixel_height as f64 * scale).floor() as u64).max(1);
    }
    let invalid = || PdfiumAutoSplitError::UnsafeRenderDimensions {
        page_number,
        width: pixel_width,
        height: pixel_height,
        dpi,
    };
    if pixel_width == 0
        || pixel_height == 0
        || pixel_width.saturating_mul(pixel_height) > MAX_QR_IMAGE_PIXELS
    {
        return Err(invalid());
    }
    Ok((
        i32::try_from(pixel_width).map_err(|_| invalid())?,
        i32::try_from(pixel_height).map_err(|_| invalid())?,
    ))
}

fn decode_qr_rgba(rgba: &[u8], width: u32, height: u32) -> Option<String> {
    let total_pixels = rgba.len() / 4;
    if total_pixels == 0 {
        return None;
    }
    let first = &rgba[..4];
    let step = (total_pixels / BLANK_QR_CHECK_SAMPLES).max(1);
    if rgba
        .chunks_exact(4)
        .step_by(step)
        .all(|pixel| pixel == first)
    {
        return None;
    }
    let luminance = rgba
        .chunks_exact(4)
        .map(|pixel| {
            let weighted =
                u16::from(pixel[0]) + u16::from(pixel[1]).saturating_mul(2) + u16::from(pixel[2]);
            u8::try_from(weighted / 4).unwrap_or(u8::MAX)
        })
        .collect::<Vec<_>>();
    let source = Luma8LuminanceSource::new(luminance, width, height);
    let hints = DecodeHints::default()
        .with(DecodeHintValue::PossibleFormats(HashSet::from([
            BarcodeFormat::QR_CODE,
        ])))
        .with(DecodeHintValue::TryHarder(true))
        .with(DecodeHintValue::AlsoInverted(true));
    let mut hybrid = BinaryBitmap::new(HybridBinarizer::new(source.clone()));
    if let Ok(result) = MultiFormatReader::default().decode_with_hints(&mut hybrid, &hints) {
        return Some(result.getText().to_owned());
    }
    let mut global = BinaryBitmap::new(GlobalHistogramBinarizer::new(source));
    MultiFormatReader::default()
        .decode_with_hints(&mut global, &hints)
        .ok()
        .map(|result| result.getText().to_owned())
}

fn valid_split_qr(content: &str) -> bool {
    matches!(
        content,
        "https://github.com/Stirling-Tools/Stirling-PDF"
            | "https://github.com/Frooodle/Stirling-PDF"
            | "https://stirlingpdf.com"
    )
}

fn add_page_to_auto_split_groups(groups: &mut Vec<Vec<i32>>, page_index: i32, is_divider: bool) {
    if is_divider && page_index != 0 {
        groups.push(Vec::new());
    }
    if !is_divider {
        if let Some(group) = groups.last_mut() {
            group.push(page_index);
        } else if page_index == 0 {
            groups.push(vec![page_index]);
        }
    } else if page_index == 0 {
        groups.push(vec![page_index]);
    }
}

fn filename_stem(filename: &str) -> &str {
    filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem)
}

pub fn try_detect_blank_image_pages(
    input_path: &Path,
    filename: &str,
    page_indices: &[usize],
    render_dpi: i32,
    threshold: i32,
    white_percent: f32,
) -> Result<PdfiumBlankDetectionAttempt, PdfiumBlankDetectionError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium
            .lock()
            .map_err(|_| PdfiumBlankDetectionError::RuntimePoisoned)?,
        Err(details) => {
            return Ok(PdfiumBlankDetectionAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumBlankDetectionError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut detected = Vec::with_capacity(page_indices.len());
    for &page_index in page_indices {
        let page_number = page_index.saturating_add(1);
        let native_index = i32::try_from(page_index)
            .map_err(|_| PdfiumBlankDetectionError::PageIndex { page_number })?;
        let page = document.pages().get(native_index).map_err(|source| {
            PdfiumBlankDetectionError::Page {
                operation: "read",
                page_number,
                source,
            }
        })?;
        let (pixel_width, pixel_height) =
            checked_blank_render_dimensions(page.width(), page.height(), render_dpi, page_number)?;
        let config = PdfRenderConfig::new()
            .set_fixed_size(pixel_width, pixel_height)
            .render_annotations(true)
            .render_form_data(true);
        let bitmap =
            page.render_with_config(&config)
                .map_err(|source| PdfiumBlankDetectionError::Page {
                    operation: "render",
                    page_number,
                    source,
                })?;
        let rgba = bitmap.as_rgba_bytes();
        let expected_bytes = usize::try_from(pixel_width)
            .ok()
            .and_then(|width| {
                usize::try_from(pixel_height)
                    .ok()
                    .and_then(|height| width.checked_mul(height))
            })
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or(PdfiumBlankDetectionError::InvalidBitmap { page_number })?;
        if rgba.len() != expected_bytes {
            return Err(PdfiumBlankDetectionError::InvalidBitmap { page_number });
        }
        detected.push(is_blank_rgba(&rgba, threshold, white_percent));
    }
    Ok(PdfiumBlankDetectionAttempt::Detected(detected))
}

fn checked_blank_render_dimensions(
    width: PdfPoints,
    height: PdfPoints,
    dpi: i32,
    page_number: usize,
) -> Result<(i32, i32), PdfiumBlankDetectionError> {
    let width = render_dimension(width.value, dpi);
    let height = render_dimension(height.value, dpi);
    let max_dimension = u64::from(i32::MAX.unsigned_abs());
    if width == 0
        || height == 0
        || width > max_dimension
        || height > max_dimension
        || width.saturating_mul(height) > max_dimension
    {
        return Err(PdfiumBlankDetectionError::UnsafeRenderDimensions {
            page_number,
            width,
            height,
            dpi,
        });
    }
    let invalid = || PdfiumBlankDetectionError::UnsafeRenderDimensions {
        page_number,
        width,
        height,
        dpi,
    };
    Ok((
        i32::try_from(width).map_err(|_| invalid())?,
        i32::try_from(height).map_err(|_| invalid())?,
    ))
}

fn is_blank_rgba(rgba: &[u8], threshold: i32, white_percent: f32) -> bool {
    let total = rgba.len() / 4;
    if total == 0 {
        return false;
    }
    let minimum_blue = 255_i32.saturating_sub(threshold);
    let white = rgba
        .chunks_exact(4)
        .filter(|pixel| i32::from(pixel[2]) >= minimum_blue)
        .count();
    let total = u32::try_from(total).unwrap_or(u32::MAX);
    let white = u32::try_from(white).unwrap_or(u32::MAX);
    (f64::from(white) / f64::from(total)) * 100.0 >= f64::from(white_percent)
}

pub fn try_extract_page_images_to_zip(
    input_path: &Path,
    filename: &str,
    base_filename: &str,
    format: ExtractImageFormat,
    extension: &str,
    output_path: &Path,
) -> Result<PdfiumExtractImagesAttempt, PdfiumExtractImagesError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumExtractImagesAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumExtractImagesError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumExtractImagesError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let mut seen_images = HashSet::new();
    for page_index in 0..document.pages().len() {
        let page_number = usize::try_from(page_index).unwrap_or_default() + 1;
        let page = document.pages().get(page_index).map_err(|source| {
            PdfiumExtractImagesError::ReadPage {
                page_number,
                source,
            }
        })?;
        let mut image_number = 1;
        for object in page.objects().iter() {
            let Some(image_object) = object.as_image_object() else {
                continue;
            };
            let image = image_object
                .get_processed_image(&document)
                .map_err(|source| PdfiumExtractImagesError::DecodeImage {
                    page_number,
                    image_number,
                    source,
                })?;
            let fingerprint = image_fingerprint(&image);
            if !seen_images.insert(fingerprint) {
                continue;
            }
            let encoded = encode_image(&image, format).map_err(|source| {
                PdfiumExtractImagesError::EncodeImage {
                    page_number,
                    image_number,
                    source,
                }
            })?;
            archive.start_file(
                format!("{base_filename}_page_{page_number}_{image_number}.{extension}"),
                options,
            )?;
            archive.write_all(&encoded)?;
            image_number += 1;
        }
    }
    archive.finish()?;
    Ok(PdfiumExtractImagesAttempt::Extracted)
}

fn image_fingerprint(image: &DynamicImage) -> u64 {
    let mut hasher = DefaultHasher::new();
    image.width().hash(&mut hasher);
    image.height().hash(&mut hasher);
    image.as_bytes().hash(&mut hasher);
    hasher.finish()
}

fn encode_image(
    image: &DynamicImage,
    format: ExtractImageFormat,
) -> Result<Vec<u8>, image::ImageError> {
    let (image, format) = match format {
        ExtractImageFormat::Png => (DynamicImage::ImageRgba8(image.to_rgba8()), ImageFormat::Png),
        ExtractImageFormat::Jpeg => (DynamicImage::ImageRgb8(image.to_rgb8()), ImageFormat::Jpeg),
        ExtractImageFormat::Gif => (DynamicImage::ImageRgba8(image.to_rgba8()), ImageFormat::Gif),
    };
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, format)?;
    Ok(output.into_inner())
}

pub fn try_locate_text_anchors(
    input_path: &Path,
    filename: &str,
    requests: &[(usize, String)],
) -> Result<PdfiumTextLocationAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumTextLocationAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count = document.pages().len();
    let mut locations = Vec::with_capacity(requests.len());
    for (page_index, needle) in requests {
        let page_index = i32::try_from(*page_index).map_err(|_| PdfiumTextError::PageIndex)?;
        if page_index < 0 || page_index >= page_count {
            locations.push(None);
            continue;
        }
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number: usize::try_from(page_index).unwrap_or_default() + 1,
                    source,
                })?;
        let text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number: usize::try_from(page_index).unwrap_or_default() + 1,
            source,
        })?;
        let normalized_needle = normalize_anchor_text(needle);
        let location = (!normalized_needle.is_empty()).then(|| {
            text.segments().iter().find_map(|segment| {
                normalize_anchor_text(&segment.text())
                    .contains(&normalized_needle)
                    .then(|| {
                        let bounds = segment.bounds();
                        DetectedTextBounds {
                            x: bounds.left().value,
                            y: bounds.bottom().value,
                            width: bounds.width().value,
                            height: bounds.height().value,
                        }
                    })
            })
        });
        let location = location.flatten();
        locations.push(location);
    }
    Ok(PdfiumTextLocationAttempt::Located(locations))
}

/// Extracts bounded positioned PDF text segments for an AI annotation request.
///
/// `PDFium` exposes segment geometry in PDF user-space coordinates, which is the
/// coordinate system expected by the annotation writer. Segment boundaries are
/// intentionally preserved instead of trying to reconstruct a whole page into
/// an unbounded string; the caller can give each segment to an AI engine as a
/// stable independently-addressable chunk.
///
/// # Errors
///
/// Returns [`PdfiumTextError`] when a configured `PDFium` runtime cannot read the
/// document or its page text. A missing non-configured runtime is returned as
/// [`PdfiumTextChunksAttempt::Unavailable`] so the HTTP layer can report that
/// this positioned-text feature is unavailable rather than emitting guessed
/// annotation locations.
pub fn try_extract_positioned_text_chunks(
    input_path: &Path,
    filename: &str,
    max_chunks: usize,
    max_text_characters: usize,
) -> Result<PdfiumTextChunksAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumTextChunksAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count = document.pages().len();
    let mut chunks = Vec::new();
    for page_index in 0..page_count {
        if chunks.len() == max_chunks {
            break;
        }
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number: usize::try_from(page_index).unwrap_or_default() + 1,
                    source,
                })?;
        let text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number: usize::try_from(page_index).unwrap_or_default() + 1,
            source,
        })?;
        let mut chunk_index = 0_usize;
        for segment in text.segments().iter() {
            if chunks.len() == max_chunks {
                break;
            }
            let value = segment.text();
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let bounds = segment.bounds();
            let width = bounds.width().value;
            let height = bounds.height().value;
            if !width.is_finite() || !height.is_finite() || width <= 0.0 || height <= 0.0 {
                continue;
            }
            let page = usize::try_from(page_index).unwrap_or_default();
            chunks.push(DetectedTextChunk {
                id: format!("p{page}-c{chunk_index}"),
                page,
                x: bounds.left().value,
                y: bounds.bottom().value,
                width,
                height,
                text: truncate_characters(value, max_text_characters),
            });
            chunk_index = chunk_index.saturating_add(1);
        }
    }
    Ok(PdfiumTextChunksAttempt::Extracted(chunks))
}

/// Extracts bounded plain text and image-presence flags for every PDF page.
///
/// This is intentionally not a general document extractor: its only consumers
/// classify pages and fulfil the bounded math-audit protocol. `PDFium` segments
/// preserve visual line groupings better than low-level content-stream token
/// concatenation, and the per-page text budget keeps the engine payload bounded.
///
/// # Errors
///
/// Returns [`PdfiumTextError`] when a configured `PDFium` runtime cannot read
/// the document. A missing non-configured runtime returns
/// [`PdfiumAiPageContentAttempt::Unavailable`].
pub fn try_extract_ai_page_content(
    input_path: &Path,
    filename: &str,
    max_text_characters_per_page: usize,
) -> Result<PdfiumAiPageContentAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumAiPageContentAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut pages = Vec::new();
    for page_index in 0..document.pages().len() {
        let page_number = usize::try_from(page_index).unwrap_or_default() + 1;
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number,
                    source,
                })?;
        let has_images = page
            .objects()
            .iter()
            .any(|object| object.as_image_object().is_some());
        let text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number,
            source,
        })?;
        let mut content = String::new();
        for segment in text.segments().iter() {
            let segment = segment.text();
            let segment = segment.trim();
            if segment.is_empty() || content.chars().count() >= max_text_characters_per_page {
                continue;
            }
            if !content.is_empty() {
                content.push('\n');
            }
            let remaining = max_text_characters_per_page.saturating_sub(content.chars().count());
            content.extend(segment.chars().take(remaining));
        }
        pages.push(PdfiumAiPageContent {
            text: content,
            has_images,
        });
    }
    Ok(PdfiumAiPageContentAttempt::Extracted(pages))
}

/// Extracts Java-workflow-compatible page text with global page/character budgets.
///
/// Requested page numbers are one-based, de-duplicated in caller order, and
/// validated before extraction. Contextual mode prepends page dimensions and
/// appends direct image bounds; ingest mode returns raw text only. Character
/// limits are counted as UTF-16 code units to match Java `String.length()`.
pub fn try_extract_workflow_page_text(
    input_path: &Path,
    filename: &str,
    requested_pages: &[usize],
    max_pages: usize,
    max_characters: usize,
    contextual: bool,
) -> Result<PdfiumWorkflowTextAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumWorkflowTextAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count = usize::try_from(document.pages().len()).unwrap_or_default();
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    if requested_pages.is_empty() {
        selected.extend(1..=page_count);
    } else {
        for &page_number in requested_pages {
            if page_number == 0 || page_number > page_count {
                return Err(PdfiumTextError::InvalidPage {
                    page_number,
                    page_count,
                });
            }
            if seen.insert(page_number) {
                selected.push(page_number);
            }
        }
    }

    let mut remaining_characters = max_characters;
    let mut output = Vec::new();
    for page_number in selected.into_iter().take(max_pages) {
        if remaining_characters == 0 {
            break;
        }
        let page_index =
            i32::try_from(page_number.saturating_sub(1)).map_err(|_| PdfiumTextError::PageIndex)?;
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number,
                    source,
                })?;
        let page_text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number,
            source,
        })?;
        let mut text = String::new();
        for segment in page_text.segments().iter() {
            let segment = segment.text();
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(segment);
        }
        if contextual {
            text = contextual_workflow_text(&page, &text);
        }
        let page_limit = remaining_characters.min(4_000);
        let text = truncate_utf16(&text, page_limit).trim().to_owned();
        if text.is_empty() {
            continue;
        }
        remaining_characters = remaining_characters.saturating_sub(text.encode_utf16().count());
        output.push(PdfiumWorkflowPageText { page_number, text });
    }
    Ok(PdfiumWorkflowTextAttempt::Extracted(output))
}

fn contextual_workflow_text(page: &PdfPage<'_>, extracted_text: &str) -> String {
    let page_width = page.width().value;
    let page_height = page.height().value;
    let mut text = format!(
        "--- Page dimensions: {page_width:.0}x{page_height:.0} pts (PDF user-space: origin bottom-left, Y up) ---\n{extracted_text}"
    );
    let mut images = Vec::new();
    for object in page.objects().iter() {
        if object.as_image_object().is_none() {
            continue;
        }
        let Ok(bounds) = object.bounds() else {
            continue;
        };
        let left = bounds.left().value;
        let bottom = bounds.bottom().value;
        let right = bounds.right().value;
        let top = bounds.top().value;
        let center_x = left.midpoint(right);
        let center_y = bottom.midpoint(top);
        let horizontal = if center_x < page_width / 3.0 {
            "left"
        } else if center_x > page_width * 2.0 / 3.0 {
            "right"
        } else {
            "center"
        };
        let vertical = if center_y < page_height / 3.0 {
            "bottom"
        } else if center_y > page_height * 2.0 / 3.0 {
            "top"
        } else {
            "middle"
        };
        images.push(format!(
            "Image {}: position={vertical}-{horizontal}, size={:.0}x{:.0} pts, bounds=(x1={left:.0}, y1={bottom:.0}, x2={right:.0}, y2={top:.0})",
            images.len() + 1,
            right - left,
            top - bottom,
        ));
    }
    if !images.is_empty() {
        text.push_str("\n\n--- Images on this page ---\n");
        text.push_str(&images.join("\n"));
    }
    text
}

fn truncate_utf16(value: &str, max_units: usize) -> String {
    let mut units = 0_usize;
    value
        .chars()
        .take_while(|character| {
            let width = character.len_utf16();
            if units.saturating_add(width) > max_units {
                return false;
            }
            units = units.saturating_add(width);
            true
        })
        .collect()
}

/// Extracts bounded text and image-presence flags from only the first and last
/// `pages_per_edge` pages. Overlapping indices are de-duplicated.
///
/// This avoids walking every page when a classifier needs only a small edge
/// window, keeping both `PDFium` work and the outbound AI payload bounded.
///
/// # Errors
///
/// Returns [`PdfiumTextError`] when a configured `PDFium` runtime cannot read
/// the document. A missing non-configured runtime returns
/// [`PdfiumAiPageWindowAttempt::Unavailable`].
pub fn try_extract_ai_page_window_content(
    input_path: &Path,
    filename: &str,
    max_text_characters_per_page: usize,
    pages_per_edge: usize,
) -> Result<PdfiumAiPageWindowAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumAiPageWindowAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count = document.pages().len();
    let pages_per_edge = i32::try_from(pages_per_edge).unwrap_or(i32::MAX);
    let page_indices = edge_page_indices(page_count, pages_per_edge);

    let mut pages = Vec::with_capacity(page_indices.len());
    for page_index in page_indices {
        let page_number = usize::try_from(page_index).unwrap_or_default() + 1;
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number,
                    source,
                })?;
        let has_images = page
            .objects()
            .iter()
            .any(|object| object.as_image_object().is_some());
        let text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number,
            source,
        })?;
        let mut content = String::new();
        for segment in text.segments().iter() {
            let segment = segment.text();
            let segment = segment.trim();
            if segment.is_empty() || content.chars().count() >= max_text_characters_per_page {
                continue;
            }
            if !content.is_empty() {
                content.push('\n');
            }
            let remaining = max_text_characters_per_page.saturating_sub(content.chars().count());
            content.extend(segment.chars().take(remaining));
        }
        pages.push(PdfiumAiPageWindowContent {
            page_number,
            content: PdfiumAiPageContent {
                text: content,
                has_images,
            },
        });
    }
    Ok(PdfiumAiPageWindowAttempt::Extracted(pages))
}

fn edge_page_indices(page_count: i32, pages_per_edge: i32) -> Vec<i32> {
    if page_count <= 0 || pages_per_edge <= 0 {
        return Vec::new();
    }
    let mut page_indices = Vec::with_capacity(
        usize::try_from(page_count).unwrap_or_default().min(
            usize::try_from(pages_per_edge)
                .unwrap_or_default()
                .saturating_mul(2),
        ),
    );
    for page_index in 0..page_count.min(pages_per_edge) {
        page_indices.push(page_index);
    }
    for page_index in page_count.saturating_sub(pages_per_edge).max(0)..page_count {
        if !page_indices.contains(&page_index) {
            page_indices.push(page_index);
        }
    }
    page_indices
}

fn truncate_characters(value: &str, max_characters: usize) -> String {
    value.chars().take(max_characters).collect()
}

pub fn try_detect_largest_text_title(
    input_path: &Path,
    filename: &str,
) -> Result<PdfiumTitleAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumTitleAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut lines: Vec<(String, f32)> = Vec::new();
    'pages: for page_index in 0..document.pages().len() {
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number: usize::try_from(page_index).unwrap_or_default() + 1,
                    source,
                })?;
        let text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number: usize::try_from(page_index).unwrap_or_default() + 1,
            source,
        })?;
        for segment in text.segments().iter() {
            if lines.len() >= 200 {
                break 'pages;
            }
            let segment_text = segment.text();
            if segment_text.is_empty() {
                continue;
            }
            let font_size = segment
                .chars()
                .map_err(|source| PdfiumTextError::ReadText {
                    page_number: usize::try_from(page_index).unwrap_or_default() + 1,
                    source,
                })?
                .iter()
                .map(|character| character.unscaled_font_size().value)
                .fold(0.0_f32, f32::max);
            if let Some((previous_text, previous_size)) = lines.last_mut()
                && previous_size.to_bits() == font_size.to_bits()
            {
                previous_text.push(' ');
                previous_text.push_str(&segment_text);
            } else {
                lines.push((segment_text, font_size));
            }
        }
    }
    let mut best: Option<(String, f32)> = None;
    for (text, font_size) in lines {
        if best
            .as_ref()
            .is_none_or(|(_, best_size)| font_size > *best_size)
        {
            best = Some((text, font_size));
        }
    }
    Ok(PdfiumTitleAttempt::Detected(best.map(|(text, _)| text)))
}

/// Upper bounds keeping the Markdown line extraction memory-safe on pathological input.
const MAX_MARKDOWN_LINES: usize = 200_000;
const MAX_MARKDOWN_GLYPH_SAMPLES: usize = 1_000_000;

/// A mutable visual line assembled from consecutive same-baseline text segments.
struct LineAccumulator {
    text: String,
    sizes: Vec<f32>,
    top: f32,
    bottom: f32,
    height: f32,
    left: f32,
    right: f32,
}

/// Extracts reconstructed visual lines with the glyph/line geometry the Markdown
/// converter uses to infer headings, or a clean indication that `PDFium` is absent.
///
/// Lines are assembled by grouping consecutive segments that share a vertical
/// baseline; the document median glyph size and line height are returned so the
/// converter can apply Java's size-ratio heading thresholds.
///
/// # Errors
///
/// Returns [`PdfiumTextError`] when the runtime lock is poisoned or `PDFium` cannot
/// read the document, a page, or its text.
pub fn try_extract_markdown_lines(
    input_path: &Path,
    filename: &str,
) -> Result<PdfiumMarkdownAttempt, PdfiumTextError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumMarkdownAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumTextError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumTextError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let mut lines = Vec::new();
    let mut glyph_sizes = Vec::new();
    let mut line_heights = Vec::new();
    for page_index in 0..document.pages().len() {
        if lines.len() >= MAX_MARKDOWN_LINES {
            break;
        }
        let page_number = usize::try_from(page_index).unwrap_or_default() + 1;
        let page =
            document
                .pages()
                .get(page_index)
                .map_err(|source| PdfiumTextError::ReadPage {
                    page_number,
                    source,
                })?;
        let text = page.text().map_err(|source| PdfiumTextError::ReadText {
            page_number,
            source,
        })?;
        let accumulators = accumulate_page_lines(&text, page_number)?;
        append_page_lines(
            usize::try_from(page_index).unwrap_or_default(),
            accumulators,
            &mut lines,
            &mut glyph_sizes,
            &mut line_heights,
        );
    }
    let median_font_size = crate::pdf_markdown::median(&glyph_sizes, 12.0);
    let median_line_height = crate::pdf_markdown::median(&line_heights, 12.0);
    Ok(PdfiumMarkdownAttempt::Extracted {
        lines,
        median_font_size,
        median_line_height,
    })
}

/// Groups a page's non-empty text segments into visual-line accumulators, carrying the
/// glyph sizes and bounding-box geometry the Markdown converter needs.
fn accumulate_page_lines(
    text: &PdfPageText,
    page_number: usize,
) -> Result<Vec<LineAccumulator>, PdfiumTextError> {
    let mut accumulators: Vec<LineAccumulator> = Vec::new();
    for segment in text.segments().iter() {
        let value = segment.text();
        if value.trim().is_empty() {
            continue;
        }
        let bounds = segment.bounds();
        let top = bounds.top().value;
        let bottom = bounds.bottom().value;
        let height = bounds.height().value;
        let left = bounds.left().value;
        let width = bounds.width().value;
        if !top.is_finite()
            || !bottom.is_finite()
            || !height.is_finite()
            || !left.is_finite()
            || !width.is_finite()
        {
            continue;
        }
        let right = left + width;
        let mut sizes = Vec::new();
        for character in segment
            .chars()
            .map_err(|source| PdfiumTextError::ReadText {
                page_number,
                source,
            })?
            .iter()
        {
            let whitespace = character.unicode_char().is_none_or(char::is_whitespace);
            let size = character.unscaled_font_size().value;
            if !whitespace && size.is_finite() && size > 0.0 {
                sizes.push(size);
            }
        }
        merge_segment_into_line(
            &mut accumulators,
            &value,
            &sizes,
            top,
            bottom,
            height,
            left,
            right,
        );
    }
    Ok(accumulators)
}

/// Appends a segment to the current line when it shares the line's vertical centre,
/// otherwise starts a new line.
#[allow(clippy::too_many_arguments)]
fn merge_segment_into_line(
    accumulators: &mut Vec<LineAccumulator>,
    text: &str,
    sizes: &[f32],
    top: f32,
    bottom: f32,
    height: f32,
    left: f32,
    right: f32,
) {
    let center = f32::midpoint(top, bottom);
    if let Some(current) = accumulators.last_mut() {
        let current_center = f32::midpoint(current.top, current.bottom);
        let tolerance = current.height.max(height) * 0.5;
        if (center - current_center).abs() <= tolerance {
            if !current.text.is_empty()
                && !current.text.ends_with(char::is_whitespace)
                && !text.starts_with(char::is_whitespace)
            {
                current.text.push(' ');
            }
            current.text.push_str(text);
            current.sizes.extend_from_slice(sizes);
            current.top = current.top.max(top);
            current.bottom = current.bottom.min(bottom);
            current.height = current.height.max(height);
            current.left = current.left.min(left);
            current.right = current.right.max(right);
            return;
        }
    }
    accumulators.push(LineAccumulator {
        text: text.to_owned(),
        sizes: sizes.to_vec(),
        top,
        bottom,
        height,
        left,
        right,
    });
}

/// Converts a page's accumulated lines into [`MarkdownTextLine`]s, flagging paragraph
/// breaks from vertical gaps and feeding the document median samples.
fn append_page_lines(
    page: usize,
    accumulators: Vec<LineAccumulator>,
    lines: &mut Vec<MarkdownTextLine>,
    glyph_sizes: &mut Vec<f32>,
    line_heights: &mut Vec<f32>,
) {
    let mut previous_bottom: Option<f32> = None;
    for accumulator in accumulators {
        if lines.len() >= MAX_MARKDOWN_LINES {
            break;
        }
        let paragraph_break_before = match previous_bottom {
            Some(previous) if accumulator.height > 0.0 => {
                (previous - accumulator.top) > accumulator.height * 0.6
            }
            _ => false,
        };
        previous_bottom = Some(accumulator.bottom);
        if glyph_sizes.len() < MAX_MARKDOWN_GLYPH_SAMPLES {
            let room = MAX_MARKDOWN_GLYPH_SAMPLES - glyph_sizes.len();
            glyph_sizes.extend(accumulator.sizes.iter().take(room).copied());
        }
        if accumulator.height > 0.0 && !accumulator.text.trim().is_empty() {
            line_heights.push(accumulator.height);
        }
        let dominant_font_size = dominant_font_size(&accumulator.sizes);
        lines.push(MarkdownTextLine {
            page,
            text: accumulator.text,
            dominant_font_size,
            height: accumulator.height,
            x: accumulator.left,
            width: (accumulator.right - accumulator.left).max(0.0),
            y: accumulator.top,
            paragraph_break_before,
        });
    }
}

/// Returns the most frequent glyph font size, breaking ties toward the larger size.
fn dominant_font_size(sizes: &[f32]) -> f32 {
    let mut best = 0.0_f32;
    let mut best_count = 0_usize;
    for size in sizes {
        let count = sizes
            .iter()
            .filter(|other| other.to_bits() == size.to_bits())
            .count();
        if count > best_count || (count == best_count && *size > best) {
            best_count = count;
            best = *size;
        }
    }
    best
}

fn normalize_anchor_text(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

pub fn try_merge_pdf_paths_to_file(
    inputs: &[MergeInput],
    generate_toc: bool,
    output_path: &Path,
) -> Result<PdfiumMergeAttempt, PdfiumMergeError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumMergeAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumMergeError::RuntimePoisoned)?;

    let Some((first_input, remaining_inputs)) = inputs.split_first() else {
        return Ok(PdfiumMergeAttempt::Merged {
            has_signatures: false,
        });
    };
    let mut destination = load_input(&pdfium, first_input)?;
    let mut generated_entries = Vec::with_capacity(inputs.len());
    let mut source_entries = Vec::new();
    let mut page_offset = document_page_count(&destination)?;
    if generate_toc {
        generated_entries.push(BookmarkEntry {
            title: toc_title(&first_input.filename, 1),
            page_index: 0,
        });
    }
    collect_bookmark_entries(&destination, 0, &mut source_entries);

    for (input_index, input) in remaining_inputs.iter().enumerate() {
        let source = load_input(&pdfium, input)?;
        if generate_toc {
            generated_entries.push(BookmarkEntry {
                title: toc_title(&input.filename, input_index + 2),
                page_index: page_offset,
            });
        }
        collect_bookmark_entries(&source, page_offset, &mut source_entries);
        let source_page_count = document_page_count(&source)?;
        if source_page_count == 0 {
            continue;
        }
        let destination_page_index = destination.pages().len();
        destination
            .pages_mut()
            .copy_pages_from_document(
                &source,
                &format!("1-{source_page_count}"),
                destination_page_index,
            )
            .map_err(|source| PdfiumMergeError::ImportPages {
                filename: input.filename.clone(),
                source,
            })?;
        page_offset = page_offset
            .checked_add(source_page_count)
            .ok_or(PdfiumMergeError::TooManyPages)?;
    }

    let has_signatures = !destination.signatures().is_empty();
    destination
        .save_to_file(output_path)
        .map_err(PdfiumMergeError::Save)?;
    generated_entries.extend(source_entries);
    append_bookmarks(output_path, &generated_entries, page_offset)
        .map_err(PdfiumMergeError::WriteBookmarks)?;
    Ok(PdfiumMergeAttempt::Merged { has_signatures })
}

pub fn try_rotate_pdf_to_file(
    input_path: &Path,
    filename: &str,
    angle: i32,
    output_path: &Path,
) -> Result<PdfiumRotateAttempt, PdfiumRotateError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumRotateAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumRotateError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumRotateError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;

    for mut page in document.pages().iter() {
        let current = rotation_degrees(page.rotation().map_err(PdfiumRotateError::ReadRotation)?);
        page.set_rotation(rotation_from_degrees(current.wrapping_add(angle)));
    }
    document
        .save_to_file(output_path)
        .map_err(PdfiumRotateError::Save)?;
    Ok(PdfiumRotateAttempt::Rotated)
}

pub fn try_remove_pdf_pages_to_file(
    input_path: &Path,
    filename: &str,
    page_numbers: &str,
    output_path: &Path,
) -> Result<PdfiumRemoveAttempt, PdfiumRemoveError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumRemoveAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumRemoveError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumRemoveError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_count =
        usize::try_from(document.pages().len()).map_err(|_| PdfiumRemoveError::PageCount)?;
    let mut pages = parse_page_list(page_numbers, page_count)?;
    pages.sort_unstable();
    for page_index in pages.into_iter().rev() {
        let page_index = i32::try_from(page_index).map_err(|_| PdfiumRemoveError::PageCount)?;
        document
            .pages()
            .get(page_index)
            .and_then(pdfium_render::prelude::PdfPage::delete)
            .map_err(PdfiumRemoveError::DeletePage)?;
    }
    document
        .save_to_file(output_path)
        .map_err(PdfiumRemoveError::Save)?;
    Ok(PdfiumRemoveAttempt::Removed)
}

pub fn try_detect_auto_crop_bounds(
    input_path: &Path,
    filename: &str,
) -> Result<PdfiumAutoCropAttempt, PdfiumAutoCropError> {
    let runtime = shared_pdfium_runtime();
    let pdfium = match &runtime.instance {
        Ok(pdfium) => pdfium,
        Err(details) => {
            return Ok(PdfiumAutoCropAttempt::Unavailable {
                explicitly_configured: runtime.explicitly_configured,
                details: details.clone(),
            });
        }
    };
    let pdfium = pdfium
        .lock()
        .map_err(|_| PdfiumAutoCropError::RuntimePoisoned)?;
    let document = pdfium
        .load_pdf_from_file(input_path, None)
        .map_err(|source| PdfiumAutoCropError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let render_config = PdfRenderConfig::new().scale_page_by_factor(150.0 / 72.0);
    let mut detected =
        Vec::with_capacity(usize::try_from(document.pages().len()).unwrap_or_default());
    for (page_index, page) in document.pages().iter().enumerate() {
        let page_width = page.width().value;
        let page_height = page.height().value;
        let bitmap = page.render_with_config(&render_config).map_err(|source| {
            PdfiumAutoCropError::Render {
                page_number: page_index + 1,
                source,
            }
        })?;
        let bitmap_width =
            u16::try_from(bitmap.width()).map_err(|_| PdfiumAutoCropError::InvalidBitmap {
                page_number: page_index + 1,
            })?;
        let bitmap_height =
            u16::try_from(bitmap.height()).map_err(|_| PdfiumAutoCropError::InvalidBitmap {
                page_number: page_index + 1,
            })?;
        if bitmap_width == 0 || bitmap_height == 0 {
            return Err(PdfiumAutoCropError::InvalidBitmap {
                page_number: page_index + 1,
            });
        }
        let width = usize::from(bitmap_width);
        let height = usize::from(bitmap_height);
        let bounds = detect_content_bounds(&bitmap.as_rgba_bytes(), width, height);
        let [left, bottom, right, top] = bounds.map(|value| {
            u16::try_from(value).map_err(|_| PdfiumAutoCropError::InvalidBitmap {
                page_number: page_index + 1,
            })
        });
        let (left, bottom, right, top) = (left?, bottom?, right?, top?);
        let scale_x = page_width / f32::from(bitmap_width);
        let scale_y = page_height / f32::from(bitmap_height);
        detected.push(DetectedCropBounds {
            x: f32::from(left) * scale_x,
            y: f32::from(bottom) * scale_y,
            width: f32::from(right.saturating_sub(left)) * scale_x,
            height: f32::from(top.saturating_sub(bottom)) * scale_y,
        });
    }
    Ok(PdfiumAutoCropAttempt::Detected(detected))
}

fn detect_content_bounds(rgba: &[u8], width: usize, height: usize) -> [usize; 4] {
    let step = if width > 2000 || height > 2000 { 2 } else { 1 };
    let is_white = |x: usize, y: usize| {
        let offset = (y * width + x) * 4;
        rgba.get(offset..offset + 3)
            .is_some_and(|pixel| pixel.iter().all(|channel| *channel >= 250))
    };

    let mut top = 0;
    'find_top: for y in (0..height).step_by(step) {
        for x in (0..width).step_by(step) {
            if !is_white(x, y) {
                top = y;
                break 'find_top;
            }
        }
    }
    let mut bottom = height - 1;
    'find_bottom: for y in (0..height).rev().step_by(step) {
        for x in (0..width).step_by(step) {
            if !is_white(x, y) {
                bottom = y;
                break 'find_bottom;
            }
        }
    }
    let mut left = 0;
    'find_left: for x in (0..width).step_by(step) {
        for y in (top..=bottom).step_by(step) {
            if !is_white(x, y) {
                left = x;
                break 'find_left;
            }
        }
    }
    let mut right = width - 1;
    'find_right: for x in (0..width).rev().step_by(step) {
        for y in (top..=bottom).step_by(step) {
            if !is_white(x, y) {
                right = x;
                break 'find_right;
            }
        }
    }
    [left, height - bottom - 1, right, height - top - 1]
}

fn rotation_degrees(rotation: PdfPageRenderRotation) -> i32 {
    match rotation {
        PdfPageRenderRotation::None => 0,
        PdfPageRenderRotation::Degrees90 => 90,
        PdfPageRenderRotation::Degrees180 => 180,
        PdfPageRenderRotation::Degrees270 => 270,
    }
}

fn rotation_from_degrees(degrees: i32) -> PdfPageRenderRotation {
    match degrees.rem_euclid(360) {
        0 => PdfPageRenderRotation::None,
        90 => PdfPageRenderRotation::Degrees90,
        180 => PdfPageRenderRotation::Degrees180,
        270 => PdfPageRenderRotation::Degrees270,
        _ => unreachable!("validated page rotations stay aligned to 90 degrees"),
    }
}

fn collect_bookmark_entries(
    document: &PdfDocument<'_>,
    page_offset: i32,
    output: &mut Vec<BookmarkEntry>,
) {
    for (processed, bookmark) in document.bookmarks().iter().enumerate() {
        if processed >= MAX_BOOKMARKS_PER_DOCUMENT {
            tracing::warn!(
                max_bookmarks = MAX_BOOKMARKS_PER_DOCUMENT,
                "source bookmark traversal reached its safety limit"
            );
            break;
        }
        let Some(title) = bookmark.title() else {
            continue;
        };
        let page_index = match bookmark.action() {
            Some(action) => action
                .as_local_destination_action()
                .and_then(|action| action.destination().ok())
                .and_then(|destination| destination.page_index().ok()),
            None => bookmark
                .destination()
                .and_then(|destination| destination.page_index().ok()),
        };
        let Some(page_index) = page_index
            .filter(|page_index| *page_index >= 0)
            .and_then(|page_index| page_offset.checked_add(page_index))
        else {
            continue;
        };
        output.push(BookmarkEntry { title, page_index });
    }
}

fn document_page_count(document: &PdfDocument<'_>) -> Result<i32, PdfiumMergeError> {
    let page_count = document.pages().len();
    if page_count < 0 {
        Err(PdfiumMergeError::TooManyPages)
    } else {
        Ok(page_count)
    }
}

fn toc_title(filename: &str, document_number: usize) -> String {
    let candidate = filename.rsplit_once('.').map_or(filename, |(stem, _)| stem);
    if candidate.trim().is_empty() {
        format!("Document {document_number}")
    } else {
        candidate.to_owned()
    }
}

fn load_input<'a>(
    pdfium: &'a Pdfium,
    input: &MergeInput,
) -> Result<pdfium_render::prelude::PdfDocument<'a>, PdfiumMergeError> {
    pdfium
        .load_pdf_from_file(&input.path, None)
        .map_err(|source| PdfiumMergeError::ReadPdf {
            filename: input.filename.clone(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use pdfium_render::prelude::Pdfium;

    use super::{
        add_page_to_auto_split_groups, detect_content_bounds, edge_page_indices, is_blank_rgba,
    };
    use crate::pdfium_runtime::pdfium_library_path;

    #[test]
    fn auto_split_keeps_a_first_page_divider_and_drops_later_dividers() {
        let mut groups = Vec::new();
        for (page, divider) in [true, false, true, false, false].into_iter().enumerate() {
            add_page_to_auto_split_groups(
                &mut groups,
                i32::try_from(page).unwrap_or_default(),
                divider,
            );
        }
        groups.retain(|group| !group.is_empty());
        assert_eq!(groups, [vec![0, 1], vec![3, 4]]);
    }

    #[test]
    fn edge_page_window_is_bounded_and_de_duplicates_short_documents() {
        assert_eq!(edge_page_indices(5, 2), [0, 1, 3, 4]);
        assert_eq!(edge_page_indices(3, 2), [0, 1, 2]);
        assert_eq!(edge_page_indices(1, 2), [0]);
        assert!(edge_page_indices(0, 2).is_empty());
        assert!(edge_page_indices(5, 0).is_empty());
    }

    #[test]
    fn detects_non_white_pixel_bounds_in_pdf_coordinates() {
        let width = 5;
        let height = 4;
        let mut pixels = vec![255; width * height * 4];
        for y in 1..=2 {
            for x in 1..=3 {
                let offset = (y * width + x) * 4;
                pixels[offset..offset + 3].fill(10);
            }
        }
        assert_eq!(detect_content_bounds(&pixels, width, height), [1, 1, 3, 2]);
    }

    #[test]
    fn blank_detection_matches_the_java_blue_channel_threshold() {
        let rgba = [255, 0, 250, 255, 0, 255, 244, 255];
        assert!(is_blank_rgba(&rgba, 10, 50.0));
        assert!(!is_blank_rgba(&rgba, 10, 50.1));
    }

    #[test]
    fn appends_the_platform_library_name_to_a_directory() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"));

        assert_eq!(
            pdfium_library_path(directory),
            Pdfium::pdfium_platform_library_name_at_path(directory)
        );
    }

    #[test]
    fn keeps_an_explicit_library_file_path() {
        let path = Path::new("not-a-real-directory/pdfium.custom");

        assert_eq!(pdfium_library_path(path), path);
    }
}
