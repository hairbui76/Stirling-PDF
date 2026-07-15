use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    env,
    fs::File,
    hash::{Hash, Hasher},
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use image::{DynamicImage, ImageFormat, Rgba, RgbaImage, imageops};
use pdfium_render::prelude::{
    PdfDocument, PdfPage, PdfPageObjectsCommon, PdfPagePaperSize, PdfPageRenderRotation, PdfPoints,
    PdfRenderConfig, Pdfium, PdfiumError,
};
use rxing::{
    BarcodeFormat, BinaryBitmap, DecodeHintValue, DecodeHints, Luma8LuminanceSource,
    MultiFormatReader, Reader,
    common::{GlobalHistogramBinarizer, HybridBinarizer},
};
use tempfile::tempdir;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    page_selection::{PageSelectionError, parse_page_list},
    pdf_bookmarks::{BookmarkEntry, append_bookmarks},
    pdf_merge::MergeInput,
};

pub const PDFIUM_LIBRARY_PATH_ENV: &str = "STIRLING_PDFIUM_LIBRARY_PATH";
const MAX_BOOKMARKS_PER_DOCUMENT: usize = 100_000;
const QR_DETECTION_DPI: i32 = 150;
const MAX_QR_IMAGE_PIXELS: u64 = 100_000_000;
const BLANK_QR_CHECK_SAMPLES: usize = 20;

static PDFIUM: OnceLock<PdfiumRuntime> = OnceLock::new();

#[derive(Debug)]
struct PdfiumRuntime {
    explicitly_configured: bool,
    instance: Result<Mutex<Pdfium>, String>,
}

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

#[derive(Debug)]
pub enum PdfiumTitleAttempt {
    Detected(Option<String>),
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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

pub fn try_auto_split_pdf_to_zip(
    input_path: &Path,
    filename: &str,
    duplex_mode: bool,
    maximum_dpi: i32,
    output_path: &Path,
) -> Result<PdfiumAutoSplitAttempt, PdfiumAutoSplitError> {
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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

pub fn try_detect_largest_text_title(
    input_path: &Path,
    filename: &str,
) -> Result<PdfiumTitleAttempt, PdfiumTextError> {
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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
    let runtime = PDFIUM.get_or_init(initialize_pdfium);
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

fn initialize_pdfium() -> PdfiumRuntime {
    let configured_path = env::var_os(PDFIUM_LIBRARY_PATH_ENV).map(PathBuf::from);
    let explicitly_configured = configured_path.is_some();
    let bindings = match configured_path {
        Some(path) => Pdfium::bind_to_library(pdfium_library_path(&path)),
        None => Pdfium::bind_to_system_library(),
    };
    PdfiumRuntime {
        explicitly_configured,
        instance: bindings.map(Pdfium::new).map(Mutex::new).map_err(|error| {
            format!(
                "{error}; set {PDFIUM_LIBRARY_PATH_ENV} to the PDFium shared library or its directory"
            )
        }),
    }
}

fn pdfium_library_path(configured_path: &Path) -> PathBuf {
    let path = if configured_path.is_dir() {
        Pdfium::pdfium_platform_library_name_at_path(configured_path)
    } else {
        configured_path.to_owned()
    };
    path.canonicalize().unwrap_or(path)
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
        add_page_to_auto_split_groups, detect_content_bounds, is_blank_rgba, pdfium_library_path,
    };

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
