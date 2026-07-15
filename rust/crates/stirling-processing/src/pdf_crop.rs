use std::{io::ErrorKind, path::Path, process::Command};

use lopdf::{Document, Stream, dictionary};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::{
    ghostscript::{exit_status, ghostscript_commands},
    pdf_page_geometry::{PageForm, page_form, replace_page_tree},
    pdfium_backend::{
        DetectedCropBounds, PdfiumAutoCropAttempt, PdfiumAutoCropError, try_detect_auto_crop_bounds,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct CropOptions {
    pub x: Option<f32>,
    pub y: Option<f32>,
    pub width: Option<f32>,
    pub height: Option<f32>,
    pub remove_data_outside_crop: bool,
    pub auto_crop: bool,
}

#[derive(Debug, Error)]
pub enum CropError {
    #[error("crop coordinates (x, y, width, height) are required when auto-crop is not enabled")]
    MissingCoordinates,
    #[error("crop coordinates must be finite numbers")]
    NonFiniteCoordinates,
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF '{filename}' has no pages")]
    NoPages { filename: String },
    #[error("automatic crop returned a different number of page bounds than the source PDF")]
    PageCountMismatch,
    #[error("automatic crop requires PDFium: {details}")]
    PdfiumRuntime {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumAutoCropError),
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write cropped PDF: {0}")]
    WritePdf(std::io::Error),
    #[error("could not create Ghostscript crop input: {0}")]
    GhostscriptInput(std::io::Error),
    #[error("Ghostscript command '{command}' failed with status {status}")]
    GhostscriptFailed { command: String, status: String },
    #[error("Ghostscript command '{command}' could not start: {source}")]
    GhostscriptStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Ghostscript reported success without producing a PDF")]
    GhostscriptNoOutput,
}

/// Crops every page using explicit coordinates or PDFium-rendered content bounds.
///
/// # Errors
///
/// Returns [`CropError`] when request coordinates are missing, the PDF cannot be
/// read or rebuilt, automatic detection has no `PDFium` runtime, or Ghostscript is
/// available but fails while physically removing out-of-crop data.
pub fn crop_pdf_to_file(
    input_path: &Path,
    filename: &str,
    options: CropOptions,
    output_path: &Path,
) -> Result<(), CropError> {
    if options.auto_crop {
        let bounds = match try_detect_auto_crop_bounds(input_path, filename)? {
            PdfiumAutoCropAttempt::Detected(bounds) => bounds,
            PdfiumAutoCropAttempt::Unavailable {
                explicitly_configured,
                details,
            } => {
                return Err(CropError::PdfiumRuntime {
                    explicitly_configured,
                    details,
                });
            }
        };
        return rebuild_cropped_pdf(input_path, filename, &bounds, output_path);
    }

    let bounds = explicit_bounds(options)?;
    if options.remove_data_outside_crop
        && try_ghostscript_crop(input_path, filename, bounds, output_path)?
    {
        return Ok(());
    }
    let page_count = page_count(input_path, filename)?;
    rebuild_cropped_pdf(input_path, filename, &vec![bounds; page_count], output_path)
}

fn explicit_bounds(options: CropOptions) -> Result<DetectedCropBounds, CropError> {
    let (Some(x), Some(y), Some(width), Some(height)) =
        (options.x, options.y, options.width, options.height)
    else {
        return Err(CropError::MissingCoordinates);
    };
    if ![x, y, width, height].into_iter().all(f32::is_finite) {
        return Err(CropError::NonFiniteCoordinates);
    }
    Ok(DetectedCropBounds {
        x,
        y,
        width,
        height,
    })
}

fn page_count(input_path: &Path, filename: &str) -> Result<usize, CropError> {
    let document = load_document(input_path, filename)?;
    let page_count = document.get_pages().len();
    if page_count == 0 {
        Err(CropError::NoPages {
            filename: filename.to_owned(),
        })
    } else {
        Ok(page_count)
    }
}

fn rebuild_cropped_pdf(
    input_path: &Path,
    filename: &str,
    bounds: &[DetectedCropBounds],
    output_path: &Path,
) -> Result<(), CropError> {
    let mut document = load_document(input_path, filename)?;
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    if page_ids.is_empty() {
        return Err(CropError::NoPages {
            filename: filename.to_owned(),
        });
    }
    if page_ids.len() != bounds.len() {
        return Err(CropError::PageCountMismatch);
    }
    let root_pages_id = document.catalog()?.get(b"Pages")?.as_reference()?;
    let forms = page_ids
        .into_iter()
        .map(|page_id| page_form(&mut document, page_id))
        .collect::<Result<Vec<_>, _>>()?;
    let pages = forms
        .into_iter()
        .zip(bounds)
        .map(|(form, bounds)| add_cropped_page(&mut document, root_pages_id, form, *bounds))
        .collect();
    replace_page_tree(&mut document, root_pages_id, pages)?;
    document.catalog_mut()?.remove(b"AcroForm");
    document.renumber_objects();
    document.compress();
    document.save(output_path).map_err(CropError::WritePdf)?;
    Ok(())
}

fn add_cropped_page(
    document: &mut Document,
    parent_id: lopdf::ObjectId,
    form: PageForm,
    bounds: DetectedCropBounds,
) -> lopdf::ObjectId {
    let content = format!(
        "q {} {} {} {} re W n /Fm0 Do Q\n",
        bounds.x, bounds.y, bounds.width, bounds.height
    );
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => parent_id,
        "MediaBox" => vec![
            bounds.x.into(),
            bounds.y.into(),
            (bounds.x + bounds.width).into(),
            (bounds.y + bounds.height).into(),
        ],
        "Resources" => dictionary! {
            "XObject" => dictionary! { "Fm0" => form.id },
        },
        "Contents" => content_id,
    })
}

fn try_ghostscript_crop(
    input_path: &Path,
    filename: &str,
    bounds: DetectedCropBounds,
    output_path: &Path,
) -> Result<bool, CropError> {
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    let mut document = load_document(input_path, filename)?;
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    if page_ids.is_empty() {
        return Err(CropError::NoPages {
            filename: filename.to_owned(),
        });
    }
    for page_id in page_ids {
        document.get_dictionary_mut(page_id)?.set(
            "CropBox",
            vec![
                bounds.x.into(),
                bounds.y.into(),
                (bounds.x + bounds.width).into(),
                (bounds.y + bounds.height).into(),
            ],
        );
    }
    let input = NamedTempFile::new_in(parent).map_err(CropError::GhostscriptInput)?;
    document
        .save(input.path())
        .map_err(CropError::GhostscriptInput)?;

    for command in ghostscript_commands().candidates {
        let status = Command::new(&command)
            .arg("-sDEVICE=pdfwrite")
            .arg("-dUseCropBox")
            .arg("-o")
            .arg(output_path)
            .arg(input.path())
            .status();
        match status {
            Ok(status) if status.success() => {
                if output_exists(output_path) {
                    return Ok(true);
                }
                return Err(CropError::GhostscriptNoOutput);
            }
            Ok(status) => {
                return Err(CropError::GhostscriptFailed {
                    command,
                    status: exit_status(status),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(CropError::GhostscriptStart { command, source }),
        }
    }
    Ok(false)
}

fn output_exists(path: &Path) -> bool {
    path.metadata().is_ok_and(|metadata| metadata.len() > 0)
}

fn load_document(path: &Path, filename: &str) -> Result<Document, CropError> {
    Document::load(path).map_err(|source| CropError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}
