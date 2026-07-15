use std::{fs::File, io, path::Path};

use lopdf::Document;
use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    pdf_filters::page_contains_image,
    pdf_flatten::configured_max_render_dpi,
    pdf_forms::prune_orphaned_form_fields_in_file,
    pdf_rearrange::{RearrangePagesError, rearrange_pdf_pages_to_file},
    pdfium_backend::{
        PdfiumBlankDetectionAttempt, PdfiumBlankDetectionError, try_detect_blank_image_pages,
    },
};

#[derive(Debug, Error)]
pub enum BlankPagesError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("the PDF page count exceeds the supported range")]
    PageCount,
    #[error("could not inspect PDF page content: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("PDFium is required to inspect image pages: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumBlankDetectionError),
    #[error(transparent)]
    Rearrange(#[from] RearrangePagesError),
    #[error("could not prune output form fields: {0}")]
    Prune(#[source] lopdf::Error),
    #[error("could not create the processed-pages ZIP: {0}")]
    Io(#[from] io::Error),
    #[error("could not create the processed-pages ZIP: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Classifies blank pages and writes the Java-compatible page groups to a ZIP.
///
/// # Errors
///
/// Returns [`BlankPagesError`] for malformed PDFs, unavailable native rendering
/// when image pages need inspection, unsafe rendering, or output failures.
pub fn remove_blank_pages_to_zip(
    input_path: &Path,
    filename: &str,
    threshold: i32,
    white_percent: f32,
    output_path: &Path,
) -> Result<(), BlankPagesError> {
    let document = Document::load(input_path).map_err(|source| BlankPagesError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    if page_ids.is_empty() {
        return Err(BlankPagesError::PageCount);
    }
    let mut blank = vec![false; page_ids.len()];
    let mut image_pages = Vec::new();
    for (page_index, page_id) in page_ids.into_iter().enumerate() {
        let page_number =
            u32::try_from(page_index.saturating_add(1)).map_err(|_| BlankPagesError::PageCount)?;
        if !document.extract_text(&[page_number])?.trim().is_empty() {
            continue;
        }
        if page_contains_image(&document, page_id)? {
            image_pages.push(page_index);
        } else {
            blank[page_index] = true;
        }
    }
    classify_image_pages(
        input_path,
        filename,
        &image_pages,
        configured_max_render_dpi(),
        threshold,
        white_percent,
        &mut blank,
    )?;
    write_page_groups(input_path, filename, &blank, output_path)
}

fn classify_image_pages(
    input_path: &Path,
    filename: &str,
    image_pages: &[usize],
    render_dpi: i32,
    threshold: i32,
    white_percent: f32,
    blank: &mut [bool],
) -> Result<(), BlankPagesError> {
    if image_pages.is_empty() {
        return Ok(());
    }
    let detected = match try_detect_blank_image_pages(
        input_path,
        filename,
        image_pages,
        render_dpi,
        threshold,
        white_percent,
    )? {
        PdfiumBlankDetectionAttempt::Detected(detected) => detected,
        PdfiumBlankDetectionAttempt::Unavailable {
            explicitly_configured,
            details,
        } => {
            return Err(BlankPagesError::PdfiumUnavailable {
                explicitly_configured,
                details,
            });
        }
    };
    if detected.len() != image_pages.len() {
        return Err(BlankPagesError::PageCount);
    }
    for (&page_index, is_blank) in image_pages.iter().zip(detected) {
        if let Some(blank) = blank.get_mut(page_index) {
            *blank = is_blank;
        }
    }
    Ok(())
}

fn write_page_groups(
    input_path: &Path,
    filename: &str,
    blank: &[bool],
    output_path: &Path,
) -> Result<(), BlankPagesError> {
    let blank_pages = blank
        .iter()
        .enumerate()
        .filter_map(|(index, blank)| blank.then_some(index))
        .collect::<Vec<_>>();
    let non_blank_pages = blank
        .iter()
        .enumerate()
        .filter_map(|(index, blank)| (!blank).then_some(index))
        .collect::<Vec<_>>();
    let base = filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem);
    let mut groups = Vec::with_capacity(2);
    if non_blank_pages.is_empty() {
        groups.push((format!("{base}_allBlankPages.pdf"), blank_pages));
    } else {
        groups.push((format!("{base}_nonBlankPages.pdf"), non_blank_pages));
        if !blank_pages.is_empty() {
            groups.push((format!("{base}_blankPages.pdf"), blank_pages));
        }
    }
    write_groups_to_zip(input_path, filename, &groups, output_path)
}

fn write_groups_to_zip(
    input_path: &Path,
    filename: &str,
    groups: &[(String, Vec<usize>)],
    output_path: &Path,
) -> Result<(), BlankPagesError> {
    let directory = tempdir()?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (group_index, (entry_name, pages)) in groups.iter().enumerate() {
        let subset_path = directory.path().join(format!("group-{group_index}.pdf"));
        let selection = pages
            .iter()
            .map(|page| page.saturating_add(1).to_string())
            .collect::<Vec<_>>()
            .join(",");
        rearrange_pdf_pages_to_file(
            input_path,
            filename,
            Some(&selection),
            Some("custom"),
            &subset_path,
        )?;
        prune_orphaned_form_fields_in_file(&subset_path).map_err(BlankPagesError::Prune)?;
        archive.start_file(entry_name, options)?;
        io::copy(&mut File::open(subset_path)?, &mut archive)?;
    }
    archive.finish()?;
    Ok(())
}
