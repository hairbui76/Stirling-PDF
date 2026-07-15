use std::{fs::File, io, ops::RangeInclusive, path::Path};

use lopdf::Document;
use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    page_selection::{PageSelectionError, parse_page_list},
    pdf_forms::prune_orphaned_form_fields_in_file,
    pdf_rearrange::{RearrangePagesError, rearrange_pdf_pages_to_file},
};

#[derive(Debug, Error)]
pub enum SplitPdfError {
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("cannot split a PDF with no pages")]
    NoPages,
    #[error(transparent)]
    Rearrange(#[from] RearrangePagesError),
    #[error("could not prune split form fields: {0}")]
    Prune(#[from] lopdf::Error),
    #[error("could not read or write a split archive: {0}")]
    Io(#[from] io::Error),
    #[error("could not build the split ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Splits a PDF after each selected page and writes the outputs into a ZIP file.
///
/// # Errors
///
/// Returns an error for unsafe selections, unreadable or empty PDFs, page-tree
/// failures, form-pruning failures, or archive I/O failures.
pub fn split_pdf_to_zip(
    input_path: &Path,
    filename: &str,
    page_numbers: &str,
    output_path: &Path,
) -> Result<(), SplitPdfError> {
    let document = Document::load(input_path).map_err(|source| SplitPdfError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let total_pages = document.get_pages().len();
    if total_pages == 0 {
        return Err(SplitPdfError::NoPages);
    }
    let mut split_points = parse_page_list(page_numbers, total_pages)?;
    if !split_points.contains(&(total_pages - 1)) {
        split_points.push(total_pages - 1);
    }

    let mut previous_page = 0usize;
    let mut ranges = Vec::with_capacity(split_points.len());
    for split_point in split_points {
        ranges.push(previous_page..=split_point);
        previous_page = split_point.saturating_add(1);
    }
    write_page_ranges_to_zip(input_path, filename, &ranges, output_path)
}

pub(crate) fn write_page_ranges_to_zip(
    input_path: &Path,
    filename: &str,
    ranges: &[RangeInclusive<usize>],
    output_path: &Path,
) -> Result<(), SplitPdfError> {
    let directory = tempdir()?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    let base_filename = filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem);

    for (split_index, range) in ranges.iter().enumerate() {
        let split_path = directory.path().join(format!("split-{split_index}.pdf"));
        let selection = format!("{}-{}", range.start() + 1, range.end() + 1);
        rearrange_pdf_pages_to_file(
            input_path,
            filename,
            Some(&selection),
            Some("custom"),
            &split_path,
        )?;
        prune_orphaned_form_fields_in_file(&split_path)?;
        archive.start_file(format!("{base_filename}_{}.pdf", split_index + 1), options)?;
        io::copy(&mut File::open(split_path)?, &mut archive)?;
    }
    archive.finish()?;
    Ok(())
}
