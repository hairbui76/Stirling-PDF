use std::{fs::File, io, path::Path};

use lopdf::{
    Dictionary, Document, Object, ObjectId, Stream,
    content::{Content, Operation},
    dictionary,
};
use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::pdf_booklet::{
    ImportedPage, import_page_form_with_normalized_crop, install_fresh_page_tree,
};
use crate::pdf_metadata::normalize_rebuilt_document_metadata;

const A4: (f32, f32) = (595.275_63, 841.889_8);
const A3: (f32, f32) = (841.889_8, 1_190.551_1);
const A5: (f32, f32) = (419.527_56, 595.275_63);
const LETTER: (f32, f32) = (612.0, 792.0);
const LEGAL: (f32, f32) = (612.0, 1008.0);
const TABLOID: (f32, f32) = (792.0, 1224.0);

#[derive(Debug, Clone)]
pub struct PosterOptions {
    pub page_size: String,
    pub x_factor: u8,
    pub y_factor: u8,
    pub right_to_left: bool,
}

#[derive(Debug, Error)]
pub enum PosterError {
    #[error("invalid page size: {0}")]
    InvalidPageSize(String),
    #[error("xFactor and yFactor must each be between 1 and 10")]
    InvalidGrid,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("page {page_number} has an invalid page box")]
    InvalidPageBox { page_number: u32 },
    #[error("could not build poster pages: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not read or write the poster archive: {0}")]
    Io(#[from] io::Error),
    #[error("could not build the poster ZIP archive: {0}")]
    Zip(#[from] zip::result::ZipError),
}

/// Splits every input page into a printable grid and writes one PDF into a ZIP archive.
///
/// # Errors
///
/// Returns [`PosterError`] for unsupported page sizes or grids, unreadable PDFs,
/// invalid page geometry, PDF construction failures, and archive I/O failures.
pub fn split_pdf_for_poster_to_zip(
    input_path: &Path,
    filename: &str,
    options: &PosterOptions,
    output_path: &Path,
) -> Result<(), PosterError> {
    let target_size = target_page_size(&options.page_size)?;
    if !(1..=10).contains(&options.x_factor) || !(1..=10).contains(&options.y_factor) {
        return Err(PosterError::InvalidGrid);
    }

    let mut document = Document::load(input_path).map_err(|source| PosterError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let source_pages = document.get_pages().into_iter().collect::<Vec<_>>();
    let imported_pages = source_pages
        .iter()
        .map(|(page_number, page_id)| {
            import_page_form_with_normalized_crop(&mut document, *page_id).map_err(|_| {
                PosterError::InvalidPageBox {
                    page_number: *page_number,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let root_pages_id = document.new_object_id();
    let mut output_pages = Vec::new();
    for imported_page in &imported_pages {
        append_poster_pages(
            &mut document,
            root_pages_id,
            imported_page,
            target_size,
            options,
            &mut output_pages,
        )?;
    }
    install_fresh_page_tree(&mut document, root_pages_id, output_pages)?;
    normalize_rebuilt_document_metadata(&mut document);
    document.prune_objects();

    let directory = tempdir()?;
    let pdf_path = directory.path().join("poster.pdf");
    document.save(&pdf_path)?;
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    archive.start_file(
        poster_pdf_filename(filename),
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored),
    )?;
    io::copy(&mut File::open(pdf_path)?, &mut archive)?;
    archive.finish()?;
    Ok(())
}

fn append_poster_pages(
    document: &mut Document,
    parent_id: ObjectId,
    imported_page: &ImportedPage,
    target_size: (f32, f32),
    options: &PosterOptions,
    output_pages: &mut Vec<ObjectId>,
) -> Result<(), lopdf::Error> {
    let crop = imported_page.crop_box;
    let rotated = matches!(imported_page.rotation, 90 | 270);
    let source_width = if rotated { crop.height() } else { crop.width() };
    let source_height = if rotated { crop.width() } else { crop.height() };
    let x_factor = f32::from(options.x_factor);
    let y_factor = f32::from(options.y_factor);
    let cell_width = source_width / x_factor;
    let cell_height = source_height / y_factor;
    let scale = (target_size.0 / cell_width).min(target_size.1 / cell_height);
    let offset_x = (target_size.0 - cell_width * scale) / 2.0;
    let offset_y = (target_size.1 - cell_height * scale) / 2.0;

    for row in 0..options.y_factor {
        for column in 0..options.x_factor {
            let actual_column = if options.right_to_left {
                options.x_factor - 1 - column
            } else {
                column
            };
            let crop_x = f32::from(actual_column) * cell_width;
            let crop_y = f32::from(options.y_factor - 1 - row) * cell_height;
            output_pages.push(add_poster_page(
                document,
                parent_id,
                imported_page.form_id,
                target_size,
                scale,
                offset_x,
                offset_y,
                crop_x,
                crop_y,
            )?);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_poster_page(
    document: &mut Document,
    parent_id: ObjectId,
    form_id: ObjectId,
    target_size: (f32, f32),
    scale: f32,
    offset_x: f32,
    offset_y: f32,
    crop_x: f32,
    crop_y: f32,
) -> Result<ObjectId, lopdf::Error> {
    let operations = vec![
        Operation::new("q", Vec::new()),
        matrix_operation([1.0, 0.0, 0.0, 1.0, offset_x, offset_y]),
        matrix_operation([scale, 0.0, 0.0, scale, 0.0, 0.0]),
        matrix_operation([1.0, 0.0, 0.0, 1.0, -crop_x, -crop_y]),
        Operation::new("Do", vec![Object::Name(b"PosterPage".to_vec())]),
        Operation::new("Q", Vec::new()),
    ];
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        Content { operations }.encode()?,
    ));
    Ok(document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => parent_id,
        "MediaBox" => vec![0.into(), 0.into(), target_size.0.into(), target_size.1.into()],
        "Resources" => dictionary! {
            "XObject" => Dictionary::from_iter([(b"PosterPage".to_vec(), Object::Reference(form_id))]),
        },
        "Contents" => content_id,
    }))
}

fn matrix_operation(values: [f32; 6]) -> Operation {
    Operation::new("cm", values.into_iter().map(Object::Real).collect())
}

fn target_page_size(page_size: &str) -> Result<(f32, f32), PosterError> {
    match page_size {
        "A4" => Ok(A4),
        "Letter" => Ok(LETTER),
        "A3" => Ok(A3),
        "A5" => Ok(A5),
        "Legal" => Ok(LEGAL),
        "Tabloid" => Ok(TABLOID),
        other => Err(PosterError::InvalidPageSize(other.to_owned())),
    }
}

fn poster_pdf_filename(filename: &str) -> String {
    let base = filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem);
    format!("{base}_poster.pdf")
}

#[cfg(test)]
mod tests {
    use super::{PosterError, poster_pdf_filename, target_page_size};

    #[test]
    fn maps_every_java_page_size_and_filename_rule() -> Result<(), PosterError> {
        assert_eq!(target_page_size("A4")?, (595.275_63, 841.889_8));
        assert_eq!(target_page_size("Tabloid")?, (792.0, 1224.0));
        assert!(matches!(
            target_page_size("a4"),
            Err(PosterError::InvalidPageSize(_))
        ));
        assert_eq!(poster_pdf_filename("report.pdf"), "report_poster.pdf");
        assert_eq!(poster_pdf_filename("noext"), "noext_poster.pdf");
        Ok(())
    }
}
