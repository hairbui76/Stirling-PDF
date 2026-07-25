use std::{collections::HashSet, path::Path};

use lopdf::{Document, ObjectId};
use thiserror::Error;

use crate::pdfium_backend::{PdfiumRotateAttempt, PdfiumRotateError, try_rotate_pdf_to_file};

#[derive(Debug, Error)]
pub enum RotateError {
    #[error("Angle must be a multiple of 90")]
    InvalidAngle,
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not update page rotation: {0}")]
    Update(#[from] lopdf::Error),
    #[error("could not write the rotated PDF: {0}")]
    Write(#[from] std::io::Error),
    #[error("the configured PDFium runtime is unavailable: {details}")]
    PdfiumRuntime { details: String },
    #[error(transparent)]
    Pdfium(#[from] PdfiumRotateError),
}

/// Rotates every page clockwise by `angle` degrees and writes the result to a file.
///
/// # Errors
///
/// Returns an error when the angle is not a multiple of 90, the input is not a
/// readable PDF, `PDFium` fails, or the output cannot be written.
pub fn rotate_pdf_path_to_file(
    input_path: &Path,
    filename: &str,
    angle: i32,
    output_path: &Path,
) -> Result<(), RotateError> {
    validate_angle(angle)?;

    match try_rotate_pdf_to_file(input_path, filename, angle, output_path)? {
        PdfiumRotateAttempt::Rotated => return Ok(()),
        PdfiumRotateAttempt::Unavailable {
            explicitly_configured: false,
            ..
        } => {}
        PdfiumRotateAttempt::Unavailable {
            explicitly_configured: true,
            details,
        } => return Err(RotateError::PdfiumRuntime { details }),
    }

    let mut document = Document::load(input_path).map_err(|source| RotateError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let pages = document.get_pages();
    for page_id in pages.into_values() {
        let current_rotation = inherited_rotation(&document, page_id);
        let rotation = current_rotation.wrapping_add(angle);
        document
            .get_dictionary_mut(page_id)?
            .set("Rotate", i64::from(rotation));
    }
    document.save(output_path)?;
    Ok(())
}

fn validate_angle(angle: i32) -> Result<(), RotateError> {
    if angle % 90 == 0 {
        Ok(())
    } else {
        Err(RotateError::InvalidAngle)
    }
}

fn inherited_rotation(document: &Document, page_id: ObjectId) -> i32 {
    let mut object_id = Some(page_id);
    let mut visited = HashSet::new();
    while let Some(current_id) = object_id.filter(|id| visited.insert(*id)) {
        let Ok(dictionary) = document.get_dictionary(current_id) else {
            return 0;
        };
        if let Ok(value) = dictionary.get(b"Rotate") {
            let Ok(value) = value.as_i64() else {
                return 0;
            };
            let Ok(value) = i32::try_from(value) else {
                return 0;
            };
            return if value % 90 == 0 {
                value.rem_euclid(360)
            } else {
                0
            };
        }
        object_id = dictionary
            .get(b"Parent")
            .ok()
            .and_then(|parent| parent.as_reference().ok());
    }
    0
}

#[cfg(test)]
mod tests {
    use lopdf::{Document, Object, Stream, dictionary};
    use tempfile::tempdir;

    use super::{RotateError, rotate_pdf_path_to_file};

    #[test]
    fn rejects_an_angle_that_is_not_a_multiple_of_ninety() {
        let error = rotate_pdf_path_to_file(
            std::path::Path::new("missing.pdf"),
            "missing.pdf",
            45,
            std::path::Path::new("unused.pdf"),
        )
        .err();

        assert!(matches!(error, Some(RotateError::InvalidAngle)));
    }

    #[test]
    fn applies_inherited_rotation_like_pdfbox() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input_path = directory.path().join("input.pdf");
        let output_path = directory.path().join("output.pdf");
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
                "Rotate" => 270,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => page_tree_id,
        });
        document.trailer.set("Root", catalog_id);
        document.save(&input_path)?;

        rotate_pdf_path_to_file(&input_path, "input.pdf", 90, &output_path)?;

        let rotated = Document::load(&output_path)?;
        let rotated_page_id = *rotated
            .get_pages()
            .values()
            .next()
            .ok_or("rotated page is missing")?;
        let rotation = rotated
            .get_dictionary(rotated_page_id)?
            .get(b"Rotate")?
            .as_i64()?;
        assert!(rotation == 0 || rotation == 360);
        Ok(())
    }
}
