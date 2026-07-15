use std::{collections::HashSet, path::Path};

use lopdf::{Document, Object, ObjectId};
use thiserror::Error;

use crate::{page_selection::PageSelectionError, pdf_page_geometry::inherited_value};

#[derive(Debug, Clone, Copy)]
pub enum Comparator {
    Greater,
    Equal,
    Less,
}

impl Comparator {
    /// Parses the three comparison strings accepted by the Java API.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError::InvalidComparator`] for any other value.
    pub fn parse(value: &str) -> Result<Self, FilterError> {
        match value {
            "Greater" => Ok(Self::Greater),
            "Equal" => Ok(Self::Equal),
            "Less" => Ok(Self::Less),
            _ => Err(FilterError::InvalidComparator(value.to_owned())),
        }
    }

    fn matches_i64(self, actual: i64, expected: i64) -> bool {
        match self {
            Self::Greater => actual > expected,
            Self::Equal => actual == expected,
            Self::Less => actual < expected,
        }
    }

    #[allow(clippy::float_cmp)]
    fn matches_f32(self, actual: f32, expected: f32) -> bool {
        // Java's Comparable branch uses exact Float equality for this API.
        match self {
            Self::Greater => actual > expected,
            Self::Equal => actual == expected,
            Self::Less => actual < expected,
        }
    }
}

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("invalid comparator '{0}'")]
    InvalidComparator(String),
    #[error("invalid standard page size '{0}'")]
    InvalidPageSize(String),
    #[error("PDF has no pages")]
    NoPages,
    #[error(transparent)]
    PageSelection(#[from] PageSelectionError),
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not inspect uploaded file size: {0}")]
    FileSize(#[from] std::io::Error),
}

/// Tests whether selected pages contain a literal text phrase.
///
/// # Errors
///
/// Returns [`FilterError`] when page selection or text extraction fails.
pub fn contains_text(
    path: &Path,
    filename: &str,
    page_numbers: &str,
    text: &str,
) -> Result<bool, FilterError> {
    let document = load(path, filename)?;
    let pages = crate::page_selection::parse_page_list(page_numbers, document.get_pages().len())?;
    for page in pages {
        let page_number = u32::try_from(page + 1).map_err(|_| FilterError::NoPages)?;
        if document.extract_text(&[page_number])?.contains(text) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Tests whether selected pages reference an image, including images nested in
/// Form `XObjects`.
///
/// # Errors
///
/// Returns [`FilterError`] when the PDF resource graph is malformed.
pub fn contains_image(
    path: &Path,
    filename: &str,
    page_numbers: &str,
) -> Result<bool, FilterError> {
    let document = load(path, filename)?;
    let pages = document.get_pages();
    let selected = crate::page_selection::parse_page_list(page_numbers, pages.len())?;
    let page_ids = pages.into_values().collect::<Vec<_>>();
    for page in selected {
        let Some(page_id) = page_ids.get(page).copied() else {
            continue;
        };
        if page_contains_image(&document, page_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn page_contains_image(
    document: &Document,
    page_id: ObjectId,
) -> Result<bool, lopdf::Error> {
    let Ok(resources) = inherited_value(document, page_id, b"Resources") else {
        return Ok(false);
    };
    resources_contain_image(document, &resources, &mut HashSet::new())
}

/// Compares the PDF page count.
///
/// # Errors
///
/// Returns [`FilterError`] when the PDF cannot be parsed.
pub fn page_count(
    path: &Path,
    filename: &str,
    expected: i64,
    comparator: Comparator,
) -> Result<bool, FilterError> {
    let actual = i64::try_from(load(path, filename)?.get_pages().len()).unwrap_or(i64::MAX);
    Ok(comparator.matches_i64(actual, expected))
}

/// Compares the first page's media-box area to a standard page size.
///
/// # Errors
///
/// Returns [`FilterError`] for an unknown size or malformed first page.
pub fn page_size(
    path: &Path,
    filename: &str,
    standard_page_size: &str,
    comparator: Comparator,
) -> Result<bool, FilterError> {
    let document = load(path, filename)?;
    let page_id = document
        .get_pages()
        .into_values()
        .next()
        .ok_or(FilterError::NoPages)?;
    let media_box = inherited_value(&document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let media_box = media_box.as_array()?;
    if media_box.len() < 4 {
        return Err(FilterError::NoPages);
    }
    let width = (media_box[2].as_float()? - media_box[0].as_float()?).abs();
    let height = (media_box[3].as_float()? - media_box[1].as_float()?).abs();
    let (standard_width, standard_height) = standard_dimensions(standard_page_size)?;
    Ok(comparator.matches_f32(width * height, standard_width * standard_height))
}

/// Compares the uploaded byte size without parsing the PDF.
///
/// # Errors
///
/// Returns [`FilterError`] when filesystem metadata cannot be read.
pub fn file_size(path: &Path, expected: i64, comparator: Comparator) -> Result<bool, FilterError> {
    let actual = i64::try_from(path.metadata()?.len()).unwrap_or(i64::MAX);
    Ok(comparator.matches_i64(actual, expected))
}

/// Compares the first page's effective inherited rotation.
///
/// # Errors
///
/// Returns [`FilterError`] when the PDF has no pages or its rotation is
/// malformed.
pub fn page_rotation(
    path: &Path,
    filename: &str,
    expected: i64,
    comparator: Comparator,
) -> Result<bool, FilterError> {
    let document = load(path, filename)?;
    let page_id = document
        .get_pages()
        .into_values()
        .next()
        .ok_or(FilterError::NoPages)?;
    let actual = inherited_value(&document, page_id, b"Rotate")
        .ok()
        .and_then(|rotation| match rotation {
            Object::Reference(object_id) => document
                .get_object(object_id)
                .ok()
                .and_then(|rotation| rotation.as_i64().ok()),
            rotation => rotation.as_i64().ok(),
        })
        .unwrap_or_default();
    Ok(comparator.matches_i64(actual, expected))
}

fn resources_contain_image(
    document: &Document,
    resources: &Object,
    visited: &mut HashSet<ObjectId>,
) -> Result<bool, lopdf::Error> {
    let (_, resources) = document.dereference(resources)?;
    let Ok(xobjects) = resources.as_dict()?.get(b"XObject") else {
        return Ok(false);
    };
    let (_, xobjects) = document.dereference(xobjects)?;
    for (_, xobject) in xobjects.as_dict()? {
        let (object_id, xobject) = document.dereference(xobject)?;
        if object_id.is_some_and(|object_id| !visited.insert(object_id)) {
            continue;
        }
        let stream = xobject.as_stream()?;
        let subtype = stream
            .dict
            .get(b"Subtype")
            .ok()
            .and_then(|subtype| document.dereference(subtype).ok())
            .and_then(|(_, subtype)| subtype.as_name().ok());
        if subtype == Some(b"Image".as_slice()) {
            return Ok(true);
        }
        if subtype == Some(b"Form".as_slice())
            && let Ok(resources) = stream.dict.get(b"Resources")
            && resources_contain_image(document, resources, visited)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn standard_dimensions(page_size: &str) -> Result<(f32, f32), FilterError> {
    match page_size {
        "A0" => Ok((2383.937, 3370.3938)),
        "A1" => Ok((1683.7795, 2383.937)),
        "A2" => Ok((1190.5513, 1683.7795)),
        "A3" => Ok((841.8898, 1190.5513)),
        "A4" => Ok((595.27563, 841.8898)),
        "A5" => Ok((419.52756, 595.27563)),
        "A6" => Ok((297.63782, 419.52756)),
        "LETTER" => Ok((612.0, 792.0)),
        "LEGAL" => Ok((612.0, 1008.0)),
        _ => Err(FilterError::InvalidPageSize(page_size.to_owned())),
    }
}

fn load(path: &Path, filename: &str) -> Result<Document, FilterError> {
    Document::load(path).map_err(|source| FilterError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::Comparator;

    #[test]
    fn comparator_matches_java_values() {
        assert!(Comparator::Greater.matches_i64(2, 1));
        assert!(Comparator::Equal.matches_i64(2, 2));
        assert!(Comparator::Less.matches_i64(1, 2));
        assert!(Comparator::parse("greater").is_err());
    }
}
