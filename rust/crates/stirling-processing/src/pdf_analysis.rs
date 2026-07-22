use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    path::Path,
};

use lopdf::{Document, Object, ObjectId, encryption::Permissions};
use serde::Serialize;
use thiserror::Error;

use crate::pdf_page_geometry::inherited_value;

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not inspect PDF file size: {0}")]
    FileSize(std::io::Error),
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("PDF page {page_number} has an invalid bounding box")]
    InvalidPageBox { page_number: u32 },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageCount {
    pub page_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BasicInfo {
    pub page_count: usize,
    pub pdf_version: f32,
    pub file_size: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentProperties {
    pub title: Option<String>,
    pub author: Option<String>,
    pub subject: Option<String>,
    pub keywords: Option<String>,
    pub creator: Option<String>,
    pub producer: Option<String>,
    pub creation_date: Option<String>,
    pub modification_date: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PageDimensions {
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormFieldInfo {
    pub field_count: usize,
    #[serde(rename = "hasXFA")]
    pub has_xfa: bool,
    pub is_signatures_exist: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnnotationInfo {
    pub total_count: usize,
    pub type_breakdown: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FontInfo {
    pub font_count: usize,
    pub fonts: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityInfo {
    pub is_encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<SecurityPermissions>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct SecurityPermissions {
    pub prevent_printing: bool,
    pub prevent_modify: bool,
    pub prevent_extract_content: bool,
    pub prevent_modify_annotations: bool,
}

/// Returns the number of pages in a PDF.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the input cannot be parsed.
pub fn page_count(path: &Path, filename: &str) -> Result<PageCount, AnalysisError> {
    let document = load(path, filename)?;
    Ok(PageCount {
        page_count: document.get_pages().len(),
    })
}

/// Returns page count, PDF version, and uploaded byte size.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the input or file metadata cannot be read.
pub fn basic_info(path: &Path, filename: &str) -> Result<BasicInfo, AnalysisError> {
    let document = load(path, filename)?;
    Ok(BasicInfo {
        page_count: document.get_pages().len(),
        pdf_version: document.version.parse::<f32>().unwrap_or_default(),
        file_size: path.metadata().map_err(AnalysisError::FileSize)?.len(),
    })
}

/// Returns the standard PDF Info dictionary properties.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the input or Info dictionary cannot be read.
pub fn document_properties(
    path: &Path,
    filename: &str,
) -> Result<DocumentProperties, AnalysisError> {
    let document = load(path, filename)?;
    let info = document
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|info| document.dereference(info).ok())
        .and_then(|(_, info)| info.as_dict().ok());
    let value = |key: &[u8]| {
        info.and_then(|info| info.get(key).ok())
            .and_then(|value| document.dereference(value).ok())
            .and_then(|(_, value)| lopdf::decode_text_string(value).ok())
    };
    Ok(DocumentProperties {
        title: value(b"Title"),
        author: value(b"Author"),
        subject: value(b"Subject"),
        keywords: value(b"Keywords"),
        creator: value(b"Creator"),
        producer: value(b"Producer"),
        creation_date: value(b"CreationDate"),
        modification_date: value(b"ModDate"),
    })
}

/// Returns the effective bounding-box dimensions of every page.
///
/// # Errors
///
/// Returns [`AnalysisError`] when a page box cannot be resolved.
pub fn page_dimensions(path: &Path, filename: &str) -> Result<Vec<PageDimensions>, AnalysisError> {
    let document = load(path, filename)?;
    document
        .get_pages()
        .into_iter()
        .map(|(page_number, page_id)| {
            let bounds = page_bounds(&document, page_id, page_number)?;
            Ok(PageDimensions {
                width: bounds[2] - bounds[0],
                height: bounds[3] - bounds[1],
            })
        })
        .collect()
}

/// Returns root field count and XFA/signature presence.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the `AcroForm` tree cannot be inspected.
pub fn form_fields(path: &Path, filename: &str) -> Result<FormFieldInfo, AnalysisError> {
    let document = load(path, filename)?;
    let Ok(acroform) = document.catalog()?.get(b"AcroForm") else {
        return Ok(FormFieldInfo {
            field_count: 0,
            has_xfa: false,
            is_signatures_exist: false,
        });
    };
    let (_, acroform) = document.dereference(acroform)?;
    let acroform = acroform.as_dict()?;
    let fields = acroform
        .get(b"Fields")
        .ok()
        .and_then(|fields| document.dereference(fields).ok())
        .and_then(|(_, fields)| fields.as_array().ok())
        .cloned()
        .unwrap_or_default();
    let mut visited = HashSet::new();
    let signatures = fields
        .iter()
        .any(|field| field_has_signature(&document, field, &mut visited));
    Ok(FormFieldInfo {
        field_count: fields.len(),
        has_xfa: acroform.has(b"XFA"),
        is_signatures_exist: signatures,
    })
}

/// Counts annotations by subtype across all pages.
///
/// # Errors
///
/// Returns [`AnalysisError`] when annotation arrays cannot be resolved.
pub fn annotation_info(path: &Path, filename: &str) -> Result<AnnotationInfo, AnalysisError> {
    let document = load(path, filename)?;
    let mut total_count = 0usize;
    let mut type_breakdown = BTreeMap::new();
    for page_id in document.get_pages().into_values() {
        let Ok(annotations) = document.get_dictionary(page_id)?.get(b"Annots") else {
            continue;
        };
        let (_, annotations) = document.dereference(annotations)?;
        for annotation in annotations.as_array()? {
            let (_, annotation) = document.dereference(annotation)?;
            let subtype = annotation
                .as_dict()?
                .get(b"Subtype")
                .ok()
                .and_then(|value| document.dereference(value).ok())
                .and_then(|(_, value)| value.as_name().ok())
                .map_or_else(String::new, |name| {
                    String::from_utf8_lossy(name).into_owned()
                });
            total_count += 1;
            *type_breakdown.entry(subtype).or_default() += 1;
        }
    }
    Ok(AnnotationInfo {
        total_count,
        type_breakdown,
    })
}

/// Returns unique page-level font resource names.
///
/// # Errors
///
/// Returns [`AnalysisError`] when page resources cannot be resolved.
pub fn font_info(path: &Path, filename: &str) -> Result<FontInfo, AnalysisError> {
    let document = load(path, filename)?;
    let mut fonts = BTreeSet::new();
    for page_id in document.get_pages().into_values() {
        let Ok(resources) = inherited_value(&document, page_id, b"Resources") else {
            continue;
        };
        let (_, resources) = document.dereference(&resources)?;
        let Ok(font_dictionary) = resources.as_dict()?.get(b"Font") else {
            continue;
        };
        let (_, font_dictionary) = document.dereference(font_dictionary)?;
        fonts.extend(
            font_dictionary
                .as_dict()?
                .iter()
                .map(|(name, _)| String::from_utf8_lossy(name).into_owned()),
        );
    }
    Ok(FontInfo {
        font_count: fonts.len(),
        fonts,
    })
}

/// Returns encryption state and the four permissions exposed by Java.
///
/// # Errors
///
/// Returns [`AnalysisError`] when the PDF cannot be parsed.
pub fn security_info(path: &Path, filename: &str) -> Result<SecurityInfo, AnalysisError> {
    let document = load(path, filename)?;
    let Some(state) = document.encryption_state.as_ref() else {
        return Ok(SecurityInfo {
            is_encrypted: false,
            key_length: None,
            permissions: None,
        });
    };
    let permissions = state.permissions();
    Ok(SecurityInfo {
        is_encrypted: true,
        key_length: Some(
            state
                .key_length()
                .unwrap_or_else(|| state.file_encryption_key().len().saturating_mul(8)),
        ),
        permissions: Some(SecurityPermissions {
            prevent_printing: !permissions.contains(Permissions::PRINTABLE),
            prevent_modify: !permissions.contains(Permissions::MODIFIABLE),
            prevent_extract_content: !permissions.contains(Permissions::COPYABLE),
            prevent_modify_annotations: !permissions.contains(Permissions::ANNOTABLE),
        }),
    })
}

fn page_bounds(
    document: &Document,
    page_id: ObjectId,
    page_number: u32,
) -> Result<[f32; 4], AnalysisError> {
    let value = inherited_value(document, page_id, b"CropBox")
        .or_else(|_| inherited_value(document, page_id, b"MediaBox"))?;
    let (_, value) = document.dereference(&value)?;
    let values = value.as_array()?;
    if values.len() < 4 {
        return Err(AnalysisError::InvalidPageBox { page_number });
    }
    Ok([
        values[0].as_float()?,
        values[1].as_float()?,
        values[2].as_float()?,
        values[3].as_float()?,
    ])
}

fn field_has_signature(
    document: &Document,
    field: &Object,
    visited: &mut HashSet<ObjectId>,
) -> bool {
    let Ok((object_id, field)) = document.dereference(field) else {
        return false;
    };
    if object_id.is_some_and(|id| !visited.insert(id)) {
        return false;
    }
    let Ok(field) = field.as_dict() else {
        return false;
    };
    if field
        .get(b"FT")
        .ok()
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_name().ok())
        == Some(b"Sig".as_slice())
    {
        return true;
    }
    field
        .get(b"Kids")
        .ok()
        .and_then(|kids| document.dereference(kids).ok())
        .and_then(|(_, kids)| kids.as_array().ok())
        .is_some_and(|kids| {
            kids.iter()
                .any(|kid| field_has_signature(document, kid, visited))
        })
}

fn load(path: &Path, filename: &str) -> Result<Document, AnalysisError> {
    Document::load(path).map_err(|source| AnalysisError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })
}
