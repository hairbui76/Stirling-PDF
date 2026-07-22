use std::{collections::HashSet, path::Path};

use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};
use regex::Regex;
use thiserror::Error;

use crate::{pdf_page_geometry::inherited_value, pdf_signatures::flatten_signature_fields};

#[derive(Debug, Error)]
pub enum DocumentOperationError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not prepare the XFA read-only matcher: {0}")]
    Regex(#[from] regex::Error),
    #[error("could not write PDF: {0}")]
    Write(std::io::Error),
}

/// Flattens root signature fields and writes an unsigned PDF.
///
/// # Errors
///
/// Returns [`DocumentOperationError`] when the PDF cannot be read, transformed,
/// or written.
pub fn remove_cert_sign_to_file(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), DocumentOperationError> {
    transform_pdf(input_path, filename, output_path, |document| {
        flatten_signature_fields(document)?;
        Ok(())
    })
}

/// Decodes every supported stream and saves without recompression.
///
/// # Errors
///
/// Returns [`DocumentOperationError`] when the PDF cannot be read or written.
pub fn decompress_pdf_to_file(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), DocumentOperationError> {
    transform_pdf(input_path, filename, output_path, |document| {
        document.decompress();
        Ok(())
    })
}

/// Clears read-only form flags, field locks, and XFA `readOnly` access markers.
///
/// # Errors
///
/// Returns [`DocumentOperationError`] when the PDF or its form tree cannot be
/// processed or written.
pub fn unlock_pdf_forms_to_file(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), DocumentOperationError> {
    transform_pdf(input_path, filename, output_path, unlock_forms)
}

/// Removes image `XObjects` from page and nested Form `XObject` resources.
///
/// # Errors
///
/// Returns [`DocumentOperationError`] when the PDF resource tree cannot be read,
/// transformed, or written.
pub fn remove_images_to_file(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), DocumentOperationError> {
    transform_pdf(input_path, filename, output_path, remove_images)
}

/// Performs the Java controller's dependency-free repair fallback by parsing
/// and rewriting the PDF structure.
///
/// # Errors
///
/// Returns [`DocumentOperationError`] when the PDF cannot be parsed or the
/// normalized output cannot be written.
pub fn repair_pdf_to_file(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), DocumentOperationError> {
    transform_pdf(input_path, filename, output_path, |_| Ok(()))
}

fn transform_pdf(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
    transform: impl FnOnce(&mut Document) -> Result<(), DocumentOperationError>,
) -> Result<(), DocumentOperationError> {
    let mut document =
        Document::load(input_path).map_err(|source| DocumentOperationError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    transform(&mut document)?;
    document
        .save(output_path)
        .map_err(DocumentOperationError::Write)?;
    Ok(())
}

fn unlock_forms(document: &mut Document) -> Result<(), DocumentOperationError> {
    let Ok(acroform) = document.catalog()?.get(b"AcroForm").cloned() else {
        return Ok(());
    };
    let (acroform_id, acroform_object) = document.dereference(&acroform)?;
    let mut acroform_dictionary = acroform_object.as_dict()?.clone();
    acroform_dictionary.set("NeedAppearances", true);
    if let Ok(fields) = acroform_dictionary.get(b"Fields").cloned() {
        let (_, fields) = document.dereference(&fields)?;
        let fields = fields.as_array()?.clone();
        let fields = fields
            .into_iter()
            .map(|field| unlock_field(document, field, 0, &mut HashSet::new()))
            .collect::<Result<Vec<_>, _>>()?;
        acroform_dictionary.set("Fields", fields);
    }
    if let Ok(xfa) = acroform_dictionary.get(b"XFA").cloned() {
        acroform_dictionary.set("XFA", unlock_xfa(document, &xfa)?);
    }
    write_dictionary(document, acroform_id, b"AcroForm", acroform_dictionary)?;
    Ok(())
}

fn unlock_field(
    document: &mut Document,
    field: Object,
    inherited_flags: i64,
    visited: &mut HashSet<ObjectId>,
) -> Result<Object, DocumentOperationError> {
    let (field_id, resolved) = document.dereference(&field)?;
    if let Some(field_id) = field_id
        && !visited.insert(field_id)
    {
        return Ok(field);
    }
    let mut dictionary = resolved.as_dict()?.clone();
    dictionary.remove(b"Lock");
    let current_flags = dictionary
        .get(b"Ff")
        .ok()
        .and_then(|flags| document.dereference(flags).ok())
        .and_then(|(_, flags)| flags.as_i64().ok())
        .unwrap_or(inherited_flags);
    if current_flags & 1 == 1 || dictionary.has(b"Ff") {
        dictionary.set("Ff", current_flags & !1);
    }
    if let Ok(kids) = dictionary.get(b"Kids").cloned() {
        let (_, kids) = document.dereference(&kids)?;
        let kids = kids.as_array()?.clone();
        let kids = kids
            .into_iter()
            .map(|kid| unlock_field(document, kid, current_flags & !1, visited))
            .collect::<Result<Vec<_>, _>>()?;
        dictionary.set("Kids", kids);
    }
    if let Some(field_id) = field_id {
        document
            .objects
            .insert(field_id, Object::Dictionary(dictionary));
        Ok(Object::Reference(field_id))
    } else {
        Ok(Object::Dictionary(dictionary))
    }
}

fn unlock_xfa(document: &mut Document, xfa: &Object) -> Result<Object, DocumentOperationError> {
    let read_only = Regex::new(r#"access\s*=\s*"readOnly""#)?;
    let (_, resolved) = document.dereference(xfa)?;
    let resolved = resolved.clone();
    match resolved {
        Object::Stream(stream) => replacement_xfa_stream(document, &stream, &read_only),
        Object::Array(mut parts) => {
            for index in (1..parts.len()).step_by(2) {
                let (_, stream) = document.dereference(&parts[index])?;
                if let Object::Stream(stream) = stream {
                    let stream = stream.clone();
                    parts[index] = replacement_xfa_stream(document, &stream, &read_only)?;
                }
            }
            Ok(Object::Array(parts))
        }
        _ => Ok(xfa.clone()),
    }
}

fn replacement_xfa_stream(
    document: &mut Document,
    stream: &Stream,
    read_only: &Regex,
) -> Result<Object, DocumentOperationError> {
    let xml = stream.decompressed_content()?;
    let xml = String::from_utf8_lossy(&xml);
    let opened = read_only.replace_all(&xml, "access=\"open\"");
    let id = document.add_object(Stream::new(dictionary! {}, opened.as_bytes().to_vec()));
    Ok(Object::Reference(id))
}

fn write_dictionary(
    document: &mut Document,
    object_id: Option<ObjectId>,
    catalog_key: &[u8],
    dictionary: Dictionary,
) -> Result<(), lopdf::Error> {
    if let Some(object_id) = object_id {
        document
            .objects
            .insert(object_id, Object::Dictionary(dictionary));
    } else {
        document
            .catalog_mut()?
            .set(catalog_key, Object::Dictionary(dictionary));
    }
    Ok(())
}

fn remove_images(document: &mut Document) -> Result<(), DocumentOperationError> {
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    let mut visited_forms = HashSet::new();
    for page_id in page_ids {
        let resources = inherited_value(document, page_id, b"Resources")
            .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
        let resources = clean_resources(document, &resources, &mut visited_forms)?;
        document
            .get_dictionary_mut(page_id)?
            .set("Resources", resources);
    }
    Ok(())
}

fn clean_resources(
    document: &mut Document,
    resources: &Object,
    visited_forms: &mut HashSet<ObjectId>,
) -> Result<Object, DocumentOperationError> {
    let (resources_id, resolved) = document.dereference(resources)?;
    let mut dictionary = resolved.as_dict()?.clone();
    if let Ok(xobjects) = dictionary.get(b"XObject").cloned() {
        let (_, xobjects) = document.dereference(&xobjects)?;
        let mut xobjects = xobjects.as_dict()?.clone();
        let names = xobjects
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in names {
            let Some(xobject) = xobjects.get(&name).ok().cloned() else {
                continue;
            };
            let (object_id, resolved) = document.dereference(&xobject)?;
            let Object::Stream(stream) = resolved else {
                continue;
            };
            match stream.dict.get(b"Subtype").and_then(Object::as_name) {
                Ok(b"Image") => {
                    xobjects.remove(&name);
                }
                Ok(b"Form") => {
                    if object_id.is_some_and(|id| !visited_forms.insert(id)) {
                        continue;
                    }
                    let mut stream = stream.clone();
                    if let Ok(form_resources) = stream.dict.get(b"Resources").cloned() {
                        let cleaned = clean_resources(document, &form_resources, visited_forms)?;
                        stream.dict.set("Resources", cleaned);
                        if let Some(object_id) = object_id {
                            document.objects.insert(object_id, Object::Stream(stream));
                        } else {
                            xobjects.set(name.clone(), Object::Stream(stream));
                        }
                    }
                }
                _ => {}
            }
        }
        dictionary.set("XObject", xobjects);
    }
    if let Some(resources_id) = resources_id {
        document
            .objects
            .insert(resources_id, Object::Dictionary(dictionary));
        Ok(Object::Reference(resources_id))
    } else {
        Ok(Object::Dictionary(dictionary))
    }
}
