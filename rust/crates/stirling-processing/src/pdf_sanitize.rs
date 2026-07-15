use std::path::Path;

use lopdf::{Dictionary, Document, Object, ObjectId};
use thiserror::Error;

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SanitizeOptions {
    pub remove_javascript: bool,
    pub remove_embedded_files: bool,
    pub remove_xmp_metadata: bool,
    pub remove_metadata: bool,
    pub remove_links: bool,
    pub remove_fonts: bool,
}

#[derive(Debug, Error)]
pub enum SanitizeError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write sanitized PDF: {0}")]
    Write(#[from] std::io::Error),
}

/// Removes the PDF structures selected by the sanitize API.
///
/// # Errors
///
/// Returns [`SanitizeError`] when the input is malformed or the output cannot
/// be written.
pub fn sanitize_pdf_to_file(
    input_path: &Path,
    filename: &str,
    options: &SanitizeOptions,
    output_path: &Path,
) -> Result<(), SanitizeError> {
    let mut document = Document::load(input_path).map_err(|source| SanitizeError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let catalog_id = document.trailer.get(b"Root")?.as_reference()?;
    let mut catalog = document.get_dictionary(catalog_id)?.clone();

    if options.remove_javascript {
        remove_nested_dictionary_entry(&mut document, &mut catalog, b"Names", b"JavaScript")?;
        remove_action(&document, &mut catalog, b"OpenAction", &[b"JavaScript"]);
        clean_additional_actions(
            &mut document,
            &mut catalog,
            &[b"WC", b"WS", b"DS", b"WP", b"DP"],
            &[b"JavaScript"],
        )?;
        sanitize_acroform_javascript(&mut document, &mut catalog)?;
    }
    if options.remove_embedded_files {
        remove_nested_dictionary_entry(&mut document, &mut catalog, b"Names", b"EmbeddedFiles")?;
    }
    if options.remove_xmp_metadata {
        catalog.remove(b"Metadata");
    }

    document
        .objects
        .insert(catalog_id, Object::Dictionary(catalog));
    sanitize_pages(&mut document, options)?;

    if options.remove_metadata {
        let info_id = document.add_object(Dictionary::new());
        document.trailer.set("Info", info_id);
    }

    document.save(output_path)?;
    Ok(())
}

fn sanitize_acroform_javascript(
    document: &mut Document,
    catalog: &mut Dictionary,
) -> Result<(), SanitizeError> {
    let Ok(acroform_object) = catalog.get(b"AcroForm").cloned() else {
        return Ok(());
    };
    let (acroform_id, mut acroform) = resolved_dictionary(document, &acroform_object)?;
    if let Ok(fields_object) = acroform.get(b"Fields").cloned() {
        let (fields_array_id, fields) = resolved_array(document, &fields_object)?;
        let mut updated_fields = Vec::with_capacity(fields.len());
        for field in fields {
            let (root_field_id, mut field_dictionary) = resolved_dictionary(document, &field)?;
            clean_additional_actions(
                document,
                &mut field_dictionary,
                &[b"C", b"F", b"K", b"V"],
                &[b"JavaScript"],
            )?;
            updated_fields.push(replace_dictionary(
                document,
                root_field_id,
                field_dictionary,
            ));
        }
        let fields = replace_array(document, fields_array_id, updated_fields);
        acroform.set("Fields", fields);
    }
    catalog.set(
        "AcroForm",
        replace_dictionary(document, acroform_id, acroform),
    );
    Ok(())
}

fn sanitize_pages(document: &mut Document, options: &SanitizeOptions) -> Result<(), SanitizeError> {
    let page_ids = document.get_pages().into_values().collect::<Vec<_>>();
    for page_id in page_ids {
        let mut page = document.get_dictionary(page_id)?.clone();
        if options.remove_javascript {
            clean_additional_actions(document, &mut page, &[b"O", b"C"], &[b"JavaScript"])?;
        }
        if options.remove_javascript || options.remove_embedded_files || options.remove_links {
            sanitize_annotations(document, &mut page, options)?;
        }
        document.objects.insert(page_id, Object::Dictionary(page));
        if options.remove_fonts {
            remove_inherited_fonts(document, page_id)?;
        }
    }
    Ok(())
}

fn sanitize_annotations(
    document: &mut Document,
    page: &mut Dictionary,
    options: &SanitizeOptions,
) -> Result<(), SanitizeError> {
    let Ok(annotations_object) = page.get(b"Annots").cloned() else {
        return Ok(());
    };
    let (annotations_array_id, annotations) = resolved_array(document, &annotations_object)?;
    let mut retained = Vec::with_capacity(annotations.len());
    for annotation in annotations {
        let (current_annotation_id, mut annotation_dictionary) =
            resolved_dictionary(document, &annotation)?;
        let subtype = dictionary_name(document, &annotation_dictionary, b"Subtype");
        if options.remove_embedded_files && subtype.as_deref() == Some(b"FileAttachment") {
            continue;
        }
        if options.remove_javascript && subtype.as_deref() == Some(b"Widget") {
            remove_action(document, &mut annotation_dictionary, b"A", &[b"JavaScript"]);
        }
        if options.remove_links && subtype.as_deref() == Some(b"Link") {
            remove_action(
                document,
                &mut annotation_dictionary,
                b"A",
                &[b"Launch", b"URI"],
            );
        }
        retained.push(replace_dictionary(
            document,
            current_annotation_id,
            annotation_dictionary,
        ));
    }
    page.set(
        "Annots",
        replace_array(document, annotations_array_id, retained),
    );
    Ok(())
}

fn remove_inherited_fonts(document: &mut Document, page_id: ObjectId) -> Result<(), SanitizeError> {
    let mut current_id = page_id;
    loop {
        let mut node = document.get_dictionary(current_id)?.clone();
        if let Ok(resources_object) = node.get(b"Resources").cloned() {
            let (resources_id, mut resources) = resolved_dictionary(document, &resources_object)?;
            resources.remove(b"Font");
            node.set(
                "Resources",
                replace_dictionary(document, resources_id, resources),
            );
            document
                .objects
                .insert(current_id, Object::Dictionary(node));
            return Ok(());
        }
        let Some(parent_id) = node
            .get(b"Parent")
            .ok()
            .and_then(|parent| parent.as_reference().ok())
        else {
            return Ok(());
        };
        current_id = parent_id;
    }
}

fn remove_nested_dictionary_entry(
    document: &mut Document,
    owner: &mut Dictionary,
    dictionary_key: &[u8],
    entry_key: &[u8],
) -> Result<(), SanitizeError> {
    let Ok(dictionary_object) = owner.get(dictionary_key).cloned() else {
        return Ok(());
    };
    let (dictionary_id, mut dictionary) = resolved_dictionary(document, &dictionary_object)?;
    dictionary.remove(entry_key);
    owner.set(
        dictionary_key,
        replace_dictionary(document, dictionary_id, dictionary),
    );
    Ok(())
}

fn clean_additional_actions(
    document: &mut Document,
    owner: &mut Dictionary,
    keys: &[&[u8]],
    action_subtypes: &[&[u8]],
) -> Result<(), SanitizeError> {
    let Ok(actions_object) = owner.get(b"AA").cloned() else {
        return Ok(());
    };
    let (actions_id, mut actions) = resolved_dictionary(document, &actions_object)?;
    for key in keys {
        remove_action(document, &mut actions, key, action_subtypes);
    }
    owner.set("AA", replace_dictionary(document, actions_id, actions));
    Ok(())
}

fn remove_action(
    document: &Document,
    owner: &mut Dictionary,
    key: &[u8],
    action_subtypes: &[&[u8]],
) {
    let should_remove = owner
        .get(key)
        .ok()
        .and_then(|action| document.dereference(action).ok())
        .and_then(|(_, action)| action.as_dict().ok())
        .and_then(|action| dictionary_name(document, action, b"S"))
        .is_some_and(|subtype| action_subtypes.contains(&subtype.as_slice()));
    if should_remove {
        owner.remove(key);
    }
}

fn dictionary_name(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<Vec<u8>> {
    dictionary
        .get(key)
        .ok()
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_name().ok())
        .map(<[u8]>::to_vec)
}

fn resolved_dictionary(
    document: &Document,
    object: &Object,
) -> Result<(Option<ObjectId>, Dictionary), lopdf::Error> {
    let (object_id, object) = document.dereference(object)?;
    Ok((object_id, object.as_dict()?.clone()))
}

fn resolved_array(
    document: &Document,
    object: &Object,
) -> Result<(Option<ObjectId>, Vec<Object>), lopdf::Error> {
    let (object_id, object) = document.dereference(object)?;
    Ok((object_id, object.as_array()?.clone()))
}

fn replace_dictionary(
    document: &mut Document,
    object_id: Option<ObjectId>,
    dictionary: Dictionary,
) -> Object {
    let Some(object_id) = object_id else {
        return Object::Dictionary(dictionary);
    };
    document
        .objects
        .insert(object_id, Object::Dictionary(dictionary));
    Object::Reference(object_id)
}

fn replace_array(
    document: &mut Document,
    object_id: Option<ObjectId>,
    array: Vec<Object>,
) -> Object {
    let Some(object_id) = object_id else {
        return Object::Array(array);
    };
    document.objects.insert(object_id, Object::Array(array));
    Object::Reference(object_id)
}
