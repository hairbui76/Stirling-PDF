use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};

use chrono::{DateTime, Local};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, encryption::Permissions};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{
    pdf_attachments::list_attachments,
    pdf_page_geometry::inherited_value,
    pdf_table_of_contents::{BookmarkItem, extract_bookmarks},
    pdf_verification::{PdfVerificationResult, verify_pdf},
};

const MAX_XMP_BYTES: usize = 16 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 256;
const MAX_TREE_ITEMS: usize = 100_000;

#[derive(Debug, Error)]
pub enum PdfInfoError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
}

/// Builds the comprehensive JSON report returned by `get-info-on-pdf`.
///
/// # Errors
///
/// Returns [`PdfInfoError`] when the PDF cannot be parsed or a required core
/// structure is malformed. Optional report sections degrade to empty values.
pub fn pdf_info_report(path: &Path, filename: &str, file_size: u64) -> Result<Value, PdfInfoError> {
    let document = Document::load(path).map_err(|source| PdfInfoError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let verification = verify_pdf(path, filename).ok();
    let metadata = metadata(&document);
    let basic_info = basic_info(&document, file_size);
    let document_info = document_info(&document);
    let compliancy = compliancy(&document, verification.as_deref());
    let encryption = encryption(&document);
    let permissions = permissions(&document);
    let fields = form_fields(&document);
    let other = other_info(&document, path, filename);
    let pages = per_page_info(&document);
    let summary = summary_data(&document, verification.as_deref());

    let mut report = Map::new();
    report.insert("Metadata".to_owned(), Value::Object(metadata));
    report.insert("BasicInfo".to_owned(), Value::Object(basic_info));
    report.insert("DocumentInfo".to_owned(), Value::Object(document_info));
    report.insert("Compliancy".to_owned(), Value::Object(compliancy));
    report.insert("Encryption".to_owned(), Value::Object(encryption));
    report.insert("Permissions".to_owned(), Value::Object(permissions));
    report.insert("FormFields".to_owned(), Value::Object(fields));
    report.insert("Other".to_owned(), Value::Object(other));
    report.insert("PerPageInfo".to_owned(), Value::Object(pages));
    if !summary.is_empty() {
        report.insert("SummaryData".to_owned(), Value::Object(summary));
    }
    Ok(Value::Object(report))
}

fn metadata(document: &Document) -> Map<String, Value> {
    let Some(info) = info_dictionary(document) else {
        return Map::new();
    };
    let standard = [
        b"Title".as_slice(),
        b"Author",
        b"Subject",
        b"Keywords",
        b"Producer",
        b"Creator",
        b"CreationDate",
        b"ModDate",
        b"Trapped",
    ];
    let mut output = Map::new();
    for (key, output_key) in [
        (b"Title".as_slice(), "Title"),
        (b"Author", "Author"),
        (b"Subject", "Subject"),
        (b"Keywords", "Keywords"),
        (b"Producer", "Producer"),
        (b"Creator", "Creator"),
    ] {
        if let Some(value) = dictionary_text(document, info, key) {
            output.insert(output_key.to_owned(), Value::String(value));
        }
    }
    for (key, output_key) in [
        (b"CreationDate".as_slice(), "CreationDate"),
        (b"ModDate", "ModificationDate"),
    ] {
        if let Ok(value) = info.get(key)
            && let Some(value) = format_pdf_date(value)
        {
            output.insert(output_key.to_owned(), Value::String(value));
        }
    }
    for (key, value) in info {
        if standard.contains(&key.as_slice()) {
            continue;
        }
        if let Some(value) = object_text(document, value).filter(|value| !value.trim().is_empty()) {
            output.insert(
                String::from_utf8_lossy(key).into_owned(),
                Value::String(value),
            );
        }
    }
    output
}

fn basic_info(document: &Document, file_size: u64) -> Map<String, Value> {
    let page_numbers = document.get_pages().keys().copied().collect::<Vec<_>>();
    let text = document.extract_text(&page_numbers).unwrap_or_default();
    let word_count = if text.is_empty() {
        1
    } else {
        text.split_whitespace().count()
    };
    let paragraph_count = if text.is_empty() {
        1
    } else {
        text.split(['\r', '\n'])
            .filter(|part| !part.is_empty())
            .count()
            .max(1)
    };
    let (total_images, unique_images) = image_statistics(document);
    let mut output = Map::new();
    output.insert("FileSizeInBytes".to_owned(), json!(file_size));
    output.insert("WordCount".to_owned(), json!(word_count));
    output.insert("ParagraphCount".to_owned(), json!(paragraph_count));
    output.insert(
        "CharacterCount".to_owned(),
        json!(text.encode_utf16().count()),
    );
    if let Some(language) = catalog_text(document, b"Lang") {
        output.insert("Language".to_owned(), Value::String(language));
    }
    output.insert(
        "Number of pages".to_owned(),
        json!(document.get_pages().len()),
    );
    output.insert("TotalImages".to_owned(), json!(total_images));
    output.insert("UniqueImages".to_owned(), json!(unique_images));
    output
}

fn document_info(document: &Document) -> Map<String, Value> {
    let mut output = Map::new();
    output.insert(
        "PDF version".to_owned(),
        Value::String(document.version.clone()),
    );
    let trapped =
        info_dictionary(document).and_then(|info| dictionary_text(document, info, b"Trapped"));
    output.insert(
        "Trapped".to_owned(),
        trapped.map_or(Value::Null, Value::String),
    );
    let page_mode = document
        .catalog()
        .ok()
        .and_then(|catalog| catalog.get(b"PageMode").ok())
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_name().ok())
        .map_or_else(|| "USE_NONE".to_owned(), page_mode_name);
    output.insert("Page Mode".to_owned(), Value::String(page_mode));
    output
}

#[allow(clippy::similar_names)]
fn compliancy(
    document: &Document,
    verification: Option<&[PdfVerificationResult]>,
) -> Map<String, Value> {
    let mut is_pdfa = false;
    let mut is_pdfua = false;
    let mut is_pdfe = false;
    let mut is_pdfb = false;
    let mut pdfa_level = None;
    if let Some(results) = verification {
        for result in results.iter().filter(|result| result.compliant) {
            let standard = result.standard.to_ascii_lowercase();
            if standard.contains("pdf_a") || standard.contains("pdfa") {
                is_pdfa = true;
                if let Some(profile) = result.validation_profile.as_deref() {
                    is_pdfb = ["1b", "2b", "3b"]
                        .into_iter()
                        .any(|level| profile.contains(level));
                    pdfa_level = Some(profile.replace("pdfa-", ""));
                }
            }
            if standard.contains("pdf_ua") || standard.contains("pdfua") {
                is_pdfua = true;
            }
            if standard.contains("pdf_e") || standard.contains("pdfe") {
                is_pdfe = true;
            }
        }
    }
    let mut output = Map::new();
    output.insert("IsPDF/ACompliant".to_owned(), json!(is_pdfa));
    output.insert("IsPDF/UACompliant".to_owned(), json!(is_pdfua));
    output.insert("IsPDF/ECompliant".to_owned(), json!(is_pdfe));
    output.insert("IsPDF/VTCompliant".to_owned(), json!(false));
    output.insert("IsPDF/BCompliant".to_owned(), json!(is_pdfb));
    if let Some(level) = pdfa_level {
        output.insert("PDF/AConformanceLevel".to_owned(), Value::String(level));
    }
    output.insert(
        "IsPDF/SECCompliant".to_owned(),
        json!(is_sec_compliant(document)),
    );
    if let Some(results) = verification {
        for result in results {
            output.insert(result.standard.clone(), json!(result.compliant));
        }
    }
    output
}

fn encryption(document: &Document) -> Map<String, Value> {
    let mut output = Map::new();
    let Some(state) = document.encryption_state.as_ref() else {
        output.insert("IsEncrypted".to_owned(), json!(false));
        return output;
    };
    output.insert("IsEncrypted".to_owned(), json!(true));
    if let Some(encrypt) = encryption_dictionary(document) {
        if let Some(filter) = dictionary_text(document, encrypt, b"Filter") {
            output.insert("EncryptionAlgorithm".to_owned(), Value::String(filter));
        }
        for (key, output_key) in [
            (b"Length".as_slice(), "KeyLength"),
            (b"V", "Version"),
            (b"R", "Revision"),
        ] {
            if let Some(value) = dictionary_integer(document, encrypt, key) {
                output.insert(output_key.to_owned(), json!(value));
            }
        }
    }
    if !output.contains_key("KeyLength") {
        output.insert(
            "KeyLength".to_owned(),
            json!(
                state
                    .key_length()
                    .unwrap_or_else(|| state.file_encryption_key().len().saturating_mul(8))
            ),
        );
    }
    output
}

fn permissions(document: &Document) -> Map<String, Value> {
    let allowed = document
        .encryption_state
        .as_ref()
        .map_or_else(Permissions::all, lopdf::EncryptionState::permissions);
    let mut output = Map::new();
    for (name, permission) in [
        ("Document Assembly", Permissions::ASSEMBLABLE),
        ("Extracting Content", Permissions::COPYABLE),
        (
            "Extracting for accessibility",
            Permissions::COPYABLE_FOR_ACCESSIBILITY,
        ),
        ("Form Filling", Permissions::FILLABLE),
        ("Modifying", Permissions::MODIFIABLE),
        ("Modifying annotations", Permissions::ANNOTABLE),
        ("Printing", Permissions::PRINTABLE),
    ] {
        output.insert(
            name.to_owned(),
            Value::String(permission_state(allowed.contains(permission)).to_owned()),
        );
    }
    output
}

fn form_fields(document: &Document) -> Map<String, Value> {
    let mut output = Map::new();
    let Ok(catalog) = document.catalog() else {
        return output;
    };
    let Ok(acroform) = catalog.get(b"AcroForm") else {
        return output;
    };
    let Some(acroform) = resolved_dictionary(document, acroform) else {
        return output;
    };
    let Ok(fields) = acroform.get(b"Fields") else {
        return output;
    };
    let Some(fields) = resolved_array(document, fields) else {
        return output;
    };
    let mut visited = HashSet::new();
    for field in fields {
        collect_form_field(document, field, None, &mut visited, &mut output);
    }
    output
}

fn collect_form_field(
    document: &Document,
    field: &Object,
    parent_name: Option<&str>,
    visited: &mut HashSet<ObjectId>,
    output: &mut Map<String, Value>,
) {
    let Ok((object_id, field)) = document.dereference(field) else {
        return;
    };
    if object_id.is_some_and(|id| !visited.insert(id)) {
        return;
    }
    let Ok(field) = field.as_dict() else {
        return;
    };
    let partial_name = dictionary_text(document, field, b"T");
    let full_name = match (parent_name, partial_name.as_deref()) {
        (Some(parent), Some(partial)) => Some(format!("{parent}.{partial}")),
        (Some(parent), None) => Some(parent.to_owned()),
        (None, Some(partial)) => Some(partial.to_owned()),
        (None, None) => None,
    };
    if field.has(b"FT")
        && let Some(name) = full_name.as_ref()
    {
        let value = field
            .get(b"V")
            .ok()
            .and_then(|value| object_text(document, value))
            .unwrap_or_default();
        output.insert(name.clone(), Value::String(value));
    }
    if let Ok(kids) = field.get(b"Kids")
        && let Some(kids) = resolved_array(document, kids)
    {
        for kid in kids {
            collect_form_field(document, kid, full_name.as_deref(), visited, output);
        }
    }
}

fn other_info(document: &Document, path: &Path, filename: &str) -> Map<String, Value> {
    let embedded_files = list_attachments(path, filename)
        .unwrap_or_default()
        .into_iter()
        .map(|attachment| {
            json!({
                "Name": attachment.filename,
                "FileSize": attachment.size,
                "MimeType": attachment.content_type,
                "CreationDate": attachment.creation_date,
                "ModificationDate": attachment.modification_date,
            })
        })
        .collect();
    let bookmarks = extract_bookmarks(path, filename)
        .map(|items| flatten_bookmarks(&items))
        .unwrap_or_default();
    let xmp = xmp_metadata(document);
    let mut output = Map::new();
    output.insert("EmbeddedFiles".to_owned(), Value::Array(embedded_files));
    output.insert(
        "Attachments".to_owned(),
        Value::Array(page_attachments(document)),
    );
    output.insert(
        "JavaScript".to_owned(),
        Value::Array(javascript_entries(document)),
    );
    output.insert("Layers".to_owned(), Value::Array(layers(document)));
    output.insert("Bookmarks/Outline/TOC".to_owned(), Value::Array(bookmarks));
    output.insert(
        "XMPMetadata".to_owned(),
        xmp.map_or(Value::Null, Value::String),
    );
    if let Some(structure) = structure_tree(document) {
        output.insert("StructureTree".to_owned(), Value::Array(structure));
    }
    output
}

fn per_page_info(document: &Document) -> Map<String, Value> {
    let mut output = Map::new();
    for (page_number, page_id) in document.get_pages() {
        if let Some(info) = single_page_info(document, page_number, page_id) {
            output.insert(format!("Page {page_number}"), Value::Object(info));
        }
    }
    output
}

fn single_page_info(
    document: &Document,
    page_number: u32,
    page_id: ObjectId,
) -> Option<Map<String, Value>> {
    let media_box = page_box(document, page_id, b"MediaBox")?;
    let width = media_box[2] - media_box[0];
    let height = media_box[3] - media_box[1];
    let mut size = Map::new();
    size.insert(
        "Width (px)".to_owned(),
        Value::String(format!("{width:.2}")),
    );
    size.insert(
        "Height (px)".to_owned(),
        Value::String(format!("{height:.2}")),
    );
    size.insert(
        "Width (in)".to_owned(),
        Value::String(format!("{:.2}", width / 72.0)),
    );
    size.insert(
        "Height (in)".to_owned(),
        Value::String(format!("{:.2}", height / 72.0)),
    );
    size.insert(
        "Width (cm)".to_owned(),
        Value::String(format!("{:.2}", width / 72.0 * 2.54)),
    );
    size.insert(
        "Height (cm)".to_owned(),
        Value::String(format!("{:.2}", height / 72.0 * 2.54)),
    );
    size.insert(
        "Standard Page".to_owned(),
        Value::String(standard_page(width, height).to_owned()),
    );
    let rotation = inherited_integer(document, page_id, b"Rotate").unwrap_or_default();
    let page_text = document.extract_text(&[page_number]).unwrap_or_default();
    let annotations = page_annotations(document, page_id);
    let mut page = Map::new();
    page.insert("Size".to_owned(), Value::Object(size));
    page.insert("Rotation".to_owned(), json!(rotation));
    page.insert(
        "Page Orientation".to_owned(),
        Value::String(page_orientation(width, height).to_owned()),
    );
    page.insert("MediaBox".to_owned(), Value::String(format_box(media_box)));
    for (key, pdf_key) in [
        ("CropBox", b"CropBox".as_slice()),
        ("BleedBox", b"BleedBox"),
        ("TrimBox", b"TrimBox"),
        ("ArtBox", b"ArtBox"),
    ] {
        let value = effective_page_box(document, page_id, pdf_key)
            .map_or_else(|| "Undefined".to_owned(), format_box);
        page.insert(key.to_owned(), Value::String(value));
    }
    page.insert(
        "Text Characters Count".to_owned(),
        json!(page_text.encode_utf16().count()),
    );
    page.insert(
        "Annotations".to_owned(),
        annotation_summary(document, &annotations),
    );
    if let Some(resources) = page_resources(document, page_id) {
        page.insert(
            "Images".to_owned(),
            Value::Array(page_images(document, &resources)),
        );
        page.insert(
            "Links".to_owned(),
            Value::Array(page_links(document, &annotations)),
        );
        page.insert(
            "Fonts".to_owned(),
            Value::Array(page_fonts(document, &resources)),
        );
        page.insert(
            "XObjectCounts".to_owned(),
            Value::Object(page_xobject_counts(document, &resources)),
        );
    }
    page.insert(
        "Multimedia".to_owned(),
        Value::Array(page_multimedia(document, &annotations)),
    );
    Some(page)
}

fn summary_data(
    document: &Document,
    verification: Option<&[PdfVerificationResult]>,
) -> Map<String, Value> {
    let mut output = Map::new();
    if document.encryption_state.is_some() {
        output.insert("encrypted".to_owned(), json!(true));
    }
    let permission_values = permissions(document);
    let restricted = [
        ("Document Assembly", "document assembly"),
        ("Extracting Content", "content extraction"),
        ("Extracting for accessibility", "accessibility extraction"),
        ("Form Filling", "form filling"),
        ("Modifying", "modification"),
        ("Modifying annotations", "annotation modification"),
        ("Printing", "printing"),
    ]
    .into_iter()
    .filter(|(key, _)| permission_values.get(*key).and_then(Value::as_str) == Some("Not Allowed"))
    .map(|(_, label)| Value::String(label.to_owned()))
    .collect::<Vec<_>>();
    if !restricted.is_empty() {
        output.insert(
            "restrictedPermissionsCount".to_owned(),
            json!(restricted.len()),
        );
        output.insert("restrictedPermissions".to_owned(), Value::Array(restricted));
    }
    if let Some(results) = verification.filter(|results| !results.is_empty()) {
        output.insert(
            "Compliance".to_owned(),
            Value::Array(
                results
                    .iter()
                    .map(|result| {
                        json!({
                            "Standard": result.standard,
                            "Compliant": result.compliant,
                            "Summary": result.compliance_summary,
                        })
                    })
                    .collect(),
            ),
        );
    }
    output
}

fn page_annotations(document: &Document, page_id: ObjectId) -> Vec<Object> {
    let Ok(page) = document.get_dictionary(page_id) else {
        return Vec::new();
    };
    page.get(b"Annots")
        .ok()
        .and_then(|value| resolved_array(document, value))
        .cloned()
        .unwrap_or_default()
}

fn annotation_summary(document: &Document, annotations: &[Object]) -> Value {
    let mut subtype_count = 0;
    let mut contents_count = 0;
    for annotation in annotations {
        let Some(annotation) = resolved_dictionary(document, annotation) else {
            continue;
        };
        subtype_count += usize::from(annotation.has(b"Subtype"));
        contents_count += usize::from(annotation.has(b"Contents"));
    }
    json!({
        "AnnotationsCount": annotations.len(),
        "SubtypeCount": subtype_count,
        "ContentsCount": contents_count,
    })
}

fn page_images(document: &Document, resources: &Dictionary) -> Vec<Value> {
    xobjects(document, resources)
        .into_iter()
        .filter_map(|(_, object)| {
            let stream = resolved_stream(document, object)?;
            (stream.dict.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Image")).then(
                || {
                    let mut image = Map::new();
                    insert_integer(document, &stream.dict, b"Width", "Width", &mut image);
                    insert_integer(document, &stream.dict, b"Height", "Height", &mut image);
                    insert_integer(
                        document,
                        &stream.dict,
                        b"BitsPerComponent",
                        "BitsPerComponent",
                        &mut image,
                    );
                    if let Ok(color_space) = stream.dict.get(b"ColorSpace")
                        && let Some(name) = color_space_name(document, color_space)
                    {
                        image.insert("ColorSpace".to_owned(), Value::String(name));
                    }
                    Value::Object(image)
                },
            )
        })
        .collect()
}

fn page_links(document: &Document, annotations: &[Object]) -> Vec<Value> {
    let mut uris = HashSet::new();
    for annotation in annotations {
        let Some(annotation) = resolved_dictionary(document, annotation) else {
            continue;
        };
        if dictionary_name(document, annotation, b"Subtype").as_deref() != Some("Link") {
            continue;
        }
        let Some(action) = annotation
            .get(b"A")
            .ok()
            .and_then(|value| resolved_dictionary(document, value))
        else {
            continue;
        };
        if dictionary_name(document, action, b"S").as_deref() == Some("URI")
            && let Some(uri) = dictionary_text(document, action, b"URI")
        {
            uris.insert(uri);
        }
    }
    let mut uris = uris.into_iter().collect::<Vec<_>>();
    uris.sort();
    uris.into_iter().map(|uri| json!({ "URI": uri })).collect()
}

fn page_fonts(document: &Document, resources: &Dictionary) -> Vec<Value> {
    let Some(fonts) = resources
        .get(b"Font")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
    else {
        return Vec::new();
    };
    let mut grouped: BTreeMap<String, (Map<String, Value>, usize)> = BTreeMap::new();
    for (_, font) in fonts {
        let Some(font) = resolved_dictionary(document, font) else {
            continue;
        };
        let mut value = Map::new();
        value.insert(
            "IsEmbedded".to_owned(),
            json!(font_descriptor(document, font).is_some_and(|descriptor| {
                [b"FontFile".as_slice(), b"FontFile2", b"FontFile3"]
                    .into_iter()
                    .any(|key| descriptor.has(key))
            })),
        );
        if let Some(name) = dictionary_name(document, font, b"BaseFont") {
            value.insert("Name".to_owned(), Value::String(name));
        }
        if let Some(subtype) = dictionary_name(document, font, b"Subtype") {
            value.insert("Subtype".to_owned(), Value::String(subtype));
        }
        if let Some(descriptor) = font_descriptor(document, font) {
            insert_number(
                document,
                descriptor,
                b"ItalicAngle",
                "ItalicAngle",
                &mut value,
            );
            let flags = dictionary_integer(document, descriptor, b"Flags").unwrap_or_default();
            for (key, mask) in [
                ("IsItalic", 1),
                ("IsBold", 64),
                ("IsFixedPitch", 2),
                ("IsSerif", 4),
                ("IsSymbolic", 8),
                ("IsScript", 16),
                ("IsNonsymbolic", 32),
            ] {
                value.insert(key.to_owned(), json!((flags & mask) != 0));
            }
            if let Some(family) = dictionary_text(document, descriptor, b"FontFamily") {
                value.insert("FontFamily".to_owned(), Value::String(family));
            }
            insert_number(
                document,
                descriptor,
                b"FontWeight",
                "FontWeight",
                &mut value,
            );
        }
        let key = serde_json::to_string(&value).unwrap_or_default();
        grouped
            .entry(key)
            .and_modify(|(_, count)| *count += 1)
            .or_insert((value, 1));
    }
    grouped
        .into_values()
        .map(|(mut font, count)| {
            font.insert("Count".to_owned(), json!(count));
            Value::Object(font)
        })
        .collect()
}

fn page_xobject_counts(document: &Document, resources: &Dictionary) -> Map<String, Value> {
    let mut counts = BTreeMap::<String, usize>::new();
    for (_, object) in xobjects(document, resources) {
        let kind = resolved_stream(document, object)
            .and_then(|stream| dictionary_name(document, &stream.dict, b"Subtype"))
            .map_or("Other", |subtype| match subtype.as_str() {
                "Image" => "Image",
                "Form" => "Form",
                _ => "Other",
            });
        *counts.entry(kind.to_owned()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(key, count)| (key, json!(count)))
        .collect()
}

fn page_multimedia(document: &Document, annotations: &[Object]) -> Vec<Value> {
    annotations
        .iter()
        .filter_map(|annotation| resolved_dictionary(document, annotation))
        .filter(|annotation| {
            dictionary_name(document, annotation, b"Subtype").as_deref() == Some("RichMedia")
        })
        .map(|annotation| {
            json!({
                "Subtype": "RichMedia",
                "Contents": dictionary_text(document, annotation, b"Contents"),
            })
        })
        .collect()
}

fn page_attachments(document: &Document) -> Vec<Value> {
    let mut output = Vec::new();
    for page_id in document.get_pages().into_values() {
        for annotation in page_annotations(document, page_id) {
            let Some(annotation) = resolved_dictionary(document, &annotation) else {
                continue;
            };
            if dictionary_name(document, annotation, b"Subtype").as_deref()
                != Some("FileAttachment")
            {
                continue;
            }
            let mut item = Map::new();
            item.insert(
                "Name".to_owned(),
                dictionary_name(document, annotation, b"Name").map_or(Value::Null, Value::String),
            );
            item.insert(
                "Description".to_owned(),
                dictionary_text(document, annotation, b"Contents")
                    .map_or(Value::Null, Value::String),
            );
            if let Some(specification) = annotation
                .get(b"FS")
                .ok()
                .and_then(|value| resolved_dictionary(document, value))
                && let Some(size) = embedded_file_size(document, specification)
            {
                item.insert("FileSize".to_owned(), json!(size));
            }
            output.push(Value::Object(item));
        }
    }
    output
}

fn javascript_entries(document: &Document) -> Vec<Value> {
    let mut entries = BTreeMap::new();
    let Some(tree) = document
        .catalog()
        .ok()
        .and_then(|catalog| catalog.get(b"Names").ok())
        .and_then(|value| resolved_dictionary(document, value))
        .and_then(|names| names.get(b"JavaScript").ok())
    else {
        return Vec::new();
    };
    collect_name_tree(document, tree, &mut HashSet::new(), &mut entries);
    entries
        .into_iter()
        .map(|(name, action)| {
            let length = javascript_text(document, &action)
                .map(|text| text.encode_utf16().count())
                .unwrap_or_default();
            json!({ "JS Name": name, "JS Script Length": length })
        })
        .collect()
}

fn layers(document: &Document) -> Vec<Value> {
    let Some(groups) = document
        .catalog()
        .ok()
        .and_then(|catalog| catalog.get(b"OCProperties").ok())
        .and_then(|value| resolved_dictionary(document, value))
        .and_then(|properties| properties.get(b"OCGs").ok())
        .and_then(|value| resolved_array(document, value))
    else {
        return Vec::new();
    };
    groups
        .iter()
        .filter_map(|group| resolved_dictionary(document, group))
        .filter_map(|group| dictionary_text(document, group, b"Name"))
        .map(|name| json!({ "Name": name }))
        .collect()
}

fn structure_tree(document: &Document) -> Option<Vec<Value>> {
    let root = document
        .catalog()
        .ok()?
        .get(b"StructTreeRoot")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))?;
    let kids = root.get(b"K").ok()?;
    let mut visited = HashSet::new();
    let mut count = 0;
    Some(structure_children(
        document,
        kids,
        0,
        &mut visited,
        &mut count,
    ))
}

fn structure_children(
    document: &Document,
    object: &Object,
    depth: usize,
    visited: &mut HashSet<ObjectId>,
    count: &mut usize,
) -> Vec<Value> {
    if depth > MAX_TREE_DEPTH || *count > MAX_TREE_ITEMS {
        return Vec::new();
    }
    if let Some(array) = resolved_array(document, object) {
        return array
            .iter()
            .flat_map(|child| structure_children(document, child, depth, visited, count))
            .collect();
    }
    let Ok((object_id, resolved)) = document.dereference(object) else {
        return Vec::new();
    };
    if object_id.is_some_and(|id| !visited.insert(id)) {
        return Vec::new();
    }
    let Ok(element) = resolved.as_dict() else {
        return Vec::new();
    };
    *count += 1;
    let mut node = Map::new();
    if let Some(kind) = dictionary_name(document, element, b"S") {
        node.insert("Type".to_owned(), Value::String(kind));
    }
    if let Ok(kids) = element.get(b"K") {
        let mut content_visited = HashSet::new();
        let mut content_count = 0;
        let content = structure_content(
            document,
            kids,
            depth + 1,
            &mut content_visited,
            &mut content_count,
        );
        node.insert("Content".to_owned(), Value::String(content));
        let children = structure_children(document, kids, depth + 1, visited, count);
        if !children.is_empty() {
            node.insert("Children".to_owned(), Value::Array(children));
        }
    } else {
        node.insert("Content".to_owned(), Value::String(String::new()));
    }
    vec![Value::Object(node)]
}

fn structure_content(
    document: &Document,
    object: &Object,
    depth: usize,
    visited: &mut HashSet<ObjectId>,
    count: &mut usize,
) -> String {
    if depth > MAX_TREE_DEPTH || *count > MAX_TREE_ITEMS {
        return String::new();
    }
    let Ok((object_id, resolved)) = document.dereference(object) else {
        return String::new();
    };
    if object_id.is_some_and(|id| !visited.insert(id)) {
        return String::new();
    }
    *count += 1;
    match resolved {
        Object::String(_, _) => lopdf::decode_text_string(resolved).unwrap_or_default(),
        Object::Array(values) => values
            .iter()
            .map(|value| structure_content(document, value, depth + 1, visited, count))
            .collect(),
        Object::Dictionary(dictionary) => dictionary
            .get(b"K")
            .ok()
            .map(|kids| structure_content(document, kids, depth + 1, visited, count))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn is_sec_compliant(document: &Document) -> bool {
    if document.encryption_state.is_some() {
        return false;
    }
    let Ok(catalog) = document.catalog() else {
        return false;
    };
    if catalog.has(b"AcroForm") || has_catalog_javascript(document, catalog) {
        return false;
    }
    if catalog
        .get(b"Names")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
        .is_some_and(|names| names.has(b"EmbeddedFiles"))
    {
        return false;
    }
    for page_id in document.get_pages().into_values() {
        for annotation in page_annotations(document, page_id) {
            let Some(annotation) = resolved_dictionary(document, &annotation) else {
                continue;
            };
            if dictionary_name(document, annotation, b"Subtype").as_deref() != Some("Link") {
                continue;
            }
            let action_kind = annotation
                .get(b"A")
                .ok()
                .and_then(|value| resolved_dictionary(document, value))
                .and_then(|action| dictionary_name(document, action, b"S"));
            if matches!(
                action_kind.as_deref(),
                Some("URI" | "Launch" | "GoToR" | "SubmitForm")
            ) {
                return false;
            }
        }
    }
    true
}

fn has_catalog_javascript(document: &Document, catalog: &Dictionary) -> bool {
    let open_action_is_javascript = catalog
        .get(b"OpenAction")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
        .and_then(|action| dictionary_name(document, action, b"S"))
        .as_deref()
        == Some("JavaScript");
    open_action_is_javascript
        || catalog
            .get(b"Names")
            .ok()
            .and_then(|value| resolved_dictionary(document, value))
            .is_some_and(|names| names.has(b"JavaScript"))
}

fn image_statistics(document: &Document) -> (usize, usize) {
    let mut total = 0;
    let mut unique = HashSet::new();
    for page_id in document.get_pages().into_values() {
        let Some(resources) = page_resources(document, page_id) else {
            continue;
        };
        for (_, object) in xobjects(document, &resources) {
            let Some(stream) = resolved_stream(document, object) else {
                continue;
            };
            if dictionary_name(document, &stream.dict, b"Subtype").as_deref() != Some("Image") {
                continue;
            }
            total += 1;
            unique.insert(format!(
                "{}_{}_{}_{}",
                dictionary_integer(document, &stream.dict, b"Width").unwrap_or_default(),
                dictionary_integer(document, &stream.dict, b"Height").unwrap_or_default(),
                dictionary_integer(document, &stream.dict, b"BitsPerComponent").unwrap_or_default(),
                dictionary_name(document, &stream.dict, b"Filter").unwrap_or_default(),
            ));
        }
    }
    (total, unique.len())
}

fn flatten_bookmarks(items: &[BookmarkItem]) -> Vec<Value> {
    let mut output = Vec::new();
    for item in items {
        output.push(json!({ "Title": item.title }));
        output.extend(flatten_bookmarks(&item.children));
    }
    output
}

fn xmp_metadata(document: &Document) -> Option<String> {
    let metadata = document.catalog().ok()?.get(b"Metadata").ok()?;
    let stream = resolved_stream(document, metadata)?;
    let bytes = stream.decompressed_content_with_limit(MAX_XMP_BYTES).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn collect_name_tree(
    document: &Document,
    node: &Object,
    visited: &mut HashSet<ObjectId>,
    output: &mut BTreeMap<String, Object>,
) {
    let Ok((object_id, node)) = document.dereference(node) else {
        return;
    };
    if object_id.is_some_and(|id| !visited.insert(id)) {
        return;
    }
    let Ok(node) = node.as_dict() else {
        return;
    };
    if let Ok(names) = node.get(b"Names")
        && let Some(names) = resolved_array(document, names)
    {
        for pair in names.chunks_exact(2) {
            if let Some(name) = object_text(document, &pair[0]) {
                output.insert(name, pair[1].clone());
            }
        }
    }
    if let Ok(kids) = node.get(b"Kids")
        && let Some(kids) = resolved_array(document, kids)
    {
        for kid in kids {
            collect_name_tree(document, kid, visited, output);
        }
    }
}

fn javascript_text(document: &Document, action: &Object) -> Option<String> {
    let action = resolved_dictionary(document, action)?;
    let script = action.get(b"JS").ok()?;
    let (_, script) = document.dereference(script).ok()?;
    match script {
        Object::String(_, _) => lopdf::decode_text_string(script).ok(),
        Object::Stream(stream) => String::from_utf8(stream.decompressed_content().ok()?).ok(),
        _ => None,
    }
}

fn embedded_file_size(document: &Document, specification: &Dictionary) -> Option<i64> {
    let embedded = specification
        .get(b"EF")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))?;
    let stream = embedded
        .get(b"UF")
        .or_else(|_| embedded.get(b"F"))
        .ok()
        .and_then(|value| resolved_stream(document, value))?;
    Some(i64::try_from(stream.content.len()).unwrap_or(i64::MAX))
}

fn xobjects<'a>(document: &'a Document, resources: &'a Dictionary) -> Vec<(&'a [u8], &'a Object)> {
    resources
        .get(b"XObject")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
        .map(|dictionary| {
            dictionary
                .iter()
                .map(|(name, object)| (name.as_slice(), object))
                .collect()
        })
        .unwrap_or_default()
}

fn page_resources(document: &Document, page_id: ObjectId) -> Option<Dictionary> {
    let value = inherited_value(document, page_id, b"Resources").ok()?;
    let (_, value) = document.dereference(&value).ok()?;
    value.as_dict().ok().cloned()
}

fn page_box(document: &Document, page_id: ObjectId, key: &[u8]) -> Option<[f32; 4]> {
    let value = inherited_value(document, page_id, key).ok()?;
    let (_, value) = document.dereference(&value).ok()?;
    let values = value.as_array().ok()?;
    if values.len() < 4 {
        return None;
    }
    Some([
        values[0].as_float().ok()?,
        values[1].as_float().ok()?,
        values[2].as_float().ok()?,
        values[3].as_float().ok()?,
    ])
}

fn effective_page_box(document: &Document, page_id: ObjectId, key: &[u8]) -> Option<[f32; 4]> {
    page_box(document, page_id, key).or_else(|| {
        if key == b"CropBox" {
            page_box(document, page_id, b"MediaBox")
        } else {
            page_box(document, page_id, b"CropBox")
                .or_else(|| page_box(document, page_id, b"MediaBox"))
        }
    })
}

fn inherited_integer(document: &Document, page_id: ObjectId, key: &[u8]) -> Option<i64> {
    let value = inherited_value(document, page_id, key).ok()?;
    let (_, value) = document.dereference(&value).ok()?;
    value.as_i64().ok()
}

fn format_box(bounds: [f32; 4]) -> String {
    format!(
        "[{}, {}, {}, {}]",
        bounds[0], bounds[1], bounds[2], bounds[3]
    )
}

fn standard_page(width: f32, height: f32) -> &'static str {
    [
        ("Letter", 612.0, 792.0),
        ("LEGAL", 612.0, 1008.0),
        ("A0", 2383.937, 3370.394),
        ("A1", 1683.78, 2383.937),
        ("A2", 1190.551, 1683.78),
        ("A3", 841.89, 1190.551),
        ("A4", 595.276, 841.89),
        ("A5", 419.528, 595.276),
        ("A6", 297.638, 419.528),
    ]
    .into_iter()
    .find(|(_, expected_width, expected_height)| {
        (width - expected_width).abs() <= 1.0 && (height - expected_height).abs() <= 1.0
    })
    .map_or("Custom", |(name, _, _)| name)
}

fn page_orientation(width: f32, height: f32) -> &'static str {
    if width > height {
        "Landscape"
    } else if height > width {
        "Portrait"
    } else {
        "Square"
    }
}

fn page_mode_name(name: &[u8]) -> String {
    match name {
        b"UseNone" => "USE_NONE",
        b"UseOutlines" => "USE_OUTLINES",
        b"UseThumbs" => "USE_THUMBS",
        b"FullScreen" => "FULL_SCREEN",
        b"UseOC" => "USE_OPTIONAL_CONTENT",
        b"UseAttachments" => "USE_ATTACHMENTS",
        _ => return String::from_utf8_lossy(name).into_owned(),
    }
    .to_owned()
}

fn permission_state(allowed: bool) -> &'static str {
    if allowed { "Allowed" } else { "Not Allowed" }
}

fn info_dictionary(document: &Document) -> Option<&Dictionary> {
    let info = document.trailer.get(b"Info").ok()?;
    resolved_dictionary(document, info)
}

fn encryption_dictionary(document: &Document) -> Option<&Dictionary> {
    let encryption = document.trailer.get(b"Encrypt").ok()?;
    resolved_dictionary(document, encryption)
}

fn catalog_text(document: &Document, key: &[u8]) -> Option<String> {
    dictionary_text(document, document.catalog().ok()?, key)
}

fn dictionary_text(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    object_text(document, dictionary.get(key).ok()?)
}

fn dictionary_name(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    let value = dictionary.get(key).ok()?;
    let (_, value) = document.dereference(value).ok()?;
    value
        .as_name()
        .ok()
        .map(|name| String::from_utf8_lossy(name).into_owned())
}

fn dictionary_integer(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<i64> {
    let value = dictionary.get(key).ok()?;
    let (_, value) = document.dereference(value).ok()?;
    value.as_i64().ok()
}

fn object_text(document: &Document, object: &Object) -> Option<String> {
    let (_, object) = document.dereference(object).ok()?;
    match object {
        Object::String(_, _) => lopdf::decode_text_string(object).ok(),
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::Integer(value) => Some(value.to_string()),
        Object::Real(value) => Some(value.to_string()),
        Object::Boolean(value) => Some(value.to_string()),
        Object::Array(values) => Some(
            values
                .iter()
                .filter_map(|value| object_text(document, value))
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}

fn resolved_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    document.dereference(object).ok()?.1.as_dict().ok()
}

fn resolved_array<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Vec<Object>> {
    document.dereference(object).ok()?.1.as_array().ok()
}

fn resolved_stream<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Stream> {
    document.dereference(object).ok()?.1.as_stream().ok()
}

fn font_descriptor<'a>(document: &'a Document, font: &'a Dictionary) -> Option<&'a Dictionary> {
    font.get(b"FontDescriptor")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
}

fn insert_integer(
    document: &Document,
    dictionary: &Dictionary,
    pdf_key: &[u8],
    output_key: &str,
    output: &mut Map<String, Value>,
) {
    if let Some(value) = dictionary_integer(document, dictionary, pdf_key) {
        output.insert(output_key.to_owned(), json!(value));
    }
}

fn insert_number(
    document: &Document,
    dictionary: &Dictionary,
    pdf_key: &[u8],
    output_key: &str,
    output: &mut Map<String, Value>,
) {
    let Some(value) = dictionary.get(pdf_key).ok() else {
        return;
    };
    let Some(value) = document.dereference(value).ok().map(|(_, value)| value) else {
        return;
    };
    if let Ok(value) = value.as_float() {
        output.insert(output_key.to_owned(), json!(value));
    }
}

fn color_space_name(document: &Document, object: &Object) -> Option<String> {
    let (_, object) = document.dereference(object).ok()?;
    match object {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::Array(values) => values
            .first()
            .and_then(|value| object_text(document, value)),
        _ => None,
    }
}

fn format_pdf_date(object: &Object) -> Option<String> {
    let date: DateTime<Local> = object.as_datetime()?.try_into().ok()?;
    Some(date.format("%Y-%m-%d %H:%M:%S").to_string())
}

#[cfg(test)]
mod tests {
    use super::{page_mode_name, page_orientation, standard_page};

    #[test]
    fn identifies_orientation_and_standard_sizes() {
        assert_eq!(page_orientation(800.0, 600.0), "Landscape");
        assert_eq!(page_orientation(600.0, 800.0), "Portrait");
        assert_eq!(page_orientation(600.0, 600.0), "Square");
        assert_eq!(standard_page(595.276, 841.89), "A4");
        assert_eq!(standard_page(612.0, 792.0), "Letter");
        assert_eq!(standard_page(300.0, 300.0), "Custom");
    }

    #[test]
    fn maps_pdf_page_modes_to_pdfbox_enum_names() {
        assert_eq!(page_mode_name(b"UseNone"), "USE_NONE");
        assert_eq!(page_mode_name(b"UseOutlines"), "USE_OUTLINES");
        assert_eq!(page_mode_name(b"VendorMode"), "VendorMode");
    }
}
