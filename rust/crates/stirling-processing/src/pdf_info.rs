use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
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
/// Ceiling on the decompressed content stream of a single page fed to text
/// extraction. Java has no equivalent because `PDFBox` streams the content, so
/// this only ever engages on decompression bombs.
const MAX_PAGE_CONTENT_BYTES: usize = 64 * 1024 * 1024;
/// `PDFBox` falls back to US Letter when a page has no `MediaBox`.
const LETTER_BOX: [f32; 4] = [0.0, 0.0, 612.0, 792.0];
/// `java.util.regex` matches `\s` against these six characters only; the
/// pattern in `RegexPatternUtils` does not set `UNICODE_CHARACTER_CLASS`.
const JAVA_WHITESPACE: [u8; 6] = [b' ', b'\t', b'\n', 0x0B, 0x0C, b'\r'];

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
    let text = document_text(document);
    let (total_images, unique_images) = image_statistics(document);
    let mut output = Map::new();
    output.insert("FileSizeInBytes".to_owned(), json!(file_size));
    output.insert(
        "WordCount".to_owned(),
        json!(java_split_len(&text, whitespace_separator)),
    );
    output.insert(
        "ParagraphCount".to_owned(),
        json!(java_split_len(&text, newline_separator)),
    );
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
        let info = single_page_info(document, page_number, page_id);
        output.insert(format!("Page {page_number}"), Value::Object(info));
    }
    output
}

fn single_page_info(
    document: &Document,
    page_number: u32,
    page_id: ObjectId,
) -> Map<String, Value> {
    // PDPage.getMediaBox() substitutes US Letter when the entry is unset.
    let media_box =
        page_box(document, page_id, b"MediaBox", Inheritance::Inherited).unwrap_or(LETTER_BOX);
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
    let rotation = page_rotation(document, page_id);
    let page_text = page_text(document, page_number, page_id);
    let annotations = page_annotations(document, page_id);
    let mut page = Map::new();
    page.insert("Size".to_owned(), Value::Object(size));
    page.insert("Rotation".to_owned(), json!(rotation));
    page.insert(
        "Page Orientation".to_owned(),
        Value::String(page_orientation(width, height).to_owned()),
    );
    page.insert("MediaBox".to_owned(), Value::String(format_box(media_box)));
    // PDPage.getCropBox() is inheritable and clipped to the media box; the
    // remaining boxes are read off the page dictionary only and fall back to
    // the crop box. None of them can be null, so Java never prints "Undefined".
    let crop_box = page_box(document, page_id, b"CropBox", Inheritance::Inherited)
        .map_or(media_box, |bounds| clip_to_media_box(bounds, media_box));
    page.insert("CropBox".to_owned(), Value::String(format_box(crop_box)));
    for (key, pdf_key) in [
        ("BleedBox", b"BleedBox".as_slice()),
        ("TrimBox", b"TrimBox"),
        ("ArtBox", b"ArtBox"),
    ] {
        let bounds = page_box(document, page_id, pdf_key, Inheritance::Direct)
            .map_or(crop_box, |bounds| clip_to_media_box(bounds, media_box));
        page.insert(key.to_owned(), Value::String(format_box(bounds)));
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
    page
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

/// Mirrors `GetInfoOnPDF.extractPageFonts`.
///
/// Java dedupes fonts by the compact JSON rendering of the node built *before*
/// `Count` is added, keyed into a `java.util.HashMap`, then emits
/// `uniqueFontsMap.values()`. That iteration order is bucket order, not
/// insertion or sort order, so it is reproduced here rather than approximated:
/// the array index of a font is observable in the response.
fn page_fonts(document: &Document, resources: &Dictionary) -> Vec<Value> {
    let Some(fonts) = resources
        .get(b"Font")
        .ok()
        .and_then(|value| resolved_dictionary(document, value))
    else {
        return Vec::new();
    };
    let mut keys: Vec<String> = Vec::new();
    let mut nodes: Vec<Vec<(&'static str, JavaJson)>> = Vec::new();
    let mut counts: Vec<usize> = Vec::new();
    // Java's HashMap lookup is O(1); a linear scan here would turn a resource
    // dictionary with many font entries into quadratic work.
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (_, font) in fonts {
        let Some(font) = resolved_dictionary(document, font) else {
            // PDResources.getFont returns null for a non-dictionary entry and
            // the ensuing NPE aborts Java's loop, discarding the whole array.
            return Vec::new();
        };
        let node = font_node(document, font);
        let key = jackson_object(&node);
        if let Some(position) = seen.get(&key) {
            counts[*position] += 1;
        } else {
            seen.insert(key.clone(), keys.len());
            keys.push(key);
            nodes.push(node);
            counts.push(1);
        }
    }
    java_hash_map_order(&keys)
        .into_iter()
        .map(|index| {
            let mut output = Map::new();
            for (name, value) in &nodes[index] {
                output.insert((*name).to_owned(), value.to_value());
            }
            output.insert("Count".to_owned(), json!(counts[index]));
            Value::Object(output)
        })
        .collect()
}

/// Builds one font node in Jackson insertion order.
///
/// `Subtype` really does carry the font dictionary's `/Type` (always `Font`):
/// Java calls `PDFont.getType()`, not `getSubType()`. This is a faithful port
/// of that quirk, not a transcription slip.
fn font_node(document: &Document, font: &Dictionary) -> Vec<(&'static str, JavaJson)> {
    let subtype = dictionary_name_as_string(document, font, b"Subtype");
    let subtype = subtype.as_deref();
    let descriptor = resolve_font_descriptor(document, font, subtype);
    let name_key: &[u8] = if subtype == Some("Type3") {
        b"Name"
    } else {
        b"BaseFont"
    };
    let mut node = Vec::with_capacity(13);
    node.push((
        "IsEmbedded",
        JavaJson::Bool(is_embedded(subtype, &descriptor)),
    ));
    node.push((
        "Name",
        JavaJson::Text(dictionary_name_as_string(document, font, name_key)),
    ));
    node.push((
        "Subtype",
        JavaJson::Text(dictionary_name_as_string(document, font, b"Type")),
    ));
    match descriptor {
        FontDescriptor::Missing => {}
        FontDescriptor::Standard14(metrics) => {
            node.push(("ItalicAngle", JavaJson::Float(metrics.italic_angle)));
            push_descriptor_flags(metrics.flags, &mut node);
            node.push((
                "FontFamily",
                JavaJson::Text(Some(metrics.family.to_owned())),
            ));
            node.push(("FontWeight", JavaJson::Float(0.0)));
        }
        FontDescriptor::Dictionary(descriptor) => {
            node.push((
                "ItalicAngle",
                JavaJson::Float(
                    dictionary_float(document, descriptor, b"ItalicAngle").unwrap_or(0.0),
                ),
            ));
            let flags = java_int_value(dictionary_integer(document, descriptor, b"Flags"));
            push_descriptor_flags(flags, &mut node);
            node.push((
                "FontFamily",
                // PDFontDescriptor.getFontFamily() only accepts a COSString.
                JavaJson::Text(dictionary_string(document, descriptor, b"FontFamily")),
            ));
            node.push((
                "FontWeight",
                JavaJson::Float(
                    dictionary_float(document, descriptor, b"FontWeight").unwrap_or(0.0),
                ),
            ));
        }
    }
    node
}

fn push_descriptor_flags(flags: i32, node: &mut Vec<(&'static str, JavaJson)>) {
    for (key, mask) in [
        ("IsItalic", 1),
        ("IsBold", 64),
        ("IsFixedPitch", 2),
        ("IsSerif", 4),
        ("IsSymbolic", 8),
        ("IsScript", 16),
        ("IsNonsymbolic", 32),
    ] {
        node.push((key, JavaJson::Bool((flags & mask) != 0)));
    }
}

/// Where `PDFBox` finds a font's descriptor.
enum FontDescriptor<'a> {
    Dictionary(&'a Dictionary),
    /// `PDFBox` synthesises a descriptor from the bundled AFM metrics when a
    /// simple font names one of the Standard 14 faces and carries no
    /// `/FontDescriptor` of its own.
    Standard14(Standard14Metrics),
    Missing,
}

fn resolve_font_descriptor<'a>(
    document: &'a Document,
    font: &'a Dictionary,
    subtype: Option<&str>,
) -> FontDescriptor<'a> {
    if let Some(descriptor) = font_descriptor(document, font) {
        return FontDescriptor::Dictionary(descriptor);
    }
    if subtype == Some("Type0") {
        // PDType0Font delegates to its descendant CIDFont.
        return font
            .get(b"DescendantFonts")
            .ok()
            .and_then(|value| resolved_array(document, value))
            .and_then(|descendants| descendants.first())
            .and_then(|descendant| resolved_dictionary(document, descendant))
            .and_then(|descendant| font_descriptor(document, descendant))
            .map_or(FontDescriptor::Missing, FontDescriptor::Dictionary);
    }
    if subtype == Some("Type3") {
        return FontDescriptor::Missing;
    }
    dictionary_name_as_string(document, font, b"BaseFont")
        .as_deref()
        .and_then(standard_14_metrics)
        .map_or(FontDescriptor::Missing, FontDescriptor::Standard14)
}

/// Approximates `PDFont.isEmbedded()`.
///
/// `PDFBox` additionally reports `false` when an embedded font program fails to
/// parse ("damaged"); without a font parser that state is not observable here,
/// so a present `FontFile*` entry is treated as embedded.
fn is_embedded(subtype: Option<&str>, descriptor: &FontDescriptor<'_>) -> bool {
    if subtype == Some("Type3") {
        // A Type 3 font carries its glyph procedures inline, so PDType3Font
        // hardcodes isEmbedded() to true.
        return true;
    }
    match descriptor {
        FontDescriptor::Dictionary(descriptor) => [
            b"FontFile".as_slice(),
            b"FontFile2".as_slice(),
            b"FontFile3".as_slice(),
        ]
        .into_iter()
        .any(|key| descriptor.has(key)),
        FontDescriptor::Standard14(_) | FontDescriptor::Missing => false,
    }
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

/// Reads the catalog's XMP packet.
///
/// `GetInfoOnPDF.extractXMPMetadata` has two paths: it parses the packet with
/// xmpbox's `DomXmpParser` and re-serialises the resulting model with
/// `XmpSerializer(pretty=true)`, and on `XmpParsingException` it falls back to
/// the raw decoded bytes. Only the fallback path is reproduced here, so a
/// packet xmpbox accepts still differs from Java: the re-serialisation
/// rewrites attribute-form properties into element form, re-groups them into
/// one `rdf:Description` per schema, sorts the namespace declarations,
/// normalises dates (`...Z` becomes `...+00:00`), re-indents, and emits its own
/// `xpacket` header. Matching that needs a port of xmpbox's schema model and
/// serialiser — including the conditions under which its parser rejects a
/// packet and Java therefore falls back to raw — which is its own work item and
/// does not belong in this module.
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

/// Whether a page box may be inherited from an ancestor `Pages` node.
///
/// `MediaBox` and `CropBox` go through `PDPageTree.getInheritableAttribute`;
/// `BleedBox`, `TrimBox` and `ArtBox` are read straight off the page.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Inheritance {
    Inherited,
    Direct,
}

/// Resolves a page box the way `PDPage` does.
///
/// Returns `None` when the entry is absent or is not an array, which is the
/// only state `PDFBox` treats as "unset". A short array is *not* an error:
/// `PDRectangle(COSArray)` reads the four corners off `toFloatArray()` with
/// missing and non-numeric entries defaulting to 0, then normalises them.
fn page_box(
    document: &Document,
    page_id: ObjectId,
    key: &[u8],
    inheritance: Inheritance,
) -> Option<[f32; 4]> {
    let value = match inheritance {
        Inheritance::Inherited => inherited_value(document, page_id, key).ok(),
        Inheritance::Direct => document
            .get_dictionary(page_id)
            .ok()
            .and_then(|page| page.get(key).ok())
            .cloned(),
    };
    let value = value?;
    let (_, value) = document.dereference(&value).ok()?;
    let values = value.as_array().ok()?;
    let corners = [0usize, 1, 2, 3].map(|index| {
        values
            .get(index)
            .and_then(|value| document.dereference(value).ok())
            .and_then(|(_, value)| value.as_float().ok())
            .unwrap_or(0.0)
    });
    Some([
        corners[0].min(corners[2]),
        corners[1].min(corners[3]),
        corners[0].max(corners[2]),
        corners[1].max(corners[3]),
    ])
}

/// Mirrors `PDPage.clipToMediaBox`, which intersects without re-normalising —
/// a box wholly outside the media box therefore stays inverted.
fn clip_to_media_box(bounds: [f32; 4], media_box: [f32; 4]) -> [f32; 4] {
    [
        bounds[0].max(media_box[0]),
        bounds[1].max(media_box[1]),
        bounds[2].min(media_box[2]),
        bounds[3].min(media_box[3]),
    ]
}

/// Mirrors `PDPage.getRotation`: non-multiples of 90 collapse to 0 and the
/// result is normalised into `0..360`.
fn page_rotation(document: &Document, page_id: ObjectId) -> i32 {
    let Some(value) = inherited_value(document, page_id, b"Rotate").ok() else {
        return 0;
    };
    let Ok((_, value)) = document.dereference(&value) else {
        return 0;
    };
    let angle = match value {
        Object::Integer(value) => java_int_value(Some(*value)),
        Object::Real(value) => java_int_value_of_real(*value),
        _ => return 0,
    };
    if angle % 90 != 0 {
        return 0;
    }
    (angle % 360 + 360) % 360
}

/// Mirrors `PDRectangle.toString()`, which concatenates four Java `float`s.
fn format_box(bounds: [f32; 4]) -> String {
    format!(
        "[{},{},{},{}]",
        java_float_to_string(bounds[0]),
        java_float_to_string(bounds[1]),
        java_float_to_string(bounds[2]),
        java_float_to_string(bounds[3])
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

/// Mirrors `COSDictionary.getFloat(key, 0)`: any `COSNumber` converts, anything
/// else falls through to the caller's default.
fn dictionary_float(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<f32> {
    let value = dictionary.get(key).ok()?;
    let (_, value) = document.dereference(value).ok()?;
    value.as_float().ok()
}

/// Mirrors `COSDictionary.getString`-style access that accepts a `COSString`
/// and nothing else.
fn dictionary_string(document: &Document, dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    let value = dictionary.get(key).ok()?;
    let (_, value) = document.dereference(value).ok()?;
    match value {
        Object::String(_, _) => lopdf::decode_text_string(value).ok(),
        _ => None,
    }
}

/// Mirrors `COSDictionary.getNameAsString`, which accepts a name or a string.
fn dictionary_name_as_string(
    document: &Document,
    dictionary: &Dictionary,
    key: &[u8],
) -> Option<String> {
    let value = dictionary.get(key).ok()?;
    let (_, value) = document.dereference(value).ok()?;
    match value {
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::String(_, _) => lopdf::decode_text_string(value).ok(),
        _ => None,
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

// ---------------------------------------------------------------------------
// Text extraction
// ---------------------------------------------------------------------------

/// `PDPage.hasContents()` — the guard `PDFStreamEngine.processPage` applies
/// before a page produces any text at all.
///
/// The stream branch is the surprising one: `COSStream` does not override
/// `size()`, so it inherits `COSDictionary.size()` — the number of **dictionary
/// entries**, not a byte count. Every parsed content stream carries at least
/// `/Length`, so a stream entry effectively always passes, however empty its
/// payload. An array is judged on its element count without dereferencing the
/// elements, and anything else — including a missing entry — is `false`.
fn has_contents(document: &Document, page_id: ObjectId) -> bool {
    let Ok(page) = document.get_dictionary(page_id) else {
        return false;
    };
    let Ok(contents) = page.get(b"Contents") else {
        return false;
    };
    let Ok((_, contents)) = document.dereference(contents) else {
        return false;
    };
    match contents {
        Object::Stream(stream) => !stream.dict.is_empty(),
        Object::Array(array) => !array.is_empty(),
        _ => false,
    }
}

/// Text of one page, shaped the way `PDFTextStripper` shapes it.
///
/// A page that fails `has_contents` contributes the empty string, *not* a bare
/// separator: `PDFTextStripper` never reaches `writePage`/`writePageEnd` for it,
/// so it emits nothing whatsoever. That distinction inverts every count — an
/// empty document is 0 characters but 1 word and 1 paragraph, because
/// `Pattern.split("")` yields a single empty element.
fn page_text(document: &Document, page_number: u32, page_id: ObjectId) -> String {
    if !has_contents(document, page_id) {
        return String::new();
    }
    let raw = document
        .extract_text_with_limit(&[page_number], MAX_PAGE_CONTENT_BYTES)
        .unwrap_or_default();
    strip_to_pdfbox_lines(&raw)
}

/// Text of the whole document, matching `new PDFTextStripper().getText(doc)`,
/// which is the concatenation of the per-page renderings.
fn document_text(document: &Document) -> String {
    document
        .get_pages()
        .iter()
        .map(|(page_number, page_id)| page_text(document, *page_number, *page_id))
        .collect()
}

/// Reshapes lopdf's raw extraction into `PDFBox`'s line model.
///
/// `PDFTextStripper` writes one line separator after every line it emits plus
/// one for the page itself, and never emits an empty line — an empty page is
/// exactly one separator. lopdf instead emits a separator per `ET`/`T*`
/// regardless of whether any glyphs were shown, and starts a fresh chunk at
/// every `Tf`, so a page with several text objects gains blank lines that Java
/// never produces. Dropping the empty lines and re-terminating recovers Java's
/// character, word and paragraph counts for unrotated pages.
///
/// Not a full port, and the reason is worth recording precisely.
/// `PDFTextStripper.writePage` decides line breaks from glyph geometry, and
/// because `GetInfoOnPDF` constructs a bare `new PDFTextStripper()` it leaves
/// `sortByPosition` at its default `false`. In that mode `writePage` reads the
/// *unrotated* `TextPosition.getX/getY/getWidth/getHeight` instead of the
/// direction-adjusted `…DirAdj` accessors, and starts a new line whenever
/// `overlap(y, height, maxYForLine, maxHeightForLine)` fails. Two consequences
/// are visible on the committed fixtures:
///
/// * `TextPosition.getY()` is `pageHeight - translateY` only for an unrotated
///   page. On a `/Rotate 90` page `getXRot`/`getYLowerLeftRot` swap the axes, so
///   `getY()` becomes the *horizontal* pen position and the same-line test is
///   applied to the advance rather than to the baseline. It then breaks a line
///   every time a glyph advances further than its own height, and the single
///   `(Test PDF #1) Tj` in `testing/test_pdf_1.pdf` renders as six lines —
///   `1\nT\nest P\nD\nF\n #1\n`, 18 characters, 7 words, 6 paragraphs — where
///   this function yields two.
/// * On an unrotated page glyphs sharing a baseline are joined into one line
///   separated by a single space, so `crop_test.pdf`'s ruler labels collapse
///   from 50 lines to 33 (436 characters to 385).
///
/// Reproducing either needs the real layout engine: per-glyph advances (hence
/// the Standard 14 AFM widths as well as `/Widths` and `/W`), the glyph height
/// rule (`FontBBox` height / 2, or `CapHeight` when that is smaller and
/// non-zero), and `writePage`'s line/word/paragraph grouping.
fn strip_to_pdfbox_lines(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len() + 1);
    for line in raw.split('\n').filter(|line| !line.is_empty()) {
        output.push_str(line);
        output.push('\n');
    }
    if output.is_empty() {
        output.push('\n');
    }
    output
}

// ---------------------------------------------------------------------------
// java.util.regex.Pattern.split parity
// ---------------------------------------------------------------------------

/// Length of the separator starting at `at`, if one starts there.
type Separator = fn(&[u8], usize) -> Option<usize>;

/// `RegexPatternUtils.getWhitespacePattern()` — `\s+`.
fn whitespace_separator(bytes: &[u8], at: usize) -> Option<usize> {
    if !JAVA_WHITESPACE.contains(&bytes[at]) {
        return None;
    }
    let mut end = at + 1;
    while end < bytes.len() && JAVA_WHITESPACE.contains(&bytes[end]) {
        end += 1;
    }
    Some(end)
}

/// `RegexPatternUtils.getMultiFormatNewlinePattern()` — `\r\n|\r|\n`.
fn newline_separator(bytes: &[u8], at: usize) -> Option<usize> {
    match bytes[at] {
        b'\r' if bytes.get(at + 1) == Some(&b'\n') => Some(at + 2),
        b'\r' | b'\n' => Some(at + 1),
        _ => None,
    }
}

/// Number of elements `Pattern.split(input)` (limit 0) would return.
///
/// The three rules that matter and that a naive `split`/`filter` gets wrong:
/// a pattern that never matches yields the whole input as a single element
/// (so `""` counts as 1, not 0); a separator at offset 0 yields a leading
/// empty element; and only *trailing* empty elements are discarded, so blank
/// lines in the middle of a document still count.
fn java_split_len(text: &str, separator: Separator) -> usize {
    let bytes = text.as_bytes();
    let mut elements = 0usize;
    let mut trailing_empty = 0usize;
    let mut segment_start = 0usize;
    let mut cursor = 0usize;
    let mut matched = false;
    while cursor < bytes.len() {
        let Some(end) = separator(bytes, cursor) else {
            cursor += 1;
            continue;
        };
        matched = true;
        elements += 1;
        trailing_empty = if cursor == segment_start {
            trailing_empty + 1
        } else {
            0
        };
        segment_start = end;
        cursor = end;
    }
    if !matched {
        return 1;
    }
    elements += 1;
    if segment_start == bytes.len() {
        trailing_empty += 1;
    } else {
        trailing_empty = 0;
    }
    elements - trailing_empty
}

// ---------------------------------------------------------------------------
// Java value formatting parity
// ---------------------------------------------------------------------------

/// One field of a Java `ObjectNode`, retained in insertion order so the node's
/// `toString()` can be rebuilt exactly.
enum JavaJson {
    Bool(bool),
    Text(Option<String>),
    Float(f32),
}

impl JavaJson {
    fn to_value(&self) -> Value {
        match self {
            Self::Bool(value) => json!(value),
            Self::Text(None) => Value::Null,
            Self::Text(Some(text)) => Value::String(text.clone()),
            // Round-tripping through Java's shortest float rendering keeps the
            // parsed number identical to the one Jackson emits; widening the
            // f32 directly would leak binary noise (0.1f32 -> 0.10000000149).
            Self::Float(value) => java_float_to_string(*value)
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map_or(Value::Null, Value::Number),
        }
    }

    fn to_jackson(&self) -> String {
        match self {
            Self::Bool(value) => value.to_string(),
            Self::Text(None) => "null".to_owned(),
            Self::Text(Some(text)) => jackson_json_string(text),
            Self::Float(value) => java_float_to_string(*value),
        }
    }
}

/// Rebuilds `ObjectNode.toString()` — compact JSON in insertion order.
fn jackson_object(fields: &[(&'static str, JavaJson)]) -> String {
    let mut output = String::from("{");
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&jackson_json_string(name));
        output.push(':');
        output.push_str(&value.to_jackson());
    }
    output.push('}');
    output
}

/// Jackson's default string escaping: quote, backslash and C0 controls only,
/// with uppercase hex in the generic `\u00XX` form.
fn jackson_json_string(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 2);
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{8}' => output.push_str("\\b"),
            '\u{9}' => output.push_str("\\t"),
            '\u{a}' => output.push_str("\\n"),
            '\u{c}' => output.push_str("\\f"),
            '\u{d}' => output.push_str("\\r"),
            control if control < ' ' => {
                let _ = write!(output, "\\u{:04X}", u32::from(control));
            }
            other => output.push(other),
        }
    }
    output.push('"');
    output
}

/// Reproduces `java.lang.Float.toString`.
///
/// Java always prints a fractional digit (`612.0`, never `612`) and switches to
/// scientific notation outside `[1e-3, 1e7)`. Rust's `{}` does neither, and
/// `PDRectangle.toString()` puts these straight into the response, so the exact
/// rendering is observable.
fn java_float_to_string(value: f32) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value.is_infinite() {
        return format!("{sign}Infinity");
    }
    let magnitude = value.abs();
    if magnitude == 0.0 {
        return format!("{sign}0.0");
    }
    // Java picks the shortest decimal that round-trips, and when two of that
    // length are equidistant it takes the one whose last digit is even. Rust's
    // shortest rendering agrees on the length but breaks ties upward
    // (359427.125f32 -> 359427.13 where Java gives 359427.12), so take only the
    // digit count from it and re-render at that fixed precision, which does
    // round half to even.
    let shortest = format!("{magnitude:e}");
    let mut significant = shortest
        .split_once('e')
        .map_or(shortest.as_str(), |(mantissa, _)| mantissa)
        .replace('.', "")
        .len();
    // When the shortest round-tripping decimal has a single digit, the JDK
    // considers the two-digit decimals as well and renders whichever lies
    // closest to the float (`Double.toString`'s "if m >= 2 ... otherwise let T
    // be the decimals of length 1 or 2"). Only subnormals can actually take the
    // two-digit branch: one ulp there is wide enough that `1E-45` round-trips
    // even though the value is 1.4012985E-45, and Java prints `1.4E-45`. For
    // every normal float the two-digit form is the one-digit form with a
    // trailing zero, whose significand is a multiple of ten and therefore not a
    // decimal of length two at all — so `0.001` stays `0.001`.
    if significant < 2 {
        let two_digit = format!("{magnitude:.1e}");
        let padded_with_zero = two_digit
            .split_once('e')
            .is_some_and(|(mantissa, _)| mantissa.ends_with('0'));
        let round_trips = two_digit
            .parse::<f32>()
            .is_ok_and(|parsed| parsed.to_bits() == magnitude.to_bits());
        if round_trips && !padded_with_zero {
            significant = 2;
        }
    }
    let scientific = format!("{magnitude:.*e}", significant - 1);
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits = mantissa.replace('.', "");
    if (-3..7).contains(&exponent) {
        let body = if exponent < 0 {
            let leading_zeros = "0".repeat(usize::try_from(-exponent - 1).unwrap_or(0));
            format!("0.{leading_zeros}{digits}")
        } else {
            let point = usize::try_from(exponent + 1).unwrap_or(0);
            if digits.len() > point {
                format!("{}.{}", &digits[..point], &digits[point..])
            } else {
                format!("{digits}{}.0", "0".repeat(point - digits.len()))
            }
        };
        format!("{sign}{body}")
    } else {
        let fraction = if digits.len() > 1 { &digits[1..] } else { "0" };
        format!("{sign}{}.{fraction}E{exponent}", &digits[..1])
    }
}

/// `COSNumber.intValue()` on an integer: Java's narrowing cast keeps the low
/// 32 bits. A missing entry yields `COSDictionary.getInt`'s zero default.
#[allow(clippy::cast_possible_truncation, reason = "Java narrows the same way")]
fn java_int_value(value: Option<i64>) -> i32 {
    value.unwrap_or_default() as i32
}

/// `COSNumber.intValue()` on a real: Java truncates toward zero and clamps to
/// the `int` bounds, which is exactly what Rust's `as` does.
#[allow(
    clippy::cast_possible_truncation,
    reason = "Java truncates the same way"
)]
fn java_int_value_of_real(value: f32) -> i32 {
    value as i32
}

/// `java.lang.String.hashCode()`, over UTF-16 code units.
fn java_string_hash(text: &str) -> i32 {
    text.encode_utf16().fold(0i32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(i32::from(unit))
    })
}

/// Order in which `java.util.HashMap` iterates the given insertion-ordered
/// keys: ascending bucket index, insertion order within a bucket.
///
/// Bins are never treeified here — that needs eight keys colliding in a table
/// of at least 64, i.e. more than 48 distinct fonts on a single page.
fn java_hash_map_order(keys: &[String]) -> Vec<usize> {
    let mut capacity = 16usize;
    while keys.len() > capacity / 4 * 3 && capacity < 1 << 30 {
        capacity *= 2;
    }
    let mask = capacity - 1;
    let mut order = (0..keys.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| {
        let hash = java_string_hash(&keys[*index]).cast_unsigned();
        (hash ^ (hash >> 16)) as usize & mask
    });
    order
}

// ---------------------------------------------------------------------------
// Standard 14 font metrics
// ---------------------------------------------------------------------------

/// The three `PDFontDescriptor` values `GetInfoOnPDF` reads out of the
/// descriptor `PDFBox` synthesises from a Standard 14 AFM. `FontWeight` is
/// absent from every AFM, so it always renders as `0.0`.
#[derive(Clone, Copy)]
struct Standard14Metrics {
    flags: i32,
    italic_angle: f32,
    family: &'static str,
}

/// `Standard14Fonts.getMappedFontName` — every alias `PDFBox` recognises,
/// including the `CourierCourierNew` entry that exists upstream.
const STANDARD_14_ALIASES: [(&str, &str); 38] = [
    ("Arial", "Helvetica"),
    ("Arial,Bold", "Helvetica-Bold"),
    ("Arial,BoldItalic", "Helvetica-BoldOblique"),
    ("Arial,Italic", "Helvetica-Oblique"),
    ("Arial-BoldItalicMT", "Helvetica-BoldOblique"),
    ("Arial-BoldMT", "Helvetica-Bold"),
    ("Arial-ItalicMT", "Helvetica-Oblique"),
    ("ArialMT", "Helvetica"),
    ("Courier", "Courier"),
    ("Courier-Bold", "Courier-Bold"),
    ("Courier-BoldOblique", "Courier-BoldOblique"),
    ("Courier-Oblique", "Courier-Oblique"),
    ("CourierCourierNew", "Courier"),
    ("CourierNew", "Courier"),
    ("CourierNew,Bold", "Courier-Bold"),
    ("CourierNew,BoldItalic", "Courier-BoldOblique"),
    ("CourierNew,Italic", "Courier-Oblique"),
    ("Helvetica", "Helvetica"),
    ("Helvetica-Bold", "Helvetica-Bold"),
    ("Helvetica-BoldOblique", "Helvetica-BoldOblique"),
    ("Helvetica-Oblique", "Helvetica-Oblique"),
    ("Symbol", "Symbol"),
    ("Symbol,Bold", "Symbol"),
    ("Symbol,BoldItalic", "Symbol"),
    ("Symbol,Italic", "Symbol"),
    ("Times", "Times-Roman"),
    ("Times,Bold", "Times-Bold"),
    ("Times,BoldItalic", "Times-BoldItalic"),
    ("Times,Italic", "Times-Italic"),
    ("Times-Bold", "Times-Bold"),
    ("Times-BoldItalic", "Times-BoldItalic"),
    ("Times-Italic", "Times-Italic"),
    ("Times-Roman", "Times-Roman"),
    ("TimesNewRoman", "Times-Roman"),
    ("TimesNewRoman,Bold", "Times-Bold"),
    ("TimesNewRoman,BoldItalic", "Times-BoldItalic"),
    ("TimesNewRoman,Italic", "Times-Italic"),
    ("ZapfDingbats", "ZapfDingbats"),
];

/// Values read back out of `PDFBox` 3.0.7's bundled AFMs. Note that Courier is
/// reported as non-fixed-pitch (flags 32, not 33) and that the symbolic faces
/// use flags 4 — both are `PDFBox`'s own numbers, reproduced verbatim.
const STANDARD_14_METRICS: [(&str, i32, f32, &str); 14] = [
    ("Courier", 32, 0.0, "Courier"),
    ("Courier-Bold", 32, 0.0, "Courier"),
    ("Courier-BoldOblique", 32, -12.0, "Courier"),
    ("Courier-Oblique", 32, -12.0, "Courier"),
    ("Helvetica", 32, 0.0, "Helvetica"),
    ("Helvetica-Bold", 32, 0.0, "Helvetica"),
    ("Helvetica-BoldOblique", 32, -12.0, "Helvetica"),
    ("Helvetica-Oblique", 32, -12.0, "Helvetica"),
    ("Symbol", 4, 0.0, "Symbol"),
    ("Times-Bold", 32, 0.0, "Times"),
    ("Times-BoldItalic", 32, -15.0, "Times"),
    ("Times-Italic", 32, -15.5, "Times"),
    ("Times-Roman", 32, 0.0, "Times"),
    ("ZapfDingbats", 4, 0.0, "ZapfDingbats"),
];

/// `PDFBox` matches the base font name exactly — a subset prefix such as
/// `ABCDEF+Helvetica` is not stripped and yields no descriptor at all.
fn standard_14_metrics(base_font: &str) -> Option<Standard14Metrics> {
    let canonical = STANDARD_14_ALIASES
        .into_iter()
        .find(|(alias, _)| *alias == base_font)
        .map(|(_, canonical)| canonical)?;
    STANDARD_14_METRICS
        .into_iter()
        .find(|(name, _, _, _)| *name == canonical)
        .map(|(_, flags, italic_angle, family)| Standard14Metrics {
            flags,
            italic_angle,
            family,
        })
}

#[cfg(test)]
mod tests {
    use lopdf::{Document, Object, Stream, dictionary};

    use super::{
        JavaJson, basic_info, clip_to_media_box, document_text, format_box, has_contents,
        jackson_object, java_float_to_string, java_hash_map_order, java_split_len,
        java_string_hash, newline_separator, page_mode_name, page_orientation, standard_14_metrics,
        standard_page, strip_to_pdfbox_lines, whitespace_separator,
    };

    /// Builds a document whose pages carry exactly the given `/Contents` entry,
    /// so the `hasContents()` gate can be exercised in every shape Java
    /// distinguishes.
    fn document_with_contents(contents: &[Option<Object>]) -> Document {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let mut kids = Vec::new();
        for content in contents {
            let mut page = dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
            };
            if let Some(content) = content {
                page.set("Contents", content.clone());
            }
            kids.push(Object::Reference(document.add_object(page)));
        }
        let count = i64::try_from(kids.len()).unwrap_or_default();
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => kids,
                "Count" => count,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        document
    }

    fn first_page_has_contents(document: &Document) -> bool {
        document
            .get_pages()
            .values()
            .next()
            .is_some_and(|page_id| has_contents(document, *page_id))
    }

    fn text_stream(content: &str) -> Object {
        Object::Stream(Stream::new(dictionary! {}, content.as_bytes().to_vec()))
    }

    /// The exact `uniqueKey` `PDFBox` + Jackson produce for the two fonts in
    /// `testing/test_pdf_1.pdf`, captured from a live `PDFBox` 3.0.7 run.
    const HELVETICA_KEY: &str = concat!(
        r#"{"IsEmbedded":false,"Name":"Helvetica","Subtype":"Font","ItalicAngle":0.0,"#,
        r#""IsItalic":false,"IsBold":false,"IsFixedPitch":false,"IsSerif":false,"#,
        r#""IsSymbolic":false,"IsScript":false,"IsNonsymbolic":true,"#,
        r#""FontFamily":"Helvetica","FontWeight":0.0}"#
    );
    const HELVETICA_BOLD_KEY: &str = concat!(
        r#"{"IsEmbedded":false,"Name":"Helvetica-Bold","Subtype":"Font","ItalicAngle":0.0,"#,
        r#""IsItalic":false,"IsBold":false,"IsFixedPitch":false,"IsSerif":false,"#,
        r#""IsSymbolic":false,"IsScript":false,"IsNonsymbolic":true,"#,
        r#""FontFamily":"Helvetica","FontWeight":0.0}"#
    );

    fn helvetica_node(name: &str) -> Vec<(&'static str, JavaJson)> {
        vec![
            ("IsEmbedded", JavaJson::Bool(false)),
            ("Name", JavaJson::Text(Some(name.to_owned()))),
            ("Subtype", JavaJson::Text(Some("Font".to_owned()))),
            ("ItalicAngle", JavaJson::Float(0.0)),
            ("IsItalic", JavaJson::Bool(false)),
            ("IsBold", JavaJson::Bool(false)),
            ("IsFixedPitch", JavaJson::Bool(false)),
            ("IsSerif", JavaJson::Bool(false)),
            ("IsSymbolic", JavaJson::Bool(false)),
            ("IsScript", JavaJson::Bool(false)),
            ("IsNonsymbolic", JavaJson::Bool(true)),
            ("FontFamily", JavaJson::Text(Some("Helvetica".to_owned()))),
            ("FontWeight", JavaJson::Float(0.0)),
        ]
    }

    #[test]
    fn renders_floats_the_way_java_does() {
        // Always a fractional digit, and no exponent inside [1e-3, 1e7).
        assert_eq!(java_float_to_string(612.0), "612.0");
        assert_eq!(java_float_to_string(0.0), "0.0");
        assert_eq!(java_float_to_string(-0.0), "-0.0");
        assert_eq!(java_float_to_string(-12.0), "-12.0");
        assert_eq!(java_float_to_string(-15.5), "-15.5");
        assert_eq!(java_float_to_string(499.9), "499.9");
        assert_eq!(java_float_to_string(631.99), "631.99");
        assert_eq!(java_float_to_string(499.921_88), "499.92188");
        assert_eq!(java_float_to_string(9_999_999.0), "9999999.0");
        assert_eq!(java_float_to_string(0.001), "0.001");
        // Scientific notation outside the plain-decimal window.
        assert_eq!(java_float_to_string(1e7), "1.0E7");
        assert_eq!(java_float_to_string(9.99e-4), "9.99E-4");
        assert_eq!(java_float_to_string(1e-4), "1.0E-4");
        // The smallest subnormal. `1E-45` round-trips, but Java's minimum of
        // two significant digits picks the far closer `1.4E-45`.
        assert_eq!(java_float_to_string(f32::from_bits(1)), "1.4E-45");
        assert_eq!(java_float_to_string(f32::MIN_POSITIVE / 1e7), "1.4E-45");
        assert_eq!(java_float_to_string(f32::from_bits(2)), "2.8E-45");
        // A normal float never takes the two-digit branch: its two-digit form
        // is just a trailing zero away, so these keep a single digit.
        assert_eq!(java_float_to_string(2.0), "2.0");
        // `Float.MIN_NORMAL`. Both `1.1754944E-38` and `1.17549435E-38` parse
        // back to it, so the JDK 19+ "fewest digits" rule takes the shorter.
        // A JDK 17 `Float.toString` still answers `1.17549435E-38` here — its
        // pre-JDK-19 algorithm was not always shortest — so it is *not* a valid
        // oracle for this function; the backend targets JDK 25.
        assert_eq!(java_float_to_string(f32::MIN_POSITIVE), "1.1754944E-38");
        assert_eq!(java_float_to_string(f32::MAX), "3.4028235E38");
        // Equidistant candidates resolve to the even last digit. This literal
        // *is* the f32 359427.125 exactly (24-bit mantissa, so no rounding);
        // it has to be spelled `359_427.13` because that is Rust's own shortest
        // round-tripping rendering of that bit pattern — which is precisely the
        // divergence, since Java renders the same float as `359427.12`.
        assert_eq!(java_float_to_string(359_427.13), "359427.12");
        assert_eq!(java_float_to_string(f32::NAN), "NaN");
        assert_eq!(java_float_to_string(f32::INFINITY), "Infinity");
        assert_eq!(java_float_to_string(f32::NEG_INFINITY), "-Infinity");
    }

    #[test]
    fn formats_boxes_like_pdrectangle_tostring() {
        assert_eq!(
            format_box([0.0, 0.0, 612.0, 792.0]),
            "[0.0,0.0,612.0,792.0]"
        );
        assert_eq!(
            format_box([0.0, 0.0, 499.921_88, 631.99]),
            "[0.0,0.0,499.92188,631.99]"
        );
    }

    #[test]
    fn clips_boxes_without_renormalising() {
        let media = [0.0, 0.0, 612.0, 792.0];
        // Compared through `format_box` rather than as raw `[f32; 4]`: the
        // rendered form is what the response actually carries, and it sidesteps
        // a direct float-array comparison.
        assert_eq!(
            format_box(clip_to_media_box([-50.0, -50.0, 700.0, 900.0], media)),
            format_box(media)
        );
        // A box entirely outside the media box stays inverted, as in Java.
        assert_eq!(
            format_box(clip_to_media_box([700.0, 900.0, 800.0, 1000.0], media)),
            "[700.0,900.0,612.0,792.0]"
        );
    }

    #[test]
    fn counts_split_elements_like_java() {
        let words = |text: &str| java_split_len(text, whitespace_separator);
        let paragraphs = |text: &str| java_split_len(text, newline_separator);
        // No match at all still yields one element, even for the empty string.
        assert_eq!(words(""), 1);
        assert_eq!(paragraphs(""), 1);
        assert_eq!(words("abc"), 1);
        // Only trailing empty elements are dropped.
        assert_eq!(words("a b "), 2);
        assert_eq!(paragraphs("a\n"), 1);
        assert_eq!(paragraphs("\n"), 0);
        assert_eq!(words("\n"), 0);
        // A leading separator produces a leading empty element.
        assert_eq!(words(" leading space\n"), 3);
        assert_eq!(paragraphs("\na"), 2);
        // An interior blank line is a real element.
        assert_eq!(paragraphs("Hello world\nSecond line\n\nHello\nWorld\n"), 5);
        // CRLF is one separator, not two.
        assert_eq!(paragraphs("a\r\nb"), 2);
        assert_eq!(paragraphs("a\rb\nc"), 3);
        // Java's \s is ASCII-only: a no-break space is not whitespace.
        assert_eq!(words("a\u{a0}b"), 1);
        assert_eq!(words("a\u{b}b\u{c}c"), 3);
        // A whitespace-only string splits away to nothing.
        assert_eq!(words("   "), 0);
        assert_eq!(paragraphs("   \n"), 1);
    }

    #[test]
    fn reshapes_extracted_text_into_pdfbox_lines() {
        // lopdf's spurious separators around empty text objects disappear.
        assert_eq!(
            strip_to_pdfbox_lines("\n\n1\n\nTest PDF #1\n"),
            "1\nTest PDF #1\n"
        );
        assert_eq!(strip_to_pdfbox_lines("Page 1\n"), "Page 1\n");
        // A page with no text is still one separator, never the empty string.
        assert_eq!(strip_to_pdfbox_lines(""), "\n");
        assert_eq!(strip_to_pdfbox_lines("\n\n\n"), "\n");
        // Lines of blanks are real lines and survive.
        assert_eq!(strip_to_pdfbox_lines("   \n"), "   \n");
    }

    #[test]
    fn gates_page_text_on_pdpage_has_contents() {
        // `COSStream` inherits `COSDictionary.size()`, which counts dictionary
        // entries — so a stream passes the gate on the strength of its
        // `/Length` alone, even with a completely empty payload.
        assert!(!first_page_has_contents(&document_with_contents(&[None])));
        assert!(first_page_has_contents(&document_with_contents(&[Some(
            text_stream("")
        )])));
        assert!(first_page_has_contents(&document_with_contents(&[Some(
            text_stream("BT ET")
        )])));
        // A stream whose dictionary really is empty is the one shape that fails.
        let mut bare = Stream::new(dictionary! {}, Vec::new());
        bare.dict.remove(b"Length");
        assert!(!first_page_has_contents(&document_with_contents(&[Some(
            Object::Stream(bare)
        )])));
        // An array is judged purely on its element count; the elements are not
        // dereferenced, so even a dangling reference counts as contents.
        assert!(!first_page_has_contents(&document_with_contents(&[Some(
            Object::Array(Vec::new())
        )])));
        assert!(first_page_has_contents(&document_with_contents(&[Some(
            Object::Array(vec![Object::Reference((999, 0))])
        )])));
        // Anything that is neither a stream nor an array is "no contents".
        assert!(!first_page_has_contents(&document_with_contents(&[Some(
            Object::Null
        )])));
        assert!(!first_page_has_contents(&document_with_contents(&[Some(
            Object::Integer(1)
        )])));
    }

    #[test]
    fn a_contentless_page_emits_nothing_not_even_a_separator() {
        // `PDFStreamEngine.processPage` skips a page whose `hasContents()` is
        // false, so `PDFTextStripper` never reaches `writePageEnd` for it and
        // the page contributes the empty string. Forcing a separator here
        // inverts every count, because `Pattern.split("")` returns one empty
        // element: Java answers 0 characters but 1 word and 1 paragraph.
        let empty = document_with_contents(&[None]);
        assert_eq!(document_text(&empty), "");
        let info = basic_info(&empty, 0);
        assert_eq!(info["CharacterCount"], 0);
        assert_eq!(info["WordCount"], 1);
        assert_eq!(info["ParagraphCount"], 1);

        // A page that *does* have contents but shows no glyphs is still exactly
        // one separator, which inverts the counts the other way.
        let blank = document_with_contents(&[Some(text_stream("BT ET"))]);
        assert_eq!(document_text(&blank), "\n");
        let info = basic_info(&blank, 0);
        assert_eq!(info["CharacterCount"], 1);
        assert_eq!(info["WordCount"], 0);
        assert_eq!(info["ParagraphCount"], 0);

        // Only the contentless pages drop out of a mixed document.
        let mixed = document_with_contents(&[Some(text_stream("BT ET")), None]);
        assert_eq!(document_text(&mixed), "\n");
    }

    #[test]
    fn rebuilds_jackson_dedup_keys() {
        assert_eq!(jackson_object(&helvetica_node("Helvetica")), HELVETICA_KEY);
        assert_eq!(
            jackson_object(&helvetica_node("Helvetica-Bold")),
            HELVETICA_BOLD_KEY
        );
        assert_eq!(
            jackson_object(&[
                ("Name", JavaJson::Text(None)),
                ("Q", JavaJson::Text(Some("a\"b\\c\u{1}".to_owned()))),
            ]),
            r#"{"Name":null,"Q":"a\"b\\c\u0001"}"#
        );
    }

    #[test]
    fn matches_java_string_hashes() {
        assert_eq!(java_string_hash(""), 0);
        assert_eq!(java_string_hash("Helvetica"), -816_292_751);
        assert_eq!(java_string_hash("\u{e9}\u{e8}"), 7_455);
        // A supplementary-plane char hashes as its two surrogates, not one char.
        assert_eq!(java_string_hash("\u{1f600}"), 1_772_899);
        // Captured from the live Java run over testing/test_pdf_1.pdf.
        assert_eq!(java_string_hash(HELVETICA_KEY), 833_243_366);
        assert_eq!(java_string_hash(HELVETICA_BOLD_KEY), -995_904_444);
    }

    #[test]
    fn reproduces_java_hash_map_iteration_order() {
        // Java inserts Helvetica first but iterates Helvetica-Bold first,
        // because their bucket indices are 12 and 7.
        let keys = vec![HELVETICA_KEY.to_owned(), HELVETICA_BOLD_KEY.to_owned()];
        assert_eq!(java_hash_map_order(&keys), vec![1, 0]);
        // Same key twice keeps insertion order within the bucket.
        let repeated = vec![HELVETICA_KEY.to_owned(), HELVETICA_KEY.to_owned()];
        assert_eq!(java_hash_map_order(&repeated), vec![0, 1]);
        assert!(java_hash_map_order(&[]).is_empty());
    }

    #[test]
    fn synthesises_standard_14_descriptors() -> Result<(), Box<dyn std::error::Error>> {
        let face = |name: &str| standard_14_metrics(name).ok_or("no Standard 14 face");
        let helvetica = face("Helvetica")?;
        assert_eq!(helvetica.flags, 32);
        assert_eq!(helvetica.family, "Helvetica");
        assert!((helvetica.italic_angle - 0.0).abs() < f32::EPSILON);
        // Aliases resolve to the canonical face's metrics.
        let arial = face("Arial,BoldItalic")?;
        assert!((arial.italic_angle - -12.0).abs() < f32::EPSILON);
        assert_eq!(arial.family, "Helvetica");
        let times_italic = face("TimesNewRoman,Italic")?;
        assert!((times_italic.italic_angle - -15.5).abs() < f32::EPSILON);
        assert_eq!(times_italic.family, "Times");
        // The symbolic faces carry flags 4, and Courier is *not* fixed-pitch.
        assert_eq!(face("ZapfDingbats")?.flags, 4);
        assert_eq!(face("Symbol")?.flags, 4);
        assert_eq!(face("Courier")?.flags, 32);
        // A subset prefix is not stripped, so no descriptor is synthesised.
        assert!(standard_14_metrics("ABCDEF+Helvetica").is_none());
        assert!(standard_14_metrics("Nope-XYZ").is_none());
        assert!(standard_14_metrics("").is_none());
        Ok(())
    }

    #[test]
    fn renders_java_json_values() {
        assert_eq!(JavaJson::Float(0.0).to_value(), serde_json::json!(0.0));
        // 0.1f32 must not leak its f64 widening (0.10000000149011612).
        assert_eq!(JavaJson::Float(0.1).to_value(), serde_json::json!(0.1));
        assert_eq!(JavaJson::Text(None).to_value(), serde_json::Value::Null);
        assert_eq!(
            JavaJson::Float(f32::NAN).to_value(),
            serde_json::Value::Null
        );
    }

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
