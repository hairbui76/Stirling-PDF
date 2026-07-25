use std::{collections::BTreeMap, path::Path};

use chrono::{Local, NaiveDateTime, TimeZone};
use lopdf::{Dictionary, Document, Object, ObjectId};
use thiserror::Error;

use crate::runtime_metrics::application_version;

#[derive(Debug, Default)]
pub struct MetadataOptions {
    pub delete_all: bool,
    pub author: Option<String>,
    pub creation_date: Option<String>,
    pub creator: Option<String>,
    pub keywords: Option<String>,
    pub modification_date: Option<String>,
    pub producer: Option<String>,
    pub subject: Option<String>,
    pub title: Option<String>,
    pub trapped: Option<String>,
    pub all_request_params: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write updated metadata: {0}")]
    Write(#[from] std::io::Error),
}

/// Applies the metadata written by Java's `CustomPDFDocumentFactory` to a
/// newly-created document in the default, non-Pro configuration.
pub(crate) fn apply_default_new_document_metadata(document: &mut Document) {
    replace_info_dictionary(document, Dictionary::new(), None, None);
}

/// Applies Java's default metadata policy when an existing document is loaded
/// for mutation.
///
/// Custom Info keys remain intact. Existing creator and creation date remain
/// intact when the date is valid, while producer is always rewritten to the
/// Stirling label and a missing modification date receives the current time.
pub(crate) fn apply_default_loaded_document_metadata(document: &mut Document) {
    let has_creation_date = document_info_date(document, b"CreationDate").is_some();
    let has_modification_date = document_info_date(document, b"ModDate").is_some();
    let mut info = document_info_dictionary(document)
        .cloned()
        .unwrap_or_default();
    for key in [b"Title".as_slice(), b"Author", b"Subject", b"Keywords"] {
        if let Some(value) = document_info_text(document, key) {
            info.set(key, Object::string_literal(value));
        } else {
            info.remove(key);
        }
    }
    let now = current_pdf_date();
    let label = format!("Stirling-PDF v{}", application_version());
    if !has_creation_date {
        info.set("Creator", Object::string_literal(label.as_str()));
        info.set("CreationDate", Object::string_literal(now.as_str()));
    }
    info.set("Producer", Object::string_literal(label));
    if !has_modification_date {
        info.set("ModDate", Object::string_literal(now));
    }
    let info_id = document.add_object(info);
    document.trailer.set("Info", info_id);
}

/// Rebuilds the Info dictionary as Java does when creating a new document
/// based on an existing PDF.
///
/// Standard descriptive fields and valid source dates are retained. Creator
/// and producer are replaced with the current Stirling label, missing dates
/// receive the current time, and non-standard Info entries are discarded.
pub(crate) fn normalize_rebuilt_document_metadata(document: &mut Document) {
    let retained = retained_rebuilt_metadata(document);
    replace_info_dictionary(
        document,
        retained.info,
        retained.creation_date.as_deref(),
        retained.modification_date.as_deref(),
    );
}

/// Applies Java's fresh-document metadata policy to `document` using standard
/// fields read from a separate source document.
pub(crate) fn normalize_rebuilt_document_metadata_from_source(
    document: &mut Document,
    source: &Document,
) {
    let retained = retained_rebuilt_metadata(source);
    replace_info_dictionary(
        document,
        retained.info,
        retained.creation_date.as_deref(),
        retained.modification_date.as_deref(),
    );
}

struct RetainedRebuiltMetadata {
    info: Dictionary,
    creation_date: Option<String>,
    modification_date: Option<String>,
}

fn retained_rebuilt_metadata(document: &Document) -> RetainedRebuiltMetadata {
    let mut retained = Dictionary::new();
    for key in [b"Title".as_slice(), b"Author", b"Subject", b"Keywords"] {
        if let Some(value) = document_info_text(document, key) {
            retained.set(key, Object::string_literal(value));
        }
    }
    let creation_date = document_info_date(document, b"CreationDate");
    let modification_date = document_info_date(document, b"ModDate");
    RetainedRebuiltMetadata {
        info: retained,
        creation_date,
        modification_date,
    }
}

fn replace_info_dictionary(
    document: &mut Document,
    mut info: Dictionary,
    creation_date: Option<&str>,
    modification_date: Option<&str>,
) {
    let now = current_pdf_date();
    let label = format!("Stirling-PDF v{}", application_version());
    info.set("Creator", Object::string_literal(label.as_str()));
    info.set("Producer", Object::string_literal(label));
    info.set(
        "CreationDate",
        Object::string_literal(creation_date.unwrap_or(&now)),
    );
    info.set(
        "ModDate",
        Object::string_literal(modification_date.unwrap_or(&now)),
    );
    let info_id = document.add_object(info);
    document.trailer.set("Info", info_id);
}

pub(crate) fn document_info_text(document: &Document, key: &[u8]) -> Option<String> {
    let info = document_info_dictionary(document)?;
    let (_, value) = document.dereference(info.get(key).ok()?).ok()?;
    lopdf::decode_text_string(value).ok()
}

fn document_info_date(document: &Document, key: &[u8]) -> Option<String> {
    let info = document_info_dictionary(document)?;
    let (_, value) = document.dereference(info.get(key).ok()?).ok()?;
    value.as_datetime()?;
    lopdf::decode_text_string(value).ok()
}

pub(crate) fn document_info_dictionary(document: &Document) -> Option<&Dictionary> {
    let (_, info) = document
        .dereference(document.trailer.get(b"Info").ok()?)
        .ok()?;
    info.as_dict().ok()
}

fn current_pdf_date() -> String {
    let now = Local::now();
    format_pdf_date_with_offset(&now.naive_local(), now.offset().local_minus_utc())
}

/// Updates the PDF Info dictionary and catalog metadata entries.
///
/// # Errors
///
/// Returns [`MetadataError`] when the input cannot be parsed or the output
/// cannot be written.
pub fn update_metadata_to_file(
    input_path: &Path,
    filename: &str,
    options: &MetadataOptions,
    output_path: &Path,
) -> Result<(), MetadataError> {
    let mut document = Document::load(input_path).map_err(|source| MetadataError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let info_id = ensure_info_dictionary(&mut document)?;

    if options.delete_all {
        let info = document.get_dictionary_mut(info_id)?;
        let keys = info.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        for key in keys {
            info.remove(&key);
        }
        let catalog = document.catalog_mut()?;
        catalog.remove(b"Metadata");
        catalog.remove(b"PieceInfo");
    } else {
        apply_custom_metadata(document.get_dictionary_mut(info_id)?, options);
    }

    let info = document.get_dictionary_mut(info_id)?;
    set_text(info, b"Author", normalized(options.author.as_deref()));
    set_text(info, b"Creator", normalized(options.creator.as_deref()));
    set_text(info, b"Keywords", normalized(options.keywords.as_deref()));
    set_text(info, b"Producer", normalized(options.producer.as_deref()));
    set_text(info, b"Subject", normalized(options.subject.as_deref()));
    set_text(info, b"Title", normalized(options.title.as_deref()));
    set_pdf_date(
        info,
        b"CreationDate",
        normalized(options.creation_date.as_deref()),
    );
    set_pdf_date(
        info,
        b"ModDate",
        normalized(options.modification_date.as_deref()),
    );
    set_trapped(info, normalized(options.trapped.as_deref()));

    document.save(output_path)?;
    Ok(())
}

/// Sets only the Stirling classification entry in the PDF Info dictionary.
///
/// Existing standard and custom metadata is preserved byte-for-byte at the
/// dictionary-value level; this helper intentionally does not apply the
/// general metadata endpoint's empty-field semantics.
///
/// # Errors
///
/// Returns [`MetadataError`] when the input cannot be parsed or the updated PDF
/// cannot be written.
pub fn set_classification_metadata_to_file(
    input_path: &Path,
    filename: &str,
    classification: &str,
    output_path: &Path,
) -> Result<(), MetadataError> {
    let mut document = Document::load(input_path).map_err(|source| MetadataError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let info_id = ensure_info_dictionary(&mut document)?;
    document.get_dictionary_mut(info_id)?.set(
        "StirlingPDFClassification",
        Object::string_literal(classification),
    );
    document.save(output_path)?;
    Ok(())
}

fn ensure_info_dictionary(document: &mut Document) -> Result<ObjectId, lopdf::Error> {
    let existing = document.trailer.get(b"Info").ok().cloned();
    if let Some(Object::Reference(info_id)) = existing {
        document.get_dictionary(info_id)?;
        return Ok(info_id);
    }
    let dictionary = match existing {
        Some(Object::Dictionary(dictionary)) => dictionary,
        _ => Dictionary::new(),
    };
    let info_id = document.add_object(dictionary);
    document.trailer.set("Info", info_id);
    Ok(info_id)
}

pub(crate) fn apply_custom_metadata(info: &mut Dictionary, options: &MetadataOptions) {
    for (key, value) in &options.all_request_params {
        if !is_standard_key(key) && !key.contains("customKey") && !key.contains("customValue") {
            info.set(key.as_bytes(), Object::string_literal(value.as_str()));
        } else if key.contains("customKey") {
            let suffix: String = key.chars().filter(char::is_ascii_digit).collect();
            let Some(custom_value) = options
                .all_request_params
                .get(&format!("customValue{suffix}"))
            else {
                continue;
            };
            if !value.is_empty() {
                info.set(
                    value.as_bytes(),
                    Object::string_literal(custom_value.as_str()),
                );
            }
        }
    }
}

fn is_standard_key(key: &str) -> bool {
    [
        "Author",
        "CreationDate",
        "Creator",
        "Keywords",
        "modificationDate",
        "Producer",
        "Subject",
        "Title",
        "Trapped",
    ]
    .iter()
    .any(|standard| key.eq_ignore_ascii_case(standard))
}

fn normalized(value: Option<&str>) -> Option<&str> {
    value.filter(|value| *value != "undefined")
}

fn set_text(info: &mut Dictionary, key: &[u8], value: Option<&str>) {
    if let Some(value) = value {
        info.set(key, Object::string_literal(value));
    } else {
        info.remove(key);
    }
}

fn set_trapped(info: &mut Dictionary, value: Option<&str>) {
    if let Some(value) = value {
        info.set("Trapped", Object::Name(value.as_bytes().to_vec()));
    } else {
        info.remove(b"Trapped");
    }
}

fn set_pdf_date(info: &mut Dictionary, key: &[u8], value: Option<&str>) {
    let Some(date) = value.and_then(pdf_date_from_java_request) else {
        info.remove(key);
        return;
    };
    info.set(key, Object::string_literal(date));
}

fn pdf_date_from_java_request(value: &str) -> Option<String> {
    let naive = NaiveDateTime::parse_from_str(value.trim(), "%Y/%m/%d %H:%M:%S").ok()?;
    let local = Local
        .from_local_datetime(&naive)
        .single()
        .or_else(|| Local.from_local_datetime(&naive).earliest())?;
    Some(format_pdf_date_with_offset(
        &naive,
        local.offset().local_minus_utc(),
    ))
}

pub(crate) fn format_pdf_date_with_offset(naive: &NaiveDateTime, offset_seconds: i32) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let offset_minutes = offset_seconds.unsigned_abs() / 60;
    format!(
        "D:{}{sign}{:02}'{:02}'",
        naive.format("%Y%m%d%H%M%S"),
        offset_minutes / 60,
        offset_minutes % 60
    )
}

#[cfg(test)]
mod tests {
    use lopdf::{Document, Object, dictionary};

    use super::{
        apply_default_loaded_document_metadata, apply_default_new_document_metadata,
        document_info_dictionary, normalize_rebuilt_document_metadata, pdf_date_from_java_request,
    };
    use crate::runtime_metrics::application_version;

    #[test]
    fn accepts_only_the_java_request_date_format() {
        assert!(
            pdf_date_from_java_request("2026/07/15 12:34:56")
                .is_some_and(|date| date.starts_with("D:20260715123456"))
        );
        assert!(pdf_date_from_java_request("2026-07-15").is_none());
        assert!(pdf_date_from_java_request("undefined").is_none());
    }

    #[test]
    fn applies_default_stirling_metadata_to_a_fresh_document() -> Result<(), lopdf::Error> {
        let mut document = Document::with_version("1.7");
        apply_default_new_document_metadata(&mut document);

        let info = document_info_dictionary(&document)
            .ok_or_else(|| lopdf::Error::Syntax("missing Info dictionary".to_owned()))?;
        let label = format!("Stirling-PDF v{}", application_version());
        assert_eq!(info.get(b"Creator")?.as_str()?, label.as_bytes());
        assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
        assert!(info.get(b"CreationDate")?.as_datetime().is_some());
        assert!(info.get(b"ModDate")?.as_datetime().is_some());
        Ok(())
    }

    #[test]
    fn normalizes_rebuilt_metadata_like_the_java_document_factory() -> Result<(), lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let info_id = document.add_object(dictionary! {
            "Title" => Object::string_literal("Source title"),
            "Author" => Object::string_literal("Source author"),
            "Creator" => Object::string_literal("Old creator"),
            "Producer" => Object::string_literal("Old producer"),
            "CreationDate" => Object::string_literal("D:20240102030405+00'00'"),
            "ModDate" => Object::string_literal("not a PDF date"),
            "Custom" => Object::string_literal("discard me"),
        });
        document.trailer.set("Info", info_id);

        normalize_rebuilt_document_metadata(&mut document);

        let info = document_info_dictionary(&document)
            .ok_or_else(|| lopdf::Error::Syntax("missing Info dictionary".to_owned()))?;
        let label = format!("Stirling-PDF v{}", application_version());
        assert_eq!(info.get(b"Title")?.as_str()?, b"Source title");
        assert_eq!(info.get(b"Author")?.as_str()?, b"Source author");
        assert_eq!(info.get(b"Creator")?.as_str()?, label.as_bytes());
        assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
        assert_eq!(
            info.get(b"CreationDate")?.as_str()?,
            b"D:20240102030405+00'00'"
        );
        assert!(info.get(b"ModDate")?.as_datetime().is_some());
        assert!(info.get(b"Custom").is_err());
        Ok(())
    }

    #[test]
    fn loaded_metadata_preserves_creator_dates_and_custom_keys() -> Result<(), lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let info_id = document.add_object(dictionary! {
            "Title" => Object::string_literal("Source title"),
            "Creator" => Object::string_literal("Source creator"),
            "Producer" => Object::string_literal("Source producer"),
            "CreationDate" => Object::string_literal("D:20240102030405+00'00'"),
            "ModDate" => Object::string_literal("D:20240203040506+00'00'"),
            "Custom" => Object::string_literal("keep me"),
        });
        document.trailer.set("Info", info_id);

        apply_default_loaded_document_metadata(&mut document);

        let info = document_info_dictionary(&document)
            .ok_or_else(|| lopdf::Error::Syntax("missing Info dictionary".to_owned()))?;
        let label = format!("Stirling-PDF v{}", application_version());
        assert_eq!(info.get(b"Title")?.as_str()?, b"Source title");
        assert_eq!(info.get(b"Creator")?.as_str()?, b"Source creator");
        assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
        assert_eq!(
            info.get(b"CreationDate")?.as_str()?,
            b"D:20240102030405+00'00'"
        );
        assert_eq!(info.get(b"ModDate")?.as_str()?, b"D:20240203040506+00'00'");
        assert_eq!(info.get(b"Custom")?.as_str()?, b"keep me");
        Ok(())
    }
}
