use std::{collections::BTreeMap, path::Path};

use chrono::{Local, NaiveDateTime, TimeZone};
use lopdf::{Dictionary, Document, Object, ObjectId};
use thiserror::Error;

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

fn apply_custom_metadata(info: &mut Dictionary, options: &MetadataOptions) {
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
    let offset_seconds = local.offset().local_minus_utc();
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let offset_minutes = offset_seconds.unsigned_abs() / 60;
    Some(format!(
        "D:{}{sign}{:02}'{:02}'",
        naive.format("%Y%m%d%H%M%S"),
        offset_minutes / 60,
        offset_minutes % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::pdf_date_from_java_request;

    #[test]
    fn accepts_only_the_java_request_date_format() {
        assert!(
            pdf_date_from_java_request("2026/07/15 12:34:56")
                .is_some_and(|date| date.starts_with("D:20260715123456"))
        );
        assert!(pdf_date_from_java_request("2026-07-15").is_none());
        assert!(pdf_date_from_java_request("undefined").is_none());
    }
}
