use std::{collections::HashMap, path::Path};

use chrono::Local;
use lopdf::{Document, Object, ObjectId, StringFormat, dictionary};
use serde::Deserialize;
use thiserror::Error;

use crate::pdfium_backend::{
    DetectedTextBounds, PdfiumTextError, PdfiumTextLocationAttempt, try_locate_text_anchors,
};

const MAX_COMMENT_TEXT_UTF16_UNITS: usize = 100_000;
const ANCHOR_ICON_SIZE: f32 = 20.0;

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct CommentInput {
    page_index: i32,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    text: Option<String>,
    author: Option<String>,
    subject: Option<String>,
    anchor_text: Option<String>,
}

#[derive(Debug, Error)]
pub enum CommentError {
    #[error("comments must be a JSON array of CommentSpec objects: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("the configured PDFium runtime is unavailable: {details}")]
    PdfiumRuntime { details: String },
    #[error("could not resolve a comment text anchor: {0}")]
    Pdfium(#[from] PdfiumTextError),
    #[error("malformed PDF annotation structure: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write the commented PDF: {0}")]
    Write(std::io::Error),
}

/// Adds PDF Text annotations using the same validation and defaults as Java.
///
/// # Errors
///
/// Returns the number of valid annotations written, or [`CommentError`] for
/// invalid JSON, unreadable PDFs, explicitly configured but unavailable
/// `PDFium`, malformed annotation arrays, or output failures.
pub fn add_comments_to_file(
    input_path: &Path,
    filename: &str,
    comments_json: &str,
    output_path: &Path,
) -> Result<usize, CommentError> {
    let comments: Vec<Option<CommentInput>> = serde_json::from_str(comments_json)?;
    let (anchor_requests, anchor_request_indices) = anchor_requests(&comments);
    let anchor_locations = if anchor_requests.is_empty() {
        Vec::new()
    } else {
        match try_locate_text_anchors(input_path, filename, &anchor_requests)? {
            PdfiumTextLocationAttempt::Located(locations) => locations,
            PdfiumTextLocationAttempt::Unavailable {
                explicitly_configured: false,
                ..
            } => vec![None; anchor_requests.len()],
            PdfiumTextLocationAttempt::Unavailable {
                explicitly_configured: true,
                details,
            } => return Err(CommentError::PdfiumRuntime { details }),
        }
    };

    let mut document = Document::load(input_path).map_err(|source| CommentError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let page_ids: Vec<ObjectId> = document.get_pages().into_values().collect();
    let creation_date = pdf_date_now();
    let mut annotations_added = 0_usize;
    for (comment_index, comment) in comments.iter().enumerate() {
        let Some(comment) = comment else {
            continue;
        };
        let location = anchor_request_indices
            .get(&comment_index)
            .and_then(|request_index| anchor_locations.get(*request_index))
            .copied()
            .flatten();
        if add_comment(&mut document, &page_ids, comment, location, &creation_date)? {
            annotations_added = annotations_added.saturating_add(1);
        }
    }
    document.save(output_path).map_err(CommentError::Write)?;
    Ok(annotations_added)
}

fn anchor_requests(
    comments: &[Option<CommentInput>],
) -> (Vec<(usize, String)>, HashMap<usize, usize>) {
    let mut requests = Vec::new();
    let mut indices = HashMap::new();
    for (comment_index, comment) in comments.iter().enumerate() {
        let Some(comment) = comment else {
            continue;
        };
        let Some(anchor_text) = comment
            .anchor_text
            .as_deref()
            .filter(|anchor_text| !anchor_text.trim().is_empty())
        else {
            continue;
        };
        let Ok(page_index) = usize::try_from(comment.page_index) else {
            continue;
        };
        indices.insert(comment_index, requests.len());
        requests.push((page_index, anchor_text.to_owned()));
    }
    (requests, indices)
}

fn add_comment(
    document: &mut Document,
    page_ids: &[ObjectId],
    comment: &CommentInput,
    anchor: Option<DetectedTextBounds>,
    creation_date: &str,
) -> Result<bool, lopdf::Error> {
    let Some(text) = comment
        .text
        .as_deref()
        .filter(|text| !text.trim().is_empty())
        .filter(|text| text.encode_utf16().count() <= MAX_COMMENT_TEXT_UTF16_UNITS)
    else {
        return Ok(false);
    };
    let Ok(page_index) = usize::try_from(comment.page_index) else {
        return Ok(false);
    };
    let Some(page_id) = page_ids.get(page_index).copied() else {
        return Ok(false);
    };
    let [x, y, width, height] = anchor.map_or(
        [comment.x, comment.y, comment.width, comment.height],
        |bounds| {
            [
                bounds.x,
                bounds.y + bounds.height - ANCHOR_ICON_SIZE,
                ANCHOR_ICON_SIZE,
                ANCHOR_ICON_SIZE,
            ]
        },
    );
    if width <= 0.0 || height <= 0.0 {
        return Ok(false);
    }
    let author = non_blank_or(comment.author.as_deref(), "Stirling AI");
    let subject = non_blank_or(comment.subject.as_deref(), "Stirling AI Comment");
    let annotation_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Text",
        "Contents" => pdf_text_string(text),
        "Rect" => vec![
            Object::Real(x),
            Object::Real(y),
            Object::Real(x + width),
            Object::Real(y + height),
        ],
        "Subj" => pdf_text_string(subject),
        "T" => pdf_text_string(author),
        "C" => vec![Object::Real(1.0), Object::Real(0.95), Object::Real(0.4)],
        "CreationDate" => Object::string_literal(creation_date),
        "CA" => Object::Real(0.9),
        "Name" => Object::Name(b"Comment".to_vec()),
    });
    let mut annotations = document
        .get_dictionary(page_id)?
        .get(b"Annots")
        .ok()
        .and_then(|annotations| document.dereference(annotations).ok())
        .and_then(|(_, annotations)| annotations.as_array().ok())
        .cloned()
        .unwrap_or_default();
    annotations.push(Object::Reference(annotation_id));
    document
        .get_dictionary_mut(page_id)?
        .set("Annots", annotations);
    Ok(true)
}

fn non_blank_or<'a>(value: Option<&'a str>, fallback: &'a str) -> &'a str {
    value
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(fallback)
}

fn pdf_text_string(value: &str) -> Object {
    let mut bytes = vec![0xFE, 0xFF];
    for code_unit in value.encode_utf16() {
        bytes.extend_from_slice(&code_unit.to_be_bytes());
    }
    Object::String(bytes, StringFormat::Hexadecimal)
}

fn pdf_date_now() -> String {
    let now = Local::now();
    let offset_seconds = now.offset().local_minus_utc();
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let offset_minutes = offset_seconds.unsigned_abs() / 60;
    format!(
        "D:{}{sign}{:02}'{:02}'",
        now.format("%Y%m%d%H%M%S"),
        offset_minutes / 60,
        offset_minutes % 60
    )
}

#[cfg(test)]
mod tests {
    use super::non_blank_or;

    #[test]
    fn applies_java_author_and_subject_defaults() {
        assert_eq!(non_blank_or(None, "fallback"), "fallback");
        assert_eq!(non_blank_or(Some("  "), "fallback"), "fallback");
        assert_eq!(non_blank_or(Some("author"), "fallback"), "author");
    }
}
