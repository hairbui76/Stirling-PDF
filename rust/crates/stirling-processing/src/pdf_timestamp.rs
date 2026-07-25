use std::{fs, io::Read as _, path::Path, time::Duration};

use bcder::{Integer, Mode, OctetString, decode::Constructed, encode::Values};
use cryptographic_message_syntax::{
    Bytes,
    asn1::{
        rfc3161::{
            MessageImprint, OID_CONTENT_TYPE_TST_INFO, PkiStatus, TimeStampReq, TimeStampResp,
            TstInfo,
        },
        rfc5652::{OID_ID_SIGNED_DATA, SignedData as CmsSignedData},
    },
};
use lopdf::{Dictionary, IncrementalDocument, Object, ObjectId, Stream, StringFormat, dictionary};
use rand::RngExt as _;
use reqwest::blocking::{Client, Response};
use thiserror::Error;
use x509_certificate::DigestAlgorithm;

const INITIAL_SIGNATURE_RESERVE_BYTES: usize = 32 * 1024;
const MAX_SIGNATURE_RESERVE_BYTES: usize = 1024 * 1024;
const BYTE_RANGE_NUMBER_WIDTH: usize = 10;
const TSA_RESPONSE_LIMIT_BYTES: u64 = 1024 * 1024;
const TSA_ERROR_BODY_LIMIT_BYTES: u64 = 2048;

#[derive(Debug, Error)]
pub enum TimestampError {
    #[error("could not read PDF: {0}")]
    Read(#[from] std::io::Error),
    #[error("could not parse or incrementally write PDF: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("PDF must contain at least one page")]
    EmptyDocument,
    #[error("could not create the PDF timestamp placeholder: {0}")]
    Placeholder(String),
    #[error("timestamp byte range exceeds the PDF-compatible limit")]
    ByteRangeTooLarge,
    #[error("invalid TSA URL: {0}")]
    InvalidTsaUrl(String),
    #[error("could not contact TSA: {0}")]
    TsaRequest(String),
    #[error("TSA response exceeds maximum allowed size of {TSA_RESPONSE_LIMIT_BYTES} bytes")]
    TsaResponseTooLarge,
    #[error("TSA server returned HTTP {status} for URL: {url}{detail}")]
    TsaHttp {
        status: u16,
        url: String,
        detail: String,
    },
    #[error("invalid TSA response: {0}")]
    TsaResponse(String),
    #[error("timestamp token requires more than {MAX_SIGNATURE_RESERVE_BYTES} bytes")]
    TimestampTooLarge,
}

struct PreparedTimestamp {
    bytes: Vec<u8>,
    contents_start: usize,
    contents_end: usize,
    signed_content: Vec<u8>,
}

/// Adds an RFC 3161 document timestamp as an incremental PDF revision.
///
/// The TSA only receives a SHA-256 digest of the document's PDF signature byte
/// ranges. The output retains every input byte, which is required for existing
/// signature validity.
///
/// # Errors
///
/// Returns an error when the source PDF cannot be incrementally updated, the
/// TSA cannot provide a matching RFC 3161 token, or the output cannot be
/// written.
pub fn timestamp_pdf_to_file(
    input_path: &Path,
    output_path: &Path,
    tsa_url: &str,
) -> Result<(), TimestampError> {
    let source = fs::read(input_path)?;
    let parsed_url = reqwest::Url::parse(tsa_url)
        .map_err(|error| TimestampError::InvalidTsaUrl(error.to_string()))?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return Err(TimestampError::InvalidTsaUrl(
            "URL scheme must be http or https".to_owned(),
        ));
    }

    let mut reserve_bytes = INITIAL_SIGNATURE_RESERVE_BYTES;
    loop {
        let prepared = prepare_timestamp_pdf(&source, reserve_bytes)?;
        let timestamp_token = request_timestamp_token(&prepared.signed_content, &parsed_url)?;
        if timestamp_token.len() <= reserve_bytes {
            let output = apply_timestamp_token(prepared, &timestamp_token)?;
            fs::write(output_path, output)?;
            return Ok(());
        }

        reserve_bytes = reserve_bytes
            .checked_mul(2)
            .filter(|capacity| *capacity <= MAX_SIGNATURE_RESERVE_BYTES)
            .ok_or(TimestampError::TimestampTooLarge)?;
    }
}

fn prepare_timestamp_pdf(
    source: &[u8],
    reserve_bytes: usize,
) -> Result<PreparedTimestamp, TimestampError> {
    let mut incremental: IncrementalDocument = source.try_into()?;
    let first_page_id = *incremental
        .get_prev_documents()
        .get_pages()
        .values()
        .next()
        .ok_or(TimestampError::EmptyDocument)?;
    let root_id = incremental
        .get_prev_documents()
        .trailer
        .get(b"Root")?
        .as_reference()?;

    incremental.opt_clone_object_to_new_document(root_id)?;
    incremental.opt_clone_object_to_new_document(first_page_id)?;

    let appearance_id = incremental.new_document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 0.into(), 0.into()],
            "Resources" => Dictionary::new(),
        },
        Vec::new(),
    ));
    let signature_id = incremental.new_document.add_object(dictionary! {
        "Type" => "DocTimeStamp",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "ETSI.RFC3161",
        "M" => Object::string_literal(pdf_date_now()),
        "ByteRange" => vec![
            0.into(),
            1_000_000_000_i64.into(),
            1_000_000_000_i64.into(),
            1_000_000_000_i64.into(),
        ],
        "Contents" => Object::String(vec![0; reserve_bytes], StringFormat::Hexadecimal),
    });
    let widget_id = incremental.new_document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "FT" => "Sig",
        "T" => Object::string_literal("DocTimeStamp"),
        "Rect" => vec![0.into(), 0.into(), 0.into(), 0.into()],
        "P" => first_page_id,
        "F" => 4,
        "AP" => dictionary! { "N" => appearance_id },
        "V" => signature_id,
    });

    append_signature_field(&mut incremental, root_id, widget_id)?;
    append_widget_to_page(&mut incremental, first_page_id, widget_id)?;

    let mut bytes = Vec::new();
    incremental.save_to(&mut bytes)?;
    let (contents_start, contents_end) =
        locate_signature_contents(&bytes, signature_id, reserve_bytes)?;
    let byte_range = [
        0,
        contents_start,
        contents_end
            .checked_add(1)
            .ok_or(TimestampError::ByteRangeTooLarge)?,
        bytes
            .len()
            .checked_sub(
                contents_end
                    .checked_add(1)
                    .ok_or(TimestampError::ByteRangeTooLarge)?,
            )
            .ok_or(TimestampError::ByteRangeTooLarge)?,
    ];
    patch_byte_range(&mut bytes, signature_id, byte_range)?;
    let signed_content = signed_content(&bytes, byte_range)?;

    Ok(PreparedTimestamp {
        bytes,
        contents_start,
        contents_end,
        signed_content,
    })
}

fn append_signature_field(
    incremental: &mut IncrementalDocument,
    root_id: ObjectId,
    widget_id: ObjectId,
) -> Result<(), TimestampError> {
    let acroform_id = acquire_acroform(incremental, root_id)?;
    let fields_reference = {
        let acroform = incremental
            .new_document
            .get_object(acroform_id)?
            .as_dict()?;
        acroform
            .get(b"Fields")
            .ok()
            .and_then(|fields| fields.as_reference().ok())
    };

    if let Some(fields_id) = fields_reference {
        incremental.opt_clone_object_to_new_document(fields_id)?;
        incremental
            .new_document
            .get_object_mut(fields_id)?
            .as_array_mut()?
            .push(Object::Reference(widget_id));
    } else {
        let acroform = incremental
            .new_document
            .get_object_mut(acroform_id)?
            .as_dict_mut()?;
        match acroform.get_mut(b"Fields") {
            Ok(fields) => fields.as_array_mut()?.push(Object::Reference(widget_id)),
            Err(_) => acroform.set("Fields", vec![Object::Reference(widget_id)]),
        }
    }

    let acroform = incremental
        .new_document
        .get_object_mut(acroform_id)?
        .as_dict_mut()?;
    let signature_flags = acroform
        .get(b"SigFlags")
        .ok()
        .and_then(|value| value.as_i64().ok())
        .unwrap_or(0)
        | 3;
    acroform.set("SigFlags", signature_flags);
    Ok(())
}

fn acquire_acroform(
    incremental: &mut IncrementalDocument,
    root_id: ObjectId,
) -> Result<ObjectId, TimestampError> {
    let existing = {
        let catalog = incremental.new_document.get_object(root_id)?.as_dict()?;
        catalog.get(b"AcroForm").ok().cloned()
    };

    match existing {
        Some(Object::Reference(acroform_id)) => {
            incremental.opt_clone_object_to_new_document(acroform_id)?;
            Ok(acroform_id)
        }
        Some(Object::Dictionary(acroform)) => {
            let acroform_id = incremental.new_document.add_object(acroform);
            incremental
                .new_document
                .get_object_mut(root_id)?
                .as_dict_mut()?
                .set("AcroForm", acroform_id);
            Ok(acroform_id)
        }
        Some(_) => Err(TimestampError::Placeholder(
            "catalog AcroForm is not a dictionary".to_owned(),
        )),
        None => {
            let acroform_id = incremental
                .new_document
                .add_object(dictionary! { "Fields" => Vec::<Object>::new() });
            incremental
                .new_document
                .get_object_mut(root_id)?
                .as_dict_mut()?
                .set("AcroForm", acroform_id);
            Ok(acroform_id)
        }
    }
}

fn append_widget_to_page(
    incremental: &mut IncrementalDocument,
    page_id: ObjectId,
    widget_id: ObjectId,
) -> Result<(), TimestampError> {
    let annots_reference = {
        let page = incremental.new_document.get_object(page_id)?.as_dict()?;
        page.get(b"Annots")
            .ok()
            .and_then(|annots| annots.as_reference().ok())
    };

    if let Some(annots_id) = annots_reference {
        incremental.opt_clone_object_to_new_document(annots_id)?;
        incremental
            .new_document
            .get_object_mut(annots_id)?
            .as_array_mut()?
            .push(Object::Reference(widget_id));
    } else {
        let page = incremental
            .new_document
            .get_object_mut(page_id)?
            .as_dict_mut()?;
        match page.get_mut(b"Annots") {
            Ok(annots) => annots.as_array_mut()?.push(Object::Reference(widget_id)),
            Err(_) => page.set("Annots", vec![Object::Reference(widget_id)]),
        }
    }
    Ok(())
}

fn locate_signature_contents(
    pdf: &[u8],
    signature_id: ObjectId,
    reserve_bytes: usize,
) -> Result<(usize, usize), TimestampError> {
    let object_header = format!("{} {} obj", signature_id.0, signature_id.1);
    let object_start = find_subslice(pdf, object_header.as_bytes()).ok_or_else(|| {
        TimestampError::Placeholder("timestamp signature object was not written".to_owned())
    })?;
    let contents_key_end = find_subslice(&pdf[object_start..], b"/Contents")
        .map(|offset| object_start + offset + b"/Contents".len())
        .ok_or_else(|| {
            TimestampError::Placeholder("timestamp Contents placeholder was not written".to_owned())
        })?;
    let contents_start = pdf[contents_key_end..]
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .map(|offset| contents_key_end + offset)
        .filter(|offset| pdf.get(*offset) == Some(&b'<'))
        .ok_or_else(|| {
            TimestampError::Placeholder(
                "timestamp Contents placeholder is not hexadecimal".to_owned(),
            )
        })?;
    let hex_start = contents_start
        .checked_add(1)
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    let hex_length = reserve_bytes
        .checked_mul(2)
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    let contents_end = hex_start
        .checked_add(hex_length)
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    if pdf.get(contents_start) != Some(&b'<') || pdf.get(contents_end) != Some(&b'>') {
        return Err(TimestampError::Placeholder(
            "timestamp Contents placeholder has an unexpected length".to_owned(),
        ));
    }
    Ok((contents_start, contents_end))
}

fn patch_byte_range(
    pdf: &mut [u8],
    signature_id: ObjectId,
    byte_range: [usize; 4],
) -> Result<(), TimestampError> {
    if byte_range
        .iter()
        .skip(1)
        .any(|value| value.to_string().len() > BYTE_RANGE_NUMBER_WIDTH)
    {
        return Err(TimestampError::ByteRangeTooLarge);
    }
    let object_header = format!("{} {} obj", signature_id.0, signature_id.1);
    let object_start = find_subslice(pdf, object_header.as_bytes()).ok_or_else(|| {
        TimestampError::Placeholder("timestamp signature object was not written".to_owned())
    })?;
    let range_key_end = find_subslice(&pdf[object_start..], b"/ByteRange")
        .map(|offset| object_start + offset + b"/ByteRange".len())
        .ok_or_else(|| {
            TimestampError::Placeholder(
                "timestamp ByteRange placeholder was not written".to_owned(),
            )
        })?;
    let range_start = pdf[range_key_end..]
        .iter()
        .position(|value| !value.is_ascii_whitespace())
        .map(|offset| range_key_end + offset + 1)
        .filter(|offset| pdf.get(offset - 1) == Some(&b'['))
        .ok_or_else(|| {
            TimestampError::Placeholder(
                "timestamp ByteRange placeholder is not an array".to_owned(),
            )
        })?;
    let range_end = pdf[range_start..]
        .iter()
        .position(|value| *value == b']')
        .map(|offset| range_start + offset)
        .ok_or_else(|| {
            TimestampError::Placeholder("timestamp ByteRange placeholder is incomplete".to_owned())
        })?;
    let values = &mut pdf[range_start..range_end];
    let mut fields = values.split_mut(|value| *value == b' ').collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0] != b"0"
        || fields.iter().skip(1).any(|field| field.len() != 10)
    {
        return Err(TimestampError::Placeholder(
            "timestamp ByteRange placeholder has an unexpected format".to_owned(),
        ));
    }
    for (field, value) in fields.iter_mut().skip(1).zip(byte_range.iter().skip(1)) {
        let formatted = format!("{value:010}");
        field.copy_from_slice(formatted.as_bytes());
    }
    Ok(())
}

fn signed_content(pdf: &[u8], byte_range: [usize; 4]) -> Result<Vec<u8>, TimestampError> {
    let first_end = byte_range[0]
        .checked_add(byte_range[1])
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    let second_end = byte_range[2]
        .checked_add(byte_range[3])
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    let first = pdf.get(byte_range[0]..first_end).ok_or_else(|| {
        TimestampError::Placeholder("timestamp ByteRange is outside the PDF".to_owned())
    })?;
    let second = pdf.get(byte_range[2]..second_end).ok_or_else(|| {
        TimestampError::Placeholder("timestamp ByteRange is outside the PDF".to_owned())
    })?;
    let mut content = Vec::with_capacity(first.len().saturating_add(second.len()));
    content.extend_from_slice(first);
    content.extend_from_slice(second);
    Ok(content)
}

fn apply_timestamp_token(
    mut prepared: PreparedTimestamp,
    timestamp_token: &[u8],
) -> Result<Vec<u8>, TimestampError> {
    let hex_start = prepared
        .contents_start
        .checked_add(1)
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    let reserve_hex_length = prepared
        .contents_end
        .checked_sub(hex_start)
        .ok_or(TimestampError::ByteRangeTooLarge)?;
    let token_hex_length = timestamp_token
        .len()
        .checked_mul(2)
        .ok_or(TimestampError::TimestampTooLarge)?;
    if token_hex_length > reserve_hex_length {
        return Err(TimestampError::TimestampTooLarge);
    }
    for (index, byte) in timestamp_token.iter().enumerate() {
        let offset = hex_start + index * 2;
        prepared.bytes[offset] = hex_digit(byte >> 4);
        prepared.bytes[offset + 1] = hex_digit(byte & 0x0f);
    }
    Ok(prepared.bytes)
}

fn request_timestamp_token(
    content: &[u8],
    tsa_url: &reqwest::Url,
) -> Result<Vec<u8>, TimestampError> {
    let mut digest = DigestAlgorithm::Sha256.digester();
    digest.update(content);
    let digest = digest.finish();

    let mut nonce_bytes = [0_u8; 8];
    rand::rng().fill(&mut nonce_bytes);
    let nonce = u64::from_be_bytes(nonce_bytes) & i64::MAX as u64;
    let request = TimeStampReq {
        version: Integer::from(1),
        message_imprint: MessageImprint {
            hash_algorithm: DigestAlgorithm::Sha256.into(),
            hashed_message: OctetString::new(Bytes::copy_from_slice(digest.as_ref())),
        },
        req_policy: None,
        nonce: Some(Integer::from(nonce.max(1))),
        cert_req: Some(true),
        extensions: None,
    };
    let mut request_bytes = Vec::new();
    request
        .encode_ref()
        .write_encoded(Mode::Der, &mut request_bytes)
        .map_err(|error| TimestampError::TsaRequest(error.to_string()))?;

    let client = Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| TimestampError::TsaRequest(error.to_string()))?;
    let response = client
        .post(tsa_url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/timestamp-query")
        .header(reqwest::header::CONTENT_LENGTH, request_bytes.len())
        .body(request_bytes)
        .send()
        .map_err(|error| TimestampError::TsaRequest(error.to_string()))?;
    let response = ensure_success_response(response, tsa_url)?;
    let response_bytes = read_bounded_response(response)?;
    let response = Constructed::decode(
        response_bytes.as_slice(),
        Mode::Der,
        TimeStampResp::take_from,
    )
    .map_err(|error| TimestampError::TsaResponse(error.to_string()))?;
    if !matches!(
        response.status.status,
        PkiStatus::Granted | PkiStatus::GrantedWithMods
    ) {
        return Err(TimestampError::TsaResponse(format!(
            "TSA returned status {:?}",
            response.status.status
        )));
    }
    let token = response.time_stamp_token.ok_or_else(|| {
        TimestampError::TsaResponse("TSA did not return a timestamp token".to_owned())
    })?;
    validate_timestamp_token(&token, &request)?;
    let mut token_bytes = Vec::new();
    token
        .write_encoded(Mode::Der, &mut token_bytes)
        .map_err(|error| TimestampError::TsaResponse(error.to_string()))?;
    Ok(token_bytes)
}

fn ensure_success_response(
    response: Response,
    tsa_url: &reqwest::Url,
) -> Result<Response, TimestampError> {
    if response.status() == reqwest::StatusCode::OK {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let mut body = String::new();
    let mut limited = response.take(TSA_ERROR_BODY_LIMIT_BYTES);
    if limited.read_to_string(&mut body).is_err() {
        body.clear();
    }
    let detail = body.trim();
    Err(TimestampError::TsaHttp {
        status,
        url: tsa_url.to_string(),
        detail: if detail.is_empty() {
            String::new()
        } else {
            format!(" — {detail}")
        },
    })
}

fn read_bounded_response(response: Response) -> Result<Vec<u8>, TimestampError> {
    if response
        .content_length()
        .is_some_and(|length| length > TSA_RESPONSE_LIMIT_BYTES)
    {
        return Err(TimestampError::TsaResponseTooLarge);
    }
    let mut limited = response.take(TSA_RESPONSE_LIMIT_BYTES.saturating_add(1));
    let mut response_bytes = Vec::new();
    limited.read_to_end(&mut response_bytes)?;
    if response_bytes.len() as u64 > TSA_RESPONSE_LIMIT_BYTES {
        return Err(TimestampError::TsaResponseTooLarge);
    }
    Ok(response_bytes)
}

fn validate_timestamp_token(
    token: &cryptographic_message_syntax::asn1::rfc3161::TimeStampToken,
    request: &TimeStampReq,
) -> Result<(), TimestampError> {
    if token.content_type != OID_ID_SIGNED_DATA {
        return Err(TimestampError::TsaResponse(
            "timestamp token does not contain CMS signed data".to_owned(),
        ));
    }
    let signed_data = token
        .content
        .clone()
        .decode(CmsSignedData::take_from)
        .map_err(|error| TimestampError::TsaResponse(error.to_string()))?;
    if signed_data.content_info.content_type != OID_CONTENT_TYPE_TST_INFO {
        return Err(TimestampError::TsaResponse(
            "timestamp token does not contain TSTInfo".to_owned(),
        ));
    }
    let timestamp_info_content = signed_data.content_info.content.ok_or_else(|| {
        TimestampError::TsaResponse("timestamp token has no TSTInfo content".to_owned())
    })?;
    let timestamp_info = Constructed::decode(
        timestamp_info_content.to_bytes().as_ref(),
        Mode::Der,
        TstInfo::take_from,
    )
    .map_err(|error| TimestampError::TsaResponse(error.to_string()))?;
    let timestamp_digest = timestamp_info.message_imprint.hashed_message.to_bytes();
    let request_digest = request.message_imprint.hashed_message.to_bytes();
    if timestamp_info.message_imprint.hash_algorithm.algorithm
        != request.message_imprint.hash_algorithm.algorithm
        || timestamp_digest.as_ref() != request_digest.as_ref()
    {
        return Err(TimestampError::TsaResponse(
            "timestamp token message imprint does not match the request".to_owned(),
        ));
    }
    if timestamp_info.nonce != request.nonce {
        return Err(TimestampError::TsaResponse(
            "timestamp token nonce does not match the request".to_owned(),
        ));
    }
    Ok(())
}

fn pdf_date_now() -> String {
    let now = chrono::Local::now();
    let offset = now.format("%z").to_string();
    format!(
        "D:{}{}'{}'",
        now.format("%Y%m%d%H%M%S"),
        &offset[..3],
        &offset[3..]
    )
}

fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + (value - 10),
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty()).then_some(()).and_then(|()| {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    })
}

#[cfg(test)]
mod tests {
    use lopdf::{Dictionary, Document, Object, Stream, dictionary};

    use super::{apply_timestamp_token, prepare_timestamp_pdf, signed_content};

    #[test]
    fn incremental_placeholder_retains_the_input_and_has_a_valid_byte_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = single_page_pdf()?;
        let prepared = prepare_timestamp_pdf(&source, 32)?;
        assert!(prepared.bytes.starts_with(&source));
        let signed = signed_content(
            &prepared.bytes,
            [
                0,
                prepared.contents_start,
                prepared.contents_end + 1,
                prepared.bytes.len() - (prepared.contents_end + 1),
            ],
        )?;
        assert_eq!(signed, prepared.signed_content);

        let output = apply_timestamp_token(prepared, &[0x30, 0x01, 0x00])?;
        let document = Document::load_mem(&output)?;
        assert!(
            document
                .objects
                .values()
                .any(|object| object.as_dict().is_ok_and(|dictionary| {
                    dictionary
                        .get(b"Type")
                        .and_then(lopdf::Object::as_name)
                        .is_ok_and(|name| name == b"DocTimeStamp")
                }))
        );
        Ok(())
    }

    #[test]
    fn appends_to_existing_indirect_form_and_annotation_arrays()
    -> Result<(), Box<dyn std::error::Error>> {
        let prepared = prepare_timestamp_pdf(&existing_form_pdf()?, 32)?;
        let document = Document::load_mem(&prepared.bytes)?;
        let root_id = document.trailer.get(b"Root")?.as_reference()?;
        let catalog = document.get_dictionary(root_id)?;
        let acroform_id = catalog.get(b"AcroForm")?.as_reference()?;
        let acroform = document.get_dictionary(acroform_id)?;
        let fields_id = acroform.get(b"Fields")?.as_reference()?;
        assert_eq!(document.get_object(fields_id)?.as_array()?.len(), 2);
        assert_eq!(acroform.get(b"SigFlags")?.as_i64()?, 3);

        let page_id = *document
            .get_pages()
            .values()
            .next()
            .ok_or("expected test page")?;
        let page = document.get_dictionary(page_id)?;
        let annots_id = page.get(b"Annots")?.as_reference()?;
        assert_eq!(document.get_object(annots_id)?.as_array()?.len(), 2);
        Ok(())
    }

    fn single_page_pdf() -> Result<Vec<u8>, lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let content_id =
            document.add_object(lopdf::Stream::new(lopdf::Dictionary::new(), Vec::new()));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Contents" => content_id,
        });
        document.objects.insert(
            page_tree_id,
            lopdf::Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![lopdf::Object::Reference(page_id)],
                "Count" => 1,
            }),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    fn existing_form_pdf() -> Result<Vec<u8>, lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let page_tree_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
        let existing_widget_id = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "FT" => "Tx",
            "T" => Object::string_literal("existing"),
            "Rect" => vec![0.into(), 0.into(), 20.into(), 20.into()],
        });
        let annots_id = document.add_object(vec![Object::Reference(existing_widget_id)]);
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
            "Contents" => content_id,
            "Annots" => annots_id,
        });
        document.objects.insert(
            page_tree_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_id)],
                "Count" => 1,
            }),
        );
        let fields_id = document.add_object(vec![Object::Reference(existing_widget_id)]);
        let acroform_id = document.add_object(dictionary! {
            "Fields" => fields_id,
            "SigFlags" => 1,
        });
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => page_tree_id,
            "AcroForm" => acroform_id,
        });
        document.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }
}
