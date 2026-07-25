use std::{fmt::Write as _, fs, path::Path, sync::OnceLock, time::Duration};

use bcder::{Mode, decode::Constructed};
use chrono::{DateTime, Datelike, FixedOffset, Local, NaiveDate, TimeZone, Utc};
use cryptographic_message_syntax::{SignedData, SignerInfo};
use lopdf::{Dictionary, Document, Object, ObjectId, decode_text_string};
use rustls_native_certs::load_native_certs;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde::Serialize;
use webpki::{
    ALL_VERIFICATION_ALGS, EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter,
    anchor_from_trusted_cert,
};
use x509_certificate::CapturedX509Certificate;
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};

static NATIVE_TRUST_ANCHORS: OnceLock<Vec<TrustAnchor<'static>>> = OnceLock::new();

#[derive(Debug, thiserror::Error)]
pub enum SignatureValidationError {
    #[error("could not read PDF: {0}")]
    Read(#[from] std::io::Error),
    #[error("could not parse PDF: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("invalid certificate file: {0}")]
    InvalidCertificate(String),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct SignatureValidationResult {
    pub valid: bool,
    pub chain_valid: bool,
    pub trust_valid: bool,
    pub chain_validation_error: Option<String>,
    pub cert_path_length: usize,
    pub not_expired: bool,
    pub covers_entire_document: bool,
    pub revocation_checked: bool,
    pub revocation_status: Option<String>,
    pub validation_time_source: Option<String>,
    pub signer_name: Option<String>,
    pub signature_date: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub error_message: Option<String>,
    #[serde(rename = "issuerDN")]
    pub issuer_dn: Option<String>,
    #[serde(rename = "subjectDN")]
    pub subject_dn: Option<String>,
    pub serial_number: Option<String>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub signature_algorithm: Option<String>,
    pub key_size: usize,
    pub version: Option<String>,
    pub key_usages: Option<Vec<String>>,
    #[serde(rename = "selfSigned")]
    pub self_signed: bool,
}

impl SignatureValidationResult {
    fn new(document_covered: bool) -> Self {
        Self {
            valid: false,
            chain_valid: false,
            trust_valid: false,
            chain_validation_error: None,
            cert_path_length: 0,
            not_expired: false,
            covers_entire_document: document_covered,
            revocation_checked: false,
            revocation_status: None,
            validation_time_source: None,
            signer_name: None,
            signature_date: None,
            reason: None,
            location: None,
            error_message: None,
            issuer_dn: None,
            subject_dn: None,
            serial_number: None,
            valid_from: None,
            valid_until: None,
            signature_algorithm: None,
            key_size: 0,
            version: None,
            key_usages: None,
            self_signed: false,
        }
    }
}

#[derive(Debug)]
struct PdfSignature {
    object_id: ObjectId,
    dictionary: Dictionary,
    byte_range: Option<[usize; 4]>,
}

#[derive(Debug, Clone, Copy)]
struct AcceptAnyExtendedKeyUsage;

impl ExtendedKeyUsageValidator for AcceptAnyExtendedKeyUsage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for key_purpose in iter {
            key_purpose?;
        }
        Ok(())
    }
}

/// Validates every digital signature dictionary in a PDF.
///
/// # Errors
///
/// Returns an error when the PDF cannot be read or parsed, or when the optional
/// custom trust anchor is not a valid DER/PEM X.509 certificate. An invalid
/// individual PDF signature is represented in the returned result array.
pub fn validate_pdf_signatures(
    path: &Path,
    custom_certificate: Option<&[u8]>,
) -> Result<Vec<SignatureValidationResult>, SignatureValidationError> {
    let bytes = fs::read(path)?;
    let document = Document::load_mem(&bytes)?;
    let custom_certificate = custom_certificate
        .map(parse_custom_certificate)
        .transpose()?;
    let signatures = collect_signatures(&document);

    Ok(signatures
        .iter()
        .map(|signature| {
            let mut result =
                SignatureValidationResult::new(covers_entire_document(signature, bytes.len()));
            if let Err(error) =
                validate_signature(signature, &bytes, custom_certificate.as_ref(), &mut result)
            {
                result.valid = false;
                result.error_message = Some(format!("Signature validation failed: {error}"));
            }
            result
        })
        .collect())
}

fn collect_signatures(document: &Document) -> Vec<PdfSignature> {
    let mut signatures = document
        .objects
        .iter()
        .filter_map(|(object_id, object)| {
            let dictionary = object.as_dict().ok()?;
            let is_signature = dictionary
                .get(b"Type")
                .and_then(Object::as_name)
                .is_ok_and(|name| name == b"Sig")
                || (dictionary.has(b"ByteRange") && dictionary.has(b"Contents"));
            is_signature.then(|| PdfSignature {
                object_id: *object_id,
                dictionary: dictionary.clone(),
                byte_range: parse_byte_range(dictionary),
            })
        })
        .collect::<Vec<_>>();
    signatures.sort_by_key(|signature| signature.object_id);
    signatures
}

/// Whether this signature's own `/ByteRange` extends to the literal end of
/// the file - i.e. whether nothing was appended to the document after this
/// specific signature was applied.
///
/// This must be computed strictly per-signature from that signature's own
/// declared range. An earlier implementation computed one shared "does any
/// object's `/ByteRange` reach the end of file" flag and applied it to every
/// signature's result; that let an attacker-supplied decoy object anywhere in
/// the file (with a fabricated `/ByteRange`/`/Contents` pair and no valid CMS
/// at all) mark an unrelated, genuinely-signed-then-tampered document as
/// fully covered, hiding real modifications appended after the real
/// signature. A missing or unparseable byte range is conservatively "not
/// covered" rather than assumed valid.
fn covers_entire_document(signature: &PdfSignature, document_len: usize) -> bool {
    signature
        .byte_range
        .and_then(|range| range[2].checked_add(range[3]))
        .is_some_and(|covered| covered >= document_len)
}

fn parse_byte_range(dictionary: &Dictionary) -> Option<[usize; 4]> {
    let values = dictionary.get(b"ByteRange").ok()?.as_array().ok()?;
    if values.len() != 4 {
        return None;
    }
    let mut range = [0usize; 4];
    for (index, value) in values.iter().enumerate() {
        range[index] = usize::try_from(value.as_i64().ok()?).ok()?;
    }
    Some(range)
}

fn validate_signature(
    signature: &PdfSignature,
    pdf_bytes: &[u8],
    custom_certificate: Option<&CapturedX509Certificate>,
    result: &mut SignatureValidationResult,
) -> Result<(), String> {
    let byte_range = signature
        .byte_range
        .ok_or_else(|| "signature ByteRange must contain four non-negative integers".to_owned())?;
    let signed_content = extract_signed_content(pdf_bytes, byte_range)?;
    let signature_bytes = signature_contents(&signature.dictionary)?;
    let signed_data = parse_cms_with_pdf_padding(signature_bytes)?;
    let certificates = signed_data.certificates().cloned().collect::<Vec<_>>();
    let signers = signed_data.signers().collect::<Vec<_>>();
    if signers.is_empty() {
        return Err("CMS signed data does not contain a signer".to_owned());
    }

    for signer in signers {
        let certificate = find_signing_certificate(signer, &certificates)?;
        let validation_time = validation_time(signer);
        result.validation_time_source = Some(validation_time.1.to_owned());
        let cryptographically_signed_content = signer.signed_content(Some(&signed_content));
        let signature_valid = signer.verify_signature_with_signed_data_and_content(
            &signed_data,
            &cryptographically_signed_content,
        );
        let digest_valid = signer.verify_message_digest_with_content(&signed_content);
        result.valid = signature_valid.is_ok() && digest_valid.is_ok();
        result.not_expired = certificate.time_constraints_valid(Some(validation_time.0));
        result.revocation_checked = false;
        result.revocation_status = Some("not-checked".to_owned());
        populate_signature_details(result, &signature.dictionary);
        populate_certificate_details(result, certificate)?;
        validate_certificate_path(
            result,
            certificate,
            &certificates,
            custom_certificate,
            validation_time.0,
        );
    }
    Ok(())
}

fn extract_signed_content(pdf_bytes: &[u8], range: [usize; 4]) -> Result<Vec<u8>, String> {
    let first_end = range[0]
        .checked_add(range[1])
        .ok_or_else(|| "signature ByteRange overflows".to_owned())?;
    let second_end = range[2]
        .checked_add(range[3])
        .ok_or_else(|| "signature ByteRange overflows".to_owned())?;
    let first = pdf_bytes
        .get(range[0]..first_end)
        .ok_or_else(|| "signature ByteRange is outside the PDF".to_owned())?;
    let second = pdf_bytes
        .get(range[2]..second_end)
        .ok_or_else(|| "signature ByteRange is outside the PDF".to_owned())?;
    let mut content = Vec::with_capacity(first.len().saturating_add(second.len()));
    content.extend_from_slice(first);
    content.extend_from_slice(second);
    Ok(content)
}

fn signature_contents(dictionary: &Dictionary) -> Result<&[u8], String> {
    let contents = dictionary
        .get(b"Contents")
        .map_err(|_| "signature does not contain Contents".to_owned())?;
    let Object::String(bytes, _) = contents else {
        return Err("signature Contents is not a string".to_owned());
    };
    if bytes.iter().all(|byte| *byte == 0) {
        return Err("signature Contents is empty".to_owned());
    }
    Ok(bytes)
}

fn parse_cms_with_pdf_padding(bytes: &[u8]) -> Result<SignedData, String> {
    let last_non_zero = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or_else(|| "signature Contents is empty".to_owned())?;
    let first_padding_byte = last_non_zero + 1;
    let available_zero_bytes = bytes.len() - first_padding_byte;
    let maximum_terminator_bytes = available_zero_bytes.min(64);
    let mut last_error = None;
    for terminator_bytes in 0..=maximum_terminator_bytes {
        match SignedData::parse_ber(&bytes[..first_padding_byte + terminator_bytes]) {
            Ok(signed_data) => return Ok(signed_data),
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "could not parse CMS signed data: {}",
        last_error.map_or_else(
            || "unknown parser error".to_owned(),
            |error| error.to_string()
        )
    ))
}

fn find_signing_certificate<'a>(
    signer: &SignerInfo,
    certificates: &'a [CapturedX509Certificate],
) -> Result<&'a CapturedX509Certificate, String> {
    let (issuer, serial_number) = signer
        .certificate_issuer_and_serial()
        .ok_or_else(|| "CMS signer does not identify its certificate".to_owned())?;
    certificates
        .iter()
        .find(|certificate| {
            certificate.issuer_name() == issuer && certificate.serial_number_asn1() == serial_number
        })
        .ok_or_else(|| "CMS signing certificate was not found".to_owned())
}

fn validation_time(signer: &SignerInfo) -> (DateTime<Utc>, &'static str) {
    if let Ok(Some(timestamp_data)) = signer.time_stamp_token_signed_data()
        && let Some(content) = timestamp_data.signed_content()
        && let Ok(timestamp_info) = Constructed::decode(
            content,
            Mode::Der,
            cryptographic_message_syntax::asn1::rfc3161::TstInfo::take_from,
        )
    {
        return (timestamp_info.gen_time.into(), "timestamp");
    }
    if let Some(signing_time) = signer
        .signed_attributes()
        .and_then(|attributes| attributes.signing_time())
    {
        return (*signing_time, "signing-time");
    }
    (Utc::now(), "current")
}

fn parse_custom_certificate(
    bytes: &[u8],
) -> Result<CapturedX509Certificate, SignatureValidationError> {
    CapturedX509Certificate::from_der(bytes.to_vec())
        .or_else(|_| CapturedX509Certificate::from_pem(bytes))
        .map_err(|error| SignatureValidationError::InvalidCertificate(error.to_string()))
}

fn validate_certificate_path(
    result: &mut SignatureValidationResult,
    signer: &CapturedX509Certificate,
    certificates: &[CapturedX509Certificate],
    custom_certificate: Option<&CapturedX509Certificate>,
    validation_time: DateTime<Utc>,
) {
    let signer_der = CertificateDer::from(signer.constructed_data().to_vec());
    let end_entity = match EndEntityCert::try_from(&signer_der) {
        Ok(certificate) => certificate,
        Err(error) => {
            set_chain_error(result, error.to_string());
            return;
        }
    };
    let intermediates = certificates
        .iter()
        .filter(|certificate| *certificate != signer)
        .map(|certificate| certificate.constructed_data().to_vec())
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let custom_anchors;
    let anchors = if let Some(custom_certificate) = custom_certificate {
        custom_anchors = custom_trust_anchors(custom_certificate);
        &custom_anchors
    } else {
        native_trust_anchors()
    };
    if anchors.is_empty() {
        set_chain_error(result, "No trust anchors available".to_owned());
        return;
    }
    let Ok(seconds) = u64::try_from(validation_time.timestamp()) else {
        set_chain_error(result, "validation time precedes the Unix epoch".to_owned());
        return;
    };
    match end_entity.verify_for_usage(
        ALL_VERIFICATION_ALGS,
        anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
        AcceptAnyExtendedKeyUsage,
        None,
        None,
    ) {
        Ok(path) => {
            result.chain_valid = true;
            result.trust_valid = true;
            result.cert_path_length = 1 + path.intermediate_certificates().count();
            result.chain_validation_error = None;
        }
        Err(error) => set_chain_error(result, error.to_string()),
    }
}

fn custom_trust_anchors(certificate: &CapturedX509Certificate) -> Vec<TrustAnchor<'static>> {
    let certificate = CertificateDer::from(certificate.constructed_data().to_vec());
    anchor_from_trusted_cert(&certificate)
        .ok()
        .map(|anchor| anchor.to_owned())
        .into_iter()
        .collect()
}

fn native_trust_anchors() -> &'static [TrustAnchor<'static>] {
    NATIVE_TRUST_ANCHORS.get_or_init(|| {
        load_native_certs()
            .certs
            .into_iter()
            .filter_map(|certificate| {
                anchor_from_trusted_cert(&certificate)
                    .ok()
                    .map(|anchor| anchor.to_owned())
            })
            .collect()
    })
}

fn set_chain_error(result: &mut SignatureValidationResult, error: String) {
    result.chain_valid = false;
    result.trust_valid = false;
    result.chain_validation_error = Some(error);
}

fn populate_certificate_details(
    result: &mut SignatureValidationResult,
    captured: &CapturedX509Certificate,
) -> Result<(), String> {
    let der = captured.constructed_data();
    let (_, certificate) = parse_x509_certificate(der)
        .map_err(|error| format!("could not parse signing certificate: {error}"))?;
    result.issuer_dn = Some(certificate.issuer().to_string());
    result.subject_dn = Some(certificate.subject().to_string());
    result.serial_number = Some(serial_number_hex(certificate.raw_serial()));
    result.valid_from = Some(format_certificate_date(
        certificate
            .validity()
            .not_before
            .to_datetime()
            .unix_timestamp(),
    ));
    result.valid_until = Some(format_certificate_date(
        certificate
            .validity()
            .not_after
            .to_datetime()
            .unix_timestamp(),
    ));
    result.signature_algorithm = Some(signature_algorithm_name(&certificate));
    result.key_size = rsa_key_size(captured);
    result.version = Some((certificate.version().0 + 1).to_string());
    result.key_usages = Some(key_usages(&certificate)?);
    result.self_signed =
        captured.subject_is_issuer() && captured.verify_signed_by_certificate(captured).is_ok();
    Ok(())
}

fn dictionary_text(dictionary: &Dictionary, key: &[u8]) -> Option<String> {
    dictionary
        .get(key)
        .ok()
        .and_then(|value| decode_text_string(value).ok())
}

fn populate_signature_details(result: &mut SignatureValidationResult, dictionary: &Dictionary) {
    result.signer_name = dictionary_text(dictionary, b"Name");
    result.signature_date = dictionary_text(dictionary, b"M")
        .and_then(|value| parse_pdf_date(&value))
        .map(format_java_date);
    result.reason = dictionary_text(dictionary, b"Reason");
    result.location = dictionary_text(dictionary, b"Location");
}

fn serial_number_hex(serial: &[u8]) -> String {
    let trimmed = serial
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&serial[serial.len().saturating_sub(1)..], |start| {
            &serial[start..]
        });
    let mut output = String::with_capacity(trimmed.len() * 2);
    for byte in trimmed {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn signature_algorithm_name(certificate: &X509Certificate<'_>) -> String {
    let oid = certificate.signature_algorithm.algorithm.to_id_string();
    match oid.as_str() {
        "1.2.840.113549.1.1.5" => "SHA1withRSA".to_owned(),
        "1.2.840.113549.1.1.11" => "SHA256withRSA".to_owned(),
        "1.2.840.113549.1.1.12" => "SHA384withRSA".to_owned(),
        "1.2.840.113549.1.1.13" => "SHA512withRSA".to_owned(),
        "1.2.840.113549.1.1.10" => "RSASSA-PSS".to_owned(),
        "1.2.840.10045.4.3.2" => "SHA256withECDSA".to_owned(),
        "1.2.840.10045.4.3.3" => "SHA384withECDSA".to_owned(),
        "1.2.840.10045.4.3.4" => "SHA512withECDSA".to_owned(),
        "1.3.101.112" => "Ed25519".to_owned(),
        _ => oid,
    }
}

fn rsa_key_size(certificate: &CapturedX509Certificate) -> usize {
    let Ok(public_key) = certificate.rsa_public_key_data() else {
        return 0;
    };
    let modulus = public_key.modulus.as_slice();
    let Some(first_non_zero) = modulus.iter().position(|byte| *byte != 0) else {
        return 0;
    };
    let first = modulus[first_non_zero];
    (modulus.len() - first_non_zero - 1) * 8 + (8 - first.leading_zeros() as usize)
}

fn key_usages(certificate: &X509Certificate<'_>) -> Result<Vec<String>, String> {
    let Some(usage) = certificate
        .key_usage()
        .map_err(|error| format!("could not parse certificate key usage: {error}"))?
    else {
        return Ok(Vec::new());
    };
    let usage = usage.value;
    let flags = [
        (usage.digital_signature(), "Digital Signature"),
        (usage.non_repudiation(), "Non-Repudiation"),
        (usage.key_encipherment(), "Key Encipherment"),
        (usage.data_encipherment(), "Data Encipherment"),
        (usage.key_agreement(), "Key Agreement"),
        (usage.key_cert_sign(), "Certificate Signing"),
        (usage.crl_sign(), "CRL Signing"),
        (usage.encipher_only(), "Encipher Only"),
        (usage.decipher_only(), "Decipher Only"),
    ];
    Ok(flags
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, label)| label.to_owned())
        .collect())
}

fn parse_pdf_date(value: &str) -> Option<DateTime<Utc>> {
    let value = value.strip_prefix("D:").unwrap_or(value);
    if value.len() < 4 {
        return None;
    }
    let year = i32::try_from(parse_date_part(value, 0, 4)?).ok()?;
    let month = parse_date_part(value, 4, 6).unwrap_or(1);
    let day = parse_date_part(value, 6, 8).unwrap_or(1);
    let hour = parse_date_part(value, 8, 10).unwrap_or(0);
    let minute = parse_date_part(value, 10, 12).unwrap_or(0);
    let second = parse_date_part(value, 12, 14).unwrap_or(0);
    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_opt(hour, minute, second)?;
    let timezone = value.as_bytes().get(14).copied();
    match timezone {
        Some(sign @ (b'+' | b'-')) => {
            let hours = parse_date_part(value, 15, 17).unwrap_or(0);
            let minutes = value
                .get(17..)
                .map(|tail| tail.trim_matches('\''))
                .and_then(|tail| tail.get(..2))
                .and_then(|part| part.parse::<u32>().ok())
                .unwrap_or(0);
            let offset_seconds = i32::try_from(hours * 3600 + minutes * 60).ok()?;
            let offset_seconds = if sign == b'-' {
                -offset_seconds
            } else {
                offset_seconds
            };
            FixedOffset::east_opt(offset_seconds)?
                .from_local_datetime(&naive)
                .single()
                .map(|date| date.with_timezone(&Utc))
        }
        _ => Some(Utc.from_utc_datetime(&naive)),
    }
}

fn parse_date_part(value: &str, start: usize, end: usize) -> Option<u32> {
    value.get(start..end)?.parse().ok()
}

fn format_certificate_date(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(format_java_date)
        .unwrap_or_default()
}

fn format_java_date(date: DateTime<Utc>) -> String {
    let local = date.with_timezone(&Local);
    format!(
        "{} {} {:02} {} {} {}",
        local.format("%a"),
        local.format("%b"),
        local.day(),
        local.format("%H:%M:%S"),
        local.format("%Z"),
        local.year()
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_pdf_date, serial_number_hex, validate_pdf_signatures};
    use lopdf::{Document, dictionary};

    #[test]
    fn parses_pdf_dates_with_offsets() {
        let date = parse_pdf_date("D:20240102030405+07'00'")
            .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH);
        assert_eq!(date.to_rfc3339(), "2024-01-01T20:04:05+00:00");
    }

    #[test]
    fn formats_serial_numbers_like_java_big_integer() {
        assert_eq!(serial_number_hex(&[0, 0, 0x0a, 0xbc]), "0abc");
        assert_eq!(serial_number_hex(&[0]), "00");
    }

    #[test]
    fn a_decoy_byte_range_cannot_spoof_a_different_signatures_document_coverage()
    -> Result<(), Box<dyn std::error::Error>> {
        // A real signature whose own `/ByteRange` does not reach the file's
        // true length (as if content had been appended after it) must report
        // `coversEntireDocument: false`, even in the presence of an unrelated
        // "signature-like" object elsewhere in the file (no valid CMS
        // required, no relationship to the real signature or AcroForm tree)
        // whose own fabricated `/ByteRange` claims to cover far more than the
        // real file length. Neither object's flag may leak into the other's.
        let mut document = Document::with_version("1.7");
        let real_id = document.add_object(dictionary! {
            "Type" => "Sig",
            "ByteRange" => vec![0.into(), 10.into(), 20.into(), 5.into()],
            "Contents" => lopdf::Object::string_literal("x"),
        });
        let decoy_id = document.add_object(dictionary! {
            "ByteRange" => vec![0.into(), 1.into(), 999_999.into(), 1.into()],
            "Contents" => lopdf::Object::string_literal("y"),
        });
        assert!(real_id.0 < decoy_id.0);
        let catalog_id = document.add_object(dictionary! { "Type" => "Catalog" });
        document.trailer.set("Root", catalog_id);

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("decoy.pdf");
        document.save(&path)?;

        let results = validate_pdf_signatures(&path, None)?;
        assert_eq!(results.len(), 2);
        assert!(
            !results[0].covers_entire_document,
            "the real signature's own (short) byte range must not be inflated by the decoy"
        );
        assert!(
            results[1].covers_entire_document,
            "the decoy's own fabricated range still resolves to its own result only"
        );
        Ok(())
    }
}
