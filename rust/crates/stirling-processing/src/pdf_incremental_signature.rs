//! Incremental PDF signature placeholder support.
//!
//! This module creates an invisible signature field and reserves an exact-size
//! `/Contents` gap in a new PDF revision. A key provider creates detached CMS
//! bytes for [`PdfSignaturePlaceholder::signed_bytes`], then the caller fills
//! that gap without changing any signed byte. No HTTP route uses this yet.

use chrono::Utc;
use lopdf::{
    Dictionary, Document, IncrementalDocument, Object, Stream, StringFormat,
    content::{Content, Operation},
    dictionary,
};
use thiserror::Error;

const BYTE_RANGE_WIDTH: usize = 19;
const BYTE_RANGE_MARKER: i64 = i64::MAX;
const MAX_RESERVED_SIGNATURE_BYTES: usize = 512 * 1024;

/// Optional metadata recorded in the PDF signature dictionary.
#[derive(Clone, Copy, Debug, Default)]
pub struct PdfSignatureMetadata<'a> {
    pub name: Option<&'a str>,
    pub location: Option<&'a str>,
    pub reason: Option<&'a str>,
}

/// Optional visible widget attached to a one-based PDF page number.
#[derive(Clone, Copy, Debug)]
pub struct PdfSignatureAppearance<'a> {
    pub page_number: usize,
    pub signer_name: &'a str,
    pub show_logo: bool,
}

/// An incremental revision with a fixed-width `/ByteRange` and `/Contents` gap.
pub struct PdfSignaturePlaceholder {
    document: Vec<u8>,
    contents: std::ops::Range<usize>,
}

impl PdfSignaturePlaceholder {
    /// Creates an invisible detached-signature field in a new PDF revision.
    ///
    /// The input remains byte-for-byte intact; only an incremental revision is
    /// appended. Encrypted PDFs are rejected by `lopdf`'s incremental writer.
    ///
    /// # Errors
    ///
    /// Returns an error when the PDF cannot be read incrementally, has no
    /// catalog, or the requested CMS reservation is invalid.
    pub fn prepare(pdf: &[u8], reserved_signature_bytes: usize) -> Result<Self, PdfSigningError> {
        Self::prepare_with_metadata(
            pdf,
            reserved_signature_bytes,
            PdfSignatureMetadata::default(),
        )
    }

    /// Creates an invisible detached-signature field with optional signer metadata.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::prepare`], plus an error if metadata
    /// has a NUL byte and cannot be represented safely as a PDF literal string.
    pub fn prepare_with_metadata(
        pdf: &[u8],
        reserved_signature_bytes: usize,
        metadata: PdfSignatureMetadata<'_>,
    ) -> Result<Self, PdfSigningError> {
        Self::prepare_with_metadata_and_appearance(pdf, reserved_signature_bytes, metadata, None)
    }

    /// Creates a detached-signature field with metadata and an optional visible
    /// page widget.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::prepare_with_metadata`], plus an
    /// error when the requested appearance page does not exist.
    pub fn prepare_with_metadata_and_appearance(
        pdf: &[u8],
        reserved_signature_bytes: usize,
        metadata: PdfSignatureMetadata<'_>,
        appearance: Option<PdfSignatureAppearance<'_>>,
    ) -> Result<Self, PdfSigningError> {
        if reserved_signature_bytes == 0 || reserved_signature_bytes > MAX_RESERVED_SIGNATURE_BYTES
        {
            return Err(PdfSigningError::InvalidReservation);
        }
        if [metadata.name, metadata.location, metadata.reason]
            .into_iter()
            .flatten()
            .any(|value| value.contains('\0'))
        {
            return Err(PdfSigningError::InvalidMetadata);
        }
        if appearance.is_some_and(|appearance| {
            appearance.page_number == 0 || appearance.signer_name.contains('\0')
        }) {
            return Err(PdfSigningError::InvalidAppearance);
        }

        let previous = Document::load_mem(pdf)?;
        let root_id = previous
            .trailer
            .get(b"Root")?
            .as_reference()
            .map_err(|_| PdfSigningError::MissingCatalog)?;
        let root = previous.get_object(root_id)?.as_dict()?.clone();
        let mut incremental = IncrementalDocument::create_from(pdf.to_vec(), previous);
        let mut acro_form = acro_form_dictionary(incremental.get_prev_documents(), &root)?;
        let signing_time = Utc::now();
        let pdf_signing_time = format!("D:{}", signing_time.format("%Y%m%d%H%M%S+00'00'"));

        let signature_id = incremental.new_document.new_object_id();
        let field_id = incremental.new_document.new_object_id();
        let mut signature = dictionary! {
            "Type" => "Sig",
            "Filter" => "Adobe.PPKLite",
            "SubFilter" => "adbe.pkcs7.detached",
            "ByteRange" => vec![
                Object::Integer(0),
                Object::Integer(BYTE_RANGE_MARKER),
                Object::Integer(BYTE_RANGE_MARKER),
                Object::Integer(BYTE_RANGE_MARKER),
            ],
            "Contents" => Object::String(vec![0; reserved_signature_bytes], StringFormat::Hexadecimal),
            "M" => Object::string_literal(pdf_signing_time),
        };
        if let Some(name) = metadata.name {
            signature.set("Name", Object::string_literal(name));
        }
        if let Some(location) = metadata.location {
            signature.set("Location", Object::string_literal(location));
        }
        if let Some(reason) = metadata.reason {
            signature.set("Reason", Object::string_literal(reason));
        }
        let mut field = dictionary! {
            "FT" => "Sig",
            "T" => Object::string_literal(format!("Stirling Rust Signature {}", field_id.0)),
            "V" => Object::Reference(signature_id),
        };
        if let Some(appearance) = appearance {
            let page_id =
                page_id_for_number(incremental.get_prev_documents(), appearance.page_number)?;
            let appearance_id = add_visible_appearance(
                &mut incremental,
                appearance,
                &signing_time.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                metadata.reason,
            )?;
            field.set("Type", "Annot");
            field.set("Subtype", "Widget");
            field.set("Rect", rectangle(0, 0, 200, 50));
            field.set("P", Object::Reference(page_id));
            field.set("F", Object::Integer(4));
            field.set(
                "AP",
                Object::Dictionary(dictionary! { "N" => Object::Reference(appearance_id) }),
            );
            append_page_annotation(&mut incremental, page_id, field_id)?;
        }
        incremental
            .new_document
            .objects
            .insert(signature_id, Object::Dictionary(signature));
        incremental
            .new_document
            .objects
            .insert(field_id, Object::Dictionary(field));

        let mut fields = acro_form_fields(incremental.get_prev_documents(), &acro_form)?;
        fields.push(Object::Reference(field_id));
        acro_form.set(b"Fields", fields);
        acro_form.set(b"SigFlags", Object::Integer(3));
        let acro_form_id = incremental.new_document.add_object(acro_form);

        let mut updated_root = root;
        updated_root.set(b"AcroForm", Object::Reference(acro_form_id));
        incremental
            .new_document
            .objects
            .insert(root_id, Object::Dictionary(updated_root));

        let mut document = Vec::new();
        incremental.save_to(&mut document)?;
        Self::finish(document, signature_id, reserved_signature_bytes)
    }

    /// Locates the real signature object's own `/Contents` placeholder and
    /// fills in its `/ByteRange`, once the incremental revision has been
    /// fully assembled and written.
    fn finish(
        mut document: Vec<u8>,
        signature_id: lopdf::ObjectId,
        reserved_signature_bytes: usize,
    ) -> Result<Self, PdfSigningError> {
        let signature_offset = signature_object_offset(&document, signature_id)?;
        let contents = locate_contents(&document, signature_offset, reserved_signature_bytes)?;
        write_byte_range(&mut document, signature_offset, contents.clone())?;
        Ok(Self { document, contents })
    }

    /// Returns the exact concatenated bytes covered by `/ByteRange`.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let excluded_start = self.contents.start - 1;
        let excluded_end = self.contents.end + 1;
        let mut result = Vec::with_capacity(self.document.len() - (excluded_end - excluded_start));
        result.extend_from_slice(&self.document[..excluded_start]);
        result.extend_from_slice(&self.document[excluded_end..]);
        result
    }

    /// Inserts detached CMS bytes into the fixed reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the CMS payload does not fit in the reservation.
    pub fn complete(mut self, cms_der: &[u8]) -> Result<Vec<u8>, PdfSigningError> {
        if cms_der.len() > self.reserved_signature_bytes() {
            return Err(PdfSigningError::CmsTooLarge);
        }
        self.document[self.contents.clone()].fill(b'0');
        for (target, byte) in self.contents.clone().step_by(2).zip(cms_der) {
            let [high, low] = hex_pair(*byte);
            self.document[target] = high;
            self.document[target + 1] = low;
        }
        Ok(self.document)
    }

    #[must_use]
    pub fn reserved_signature_bytes(&self) -> usize {
        self.contents.len() / 2
    }
}

/// Errors while preparing or filling an incremental signature revision.
#[derive(Debug, Error)]
pub enum PdfSigningError {
    #[error("PDF parsing or incremental writing failed: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("incremental PDF output failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "a detached CMS reservation must be between 1 and {MAX_RESERVED_SIGNATURE_BYTES} bytes"
    )]
    InvalidReservation,
    #[error("the PDF catalog is missing or not an indirect reference")]
    MissingCatalog,
    #[error("signature metadata cannot contain NUL bytes")]
    InvalidMetadata,
    #[error("visible signature appearance requires a valid page and NUL-free signer text")]
    InvalidAppearance,
    #[error("visible signature page {0} does not exist")]
    AppearancePageMissing(usize),
    #[error("the incremental signature placeholder was not written as expected")]
    PlaceholderMissing,
    #[error("the signed PDF is too large for the fixed-width /ByteRange")]
    ByteRangeTooLarge,
    #[error("the detached CMS payload does not fit in the reserved /Contents value")]
    CmsTooLarge,
}

fn page_id_for_number(
    previous: &Document,
    page_number: usize,
) -> Result<lopdf::ObjectId, PdfSigningError> {
    let page_number = u32::try_from(page_number)
        .map_err(|_| PdfSigningError::AppearancePageMissing(page_number))?;
    previous
        .get_pages()
        .get(&page_number)
        .copied()
        .ok_or(PdfSigningError::AppearancePageMissing(page_number as usize))
}

fn add_visible_appearance(
    incremental: &mut IncrementalDocument,
    appearance: PdfSignatureAppearance<'_>,
    signing_time: &str,
    reason: Option<&str>,
) -> Result<lopdf::ObjectId, PdfSigningError> {
    let font_id = incremental.new_document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica-Bold",
        "Encoding" => "WinAnsiEncoding",
    });
    let resources = dictionary! {
        "Font" => dictionary! { "F1" => Object::Reference(font_id) },
    };
    let mut operations = vec![
        Operation::new("q", Vec::new()),
        Operation::new("rg", vec![0.97.into(), 0.97.into(), 0.97.into()]),
        Operation::new("re", vec![0.into(), 0.into(), 200.into(), 50.into()]),
        Operation::new("f", Vec::new()),
        Operation::new("RG", vec![0.3.into(), 0.3.into(), 0.3.into()]),
        Operation::new("w", vec![1.into()]),
        Operation::new("re", vec![0.5.into(), 0.5.into(), 199.into(), 49.into()]),
        Operation::new("S", Vec::new()),
    ];
    if appearance.show_logo {
        operations.extend([
            Operation::new("RG", vec![0.55.into(), 0.55.into(), 0.55.into()]),
            Operation::new("w", vec![3.into()]),
            Operation::new("m", vec![158.into(), 22.into()]),
            Operation::new("l", vec![169.into(), 10.into()]),
            Operation::new("l", vec![192.into(), 39.into()]),
            Operation::new("S", Vec::new()),
        ]);
    }
    operations.extend([
        Operation::new("BT", Vec::new()),
        Operation::new("Tf", vec![Object::Name(b"F1".to_vec()), 8.into()]),
        Operation::new("rg", vec![0.into(), 0.into(), 0.into()]),
        Operation::new("Td", vec![8.into(), 36.into()]),
        Operation::new(
            "Tj",
            vec![Object::string_literal(appearance_line(
                &format!("Signed by {}", appearance.signer_name),
                36,
            ))],
        ),
        Operation::new("Td", vec![0.into(), (-12).into()]),
        Operation::new(
            "Tj",
            vec![Object::string_literal(appearance_line(signing_time, 36))],
        ),
    ]);
    if let Some(reason) = reason.filter(|reason| !reason.trim().is_empty()) {
        operations.extend([
            Operation::new("Td", vec![0.into(), (-12).into()]),
            Operation::new(
                "Tj",
                vec![Object::string_literal(appearance_line(reason, 36))],
            ),
        ]);
    }
    operations.extend([
        Operation::new("ET", Vec::new()),
        Operation::new("Q", Vec::new()),
    ]);
    let content = Content { operations }.encode()?;
    let stream = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "FormType" => 1,
            "BBox" => rectangle(0, 0, 200, 50),
            "Resources" => resources,
        },
        content,
    );
    Ok(incremental.new_document.add_object(stream))
}

fn append_page_annotation(
    incremental: &mut IncrementalDocument,
    page_id: lopdf::ObjectId,
    field_id: lopdf::ObjectId,
) -> Result<(), PdfSigningError> {
    let previous = incremental.get_prev_documents();
    let mut page = previous.get_object(page_id)?.as_dict()?.clone();
    let mut annotations = match page.get(b"Annots") {
        Ok(value) => previous.dereference(value)?.1.as_array()?.clone(),
        Err(_) => Vec::new(),
    };
    annotations.push(Object::Reference(field_id));
    page.set("Annots", annotations);
    incremental
        .new_document
        .objects
        .insert(page_id, Object::Dictionary(page));
    Ok(())
}

fn appearance_line(value: &str, max_characters: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                '?'
            }
        })
        .take(max_characters)
        .collect()
}

fn rectangle(left: i64, bottom: i64, right: i64, top: i64) -> Object {
    Object::Array(vec![left.into(), bottom.into(), right.into(), top.into()])
}

fn acro_form_dictionary(
    previous: &Document,
    root: &Dictionary,
) -> Result<Dictionary, PdfSigningError> {
    match root.get(b"AcroForm") {
        Ok(value) => Ok(previous.dereference(value)?.1.as_dict()?.clone()),
        Err(_) => Ok(Dictionary::new()),
    }
}

fn acro_form_fields(
    previous: &Document,
    acro_form: &Dictionary,
) -> Result<Vec<Object>, PdfSigningError> {
    match acro_form.get(b"Fields") {
        Ok(value) => Ok(previous.dereference(value)?.1.as_array()?.clone()),
        Err(_) => Ok(Vec::new()),
    }
}

/// Returns the exact byte offset where the freshly-created signature object's
/// own serialization begins, from the just-written document's real,
/// PDF-parsed cross-reference table.
///
/// [`locate_contents`] and [`write_byte_range`] must search starting only
/// from this offset, never from `pdf.len()` (the start of the whole appended
/// incremental section). Every other object re-serialized alongside the
/// signature - most importantly the input PDF's own (attacker-controlled)
/// Catalog/Root dictionary, cloned and rewritten at `root_id` - keeps its
/// original, strictly-lower object id and is therefore always written earlier
/// in the appended section (`lopdf` serializes its `BTreeMap<ObjectId, _>` in
/// ascending id order, and `signature_id` is always freshly allocated higher
/// than every id that existed in the input document). A raw byte search that
/// starts at `pdf.len()` would find the *first* occurrence of a marker
/// anywhere in that whole section, so an attacker could plant a decoy
/// `/Contents<...>` (or `/ByteRange[...]`) value as an extra key on their own
/// Root dictionary and hijack which bytes get treated as the placeholder.
/// Re-parsing with `lopdf` (rather than trusting a raw byte scan) means only
/// a real object boundary counts, exactly like any other PDF consumer would
/// see it - a decoy string value can never be misread as a new object.
fn signature_object_offset(
    document: &[u8],
    signature_id: lopdf::ObjectId,
) -> Result<usize, PdfSigningError> {
    let reparsed = Document::load_mem(document)?;
    match reparsed.reference_table.entries.get(&signature_id.0) {
        Some(lopdf::xref::XrefEntry::Normal { offset, .. }) => Ok(*offset as usize),
        _ => Err(PdfSigningError::PlaceholderMissing),
    }
}

fn locate_contents(
    document: &[u8],
    appended_start: usize,
    reserved_signature_bytes: usize,
) -> Result<std::ops::Range<usize>, PdfSigningError> {
    let marker = b"/Contents<";
    let start = document[appended_start..]
        .windows(marker.len())
        .position(|window| window == marker)
        .map(|offset| appended_start + offset + marker.len())
        .ok_or(PdfSigningError::PlaceholderMissing)?;
    let contents_length = reserved_signature_bytes
        .checked_mul(2)
        .ok_or(PdfSigningError::InvalidReservation)?;
    let end = start
        .checked_add(contents_length)
        .ok_or(PdfSigningError::InvalidReservation)?;
    if document.get(end) != Some(&b'>') || document[start..end].iter().any(|byte| *byte != b'0') {
        return Err(PdfSigningError::PlaceholderMissing);
    }
    Ok(start..end)
}

fn write_byte_range(
    document: &mut [u8],
    appended_start: usize,
    contents: std::ops::Range<usize>,
) -> Result<(), PdfSigningError> {
    let marker =
        format!("/ByteRange[0 {BYTE_RANGE_MARKER} {BYTE_RANGE_MARKER} {BYTE_RANGE_MARKER}]");
    let byte_range_start = document[appended_start..]
        .windows(marker.len())
        .position(|window| window == marker.as_bytes())
        .map(|offset| appended_start + offset + b"/ByteRange[0 ".len())
        .ok_or(PdfSigningError::PlaceholderMissing)?;
    let excluded_start = contents.start - 1;
    let excluded_end = contents.end + 1;
    let values = [excluded_start, excluded_end, document.len() - excluded_end];
    for (index, value) in values.into_iter().enumerate() {
        let offset = byte_range_start + index * (BYTE_RANGE_WIDTH + 1);
        let encoded = fixed_width_number(value)?;
        document[offset..offset + BYTE_RANGE_WIDTH].copy_from_slice(encoded.as_bytes());
    }
    Ok(())
}

fn fixed_width_number(value: usize) -> Result<String, PdfSigningError> {
    let value = i64::try_from(value).map_err(|_| PdfSigningError::ByteRangeTooLarge)?;
    Ok(format!("{value:0BYTE_RANGE_WIDTH$}"))
}

fn hex_pair(byte: u8) -> [u8; 2] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0F)]]
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use cryptographic_message_syntax::SignedData;
    use lopdf::{Dictionary, Document, Object, Stream, StringFormat, dictionary};
    use x509_certificate::{Sign, testutil::self_signed_ecdsa_key_pair};

    use crate::signing_key::{PemSigningKey, SigningSecret};

    use super::{
        PdfSignatureAppearance, PdfSignatureMetadata, PdfSignaturePlaceholder, PdfSigningError,
    };

    #[test]
    #[allow(deprecated)]
    fn creates_incremental_field_and_signs_the_exact_byte_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = one_page_pdf()?;
        let placeholder = PdfSignaturePlaceholder::prepare(&source, 8_192)?;
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let private_key = pem_document(
            "PRIVATE KEY",
            &key.private_key_data().ok_or("private key is unavailable")?,
        );
        let signer = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(private_key.into_bytes()),
            certificate.encode_pem().as_bytes(),
        )?;
        let signed_bytes = placeholder.signed_bytes();
        let cms = signer.detached_cms_der(&signed_bytes)?;
        let signed_pdf = placeholder.complete(&cms)?;

        assert!(signed_pdf.starts_with(&source));
        assert!(
            signed_pdf
                .windows(b"/ByteRange[0 ".len())
                .any(|item| item == b"/ByteRange[0 ")
        );
        let document = Document::load_mem(&signed_pdf)?;
        let acro_form_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
        let acro_form = document.get_object(acro_form_id)?.as_dict()?;
        let fields = acro_form.get(b"Fields")?.as_array()?;
        assert_eq!(fields.len(), 1);
        let field_id = fields[0].as_reference()?;
        let field = document.get_object(field_id)?.as_dict()?;
        let signature_id = field.get(b"V")?.as_reference()?;
        let signature = document.get_object(signature_id)?.as_dict()?;
        let byte_range = signature
            .get(b"ByteRange")?
            .as_array()?
            .iter()
            .map(Object::as_i64)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(byte_range.len(), 4);
        let range_start = usize::try_from(byte_range[1])?;
        let second_start = usize::try_from(byte_range[2])?;
        let second_length = usize::try_from(byte_range[3])?;
        let mut reconstructed = signed_pdf[..range_start].to_vec();
        reconstructed.extend_from_slice(&signed_pdf[second_start..second_start + second_length]);
        assert_eq!(reconstructed, signed_bytes);

        let cms_from_pdf = signature.get(b"Contents")?.as_str()?;
        assert_eq!(&cms_from_pdf[..cms.len()], cms);
        assert!(cms_from_pdf[cms.len()..].iter().all(|byte| *byte == 0));
        let signed_data = SignedData::parse_ber(cms_from_pdf)?;
        for signer in signed_data.signers() {
            signer.verify_message_digest_with_content(&reconstructed)?;
            signer.verify_signature_with_signed_data(&signed_data)?;
        }
        verify_cms_with_openssl_when_requested(&cms, &reconstructed)?;
        Ok(())
    }

    /// A P-521 (secp521r1) private key and its self-signed `ecdsa-with-SHA512`
    /// certificate (OpenSSL-generated), shared with `signing_key`'s unit tests.
    const P521_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBwjfNy3ndVkidl8/i\n\
V2pPvah68CP9+MDrdk223SvIQTigHgAidxkIXw3spX3uSIZLNIXagXxxEEvkpBiv\n\
3Z6UNhOhgYkDgYYABAGdFIoAYJTKMikaLqe+tTxctMDRnBVC+kFwgDDunFexpDJf\n\
fUwlVIqHAJQ0aVoHnQncLFKYb6FX12BVmLjb+syY2AALBAFAiqfJndYEYQ2utLGA\n\
UWoqkItFKVQRtwpTqHDB72WHcSe41pZJt/XujLiZSTKsFYCLrPLRA6DuJEpamSp0\n\
sA==\n\
-----END PRIVATE KEY-----\n";

    const P521_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIICGTCCAXqgAwIBAgIURyuRCEttmk0wOq2ytxrpIgOZlJcwCgYIKoZIzj0EAwQw\n\
HjEcMBoGA1UEAwwTU3RpcmxpbmcgUC01MjEgVGVzdDAeFw0yNjA3MjUxNDUxMDVa\n\
Fw0zNjA3MjIxNDUxMDVaMB4xHDAaBgNVBAMME1N0aXJsaW5nIFAtNTIxIFRlc3Qw\n\
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAGdFIoAYJTKMikaLqe+tTxctMDRnBVC\n\
+kFwgDDunFexpDJffUwlVIqHAJQ0aVoHnQncLFKYb6FX12BVmLjb+syY2AALBAFA\n\
iqfJndYEYQ2utLGAUWoqkItFKVQRtwpTqHDB72WHcSe41pZJt/XujLiZSTKsFYCL\n\
rPLRA6DuJEpamSp0sKNTMFEwHQYDVR0OBBYEFAg5plmhxEqSaLrJqbFy8hQkL6hA\n\
MB8GA1UdIwQYMBaAFAg5plmhxEqSaLrJqbFy8hQkL6hAMA8GA1UdEwEB/wQFMAMB\n\
Af8wCgYIKoZIzj0EAwQDgYwAMIGIAkIBTCtwawyMW65d7KK1C6rYZcm61/S1uUMC\n\
4MiORYKcKBlAe/dFgs3gZ6dvLU/rswaau+6NECe0RYvjhTYkBh/aQNYCQgEdm5gs\n\
0OhBQ0hHKV6fln9/bStY/qH3kOBG1jD60nj8AKV61+EWtRuBX4gmlYMY4CWhTE1U\n\
amwXixTh3YlrdOneww==\n\
-----END CERTIFICATE-----\n";

    /// The full cert-sign path (reserved `/ByteRange` + `/Contents`) must work
    /// unchanged for a P-521 key: the placeholder is agnostic to how the CMS is
    /// produced, so the only new behavior is the P-521 CMS itself. The CMS is
    /// verified independently with `p521` because the `cryptographic-message-syntax`
    /// verifier can't resolve `ecdsa-with-SHA512`.
    #[test]
    fn signs_the_exact_byte_range_with_a_p521_key() -> Result<(), Box<dyn std::error::Error>> {
        use cryptographic_message_syntax::asn1::rfc5652::SignedData as Asn1SignedData;
        use p521::ecdsa::{Signature as EcdsaSignature, signature::Verifier};
        use pkcs8::DecodePrivateKey;
        use sha2::{Digest as _, Sha512};

        // ecdsa-with-SHA512 = 1.2.840.10045.4.3.4; SHA-512 = 2.16.840.1.101.3.4.2.3.
        const OID_ECDSA_WITH_SHA512: &[u8] = &[42, 134, 72, 206, 61, 4, 3, 4];
        const OID_SHA512: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 3];

        let source = one_page_pdf()?;
        let placeholder = PdfSignaturePlaceholder::prepare(&source, 8_192)?;
        let signer = PemSigningKey::from_pkcs8_pem(
            SigningSecret::new(P521_PKCS8_PEM.as_bytes().to_vec()),
            P521_CERTIFICATE_PEM.as_bytes(),
        )?;
        let signed_bytes = placeholder.signed_bytes();
        let cms = signer.detached_cms_der(&signed_bytes)?;
        let signed_pdf = placeholder.complete(&cms)?;

        assert!(signed_pdf.starts_with(&source));
        let document = Document::load_mem(&signed_pdf)?;
        let acro_form_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
        let acro_form = document.get_object(acro_form_id)?.as_dict()?;
        let fields = acro_form.get(b"Fields")?.as_array()?;
        assert_eq!(fields.len(), 1);
        let field_id = fields[0].as_reference()?;
        let field = document.get_object(field_id)?.as_dict()?;
        let signature_id = field.get(b"V")?.as_reference()?;
        let signature = document.get_object(signature_id)?.as_dict()?;
        let byte_range = signature
            .get(b"ByteRange")?
            .as_array()?
            .iter()
            .map(Object::as_i64)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(byte_range.len(), 4);
        let range_start = usize::try_from(byte_range[1])?;
        let second_start = usize::try_from(byte_range[2])?;
        let second_length = usize::try_from(byte_range[3])?;
        let mut reconstructed = signed_pdf[..range_start].to_vec();
        reconstructed.extend_from_slice(&signed_pdf[second_start..second_start + second_length]);
        assert_eq!(reconstructed, signed_bytes);

        let cms_from_pdf = signature.get(b"Contents")?.as_str()?;
        assert_eq!(&cms_from_pdf[..cms.len()], cms);
        assert!(cms_from_pdf[cms.len()..].iter().all(|byte| *byte == 0));

        // Independent P-521 verification of the CMS recovered from the PDF.
        let expected_digest = Sha512::digest(&reconstructed);
        let mut expected_message_digest = vec![0x04u8, 0x40u8];
        expected_message_digest.extend_from_slice(expected_digest.as_slice());
        assert!(
            cms.windows(expected_message_digest.len())
                .any(|window| window == expected_message_digest),
            "CMS must bind SHA-512 of the covered byte range"
        );
        let secret_key = p521::SecretKey::from_pkcs8_pem(P521_PKCS8_PEM)?;
        let verifier_key = p521::ecdsa::SigningKey::from(&secret_key);
        let signed_data = Asn1SignedData::decode_ber(&cms)?;
        assert!(!signed_data.signer_infos.is_empty());
        for signer_info in signed_data.signer_infos.iter() {
            assert_eq!(signer_info.digest_algorithm.algorithm.as_ref(), OID_SHA512);
            assert_eq!(
                signer_info.signature_algorithm.algorithm.as_ref(),
                OID_ECDSA_WITH_SHA512
            );
            let signed_content = signer_info
                .signed_attributes_digested_content()?
                .ok_or("signed attributes present")?;
            let ecdsa_signature =
                EcdsaSignature::from_der(signer_info.signature.to_bytes().as_ref())?;
            verifier_key
                .verifying_key()
                .verify(&signed_content, &ecdsa_signature)?;
        }
        verify_cms_with_openssl_when_requested(&cms, &reconstructed)?;
        Ok(())
    }

    #[test]
    fn rejects_invalid_reservations_and_oversized_cms() -> Result<(), Box<dyn std::error::Error>> {
        let source = one_page_pdf()?;
        assert!(matches!(
            PdfSignaturePlaceholder::prepare(&source, 0),
            Err(PdfSigningError::InvalidReservation)
        ));
        let placeholder = PdfSignaturePlaceholder::prepare(&source, 2)?;
        assert!(matches!(
            placeholder.complete(&[1, 2, 3]),
            Err(PdfSigningError::CmsTooLarge)
        ));
        Ok(())
    }

    #[test]
    fn a_decoy_contents_key_on_the_input_catalog_cannot_hijack_the_real_placeholder()
    -> Result<(), Box<dyn std::error::Error>> {
        let reserved = 64usize;
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
        let page_object_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        // A decoy `/Contents<0...0>` hex string, sized to exactly match the
        // real CMS reservation, planted directly on the Catalog - the one
        // dictionary this module always clones and re-serializes verbatim
        // (plus an added AcroForm key) ahead of the real signature object in
        // the appended incremental bytes, since it keeps its original,
        // strictly-lower object id.
        let decoy = Object::String(vec![0; reserved], StringFormat::Hexadecimal);
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
            "Contents" => decoy,
        });
        document.trailer.set("Root", Object::Reference(catalog_id));
        let mut source = Vec::new();
        document.save_to(&mut source)?;

        let placeholder = PdfSignaturePlaceholder::prepare(&source, reserved)?;
        let cms = vec![0xAB; reserved];
        let signed_pdf = placeholder.complete(&cms)?;

        let reloaded = Document::load_mem(&signed_pdf)?;
        let acro_form_id = reloaded.catalog()?.get(b"AcroForm")?.as_reference()?;
        let acro_form = reloaded.get_object(acro_form_id)?.as_dict()?;
        let field_id = acro_form.get(b"Fields")?.as_array()?[0].as_reference()?;
        let field = reloaded.get_object(field_id)?.as_dict()?;
        let signature_id = field.get(b"V")?.as_reference()?;
        let signature = reloaded.get_object(signature_id)?.as_dict()?;
        // The real signature object must hold the actual CMS bytes we supplied...
        assert_eq!(signature.get(b"Contents")?.as_str()?, cms.as_slice());

        // ...and the decoy on the Catalog must remain exactly as planted
        // (still all-zero), proving the placeholder search never touched it.
        let catalog = reloaded.catalog()?;
        assert_eq!(
            catalog.get(b"Contents")?.as_str()?,
            vec![0u8; reserved].as_slice()
        );
        Ok(())
    }

    #[test]
    fn creates_visible_widget_and_appearance_on_requested_page()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = one_page_pdf()?;
        let placeholder = PdfSignaturePlaceholder::prepare_with_metadata_and_appearance(
            &source,
            8_192,
            PdfSignatureMetadata {
                name: Some("Signer"),
                location: Some("Test"),
                reason: Some("Approved"),
            },
            Some(PdfSignatureAppearance {
                page_number: 1,
                signer_name: "Signer Name",
                show_logo: true,
            }),
        )?;
        let document = Document::load_mem(&placeholder.complete(&[])?)?;
        let page_id = document.get_pages()[&1];
        let page = document.get_object(page_id)?.as_dict()?;
        let annotations = page.get(b"Annots")?.as_array()?;
        assert_eq!(annotations.len(), 1);

        let field_id = annotations[0].as_reference()?;
        let field = document.get_object(field_id)?.as_dict()?;
        assert_eq!(field.get(b"Subtype")?.as_name()?, b"Widget");
        assert_eq!(field.get(b"P")?.as_reference()?, page_id);
        assert_eq!(field.get(b"Rect")?.as_array()?.len(), 4);
        let appearance_id = field.get(b"AP")?.as_dict()?.get(b"N")?.as_reference()?;
        let appearance = document.get_object(appearance_id)?.as_stream()?;
        assert_eq!(appearance.dict.get(b"Subtype")?.as_name()?, b"Form");
        assert!(
            appearance
                .content
                .windows(b"Signed by Signer Name".len())
                .any(|window| window == b"Signed by Signer Name")
        );
        Ok(())
    }

    #[test]
    fn rejects_visible_widget_on_missing_page() -> Result<(), Box<dyn std::error::Error>> {
        let source = one_page_pdf()?;
        assert!(matches!(
            PdfSignaturePlaceholder::prepare_with_metadata_and_appearance(
                &source,
                8_192,
                PdfSignatureMetadata::default(),
                Some(PdfSignatureAppearance {
                    page_number: 2,
                    signer_name: "Signer",
                    show_logo: false,
                }),
            ),
            Err(PdfSigningError::AppearancePageMissing(2))
        ));
        Ok(())
    }

    fn one_page_pdf() -> Result<Vec<u8>, lopdf::Error> {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
        let page_object_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
            "Contents" => content_id,
        });
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_object_id)],
                "Count" => 1,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", Object::Reference(catalog_id));
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    fn pem_document(label: &str, der: &[u8]) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD};

        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            STANDARD.encode(der)
        )
    }

    fn verify_cms_with_openssl_when_requested(
        cms: &[u8],
        signed_content: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os("STIRLING_VERIFY_OPENSSL").is_none() {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let cms_path = directory.path().join("signature.der");
        let content_path = directory.path().join("content.bin");
        let output_path = directory.path().join("verified.bin");
        fs::write(&cms_path, cms)?;
        fs::write(&content_path, signed_content)?;
        let output = Command::new("openssl")
            .args([
                "cms",
                "-verify",
                "-binary",
                "-inform",
                "DER",
                "-in",
                cms_path.to_string_lossy().as_ref(),
                "-content",
                content_path.to_string_lossy().as_ref(),
                "-noverify",
                "-out",
                output_path.to_string_lossy().as_ref(),
            ])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "OpenSSL CMS verification failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }
}
