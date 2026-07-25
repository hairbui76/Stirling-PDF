use std::{fs, path::PathBuf};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn returns_an_empty_array_for_unsigned_pdfs() -> Result<(), Box<dyn std::error::Error>> {
    let response = post(&unsigned_pdf()?, None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(body, Value::Array(Vec::new()));
    Ok(())
}

#[tokio::test]
async fn validates_cms_integrity_and_returns_the_java_schema()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(post(&signed_fixture()?, None).await?, StatusCode::OK).await?;
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let result = body
        .as_array()
        .and_then(|results| results.first())
        .ok_or("signed fixture should produce a validation result")?;
    assert_eq!(result["valid"], true);
    assert_eq!(result["coversEntireDocument"], true);
    assert_eq!(result["revocationChecked"], false);
    assert_eq!(result["revocationStatus"], "not-checked");
    assert_eq!(result["signerName"], "ARE Production V8.1 G3 P24 1007685");
    assert!(result["issuerDN"].is_string(), "{result:#}");
    assert!(result["subjectDN"].is_string());
    assert!(result["serialNumber"].is_string());
    assert!(result["notExpired"].is_boolean());
    assert!(result["chainValid"].is_boolean());
    assert!(result["trustValid"].is_boolean());
    assert!(result["selfSigned"].is_boolean());
    assert!(result["keyUsages"].is_array());
    Ok(())
}

#[tokio::test]
async fn distinguishes_tampering_from_unsigned_appended_content()
-> Result<(), Box<dyn std::error::Error>> {
    let original = signed_fixture()?;
    let mut tampered = original.clone();
    let name_offset = find_bytes(&tampered, b"ARE Production")
        .ok_or("signed fixture should contain its signer name")?;
    tampered[name_offset] = b'B';
    let tampered_result = first_result(post(&tampered, None).await?).await?;
    assert_eq!(tampered_result["valid"], false);
    assert_eq!(tampered_result["coversEntireDocument"], true);

    let mut appended = original;
    appended.extend_from_slice(b"\n% appended after signing\n");
    let appended_result = first_result(post(&appended, None).await?).await?;
    assert_eq!(appended_result["valid"], true);
    assert_eq!(appended_result["coversEntireDocument"], false);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_requests_and_custom_certificates() -> Result<(), Box<dyn std::error::Error>>
{
    assert_eq!(
        post_raw(None, None).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(b"not a PDF", None).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&unsigned_pdf()?, Some(b"not a certificate"))
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post(&signed_fixture()?, Some(&custom_certificate_fixture()?))
            .await?
            .status(),
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn keeps_java_defaults_when_a_signature_cannot_be_parsed()
-> Result<(), Box<dyn std::error::Error>> {
    let result = first_result(post(&malformed_signature_pdf()?, None).await?).await?;
    assert_eq!(result["valid"], false);
    assert_eq!(result["coversEntireDocument"], false);
    assert!(
        result["errorMessage"]
            .as_str()
            .is_some_and(|message| message.starts_with("Signature validation failed:"))
    );
    assert!(result["signerName"].is_null());
    assert!(result["signatureDate"].is_null());
    assert!(result["revocationStatus"].is_null());
    assert!(result["issuerDN"].is_null());
    Ok(())
}

async fn first_result(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let response = require_status(response, StatusCode::OK).await?;
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    body.as_array()
        .and_then(|results| results.first())
        .cloned()
        .ok_or_else(|| "expected a signature validation result".into())
}

async fn post(
    pdf: &[u8],
    certificate: Option<&[u8]>,
) -> Result<Response, Box<dyn std::error::Error>> {
    post_raw(Some(pdf), certificate).await
}

async fn post_raw(
    pdf: Option<&[u8]>,
    certificate: Option<&[u8]>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-validate-signature-boundary";
    let mut body = Vec::new();
    if let Some(pdf) = pdf {
        append_part(
            &mut body,
            boundary,
            "fileInput",
            "signed.pdf",
            "application/pdf",
            pdf,
        );
    }
    if let Some(certificate) = certificate {
        append_part(
            &mut body,
            boundary,
            "certFile",
            "trust-anchor.pem",
            "application/x-pem-file",
            certificate,
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/validate-signature")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn append_part(
    body: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    filename: &str,
    content_type: &str,
    contents: &[u8],
) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(contents);
    body.extend_from_slice(b"\r\n");
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

fn signed_fixture() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("test_irs_signed.pdf");
    Ok(fs::read(path)?)
}

fn custom_certificate_fixture() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../app/core/src/test/resources/certs/test-cert.der");
    Ok(fs::read(path)?)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn unsigned_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
        "Resources" => Dictionary::new(),
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn malformed_signature_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let signature_id = document.add_object(dictionary! {
        "Type" => "Sig",
        "ByteRange" => vec![0.into(), 1.into(), 2.into(), 3.into()],
        "Contents" => Object::string_literal(b"not CMS".to_vec()),
        "Name" => Object::string_literal("Must remain hidden on parse failure"),
        "M" => Object::string_literal("D:20240102030405Z"),
    });
    let field_id = document.add_object(dictionary! {
        "FT" => "Sig",
        "T" => Object::string_literal("Signature1"),
        "V" => signature_id,
    });
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
        "Resources" => Dictionary::new(),
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
        "AcroForm" => dictionary! {
            "Fields" => vec![Object::Reference(field_id)],
        },
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
