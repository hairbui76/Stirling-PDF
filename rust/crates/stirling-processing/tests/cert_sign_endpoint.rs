use std::{error::Error, fs, time::SystemTime};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use cryptographic_message_syntax::SignedData;
use jks::{Certificate as JksCertificate, KeyStore as JksKeyStore, PrivateKeyEntry};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use p12_keystore::{Certificate, KeyStore, KeyStoreEntry, PrivateKey, PrivateKeyChain};
use pkcs8::{LineEnding, PrivateKeyInfoRef};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app, app_with_reviewed_security, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;
use x509_certificate::{Sign, testutil::self_signed_ecdsa_key_pair};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
#[allow(deprecated)]
async fn signs_a_pdf_with_an_uploaded_pem_key_and_der_certificate() -> TestResult {
    let (certificate, key) = self_signed_ecdsa_key_pair(None);
    let private_key = pem_document(
        "PRIVATE KEY",
        &key.private_key_data().ok_or("test key is unavailable")?,
    );
    let response = post_cert_sign(
        &single_page_pdf()?,
        &private_key,
        certificate.constructed_data(),
        &[("name", "Stirling Test")],
    )
    .await?;

    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        return Err(format!(
            "certificate signing returned {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("input_signed.pdf")
    );
    let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    let document = Document::load_mem(&signed_pdf)?;
    let signature = signature_dictionary(&document)?;
    // /Sig/Name must reflect the signing certificate's own CN ("test", set by
    // self_signed_ecdsa_key_pair), not the client-supplied "name" field above
    // - a raw client string here would let a signer claim an unverified
    // identity that Stirling's own signature-validation endpoint later
    // reports back out as `signerName`.
    assert_eq!(signature.get(b"Name")?.as_str()?, b"test");
    let byte_range = signature
        .get(b"ByteRange")?
        .as_array()?
        .iter()
        .map(Object::as_i64)
        .collect::<Result<Vec<_>, _>>()?;
    let excluded_start = usize::try_from(byte_range[1])?;
    let second_start = usize::try_from(byte_range[2])?;
    let second_length = usize::try_from(byte_range[3])?;
    assert_eq!(
        second_start,
        excluded_start + (signature.get(b"Contents")?.as_str()?.len() * 2 + 2)
    );
    let mut signed_content = signed_pdf[..excluded_start].to_vec();
    signed_content.extend_from_slice(&signed_pdf[second_start..second_start + second_length]);
    let signed_data = SignedData::parse_ber(signature.get(b"Contents")?.as_str()?)?;
    for signer in signed_data.signers() {
        signer.verify_message_digest_with_content(&signed_content)?;
        signer.verify_signature_with_signed_data(&signed_data)?;
    }
    Ok(())
}

/// A P-521 (secp521r1) private key and its self-signed certificate.
/// Generated with OpenSSL (`ecparam secp521r1` + `req -x509 -sha512`); the
/// same fixture the `signing_key` unit tests verify against OpenSSL semantics.
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

/// P-521 keys sign through the dedicated pure-Rust path (`ecdsa-with-SHA512`),
/// so the endpoint accepts them end-to-end. The high-level
/// `cryptographic-message-syntax` verifier cannot parse an `ecdsa-with-SHA512`
/// `SignerInfo`, so this asserts the digest binding directly: the CMS must
/// embed SHA-512 of the `ByteRange` content as its `messageDigest` OCTET STRING.
/// Deep, OpenSSL-equivalent CMS verification lives in the `signing_key` and
/// `pdf_incremental_signature` unit tests.
#[tokio::test]
async fn signs_a_pdf_with_a_p521_key_and_its_certificate() -> TestResult {
    use sha2::{Digest, Sha512};

    let response = post_cert_sign(
        &single_page_pdf()?,
        P521_PKCS8_PEM,
        P521_CERTIFICATE_PEM.as_bytes(),
        &[("name", "Stirling Test")],
    )
    .await?;

    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        return Err(format!(
            "P-521 certificate signing returned {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    let document = Document::load_mem(&signed_pdf)?;
    let signature = signature_dictionary(&document)?;
    assert_eq!(signature.get(b"Name")?.as_str()?, b"Stirling P-521 Test");
    let byte_range = signature
        .get(b"ByteRange")?
        .as_array()?
        .iter()
        .map(Object::as_i64)
        .collect::<Result<Vec<_>, _>>()?;
    let excluded_start = usize::try_from(byte_range[1])?;
    let second_start = usize::try_from(byte_range[2])?;
    let second_length = usize::try_from(byte_range[3])?;
    let mut signed_content = signed_pdf[..excluded_start].to_vec();
    signed_content.extend_from_slice(&signed_pdf[second_start..second_start + second_length]);
    // messageDigest = SHA-512(content) as an OCTET STRING (tag 0x04, len 0x40).
    let mut expected_message_digest = vec![0x04u8, 0x40u8];
    expected_message_digest.extend_from_slice(Sha512::digest(&signed_content).as_slice());
    let cms = signature.get(b"Contents")?.as_str()?;
    assert!(
        cms.windows(expected_message_digest.len())
            .any(|window| window == expected_message_digest),
        "CMS must bind SHA-512 of the signed content via the messageDigest attribute"
    );
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn signs_a_pdf_with_an_encrypted_pkcs8_pem_key() -> TestResult {
    let (certificate, key) = self_signed_ecdsa_key_pair(None);
    let private_key = key.private_key_data().ok_or("test key is unavailable")?;
    let encrypted =
        PrivateKeyInfoRef::try_from(private_key.as_slice())?.encrypt(b"correct horse")?;
    let encrypted_pem = encrypted.to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)?;
    let response = post_encrypted_pem_sign(
        &single_page_pdf()?,
        encrypted_pem.as_bytes(),
        certificate.constructed_data(),
        "correct horse",
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    verify_pdf_signature(&signed_pdf)?;

    let wrong_password = post_encrypted_pem_sign(
        &single_page_pdf()?,
        encrypted_pem.as_bytes(),
        certificate.constructed_data(),
        "wrong",
    )
    .await?;
    assert_eq!(wrong_password.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn signs_a_pdf_with_an_uploaded_pkcs12_or_pfx_key() -> TestResult {
    for cert_type in ["PKCS12", "PFX"] {
        let (certificate, key) = self_signed_ecdsa_key_pair(None);
        let private_key = key.private_key_data().ok_or("test key is unavailable")?;
        let key_chain = PrivateKeyChain::new(
            b"stirling-endpoint-key".as_slice(),
            PrivateKey::from_der(&private_key)?,
            [Certificate::from_der(certificate.constructed_data())?],
        );
        let mut keystore = KeyStore::new();
        keystore.add_entry("signing-key", KeyStoreEntry::PrivateKeyChain(key_chain));
        let archive = keystore.writer("changeit").write()?;
        let response = post_pkcs12_sign(
            &single_page_pdf()?,
            &archive,
            cert_type,
            "changeit",
            Some("signing-key"),
        )
        .await?;

        if response.status() != StatusCode::OK {
            let status = response.status();
            let body = to_bytes(response.into_body(), usize::MAX).await?;
            return Err(format!(
                "{cert_type} signing returned {status}: {}",
                String::from_utf8_lossy(&body)
            )
            .into());
        }
        let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
        verify_pdf_signature(&signed_pdf)?;
    }
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn rejects_wrong_pkcs12_password_and_alias() -> TestResult {
    let (certificate, key) = self_signed_ecdsa_key_pair(None);
    let private_key = key.private_key_data().ok_or("test key is unavailable")?;
    let key_chain = PrivateKeyChain::new(
        b"stirling-endpoint-key".as_slice(),
        PrivateKey::from_der(&private_key)?,
        [Certificate::from_der(certificate.constructed_data())?],
    );
    let mut keystore = KeyStore::new();
    keystore.add_entry("signing-key", KeyStoreEntry::PrivateKeyChain(key_chain));
    let archive = keystore.writer("changeit").write()?;

    let wrong_password =
        post_pkcs12_sign(&single_page_pdf()?, &archive, "PKCS12", "wrong", None).await?;
    assert_eq!(wrong_password.status(), StatusCode::BAD_REQUEST);
    let wrong_alias = post_pkcs12_sign(
        &single_page_pdf()?,
        &archive,
        "PKCS12",
        "changeit",
        Some("missing"),
    )
    .await?;
    assert_eq!(wrong_alias.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn signs_a_pdf_with_an_uploaded_jks_key() -> TestResult {
    let (certificate, key) = self_signed_ecdsa_key_pair(None);
    let archive = jks_archive(&certificate, &key, b"changeit", "signing-key")?;
    let response = post_jks_sign(
        &single_page_pdf()?,
        &archive,
        "changeit",
        Some("SIGNING-KEY"),
    )
    .await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        return Err(format!(
            "JKS signing returned {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    verify_pdf_signature(&signed_pdf)?;

    let wrong_password =
        post_jks_sign(&single_page_pdf()?, &archive, "wrong-password", None).await?;
    assert_eq!(wrong_password.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn signs_a_pdf_with_the_managed_server_certificate() -> TestResult {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nsystem:\n  serverCertificate:\n    enabled: true\n    organizationName: Stirling Endpoint Test\n    validity: 30\n",
    )?;
    let app = app_with_reviewed_security(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        RuntimeConfig::from_files(&settings, config_directory.join("missing.yml")),
    )?;
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"admin@example.test","password":"test-only-password"}"#,
                ))?,
        )
        .await?;
    assert_eq!(login.status(), StatusCode::OK);
    let login: Value = serde_json::from_slice(&to_bytes(login.into_body(), 64 * 1024).await?)?;
    let access_token = login["session"]["access_token"]
        .as_str()
        .ok_or("missing access token")?;

    let info = app
        .clone()
        .oneshot(
            Request::get("/api/v1/admin/server-certificate/info")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(info.status(), StatusCode::OK);

    let boundary = "stirling-server-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "SERVER");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        &single_page_pdf()?,
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let response = app
        .oneshot(
            Request::post("/api/v1/security/cert-sign")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::from(body))?,
        )
        .await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        return Err(format!(
            "managed certificate signing returned {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    verify_pdf_signature(&to_bytes(response.into_body(), usize::MAX).await?)?;
    Ok(())
}

#[tokio::test]
async fn pkcs11_signing_is_desktop_gated_without_echoing_the_pin() -> TestResult {
    let pin = "never-echo-pkcs11-signing-pin";
    let boundary = "stirling-pkcs11-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "PKCS11");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        &single_page_pdf()?,
    );
    append_value_part(
        &mut body,
        boundary,
        "pkcs11LibraryPath",
        r"C:\not-a-driver.dll",
    );
    append_value_part(&mut body, boundary, "pkcs11Slot", "0");
    append_value_part(&mut body, boundary, "alias", "pkcs11:00");
    append_value_part(&mut body, boundary, "password", pin);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = post_body(boundary, body).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response_body = to_bytes(response.into_body(), usize::MAX).await?;
    let response_body = String::from_utf8_lossy(&response_body);
    assert!(response_body.contains("desktop app"));
    assert!(!response_body.contains(pin));
    Ok(())
}

#[tokio::test]
async fn windows_store_signing_is_desktop_gated() -> TestResult {
    let boundary = "stirling-windows-store-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "WINDOWS_STORE");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        &single_page_pdf()?,
    );
    append_value_part(
        &mut body,
        boundary,
        "alias",
        "00112233445566778899aabbccddeeff00112233",
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = post_body(boundary, body).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response_body = to_bytes(response.into_body(), usize::MAX).await?;
    assert!(String::from_utf8_lossy(&response_body).contains("desktop app"));
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
#[ignore = "requires STIRLING_WINDOWS_TEST_CERT_ALIAS and its CurrentUser private key"]
async fn signs_with_a_live_windows_store_certificate() -> TestResult {
    let alias = std::env::var("STIRLING_WINDOWS_TEST_CERT_ALIAS")?;
    let boundary = "stirling-live-windows-store-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "WINDOWS_STORE");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        &single_page_pdf()?,
    );
    append_value_part(&mut body, boundary, "alias", &alias);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = post_body(boundary, body).await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let response_body = to_bytes(response.into_body(), usize::MAX).await?;
        return Err(format!(
            "Windows store signing returned {status}: {}",
            String::from_utf8_lossy(&response_body)
        )
        .into());
    }
    let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    verify_pdf_signature(&signed_pdf)?;
    Ok(())
}

#[tokio::test]
#[allow(deprecated)]
async fn creates_and_signs_a_visible_widget() -> TestResult {
    let (certificate, key) = self_signed_ecdsa_key_pair(None);
    let private_key = pem_document(
        "PRIVATE KEY",
        &key.private_key_data().ok_or("test key is unavailable")?,
    );
    let response = post_cert_sign(
        &single_page_pdf()?,
        &private_key,
        certificate.constructed_data(),
        &[
            ("name", "Visible Test"),
            ("reason", "Approved"),
            ("showSignature", "true"),
            ("pageNumber", "1"),
            ("showLogo", "true"),
        ],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let signed_pdf = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
    verify_pdf_signature(&signed_pdf)?;

    let document = Document::load_mem(&signed_pdf)?;
    let field = signature_field_dictionary(&document)?;
    assert_eq!(field.get(b"Subtype")?.as_name()?, b"Widget");
    assert_eq!(field.get(b"Rect")?.as_array()?.len(), 4);
    let page_id = document.get_pages()[&1];
    assert_eq!(field.get(b"P")?.as_reference()?, page_id);
    let appearance_id = field.get(b"AP")?.as_dict()?.get(b"N")?.as_reference()?;
    assert_eq!(
        document
            .get_object(appearance_id)?
            .as_stream()?
            .dict
            .get(b"Subtype")?
            .as_name()?,
        b"Form"
    );

    let invalid_page = post_cert_sign(
        &single_page_pdf()?,
        &private_key,
        certificate.constructed_data(),
        &[("showSignature", "true"), ("pageNumber", "2")],
    )
    .await?;
    assert_eq!(invalid_page.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

async fn post_jks_sign(
    pdf: &[u8],
    archive: &[u8],
    password: &str,
    alias: Option<&str>,
) -> TestResult<axum::response::Response> {
    let boundary = "stirling-jks-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "JKS");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        pdf,
    );
    append_file_part(
        &mut body,
        boundary,
        "jksFile",
        "signer.jks",
        "application/octet-stream",
        archive,
    );
    append_value_part(&mut body, boundary, "password", password);
    if let Some(alias) = alias {
        append_value_part(&mut body, boundary, "alias", alias);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    post_body(boundary, body).await
}

async fn post_pkcs12_sign(
    pdf: &[u8],
    archive: &[u8],
    cert_type: &str,
    password: &str,
    alias: Option<&str>,
) -> TestResult<axum::response::Response> {
    let boundary = "stirling-pkcs12-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", cert_type);
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        pdf,
    );
    append_file_part(
        &mut body,
        boundary,
        "p12File",
        "signer.p12",
        "application/x-pkcs12",
        archive,
    );
    append_value_part(&mut body, boundary, "password", password);
    if let Some(alias) = alias {
        append_value_part(&mut body, boundary, "alias", alias);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    post_body(boundary, body).await
}

async fn post_cert_sign(
    pdf: &[u8],
    private_key: &str,
    certificate: &[u8],
    values: &[(&str, &str)],
) -> TestResult<axum::response::Response> {
    let boundary = "stirling-cert-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "PEM");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        pdf,
    );
    append_file_part(
        &mut body,
        boundary,
        "privateKeyFile",
        "key.pem",
        "application/x-pem-file",
        private_key.as_bytes(),
    );
    append_file_part(
        &mut body,
        boundary,
        "certFile",
        "certificate.der",
        "application/pkix-cert",
        certificate,
    );
    for (name, value) in values {
        append_value_part(&mut body, boundary, name, value);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    post_body(boundary, body).await
}

async fn post_encrypted_pem_sign(
    pdf: &[u8],
    private_key: &[u8],
    certificate: &[u8],
    password: &str,
) -> TestResult<axum::response::Response> {
    let boundary = "stirling-encrypted-pem-sign-boundary";
    let mut body = Vec::new();
    append_value_part(&mut body, boundary, "certType", "PEM");
    append_file_part(
        &mut body,
        boundary,
        "fileInput",
        "input.pdf",
        "application/pdf",
        pdf,
    );
    append_file_part(
        &mut body,
        boundary,
        "privateKeyFile",
        "key.pem",
        "application/x-pem-file",
        private_key,
    );
    append_file_part(
        &mut body,
        boundary,
        "certFile",
        "certificate.der",
        "application/pkix-cert",
        certificate,
    );
    append_value_part(&mut body, boundary, "password", password);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    post_body(boundary, body).await
}

async fn post_body(boundary: &str, body: Vec<u8>) -> TestResult<axum::response::Response> {
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/cert-sign")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn append_file_part(
    body: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    filename: &str,
    content_type: &str,
    value: &[u8],
) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(value);
    body.extend_from_slice(b"\r\n");
}

fn append_value_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

fn signature_field_dictionary(document: &Document) -> TestResult<&Dictionary> {
    let acro_form_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
    let fields = document
        .get_object(acro_form_id)?
        .as_dict()?
        .get(b"Fields")?
        .as_array()?;
    let field_id = fields
        .first()
        .ok_or_else(|| std::io::Error::other("signature field is missing"))?
        .as_reference()?;
    Ok(document.get_object(field_id)?.as_dict()?)
}

fn signature_dictionary(document: &Document) -> TestResult<&Dictionary> {
    let signature_id = signature_field_dictionary(document)?
        .get(b"V")?
        .as_reference()?;
    Ok(document.get_object(signature_id)?.as_dict()?)
}

fn verify_pdf_signature(signed_pdf: &[u8]) -> TestResult {
    let document = Document::load_mem(signed_pdf)?;
    let signature = signature_dictionary(&document)?;
    let byte_range = signature
        .get(b"ByteRange")?
        .as_array()?
        .iter()
        .map(Object::as_i64)
        .collect::<Result<Vec<_>, _>>()?;
    let first_length = usize::try_from(byte_range[1])?;
    let second_start = usize::try_from(byte_range[2])?;
    let second_length = usize::try_from(byte_range[3])?;
    let mut signed_content = signed_pdf[..first_length].to_vec();
    signed_content.extend_from_slice(&signed_pdf[second_start..second_start + second_length]);
    let signed_data = SignedData::parse_ber(signature.get(b"Contents")?.as_str()?)?;
    for signer in signed_data.signers() {
        signer.verify_message_digest_with_content(&signed_content)?;
        signer.verify_signature_with_signed_data(&signed_data)?;
    }
    Ok(())
}

fn single_page_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
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

#[allow(deprecated)]
fn jks_archive(
    certificate: &x509_certificate::CapturedX509Certificate,
    key: &x509_certificate::InMemorySigningKeyPair,
    password: &[u8],
    alias: &str,
) -> TestResult<Vec<u8>> {
    let mut keystore = JksKeyStore::new();
    keystore.set_private_key_entry(
        alias,
        PrivateKeyEntry {
            creation_time: SystemTime::now(),
            private_key: key
                .private_key_data()
                .ok_or("test key is unavailable")?
                .to_vec(),
            certificate_chain: vec![JksCertificate {
                cert_type: "X.509".to_owned(),
                content: certificate.constructed_data().to_vec(),
            }],
        },
        password,
    )?;
    let mut archive = Vec::new();
    keystore.store(&mut archive, password)?;
    Ok(archive)
}

fn pem_document(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(der)
    )
}
