use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, LoadOptions, Object, Permissions, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn adds_all_supported_key_lengths_and_removes_a_password()
-> Result<(), Box<dyn std::error::Error>> {
    let source = basic_pdf()?;
    let mut encrypted_128 = None;
    for key_length in [40, 128, 256] {
        let key_length_string = key_length.to_string();
        let response = require_status(
            post_password(
                "/api/v1/security/add-password",
                &source,
                &[
                    ("ownerPassword", "owner-secret"),
                    ("password", "user-secret"),
                    ("keyLength", key_length_string.as_str()),
                    ("preventPrinting", "true"),
                    ("preventModify", "true"),
                ],
            )
            .await?,
            StatusCode::OK,
        )
        .await?;
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("source_passworded.pdf")
        );
        let encrypted = response_bytes(response).await?;
        assert!(
            Document::load_mem_with_options(&encrypted, LoadOptions::with_password("wrong"),)
                .is_err()
        );
        let document =
            Document::load_mem_with_options(&encrypted, LoadOptions::with_password("user-secret"))?;
        let state = document
            .encryption_state
            .as_ref()
            .ok_or("missing encryption state")?;
        assert_eq!(effective_key_length(state), key_length);
        let permissions = state.permissions();
        assert!(!permissions.contains(Permissions::PRINTABLE));
        assert!(!permissions.contains(Permissions::MODIFIABLE));
        assert!(permissions.contains(Permissions::COPYABLE));
        if key_length == 128 {
            encrypted_128 = Some(encrypted);
        }
    }

    let encrypted = encrypted_128.ok_or("missing 128-bit fixture")?;
    let wrong = post_password(
        "/api/v1/security/remove-password",
        &encrypted,
        &[("password", "wrong")],
    )
    .await?;
    assert_eq!(wrong.status(), StatusCode::BAD_REQUEST);

    let response = require_status(
        post_password(
            "/api/v1/security/remove-password",
            &encrypted,
            &[("password", "user-secret")],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_password_removed.pdf")
    );
    let decrypted = response_bytes(response).await?;
    let document = Document::load_mem(&decrypted)?;
    assert!(!document.was_encrypted());
    assert_eq!(document.get_pages().len(), 1);
    Ok(())
}

#[tokio::test]
async fn applies_permissions_with_empty_passwords_and_default_256_bits()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_password(
            "/api/v1/security/add-password",
            &basic_pdf()?,
            &[("preventAssembly", "true")],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_permissions.pdf")
    );
    let encrypted = response_bytes(response).await?;
    let document = Document::load_mem(&encrypted)?;
    let state = document
        .encryption_state
        .as_ref()
        .ok_or("missing encryption state")?;
    assert_eq!(effective_key_length(state), 256);
    assert!(!state.permissions().contains(Permissions::ASSEMBLABLE));
    Ok(())
}

fn effective_key_length(state: &lopdf::EncryptionState) -> usize {
    state
        .key_length()
        .unwrap_or_else(|| state.file_encryption_key().len() * 8)
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = response_bytes(response).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

async fn post_password(
    path: &str,
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-password-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn basic_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
