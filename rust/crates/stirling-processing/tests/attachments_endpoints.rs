use std::{
    io::{Cursor, Read},
    process::Command,
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn add_list_extract_rename_and_delete_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let source = basic_pdf()?;
    let response = require_status(
        post_pdf(
            "/api/v1/misc/add-attachments",
            &source,
            &[("convertToPdfA3b", "false")],
            &[("alpha.txt", "text/plain", b"alpha data")],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_with_attachments.pdf")
    );
    let added = response_bytes(response).await?;
    let added_document = Document::load_mem(&added)?;
    assert_eq!(
        added_document.catalog()?.get(b"PageMode")?.as_name()?,
        b"UseAttachments"
    );

    let listed =
        json_response(post_pdf("/api/v1/misc/list-attachments", &added, &[], &[]).await?).await?;
    assert_eq!(listed.as_array().ok_or("expected array")?.len(), 1);
    assert_eq!(listed[0]["filename"], "alpha.txt");
    assert_eq!(listed[0]["size"], 10);
    assert_eq!(listed[0]["contentType"], "text/plain");
    assert_eq!(listed[0]["description"], "Embedded attachment: alpha.txt");
    assert!(listed[0]["creationDate"].as_str().is_some());

    let extracted_response = require_status(
        post_pdf("/api/v1/misc/extract-attachments", &added, &[], &[]).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        extracted_response.headers()[header::CONTENT_TYPE],
        "application/zip"
    );
    let extracted = response_bytes(extracted_response).await?;
    let mut archive = ZipArchive::new(Cursor::new(extracted))?;
    let mut entry = archive.by_name("alpha.txt")?;
    let mut attachment = Vec::new();
    entry.read_to_end(&mut attachment)?;
    assert_eq!(attachment, b"alpha data");
    drop(entry);
    drop(archive);

    let renamed_response = require_status(
        post_pdf(
            "/api/v1/misc/rename-attachment",
            &added,
            &[("attachmentName", "alpha.txt"), ("newName", "renamed.txt")],
            &[],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let renamed = response_bytes(renamed_response).await?;
    let listed =
        json_response(post_pdf("/api/v1/misc/list-attachments", &renamed, &[], &[]).await?).await?;
    assert_eq!(listed[0]["filename"], "renamed.txt");

    let deleted_response = require_status(
        post_pdf(
            "/api/v1/misc/delete-attachment",
            &renamed,
            &[("attachmentName", "renamed.txt")],
            &[],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let deleted = response_bytes(deleted_response).await?;
    let listed =
        json_response(post_pdf("/api/v1/misc/list-attachments", &deleted, &[], &[]).await?).await?;
    assert_eq!(listed, Value::Array(Vec::new()));
    Ok(())
}

#[tokio::test]
async fn validates_missing_attachments_and_optionally_creates_pdfa3b()
-> Result<(), Box<dyn std::error::Error>> {
    let source = basic_pdf()?;
    let missing = post_pdf("/api/v1/misc/add-attachments", &source, &[], &[]).await?;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);

    let pdfa = post_pdf(
        "/api/v1/misc/add-attachments",
        &source,
        &[("convertToPdfA3b", "true")],
        &[("alpha.txt", "text/plain", b"alpha")],
    )
    .await?;
    if !ghostscript_present() {
        assert_eq!(pdfa.status(), StatusCode::NOT_IMPLEMENTED);
        let body = response_bytes(pdfa).await?;
        assert!(String::from_utf8_lossy(&body).contains("Ghostscript"));
        return Ok(());
    }
    let pdfa = require_status(pdfa, StatusCode::OK).await?;
    assert!(
        pdfa.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_with_attachments_PDFA-3b.pdf")
    );
    let document = Document::load_mem(&response_bytes(pdfa).await?)?;
    assert_eq!(document.catalog()?.get(b"AF")?.as_array()?.len(), 1);
    Ok(())
}

fn ghostscript_present() -> bool {
    let candidates: &[&str] = if cfg!(windows) {
        &["gswin64c", "gswin32c", "gs"]
    } else {
        &["gs"]
    };
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    candidates
        .iter()
        .any(|command| Command::new(command).arg("--version").output().is_ok())
}

async fn json_response(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    Ok(serde_json::from_slice(&response_bytes(response).await?)?)
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

async fn post_pdf(
    path: &str,
    pdf: &[u8],
    fields: &[(&str, &str)],
    attachments: &[(&str, &str, &[u8])],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-attachment-boundary";
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
    for (filename, content_type, data) in attachments {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"attachments\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
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
