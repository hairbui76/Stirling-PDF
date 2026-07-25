use std::{io::Write, process::Command};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use stirling_processing::app;
use tower::ServiceExt;
use zip::{ZipWriter, write::SimpleFileOptions};

#[tokio::test]
async fn rejects_an_unknown_extension() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_file(b"not a real document", "notes.xyz").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn rejects_unsafe_office_xml_before_starting_libreoffice()
-> Result<(), Box<dyn std::error::Error>> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut archive = ZipWriter::new(cursor);
    archive.start_file("_rels/.rels", SimpleFileOptions::default())?;
    archive.write_all(
        br#"<!DOCTYPE Relationships [<!ENTITY leak SYSTEM "file:///etc/passwd">]><Relationships>&leak;</Relationships>"#,
    )?;
    let bytes = archive.finish()?.into_inner();
    let response = post_file(&bytes, "unsafe.docx").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn converts_sanitized_html_or_reports_missing_libreoffice()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_file(
        b"<html><body><h1>Safe</h1><script>alert(1)</script><img src=https://internal/secret></body></html>",
        "page.html",
    )
    .await?;
    if libreoffice_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert!(response_bytes(response).await?.starts_with(b"%PDF"));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

#[tokio::test]
async fn converts_a_text_file_or_reports_missing_libreoffice()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_file(b"hello scanner world\n", "notes.txt").await?;
    if libreoffice_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("notes_convertedToPDF.pdf")
        );
        let bytes = response_bytes(response).await?;
        assert!(bytes.starts_with(b"%PDF"));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

fn libreoffice_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_SOFFICE_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["soffice.com", "soffice.exe", "soffice"]
    } else {
        &["soffice", "/usr/bin/soffice"]
    };
    candidates
        .iter()
        .any(|command| Command::new(command).arg("--version").output().is_ok())
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

async fn post_file(content: &[u8], filename: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-file-to-pdf-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/file/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}
