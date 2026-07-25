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
async fn rejects_non_markdown_and_packages_without_markdown()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_file(b"hello", "notes.txt").await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_file(&zip_without_markdown()?, "package.zip")
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn converts_markdown_or_reports_missing_weasyprint() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_file(
        b"# Safe title\n\n| A | B |\n| - | - |\n| 1 | 2 |\n",
        "page.md",
    )
    .await?;
    if weasyprint_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("page.pdf")
        );
        assert!(response_bytes(response).await?.starts_with(b"%PDF"));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

async fn post_file(content: &[u8], filename: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-markdown-to-pdf-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/markdown/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn zip_without_markdown() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut archive = ZipWriter::new(std::io::Cursor::new(&mut bytes));
    archive.start_file("notes.txt", SimpleFileOptions::default())?;
    archive.write_all(b"not markdown")?;
    archive.finish()?;
    Ok(bytes)
}

fn weasyprint_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_WEASYPRINT_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["weasyprint.exe", "weasyprint"]
    } else {
        &["weasyprint", "/usr/bin/weasyprint"]
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
