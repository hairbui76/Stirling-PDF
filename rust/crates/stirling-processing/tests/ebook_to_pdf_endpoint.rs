use std::process::Command;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn rejects_unsupported_extensions_and_invalid_options()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_ebook(b"not an ebook", "book.pdf", &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_ebook(
            b"chapter",
            "book.txt",
            &[("includePageNumbers", "sometimes")]
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn converts_ebook_or_reports_missing_calibre() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_ebook(
        b"Chapter one\n\nA small book for conversion.\n",
        "book.txt",
        &[
            ("embedAllFonts", "true"),
            ("includeTableOfContents", "true"),
            ("includePageNumbers", "true"),
            ("optimizeForEbook", "true"),
        ],
    )
    .await?;
    if calibre_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("book_convertedToPDF.pdf")
        );
        assert!(response_bytes(response).await?.starts_with(b"%PDF"));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

async fn post_ebook(
    content: &[u8],
    filename: &str,
    options: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-ebook-to-pdf-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(content);
    for (name, value) in options {
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/ebook/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn calibre_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_EBOOK_CONVERT_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["ebook-convert.exe", "ebook-convert"]
    } else {
        &["ebook-convert", "/usr/bin/ebook-convert"]
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
