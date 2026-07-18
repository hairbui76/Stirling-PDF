use std::fs;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

const CREATE_PDF_AGENT_PATH: &str = "/api/v1/ai/tools/create-pdf-from-html-agent";

#[tokio::test]
async fn requires_document_and_filename_multipart_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let missing_document =
        post_create_pdf_agent(disabled_engine_app()?, None, Some("report.pdf")).await?;
    assert_error(
        missing_document,
        StatusCode::BAD_REQUEST,
        "document is required",
    )
    .await?;

    let missing_filename = post_create_pdf_agent(disabled_engine_app()?, Some("{}"), None).await?;
    assert_error(
        missing_filename,
        StatusCode::BAD_REQUEST,
        "filename is required",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn returns_not_found_when_the_ai_engine_is_disabled() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_create_pdf_agent(
        disabled_engine_app()?,
        Some(r#"{"title":"Generated invoice"}"#),
        Some("invoice.pdf"),
    )
    .await?;
    assert_error(response, StatusCode::NOT_FOUND, "AI engine is not enabled").await
}

fn disabled_engine_app() -> Result<Router, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("settings.yml");
    fs::write(&settings, "aiEngine:\n  enabled: false\n")?;
    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        RuntimeConfig::from_files(settings, directory.path().join("custom.yml")),
    ))
}

async fn post_create_pdf_agent(
    app: Router,
    document: Option<&str>,
    filename: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-create-pdf-agent-boundary";
    let mut body = Vec::new();
    if let Some(document) = document {
        append_text_field(&mut body, boundary, "document", document);
    }
    if let Some(filename) = filename {
        append_text_field(&mut body, boundary, "filename", filename);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(CREATE_PDF_AGENT_PATH)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn append_text_field(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

async fn assert_error(
    response: Response,
    expected_status: StatusCode,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), expected_status);
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert!(
        String::from_utf8_lossy(&body).contains(expected_message),
        "response body: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}
