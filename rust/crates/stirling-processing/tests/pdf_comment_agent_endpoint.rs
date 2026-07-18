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

const PDF_COMMENT_AGENT_PATH: &str = "/api/v1/ai/tools/pdf-comment-agent";

#[tokio::test]
async fn validates_multipart_input_before_contacting_the_engine()
-> Result<(), Box<dyn std::error::Error>> {
    let missing_prompt = post_comment_agent(
        disabled_engine_app()?,
        &basic_pdf(),
        None,
        "application/pdf",
    )
    .await?;
    assert_error(
        missing_prompt,
        StatusCode::BAD_REQUEST,
        "Prompt is required",
    )
    .await?;

    let wrong_content_type = post_comment_agent(
        disabled_engine_app()?,
        &basic_pdf(),
        Some("Review dates"),
        "text/plain",
    )
    .await?;
    assert_error(
        wrong_content_type,
        StatusCode::BAD_REQUEST,
        "Only application/pdf uploads are supported",
    )
    .await?;

    let overlong_prompt = post_comment_agent(
        disabled_engine_app()?,
        &basic_pdf(),
        Some(&"x".repeat(4_001)),
        "application/pdf",
    )
    .await?;
    assert_error(
        overlong_prompt,
        StatusCode::BAD_REQUEST,
        "Prompt exceeds maximum length of 4000 characters",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn returns_service_unavailable_when_ai_engine_is_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_comment_agent(
        disabled_engine_app()?,
        &basic_pdf(),
        Some("Add a note to questionable dates"),
        "application/pdf",
    )
    .await?;
    assert_error(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "AI engine is not enabled",
    )
    .await
}

fn disabled_engine_app() -> Result<Router, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("settings.yml");
    fs::write(
        &settings,
        "aiEngine:\n  enabled: false\n  url: http://127.0.0.1:5001\n  timeoutSeconds: 9\n",
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, directory.path().join("custom.yml"));
    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    ))
}

async fn post_comment_agent(
    app: Router,
    pdf: &[u8],
    prompt: Option<&str>,
    pdf_content_type: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-comment-agent-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: {pdf_content_type}\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    if let Some(prompt) = prompt {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"prompt\"\r\n\r\n{prompt}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(PDF_COMMENT_AGENT_PATH)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn assert_error(
    response: Response,
    expected_status: StatusCode,
    expected_message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    assert!(
        String::from_utf8_lossy(&body).contains(expected_message),
        "response body: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

fn basic_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n".to_vec()
}
