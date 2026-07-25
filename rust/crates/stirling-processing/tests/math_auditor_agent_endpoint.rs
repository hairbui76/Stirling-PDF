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

const MATH_AUDITOR_AGENT_PATH: &str = "/api/v1/ai/tools/math-auditor-agent";

#[tokio::test]
async fn validates_pdf_multipart_input_and_negative_tolerance()
-> Result<(), Box<dyn std::error::Error>> {
    let wrong_content_type = post_math_auditor(
        disabled_engine_app()?,
        Some((b"not a PDF", "text/plain")),
        Some("0.01"),
    )
    .await?;
    assert_error(
        wrong_content_type,
        StatusCode::BAD_REQUEST,
        "Only application/pdf uploads are supported",
    )
    .await?;

    let negative_tolerance = post_math_auditor(
        disabled_engine_app()?,
        Some((&basic_pdf(), "application/pdf")),
        Some("-0.01"),
    )
    .await?;
    assert_error(
        negative_tolerance,
        StatusCode::BAD_REQUEST,
        "tolerance must be a non-negative decimal",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn returns_service_unavailable_when_the_ai_engine_is_disabled()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_math_auditor(
        disabled_engine_app()?,
        Some((&basic_pdf(), "application/pdf")),
        None,
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
    fs::write(&settings, "aiEngine:\n  enabled: false\n")?;
    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        RuntimeConfig::from_files(settings, directory.path().join("custom.yml")),
    ))
}

async fn post_math_auditor(
    app: Router,
    file: Option<(&[u8], &str)>,
    tolerance: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-math-auditor-boundary";
    let mut body = Vec::new();
    if let Some((pdf, content_type)) = file {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(pdf);
        body.extend_from_slice(b"\r\n");
    }
    if let Some(tolerance) = tolerance {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"tolerance\"\r\n\r\n{tolerance}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(MATH_AUDITOR_AGENT_PATH)
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
