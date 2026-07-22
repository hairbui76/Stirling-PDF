use std::fs;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use stirling_processing::{
    TimestampSettings, app, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn disabled_url_conversion_is_rejected_by_the_api_interceptor()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_url(app(2 * 1024 * 1024), &[]).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_no_store(&response);
    Ok(())
}

#[tokio::test]
async fn requires_url_input_when_url_conversion_is_enabled()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_url(url_enabled_app()?, &[]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_store(&response);
    Ok(())
}

#[tokio::test]
async fn redirects_when_enabled_url_conversion_receives_an_unsafe_url()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_url(url_enabled_app()?, &[("urlInput", "file:///etc/passwd")]).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response.headers().contains_key(header::LOCATION));
    assert_no_store(&response);
    Ok(())
}

fn url_enabled_app() -> Result<Router, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("settings.yml");
    fs::write(&settings, "system:\n  enableUrlToPDF: true\n")?;
    let runtime_config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));
    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    ))
}

async fn post_url(
    app: Router,
    fields: &[(&str, &str)],
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-url-to-pdf-boundary";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/url/pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
}
