use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn robots_txt_follows_google_visibility_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let disabled_settings = directory.path().join("disabled.yml");
    fs::write(&disabled_settings, "system:\n  googlevisibility: false\n")?;
    let disabled = request(RuntimeConfig::from_files(
        disabled_settings,
        directory.path().join("disabled-custom.yml"),
    ))
    .await?;
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_eq!(
        disabled
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );
    assert_eq!(
        to_bytes(disabled.into_body(), 1024).await?.as_ref(),
        b"User-agent: *\nDisallow: /\n"
    );

    let enabled_settings = directory.path().join("enabled.yml");
    fs::write(&enabled_settings, "system:\n  googlevisibility: true\n")?;
    let enabled = request(RuntimeConfig::from_files(
        enabled_settings,
        directory.path().join("enabled-custom.yml"),
    ))
    .await?;
    assert_eq!(
        to_bytes(enabled.into_body(), 1024).await?.as_ref(),
        b"User-agent: *\nAllow: /\n"
    );
    Ok(())
}

async fn request(
    runtime_config: RuntimeConfig,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), runtime_config)
            .oneshot(Request::builder().uri("/robots.txt").body(Body::empty())?)
            .await?,
    )
}
