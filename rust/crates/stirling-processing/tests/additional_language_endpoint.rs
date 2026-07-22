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
async fn serves_legacy_language_javascript_with_the_ui_allowlist()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("settings.yml");
    fs::write(&settings, "ui:\n  languages: [vi_VN]\n")?;
    let runtime_config =
        RuntimeConfig::from_files(settings, directory.path().join("custom_settings.yml"));
    let response =
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), runtime_config)
            .oneshot(
                Request::builder()
                    .uri("/js/additionalLanguageCode.js")
                    .body(Body::empty())?,
            )
            .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/javascript")
    );
    let javascript =
        String::from_utf8(to_bytes(response.into_body(), 1024 * 1024).await?.to_vec())?;
    let languages = javascript
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("const supportedLanguages = "))
        .and_then(|line| line.strip_suffix(';'))
        .ok_or("missing supportedLanguages declaration")?;
    assert_eq!(languages, "[\"vi_VN\"]");
    assert!(javascript.contains("function getDetailedLanguageCode()"));
    assert!(javascript.contains("return \"en_US\";"));
    Ok(())
}
