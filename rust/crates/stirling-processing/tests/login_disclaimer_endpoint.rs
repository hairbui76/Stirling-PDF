use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn serves_the_requested_locale_then_the_base_locale() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let settings = directory.path().join("configs/settings.yml");
    let disclaimer = directory.path().join("customFiles/disclaimer/vi.md");
    fs::create_dir_all(settings.parent().ok_or("missing settings parent")?)?;
    fs::create_dir_all(disclaimer.parent().ok_or("missing disclaimer parent")?)?;
    fs::write(
        &settings,
        "system:\n  defaultLocale: en-US\nlegal:\n  loginAgreement:\n    enabled: true\n    showInAnonymousMode: false\n    fallbackText: fallback\n",
    )?;
    fs::write(&disclaimer, "# Thoa thuan\n")?;

    let response = get_disclaimer(
        RuntimeConfig::from_files(
            settings,
            directory.path().join("configs/custom_settings.yml"),
        ),
        "/api/v1/config/login-disclaimer?lang=vi-VN",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_store(&response);
    let body = json_body(response).await?;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["showInAnonymousMode"], false);
    assert_eq!(body["content"], "# Thoa thuan\n");
    assert_eq!(body["format"], "markdown");
    Ok(())
}

#[tokio::test]
async fn disabled_login_agreement_does_not_expose_local_content()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("configs/settings.yml");
    let disclaimer = directory.path().join("customFiles/disclaimer/en-US.md");
    fs::create_dir_all(settings.parent().ok_or("missing settings parent")?)?;
    fs::create_dir_all(disclaimer.parent().ok_or("missing disclaimer parent")?)?;
    fs::write(
        &settings,
        "legal:\n  loginAgreement:\n    enabled: false\n    showInAnonymousMode: false\n",
    )?;
    fs::write(&disclaimer, "private agreement")?;

    let response = get_disclaimer(
        RuntimeConfig::from_files(
            settings,
            directory.path().join("configs/custom_settings.yml"),
        ),
        "/api/v1/config/login-disclaimer",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["enabled"], false);
    assert_eq!(body["showInAnonymousMode"], false);
    assert_eq!(body["content"], "");
    Ok(())
}

#[tokio::test]
async fn rejects_path_like_locales_and_oversized_disclaimers()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings = directory.path().join("configs/settings.yml");
    let disclaimer = directory.path().join("customFiles/disclaimer/en-US.md");
    fs::create_dir_all(settings.parent().ok_or("missing settings parent")?)?;
    fs::create_dir_all(disclaimer.parent().ok_or("missing disclaimer parent")?)?;
    fs::write(
        &settings,
        "system:\n  defaultLocale: en-US\nlegal:\n  loginAgreement:\n    enabled: true\n    fallbackText: fallback agreement\n",
    )?;
    fs::write(&disclaimer, "x".repeat(256 * 1024 + 1))?;

    let runtime_config = RuntimeConfig::from_files(
        settings,
        directory.path().join("configs/custom_settings.yml"),
    );
    let response = get_disclaimer(
        runtime_config,
        "/api/v1/config/login-disclaimer?lang=..%2Fsecret",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["content"], "fallback agreement");
    Ok(())
}

#[tokio::test]
async fn requires_authentication_when_login_is_configured() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let settings = directory.path().join("configs/settings.yml");
    fs::create_dir_all(settings.parent().ok_or("missing settings parent")?)?;
    fs::write(&settings, "security:\n  enableLogin: true\n")?;

    let response = get_disclaimer(
        RuntimeConfig::from_files(
            settings,
            directory.path().join("configs/custom_settings.yml"),
        ),
        "/api/v1/config/login-disclaimer",
    )
    .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_store(&response);
    Ok(())
}

async fn get_disclaimer(
    runtime_config: RuntimeConfig,
    uri: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), runtime_config)
            .oneshot(Request::builder().uri(uri).body(Body::empty())?)
            .await?,
    )
}

async fn json_body(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&body)?)
}

fn assert_no_store(response: &Response) {
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
}
