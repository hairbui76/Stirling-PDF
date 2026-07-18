use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

#[tokio::test]
async fn reviewed_security_wraps_the_real_processing_router_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n",
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;

    let health = app
        .clone()
        .oneshot(Request::get("/api/v1/info/status").body(Body::empty())?)
        .await?;
    assert_eq!(health.status(), StatusCode::OK);
    assert!(health.headers().contains_key("x-request-id"));

    let denied = app
        .clone()
        .oneshot(Request::get("/api/v1/config/app-config").body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let login = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"admin@example.test","password":"test-only-password"}"#,
                ))?,
        )
        .await?;
    assert_eq!(login.status(), StatusCode::OK);
    let login: Value = serde_json::from_slice(&to_bytes(login.into_body(), 1024 * 1024).await?)?;
    let access_token = login["session"]["access_token"]
        .as_str()
        .ok_or("missing access token")?;

    let config = app
        .oneshot(
            Request::get("/api/v1/config/app-config")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(config.status(), StatusCode::OK);
    Ok(())
}
