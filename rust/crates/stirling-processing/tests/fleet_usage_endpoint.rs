use std::{collections::BTreeSet, fs};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use chrono::Utc;
use serde_json::Value;
use stirling_processing::{
    TimestampSettings,
    runtime_config::RuntimeConfig,
    security::{AuthContext, AuthenticationSource, SecurityStore},
    security_policy::LicenseTier,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

mod support;

use support::reviewed_security_app_at_tier;

#[tokio::test]
async fn self_hosted_fleet_stats_count_users_and_standard_web_audit_events()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\npremium:\n  enterpriseFeatures:\n    audit:\n      enabled: true\n      level: 2\n",
    )?;
    let database = config_directory.join("security.db");
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app = reviewed_security_app_at_tier(
        1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
        LicenseTier::Enterprise,
    )?;

    let denied = app
        .clone()
        .oneshot(Request::get("/api/v1/usage/fleet-stats").body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let now = Utc::now().timestamp();
    let store = SecurityStore::open(&database)?;
    record(
        &store,
        "alpha@example.test",
        AuthenticationSource::AccessToken,
        "PDF_PROCESS",
        now - 1,
    )?;
    record(
        &store,
        "beta@example.test",
        AuthenticationSource::AccessToken,
        "FILE_OPERATION",
        now - 2,
    )?;
    record(
        &store,
        "ignored@example.test",
        AuthenticationSource::AccessToken,
        "UI_DATA",
        now - 3,
    )?;
    record(
        &store,
        "old@example.test",
        AuthenticationSource::AccessToken,
        "PDF_PROCESS",
        now - 31 * 24 * 60 * 60,
    )?;
    record(
        &store,
        "api@example.test",
        AuthenticationSource::ApiKey,
        "PDF_PROCESS",
        now - 4,
    )?;
    drop(store);

    let admin_token = login_token(&app).await?;
    let response = authorized_get(&app, "/api/v1/usage/fleet-stats", &admin_token).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await?,
        serde_json::json!({
            "editorsDeployed": 1,
            "activeThisMonth": 1,
            "pdfsProcessed": 3,
        })
    );
    Ok(())
}

#[tokio::test]
async fn self_hosted_fleet_stats_return_null_audit_figures_below_standard()
-> Result<(), Box<dyn std::error::Error>> {
    for audit in [
        "      enabled: false\n      level: 3\n",
        "      enabled: true\n      level: 1\n",
        "      enabled: true\n      level: -1\n",
    ] {
        let directory = tempdir()?;
        let config_directory = directory.path().join("configs");
        fs::create_dir_all(&config_directory)?;
        let settings = config_directory.join("settings.yml");
        fs::write(
            &settings,
            format!(
                "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\npremium:\n  enterpriseFeatures:\n    audit:\n{audit}"
            ),
        )?;
        let runtime_config =
            RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
        let app = reviewed_security_app_at_tier(
            1024 * 1024,
            TimestampSettings::default(),
            runtime_config,
            LicenseTier::Enterprise,
        )?;
        let admin_token = login_token(&app).await?;
        let stats =
            response_json(authorized_get(&app, "/api/v1/usage/fleet-stats", &admin_token).await?)
                .await?;
        assert_eq!(stats["editorsDeployed"], 1);
        assert!(stats["activeThisMonth"].is_null());
        assert!(stats["pdfsProcessed"].is_null());
    }
    Ok(())
}

fn record(
    store: &SecurityStore,
    principal: &str,
    authentication_source: AuthenticationSource,
    event_type: &str,
    timestamp: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    store.record_audit(
        &AuthContext {
            user_id: 1,
            username: principal.to_owned(),
            authentication_source,
            authentication_type: "web".to_owned(),
            roles: BTreeSet::from(["ROLE_ADMIN".to_owned()]),
            team_id: Some(1),
            permissions: BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: format!("session-{principal}"),
            correlation_id: format!("request-{principal}"),
        },
        event_type,
        "/api/v1/general/test",
        "success",
        timestamp,
    )?;
    Ok(())
}

async fn login_token(app: &axum::Router) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"admin@example.test","password":"test-only-password"}"#,
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn authorized_get(
    app: &axum::Router,
    path: &str,
    token: &str,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn response_json(
    response: axum::response::Response,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1024 * 1024).await?,
    )?)
}
