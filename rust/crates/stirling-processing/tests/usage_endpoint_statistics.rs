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

const USAGE_PATH: &str = "/api/v1/proprietary/ui-data/usage-endpoint-statistics";

#[tokio::test]
async fn administrator_endpoint_usage_preserves_java_filters_totals_and_self_capture()
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
        .oneshot(Request::get(USAGE_PATH).body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let token = login_token(&app).await?;
    seed_usage_events(&database)?;
    assert_limited_all(&app, &token).await?;
    assert_invalid_and_unknown(&app, &token).await?;
    assert_ui_and_api_filters(&app, &token).await?;
    Ok(())
}

async fn assert_limited_all(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let all =
        response_json(authorized_get(app, &format!("{USAGE_PATH}?limit=1"), token).await?).await?;
    assert_eq!(all["totalEndpoints"], 4);
    assert_eq!(all["totalVisits"], 5);
    assert_eq!(all["endpoints"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        all["endpoints"][0]["endpoint"],
        "/api/v1/general/merge-pdfs"
    );
    assert_eq!(all["endpoints"][0]["visits"], 2);
    assert_eq!(all["endpoints"][0]["percentage"], 40.0);
    Ok(())
}

async fn assert_invalid_and_unknown(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let malformed = authorized_get(app, &format!("{USAGE_PATH}?days=not-a-number"), token).await?;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

    let unknown = response_json(
        authorized_get(app, &format!("{USAGE_PATH}?dataType=%20api%20"), token).await?,
    )
    .await?;
    assert_eq!(
        unknown,
        serde_json::json!({
            "endpoints": [],
            "totalEndpoints": 0,
            "totalVisits": 0,
        })
    );
    Ok(())
}

async fn assert_ui_and_api_filters(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ui = response_json(
        authorized_get(app, &format!("{USAGE_PATH}?dataType=UI&days=-4"), token).await?,
    )
    .await?;
    assert_eq!(ui["totalEndpoints"], 2);
    assert_eq!(ui["totalVisits"], 4);
    assert_eq!(ui["endpoints"][0]["endpoint"], USAGE_PATH);
    assert_eq!(ui["endpoints"][0]["visits"], 3);
    assert_eq!(ui["endpoints"][0]["percentage"], 75.0);

    let api = response_json(
        authorized_get(
            app,
            &format!("{USAGE_PATH}?dataType=api&limit=0&days=9999"),
            token,
        )
        .await?,
    )
    .await?;
    assert_eq!(api["totalEndpoints"], 3);
    assert_eq!(api["totalVisits"], 4);
    assert_eq!(api["endpoints"].as_array().map(Vec::len), Some(3));
    assert_eq!(
        api["endpoints"][0]["endpoint"],
        "/api/v1/general/merge-pdfs"
    );
    assert_eq!(api["endpoints"][0]["percentage"], 50.0);
    Ok(())
}

fn seed_usage_events(database: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let store = SecurityStore::open(database)?;
    let now = Utc::now().timestamp();
    let context = audit_context();
    for (event_type, path, age) in [
        ("UI_DATA", "/api/v1/ui-data/home?tab=all", 1),
        ("PDF_PROCESS", "/api/v1/general/merge-pdfs?first=true", 2),
        ("PDF_PROCESS", "/api/v1/general/merge-pdfs", 3),
        ("FILE_OPERATION", "/api/v1/file/upload/document", 4),
        ("UI_DATA", "/too-old", 366 * 86_400),
    ] {
        record(&store, &context, event_type, path, now - age)?;
    }
    Ok(())
}

fn audit_context() -> AuthContext {
    AuthContext {
        user_id: 1,
        username: "admin@example.test".to_owned(),
        authentication_source: AuthenticationSource::AccessToken,
        authentication_type: "web".to_owned(),
        roles: BTreeSet::from(["ROLE_ADMIN".to_owned()]),
        team_id: Some(1),
        permissions: BTreeSet::new(),
        external_subject: None,
        force_password_change: false,
        session_id: "usage-test-session".to_owned(),
        correlation_id: "usage-test-request".to_owned(),
    }
}

fn record(
    store: &SecurityStore,
    context: &AuthContext,
    event_type: &str,
    path: &str,
    timestamp: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    store.record_audit(context, event_type, path, "success", timestamp)?;
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
