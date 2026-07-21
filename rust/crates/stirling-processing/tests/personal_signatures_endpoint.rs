use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

#[tokio::test]
async fn authenticated_saved_signatures_preserve_personal_precedence_and_shared_admin_rules()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(&settings_path, "{}\n")?;
    let security_database = config_directory.join("security.db");
    let store = SecurityStore::open(&security_database)?;
    assert!(store.bootstrap_admin("admin@example.test", "test-only-password")?);
    store.create_local_user(
        "user@example.test",
        "user-test-password",
        ["ROLE_USER"],
        None,
    )?;
    store.create_local_user(
        "demo@example.test",
        "demo-test-password",
        ["ROLE_DEMO_USER"],
        None,
    )?;
    drop(store);

    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app = app_with_reviewed_security(
        8 * 1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    )?;
    let admin_token = login(&app, "admin@example.test", "test-only-password").await?;
    let user_token = login(&app, "user@example.test", "user-test-password").await?;
    let demo_token = login(&app, "demo@example.test", "demo-test-password").await?;

    assert_access_rules(&app, &user_token, &demo_token).await?;
    save_personal_and_shared(&app, &user_token, &admin_token).await?;
    assert_listing_and_asset_precedence(&app, &user_token, &admin_token).await?;
    assert_mutation_rules_and_shared_fallback(&app, &user_token, &admin_token).await?;
    Ok(())
}

async fn assert_access_rules(
    app: &axum::Router,
    user_token: &str,
    demo_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        get(app, "/api/v1/proprietary/signatures", None)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(app, "/api/v1/proprietary/signatures", Some(demo_token))
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let denied_shared = post_json(
        app,
        "/api/v1/proprietary/signatures",
        user_token,
        signature("same-id", "shared", b"denied"),
    )
    .await?;
    assert_eq!(denied_shared.status(), StatusCode::FORBIDDEN);
    Ok(())
}

async fn save_personal_and_shared(
    app: &axum::Router,
    user_token: &str,
    admin_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let personal = post_json(
        app,
        "/api/v1/proprietary/signatures",
        user_token,
        signature("same-id", "personal", b"personal-image"),
    )
    .await?;
    assert_eq!(personal.status(), StatusCode::OK);
    let personal = response_json(personal).await?;
    assert_eq!(personal["scope"], "personal");
    assert_eq!(
        personal["dataUrl"],
        "/api/v1/general/signatures/same-id.png"
    );

    let shared = post_json(
        app,
        "/api/v1/proprietary/signatures",
        admin_token,
        signature("same-id", "shared", b"shared-image"),
    )
    .await?;
    assert_eq!(shared.status(), StatusCode::OK);
    Ok(())
}

async fn assert_listing_and_asset_precedence(
    app: &axum::Router,
    user_token: &str,
    admin_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let listed = get(app, "/api/v1/proprietary/signatures", Some(user_token)).await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await?;
    let listed = listed.as_array().ok_or("signature list was not an array")?;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["scope"], "personal");
    assert_eq!(listed[1]["scope"], "shared");

    let personal_asset = get(
        app,
        "/api/v1/general/signatures/same-id.png",
        Some(user_token),
    )
    .await?;
    assert_eq!(personal_asset.status(), StatusCode::OK);
    assert_eq!(response_bytes(personal_asset).await?, b"personal-image");
    let shared_asset = get(
        app,
        "/api/v1/general/signatures/same-id.png",
        Some(admin_token),
    )
    .await?;
    assert_eq!(shared_asset.status(), StatusCode::OK);
    assert_eq!(response_bytes(shared_asset).await?, b"shared-image");
    Ok(())
}

async fn assert_mutation_rules_and_shared_fallback(
    app: &axum::Router,
    user_token: &str,
    admin_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let denied_label = post_json(
        app,
        "/api/v1/proprietary/signatures/same-id/label",
        user_token,
        json!({ "label": "Not Allowed" }),
    )
    .await?;
    assert_eq!(denied_label.status(), StatusCode::FORBIDDEN);

    let deleted_personal =
        delete(app, "/api/v1/proprietary/signatures/same-id", user_token).await?;
    assert_eq!(deleted_personal.status(), StatusCode::NO_CONTENT);
    let fallback_asset = get(
        app,
        "/api/v1/general/signatures/same-id.png",
        Some(user_token),
    )
    .await?;
    assert_eq!(response_bytes(fallback_asset).await?, b"shared-image");
    assert_eq!(
        delete(app, "/api/v1/proprietary/signatures/same-id", user_token)
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        delete(app, "/api/v1/proprietary/signatures/same-id", admin_token)
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    Ok(())
}

fn signature(id: &str, scope: &str, bytes: &[u8]) -> Value {
    json!({
        "id": id,
        "label": "My signature",
        "type": "image",
        "scope": scope,
        "dataUrl": format!("data:image/png;base64,{}", STANDARD.encode(bytes)),
    })
}

async fn login(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "username": username,
                    "password": password,
                }))?))?,
        )
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("login failed for {username}: {}", response.status()).into());
    }
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "login response had no access token".into())
}

async fn get(
    app: &axum::Router,
    path: &str,
    token: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::get(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    Ok(app.clone().oneshot(request.body(Body::empty())?).await?)
}

async fn post_json(
    app: &axum::Router,
    path: &str,
    token: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?)
}

async fn delete(
    app: &axum::Router,
    path: &str,
    token: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::delete(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 8 * 1024 * 1024).await?,
    )?)
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), 8 * 1024 * 1024)
        .await?
        .to_vec())
}
