use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

const LANGUAGES_PATH: &str = "/api/v1/ui-data/tessdata-languages";
const DOWNLOAD_PATH: &str = "/api/v1/ui-data/tessdata/download";

#[tokio::test]
async fn tessdata_administration_requires_an_administrator_and_valid_languages()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        format!(
            "system:\n  tessdataDir: {}\n",
            directory.path().join("tessdata").display()
        ),
    )?;

    let store = SecurityStore::open(&config_directory.join("security.db"))?;
    assert!(store.bootstrap_admin("admin@example.test", "test-only-password")?);
    store.create_local_user(
        "user@example.test",
        "user-test-password",
        ["ROLE_USER"],
        None,
    )?;
    drop(store);

    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;

    assert_eq!(
        get(&app, LANGUAGES_PATH, None).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    let user_token = login(&app, "user@example.test", "user-test-password").await?;
    assert_eq!(
        get(&app, LANGUAGES_PATH, Some(&user_token)).await?.status(),
        StatusCode::FORBIDDEN
    );

    let admin_token = login(&app, "admin@example.test", "test-only-password").await?;
    let missing = post_json(&app, DOWNLOAD_PATH, &admin_token, json!({})).await?;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing).await?,
        json!({ "message": "No languages provided for download" })
    );
    let empty = post_json(
        &app,
        DOWNLOAD_PATH,
        &admin_token,
        json!({ "languages": [] }),
    )
    .await?;
    assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(empty).await?,
        json!({ "message": "No languages provided for download" })
    );
    Ok(())
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

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1024 * 1024).await?,
    )?)
}
