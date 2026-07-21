use std::fs;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, app_with_runtime_config,
    runtime_config::RuntimeConfig,
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;

const LABELS_PATH: &str = "/api/v1/classification/labels";
const CLASSIFY_PATH: &str = "/api/v1/ai/tools/classify-and-label";

#[tokio::test]
async fn disabled_policies_hide_label_crud_and_classification_passes_through()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app) = open_app("policies:\n  enabled: false\n")?;
    let labels = app
        .clone()
        .oneshot(Request::get(LABELS_PATH).body(Body::empty())?)
        .await?;
    assert_eq!(labels.status(), StatusCode::NOT_FOUND);

    let source = b"%PDF-1.4\npass-through fixture\n%%EOF\n";
    let response = post_pdf(&app, source, None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &to_bytes(response.into_body(), usize::MAX).await?[..],
        source
    );
    Ok(())
}

#[tokio::test]
async fn open_mode_manages_the_team_zero_vocabulary_and_rejects_null_labels()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app) = open_app("policies:\n  enabled: true\naiEngine:\n  enabled: false\n")?;
    let missing = app
        .clone()
        .oneshot(Request::get(LABELS_PATH).body(Body::empty())?)
        .await?;
    assert_eq!(missing.status(), StatusCode::NO_CONTENT);

    for body in [serde_json::json!({}), serde_json::json!({"labels": null})] {
        let invalid = json_put(&app, LABELS_PATH, None, body).await?;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }
    let vocabulary = serde_json::json!({
        "labels": [{"id": "invoice", "name": "Invoice", "icon": "receipt-long"}]
    });
    let saved = json_put(&app, LABELS_PATH, None, vocabulary.clone()).await?;
    assert_eq!(saved.status(), StatusCode::OK);
    assert_eq!(response_json(saved).await?, vocabulary);
    assert_eq!(
        response_json(
            app.clone()
                .oneshot(Request::get(LABELS_PATH).body(Body::empty())?)
                .await?,
        )
        .await?,
        vocabulary
    );

    let disabled_engine = post_pdf(&app, b"%PDF-1.4\n%%EOF\n", None).await?;
    assert_eq!(disabled_engine.status(), StatusCode::SERVICE_UNAVAILABLE);

    let deleted = app
        .clone()
        .oneshot(Request::delete(LABELS_PATH).body(Body::empty())?)
        .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn secured_mode_requires_authentication_and_admin_for_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app) = secured_app()?;
    let unauthenticated =
        json_put(&app, LABELS_PATH, None, serde_json::json!({"labels": []})).await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let admin = login_token(&app, "admin@example.test", "test-only-password").await?;
    let create_user = authorized_multipart(
        &app,
        "/api/v1/user/admin/saveUser",
        &admin,
        &[
            ("username", "labels-user@example.test"),
            ("password", "labels-user-password"),
            ("role", "ROLE_USER"),
            ("authType", "WEB"),
        ],
    )
    .await?;
    assert_eq!(create_user.status(), StatusCode::OK);
    let user = login_token(&app, "labels-user@example.test", "labels-user-password").await?;
    let forbidden = json_put(
        &app,
        LABELS_PATH,
        Some(&user),
        serde_json::json!({"labels": []}),
    )
    .await?;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let saved = json_put(
        &app,
        LABELS_PATH,
        Some(&admin),
        serde_json::json!({"labels": [{"id": "contract", "name": "Contract"}]}),
    )
    .await?;
    assert_eq!(saved.status(), StatusCode::OK);
    drop(directory);
    Ok(())
}

fn open_app(settings_yaml: &str) -> Result<(TempDir, Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(&settings, settings_yaml)?;
    let config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    Ok((
        directory,
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), config),
    ))
}

fn secured_app() -> Result<(TempDir, Router), Box<dyn std::error::Error>> {
    let yaml = "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\npolicies:\n  enabled: true\n";
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(&settings, yaml)?;
    let config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app = app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), config)?;
    Ok((directory, app))
}

async fn post_pdf(
    app: &Router,
    source: &[u8],
    token: Option<&str>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-classification-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(source);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let mut request = Request::post(CLASSIFY_PATH)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))?;
    if let Some(token) = token {
        request
            .headers_mut()
            .insert(header::AUTHORIZATION, format!("Bearer {token}").parse()?);
    }
    Ok(app.clone().oneshot(request).await?)
}

async fn json_put(
    app: &Router,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::put(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body)?))?;
    if let Some(token) = token {
        request
            .headers_mut()
            .insert(header::AUTHORIZATION, format!("Bearer {token}").parse()?);
    }
    Ok(app.clone().oneshot(request).await?)
}

async fn login_token(
    app: &Router,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "username": username,
                    "password": password,
                }))?))?,
        )
        .await?;
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn authorized_multipart(
    app: &Router,
    path: &str,
    token: &str,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-classification-user-boundary";
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
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&body)?)
}
