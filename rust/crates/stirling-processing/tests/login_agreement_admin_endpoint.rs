use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;

const ADMIN_LOGIN_AGREEMENT_PATH: &str = "/api/v1/admin/login-agreement";

#[tokio::test]
async fn administrator_manages_live_login_agreement_files() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, app) = agreement_app()?;
    let denied = app
        .clone()
        .oneshot(Request::get(ADMIN_LOGIN_AGREEMENT_PATH).body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let admin_token = login_token(&app, "admin@example.test", "test-only-password").await?;
    let written = authorized_json_put(
        &app,
        &format!("{ADMIN_LOGIN_AGREEMENT_PATH}/en-US"),
        &admin_token,
        serde_json::json!({ "content": "# Login terms\n" }),
    )
    .await?;
    assert_eq!(written.status(), StatusCode::NO_CONTENT);

    let listed =
        response_json(authorized_get(&app, ADMIN_LOGIN_AGREEMENT_PATH, &admin_token).await?)
            .await?;
    assert_eq!(listed, serde_json::json!(["en-US"]));
    let read = response_json(
        authorized_get(
            &app,
            &format!("{ADMIN_LOGIN_AGREEMENT_PATH}/en-US"),
            &admin_token,
        )
        .await?,
    )
    .await?;
    assert_eq!(read["locale"], "en-US");
    assert_eq!(read["content"], "# Login terms\n");

    let public = response_json(
        authorized_get(
            &app,
            "/api/v1/config/login-disclaimer?lang=en-US",
            &admin_token,
        )
        .await?,
    )
    .await?;
    assert_eq!(public["enabled"], true);
    assert_eq!(public["content"], "# Login terms\n");

    let invalid = authorized_get(
        &app,
        &format!("{ADMIN_LOGIN_AGREEMENT_PATH}/..%2Fsecret"),
        &admin_token,
    )
    .await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let cleared = authorized_json_put(
        &app,
        &format!("{ADMIN_LOGIN_AGREEMENT_PATH}/en-US"),
        &admin_token,
        serde_json::json!({ "content": "  \n" }),
    )
    .await?;
    assert_eq!(cleared.status(), StatusCode::NO_CONTENT);
    let cleared = response_json(
        authorized_get(
            &app,
            &format!("{ADMIN_LOGIN_AGREEMENT_PATH}/en-US"),
            &admin_token,
        )
        .await?,
    )
    .await?;
    assert_eq!(cleared["content"], "");
    Ok(())
}

#[tokio::test]
async fn non_administrator_cannot_manage_login_agreements() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, app) = agreement_app()?;
    let admin_token = login_token(&app, "admin@example.test", "test-only-password").await?;
    let created = authorized_multipart(
        &app,
        "/api/v1/user/admin/saveUser",
        &admin_token,
        &[
            ("username", "agreement-user@example.test"),
            ("password", "agreement-user-password"),
            ("role", "ROLE_USER"),
            ("authType", "WEB"),
        ],
    )
    .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let user_token = login_token(
        &app,
        "agreement-user@example.test",
        "agreement-user-password",
    )
    .await?;

    let forbidden = authorized_get(&app, ADMIN_LOGIN_AGREEMENT_PATH, &user_token).await?;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    Ok(())
}

fn agreement_app() -> Result<(TempDir, axum::Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nlegal:\n  loginAgreement:\n    enabled: true\n",
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
    Ok((directory, app))
}

async fn login_token(
    app: &axum::Router,
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
    if response.status() != StatusCode::OK {
        return Err("login failed".into());
    }
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn authorized_get(
    app: &axum::Router,
    path: &str,
    token: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn authorized_json_put(
    app: &axum::Router,
    path: &str,
    token: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::put(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?)
}

async fn authorized_multipart(
    app: &axum::Router,
    path: &str,
    token: &str,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-login-agreement-boundary";
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
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1024 * 1024).await?,
    )?)
}
