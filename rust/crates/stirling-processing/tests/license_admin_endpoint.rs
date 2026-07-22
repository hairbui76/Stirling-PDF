use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

const INSTALLATION_ID: &str = "/api/v1/admin/installation-id";
const LICENSE_KEY: &str = "/api/v1/admin/license-key";
const LICENSE_RESYNC: &str = "/api/v1/admin/license/resync";
const LICENSE_INFO: &str = "/api/v1/admin/license-info";
const LICENSE_FILE: &str = "/api/v1/admin/license-file";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn administrator_manages_the_live_license_lifecycle() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        "premium:\n  enabled: false\n  key: ''\n  maxUsers: 5\n",
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
        RuntimeConfig::from_files(&settings_path, config_directory.join("missing.yml"));
    let app = app_with_reviewed_security(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    )?;
    let admin_token = login(&app, "admin@example.test", "test-only-password").await?;
    let user_token = login(&app, "user@example.test", "user-test-password").await?;

    for (method, path, content_type, body) in route_probes() {
        assert_eq!(
            send(
                &app,
                method.clone(),
                path,
                None,
                content_type.as_deref(),
                body.clone(),
            )
            .await?
            .status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must require authentication"
        );
        assert_eq!(
            send(
                &app,
                method,
                path,
                Some(&user_token),
                content_type.as_deref(),
                body,
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN,
            "{path} must require an administrator"
        );
    }

    let first_installation = response_json(
        send(
            &app,
            Method::GET,
            INSTALLATION_ID,
            Some(&admin_token),
            None,
            Vec::new(),
        )
        .await?,
    )
    .await?;
    let second_installation = response_json(
        send(
            &app,
            Method::GET,
            INSTALLATION_ID,
            Some(&admin_token),
            None,
            Vec::new(),
        )
        .await?,
    )
    .await?;
    assert_eq!(first_installation, second_installation);
    assert!(
        first_installation["installationId"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    let initial = response_json(
        send(
            &app,
            Method::GET,
            LICENSE_INFO,
            Some(&admin_token),
            None,
            Vec::new(),
        )
        .await?,
    )
    .await?;
    assert_eq!(
        initial,
        json!({
            "licenseType": "NORMAL",
            "enabled": false,
            "maxUsers": 5,
            "hasKey": false,
        })
    );

    let missing_key = send_json(&app, LICENSE_KEY, &admin_token, json!({})).await?;
    assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_key).await?,
        json!({ "success": false, "error": "License key is required" })
    );

    let cleared = send_json(
        &app,
        LICENSE_KEY,
        &admin_token,
        json!({ "licenseKey": " \t\n" }),
    )
    .await?;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(
        response_json(cleared).await?,
        json!({
            "success": true,
            "licenseType": "NORMAL",
            "enabled": true,
            "maxUsers": 5,
            "requiresRestart": false,
            "message": "License key saved and activated",
        })
    );
    let persisted: Value = serde_yaml::from_str(&fs::read_to_string(&settings_path)?)?;
    assert_eq!(persisted["premium"]["key"], "");
    assert_eq!(persisted["premium"]["enabled"], false);

    let no_key_resync = send(
        &app,
        Method::POST,
        LICENSE_RESYNC,
        Some(&admin_token),
        None,
        Vec::new(),
    )
    .await?;
    assert_eq!(no_key_resync.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(no_key_resync).await?,
        json!({ "success": false, "error": "No license key configured" })
    );

    for (filename, bytes, expected_error) in [
        (
            "../offline.lic",
            certificate("one"),
            "Filename must not contain path separators or '..'",
        ),
        (
            "offline.txt",
            certificate("one"),
            "Invalid file type. Expected .lic or .cert",
        ),
        (
            "offline.lic",
            b"not a certificate".to_vec(),
            "Invalid license certificate format",
        ),
    ] {
        let response = send_multipart(&app, &admin_token, filename, &bytes).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await?,
            json!({ "success": false, "error": expected_error })
        );
    }
    let oversized = send_multipart(
        &app,
        &admin_token,
        "offline.cert",
        &vec![b'x'; 1024 * 1024 + 1],
    )
    .await?;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(oversized).await?,
        json!({ "success": false, "error": "File too large. Maximum 1MB allowed" })
    );

    let first_contents = certificate("first");
    let uploaded = send_multipart(&app, &admin_token, "offline.lic", &first_contents).await?;
    assert_eq!(uploaded.status(), StatusCode::OK);
    assert_eq!(
        response_json(uploaded).await?,
        json!({
            "success": true,
            "licenseType": "NORMAL",
            "filename": "offline.lic",
            "filePath": "configs/offline.lic",
            "enabled": true,
            "maxUsers": 5,
            "message": "License file uploaded and activated",
        })
    );
    assert_eq!(
        fs::read(config_directory.join("offline.lic"))?,
        first_contents
    );

    let second_contents = certificate("second");
    let replaced = send_multipart(&app, &admin_token, "offline.lic", &second_contents).await?;
    assert_eq!(replaced.status(), StatusCode::OK);
    assert_eq!(
        fs::read(config_directory.join("offline.lic"))?,
        second_contents
    );
    let backups = fs::read_dir(config_directory.join("backup"))?.collect::<Result<Vec<_>, _>>()?;
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(backups[0].path())?, first_contents);

    let after_upload = response_json(
        send(
            &app,
            Method::GET,
            LICENSE_INFO,
            Some(&admin_token),
            None,
            Vec::new(),
        )
        .await?,
    )
    .await?;
    assert_eq!(after_upload["licenseType"], "NORMAL");
    assert_eq!(after_upload["enabled"], true);
    assert_eq!(after_upload["hasKey"], true);
    assert_eq!(after_upload["licenseKey"], "file:configs/offline.lic");

    let app_config = response_json(
        send(
            &app,
            Method::GET,
            "/api/v1/config/app-config",
            Some(&admin_token),
            None,
            Vec::new(),
        )
        .await?,
    )
    .await?;
    assert_eq!(app_config["license"], "NORMAL");
    assert_eq!(app_config["runningProOrHigher"], false);
    assert_eq!(app_config["runningEE"], false);
    Ok(())
}

fn route_probes() -> Vec<(Method, &'static str, Option<String>, Vec<u8>)> {
    let boundary = "license-route-probe";
    vec![
        (Method::GET, INSTALLATION_ID, None, Vec::new()),
        (
            Method::POST,
            LICENSE_KEY,
            Some("application/json".to_owned()),
            b"{}".to_vec(),
        ),
        (Method::POST, LICENSE_RESYNC, None, Vec::new()),
        (Method::GET, LICENSE_INFO, None, Vec::new()),
        (
            Method::POST,
            LICENSE_FILE,
            Some(format!("multipart/form-data; boundary={boundary}")),
            format!("--{boundary}--\r\n").into_bytes(),
        ),
    ]
}

fn certificate(marker: &str) -> Vec<u8> {
    format!("-----BEGIN LICENSE FILE-----\n{marker}\n-----END LICENSE FILE-----").into_bytes()
}

async fn login(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = send_json(
        app,
        "/api/v1/auth/login",
        "",
        json!({ "username": username, "password": password }),
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

async fn send_json(
    app: &axum::Router,
    path: &str,
    token: &str,
    value: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    send(
        app,
        Method::POST,
        path,
        (!token.is_empty()).then_some(token),
        Some("application/json"),
        serde_json::to_vec(&value)?,
    )
    .await
}

async fn send_multipart(
    app: &axum::Router,
    token: &str,
    filename: &str,
    bytes: &[u8],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-license-admin-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    send(
        app,
        Method::POST,
        LICENSE_FILE,
        Some(token),
        Some(&format!("multipart/form-data; boundary={boundary}")),
        body,
    )
    .await
}

async fn send(
    app: &axum::Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    content_type: Option<&str>,
    body: Vec<u8>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(content_type) = content_type {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    Ok(app.clone().oneshot(request.body(Body::from(body))?).await?)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 3 * 1024 * 1024).await?,
    )?)
}
