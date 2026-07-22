use std::{fs, io, time::Duration};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tower::ServiceExt as _;

#[tokio::test]
async fn reviewed_security_ports_registration_settings_and_initial_setup()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n",
    )?;
    let database_path = config_directory.join("security.db");
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;

    let user_id = register_pending_user(&app).await?;

    let admin_token = login_access_token(&app).await?;
    let enabled = authorized_multipart(
        &app,
        "/api/v1/user/admin/changeUserEnabled/pending@example.test",
        &admin_token,
        &[("enabled", "true")],
    )
    .await?;
    assert_eq!(enabled.status(), StatusCode::OK);
    let login = login_credentials(&app, "pending@example.test", "pending-test-password").await?;
    assert_eq!(login.status(), StatusCode::OK);
    let login = response_json(login).await?;
    let user_token = login["session"]["access_token"]
        .as_str()
        .ok_or("missing registered access token")?;

    let updated = json_post(
        &app,
        "/api/v1/user/updateUserSettings",
        Some(user_token),
        serde_json::json!({ "language": "en-US", "theme": "dark" }),
    )
    .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(
        response_json(updated).await?["message"],
        "Settings updated successfully"
    );
    let completed = app
        .clone()
        .oneshot(
            Request::post("/api/v1/user/complete-initial-setup")
                .header(header::AUTHORIZATION, format!("Bearer {user_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(response_json(completed).await?["success"], true);
    drop(app);

    let store = SecurityStore::open(&database_path)?;
    assert_eq!(
        store.user_settings(user_id)?,
        [
            ("language".to_owned(), "en-US".to_owned()),
            ("theme".to_owned(), "dark".to_owned()),
        ]
        .into_iter()
        .collect()
    );
    assert!(store.initial_setup_is_complete(user_id)?);
    Ok(())
}

async fn register_pending_user(app: &axum::Router) -> Result<i64, Box<dyn std::error::Error>> {
    let denied = json_post(
        app,
        "/api/v1/user/updateUserSettings",
        None,
        serde_json::json!({ "theme": "dark" }),
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let registered = json_post(
        app,
        "/api/v1/user/register",
        None,
        serde_json::json!({
            "username": "pending@example.test",
            "password": "pending-test-password",
        }),
    )
    .await?;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered = response_json(registered).await?;
    assert_eq!(registered["user"]["enabled"], false);
    assert_eq!(registered["user"]["role"], "ROLE_USER");
    let user_id = registered["user"]["id"]
        .as_i64()
        .ok_or("missing registered user ID")?;
    assert_eq!(
        login_credentials(app, "pending@example.test", "pending-test-password")
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let duplicate = json_post(
        app,
        "/api/v1/user/register",
        None,
        serde_json::json!({
            "username": "PENDING@example.test",
            "password": "other-test-password",
        }),
    )
    .await?;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(duplicate).await?["error"],
        "User already exists"
    );
    Ok(user_id)
}

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

#[tokio::test]
async fn reviewed_security_sends_invite_mail_and_retains_invite_on_delivery_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let smtp_port = listener.local_addr()?.port();
    let smtp_server = tokio::spawn(capture_one_message(listener));
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        format!(
            "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nmail:\n  enabled: true\n  enableInvites: true\n  inviteLinkExpiryHours: 24\n  host: 127.0.0.1\n  port: {smtp_port}\n  from: sender@example.test\n  startTlsEnable: false\nsystem:\n  frontendUrl: https://frontend.example.test\n"
        ),
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
    let access_token = login_access_token(&app).await?;

    let sent = authorized_multipart(
        &app,
        "/api/v1/invite/generate",
        &access_token,
        &[
            ("email", "first-invite@example.test"),
            ("sendEmail", "true"),
            ("frontendBaseUrl", "https://caller.example.test"),
        ],
    )
    .await?;
    assert_eq!(sent.status(), StatusCode::OK);
    let sent = response_json(sent).await?;
    assert_eq!(sent["emailSent"], true);
    assert!(sent.get("emailError").is_none());
    let invite_url = sent["inviteUrl"]
        .as_str()
        .ok_or("missing invite URL")?
        .to_owned();
    assert!(invite_url.starts_with("https://frontend.example.test/invite/"));

    let message = timeout(Duration::from_secs(3), smtp_server).await???;
    let message = String::from_utf8(message)?;
    let message_without_soft_wraps = message.replace("=\r\n", "");
    assert!(message.contains("Subject: You've been invited to Stirling PDF"));
    assert!(message.contains("first-invite@example.test"));
    assert!(message_without_soft_wraps.contains(&invite_url));

    let failed = authorized_multipart(
        &app,
        "/api/v1/invite/generate",
        &access_token,
        &[
            ("email", "second-invite@example.test"),
            ("sendEmail", "true"),
        ],
    )
    .await?;
    assert_eq!(failed.status(), StatusCode::OK);
    let failed = response_json(failed).await?;
    assert_eq!(failed["emailSent"], false);
    assert_eq!(failed["emailError"], "SMTP delivery failed");
    let failed_token = failed["token"].as_str().ok_or("missing failed token")?;
    let validate = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/invite/validate/{failed_token}")).body(Body::empty())?,
        )
        .await?;
    assert_eq!(validate.status(), StatusCode::OK);

    let missing_recipient = authorized_multipart(
        &app,
        "/api/v1/invite/generate",
        &access_token,
        &[("sendEmail", "true")],
    )
    .await?;
    assert_eq!(missing_recipient.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing_recipient).await?["error"],
        "Cannot send email without an email address"
    );
    Ok(())
}

#[tokio::test]
async fn reviewed_security_bulk_invites_create_forced_accounts_and_report_partial_results()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let smtp_port = listener.local_addr()?.port();
    let smtp_server = tokio::spawn(capture_one_message(listener));
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        format!(
            "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nmail:\n  enabled: true\n  enableInvites: true\n  host: 127.0.0.1\n  port: {smtp_port}\n  from: sender@example.test\n  startTlsEnable: false\nsystem:\n  frontendUrl: https://frontend.example.test/\n"
        ),
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
    let admin_token = login_access_token(&app).await?;

    assert_bulk_invite_partial_success(&app, &admin_token, smtp_server).await?;
    assert_bulk_invite_blank_token_behavior(&app, &admin_token).await?;

    let missing_team = authorized_multipart(
        &app,
        "/api/v1/user/admin/inviteUsers",
        &admin_token,
        &[("emails", "missing-team@example.test"), ("teamId", "9999")],
    )
    .await?;
    assert_eq!(missing_team.status(), StatusCode::BAD_REQUEST);
    let missing_team = response_json(missing_team).await?;
    assert_eq!(missing_team["successCount"], 0);
    assert_eq!(missing_team["failureCount"], 1);
    assert_eq!(
        missing_team["errors"],
        "missing-team@example.test: Invalid team ID: 9999; "
    );
    assert_eq!(missing_team["error"], "Failed to invite any users");

    let over_capacity = authorized_multipart(
        &app,
        "/api/v1/user/admin/inviteUsers",
        &admin_token,
        &[
            (
                "emails",
                "one@example.test,two@example.test,three@example.test,four@example.test",
            ),
            ("role", "INVALID"),
        ],
    )
    .await?;
    assert_eq!(over_capacity.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(over_capacity).await?["error"],
        "Not enough user slots available. Allowed: 5, Available: 3, Requested: 4"
    );

    let delivery_failure = authorized_multipart(
        &app,
        "/api/v1/user/admin/inviteUsers",
        &admin_token,
        &[("emails", "delivery-failure@example.test")],
    )
    .await?;
    assert_eq!(delivery_failure.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(delivery_failure).await?["errors"],
        "delivery-failure@example.test: User created but email failed to send; "
    );
    let retained_user = authorized_multipart(
        &app,
        "/api/v1/user/admin/inviteUsers",
        &admin_token,
        &[("emails", "DELIVERY-FAILURE@example.test")],
    )
    .await?;
    assert_eq!(retained_user.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(retained_user).await?["errors"],
        "DELIVERY-FAILURE@example.test: User already exists; "
    );
    Ok(())
}

async fn assert_bulk_invite_blank_token_behavior(
    app: &axum::Router,
    admin_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let blank = authorized_multipart(
        app,
        "/api/v1/user/admin/inviteUsers",
        admin_token,
        &[("emails", "")],
    )
    .await?;
    assert_eq!(blank.status(), StatusCode::BAD_REQUEST);
    let blank = response_json(blank).await?;
    assert_eq!(blank["successCount"], 0);
    assert_eq!(blank["failureCount"], 0);
    assert_eq!(blank["error"], "Failed to invite any users");

    let separators_only = authorized_multipart(
        app,
        "/api/v1/user/admin/inviteUsers",
        admin_token,
        &[("emails", ",")],
    )
    .await?;
    assert_eq!(separators_only.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(separators_only).await?["error"],
        "At least one email address is required"
    );
    Ok(())
}

async fn assert_bulk_invite_partial_success(
    app: &axum::Router,
    admin_token: &str,
    smtp_server: tokio::task::JoinHandle<io::Result<Vec<u8>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let invited = authorized_multipart(
        app,
        "/api/v1/user/admin/inviteUsers",
        admin_token,
        &[
            (
                "emails",
                " invited@example.test,invalid-address,INVITED@example.test",
            ),
            ("role", "role_web_only_user"),
        ],
    )
    .await?;
    assert_eq!(invited.status(), StatusCode::OK);
    let invited = response_json(invited).await?;
    assert_eq!(invited["successCount"], 1);
    assert_eq!(invited["failureCount"], 2);
    assert_eq!(invited["message"], "1 user(s) invited successfully");
    assert_eq!(
        invited["errors"],
        "invalid-address: Invalid email format; INVITED@example.test: User already exists; "
    );

    let message = timeout(Duration::from_secs(3), smtp_server).await???;
    let message = String::from_utf8(message)?.replace("=\r\n", "");
    assert!(message.contains("Subject: Welcome to Stirling PDF"));
    assert!(message.contains("invited@example.test"));
    assert!(message.contains("https://frontend.example.test/login"));
    let temporary_password = temporary_password_from_message(&message)?;
    assert_eq!(temporary_password.len(), 12);
    assert_eq!(temporary_password.as_bytes()[8], b'-');
    assert!(
        temporary_password
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 8
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(&byte))
    );
    let login = login_credentials(app, "invited@example.test", &temporary_password).await?;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(
        response_json(login).await?["user"]["user_metadata"]["forcePasswordChange"],
        true
    );
    Ok(())
}

#[tokio::test]
async fn reviewed_security_bulk_invites_require_both_invite_and_smtp_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    for (enable_invites, expected_status, expected_error) in [
        (
            false,
            StatusCode::BAD_REQUEST,
            "Email invites are not enabled",
        ),
        (
            true,
            StatusCode::SERVICE_UNAVAILABLE,
            "Email service is not configured. Please configure SMTP settings.",
        ),
    ] {
        let directory = tempdir()?;
        let config_directory = directory.path().join("configs");
        fs::create_dir_all(&config_directory)?;
        let settings = config_directory.join("settings.yml");
        fs::write(
            &settings,
            format!(
                "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nmail:\n  enableInvites: {enable_invites}\n"
            ),
        )?;
        let runtime_config =
            RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
        let app =
            app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
        let admin_token = login_access_token(&app).await?;
        let response = authorized_multipart(
            &app,
            "/api/v1/user/admin/inviteUsers",
            &admin_token,
            &[("emails", "invited@example.test")],
        )
        .await?;
        assert_eq!(response.status(), expected_status);
        assert_eq!(response_json(response).await?["error"], expected_error);
    }
    Ok(())
}

#[tokio::test]
async fn reviewed_security_generates_and_delivers_forced_password_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let smtp_port = listener.local_addr()?.port();
    let smtp_server = tokio::spawn(capture_one_message(listener));
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        format!(
            "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nmail:\n  enabled: true\n  host: 127.0.0.1\n  port: {smtp_port}\n  from: sender@example.test\n  startTlsEnable: false\nsystem:\n  frontendUrl: https://frontend.example.test/\n"
        ),
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
    let admin_token = login_access_token(&app).await?;
    let original_token = provision_password_change_user(&app, &admin_token).await?;

    let changed = authorized_multipart(
        &app,
        "/api/v1/user/admin/changePasswordForUser",
        &admin_token,
        &[
            ("username", "managed@example.test"),
            ("generateRandom", "true"),
            ("sendEmail", "true"),
            ("includePassword", "true"),
            ("forcePasswordChange", "true"),
        ],
    )
    .await?;
    assert_eq!(changed.status(), StatusCode::OK);
    assert_eq!(
        response_json(changed).await?["message"],
        "User password updated successfully"
    );

    let message = timeout(Duration::from_secs(3), smtp_server).await???;
    let temporary_password = generated_password_from_message(message)?;

    let revoked = app
        .clone()
        .oneshot(
            Request::get("/api/v1/config/app-config")
                .header(header::AUTHORIZATION, format!("Bearer {original_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        login_credentials(&app, "managed@example.test", "original-managed-password")
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let forced_login = login_credentials(&app, "managed@example.test", &temporary_password).await?;
    assert_eq!(forced_login.status(), StatusCode::OK);
    let forced_login = response_json(forced_login).await?;
    assert_eq!(
        forced_login["user"]["user_metadata"]["forcePasswordChange"],
        true
    );
    let forced_token = forced_login["session"]["access_token"]
        .as_str()
        .ok_or("missing forced-change access token")?
        .to_owned();
    let completed = authorized_multipart(
        &app,
        "/api/v1/user/change-password-on-login",
        &forced_token,
        &[
            ("currentPassword", &temporary_password),
            ("newPassword", "final-managed-password"),
            ("confirmPassword", "final-managed-password"),
        ],
    )
    .await?;
    assert_eq!(completed.status(), StatusCode::OK);
    let final_login =
        login_credentials(&app, "managed@example.test", "final-managed-password").await?;
    assert_eq!(final_login.status(), StatusCode::OK);
    assert_eq!(
        response_json(final_login).await?["user"]["user_metadata"]["forcePasswordChange"],
        false
    );
    Ok(())
}

async fn provision_password_change_user(
    app: &axum::Router,
    admin_token: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let created = authorized_multipart(
        app,
        "/api/v1/user/admin/saveUser",
        admin_token,
        &[
            ("username", "managed@example.test"),
            ("password", "original-managed-password"),
            ("role", "ROLE_USER"),
            ("authType", "WEB"),
        ],
    )
    .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let login = login_credentials(app, "managed@example.test", "original-managed-password").await?;
    assert_eq!(login.status(), StatusCode::OK);
    response_json(login).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing managed access token".into())
}

fn generated_password_from_message(message: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
    let message = String::from_utf8(message)?.replace("=\r\n", "");
    assert!(message.contains("Subject: Your Stirling PDF password has been updated"));
    assert!(message.contains("managed@example.test"));
    assert!(message.contains("https://frontend.example.test/login"));
    let password = temporary_password_from_message(&message)?;
    assert_eq!(password.len(), 12);
    assert!(
        password
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    Ok(password)
}

async fn login_access_token(app: &axum::Router) -> Result<String, Box<dyn std::error::Error>> {
    let login = login_credentials(app, "admin@example.test", "test-only-password").await?;
    if login.status() != StatusCode::OK {
        return Err("administrator login failed".into());
    }
    response_json(login).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn login_credentials(
    app: &axum::Router,
    username: &str,
    password: &str,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({
                    "username": username,
                    "password": password,
                }))?))?,
        )
        .await?)
}

async fn json_post(
    app: &axum::Router,
    path: &str,
    access_token: Option<&str>,
    body: Value,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let mut request = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(access_token) = access_token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {access_token}"));
    }
    Ok(app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?)
}

fn temporary_password_from_message(message: &str) -> Result<String, Box<dyn std::error::Error>> {
    let marker = "Temporary Password:</strong> ";
    let start = message.find(marker).ok_or("missing temporary password")? + marker.len();
    let remainder = &message[start..];
    let end = remainder
        .find("</p>")
        .ok_or("unterminated temporary password")?;
    Ok(remainder[..end].trim().to_owned())
}

async fn authorized_multipart(
    app: &axum::Router,
    path: &str,
    access_token: &str,
    fields: &[(&str, &str)],
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-security-mail-boundary";
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
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
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

async fn capture_one_message(listener: TcpListener) -> io::Result<Vec<u8>> {
    let (stream, _) = listener.accept().await?;
    smtp_session(stream).await
}

async fn smtp_session(stream: TcpStream) -> io::Result<Vec<u8>> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    writer.write_all(b"220 localhost ESMTP ready\r\n").await?;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "SMTP client disconnected before DATA",
            ));
        }
        let command = line.to_ascii_uppercase();
        if command.starts_with("EHLO ") {
            writer
                .write_all(b"250-localhost\r\n250 8BITMIME\r\n")
                .await?;
        } else if command.starts_with("HELO ")
            || command.starts_with("MAIL FROM:")
            || command.starts_with("RCPT TO:")
        {
            writer.write_all(b"250 OK\r\n").await?;
        } else if command == "DATA\r\n" {
            writer.write_all(b"354 Send message\r\n").await?;
            let mut message = Vec::new();
            loop {
                let mut data_line = Vec::new();
                if reader.read_until(b'\n', &mut data_line).await? == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "SMTP client disconnected during DATA",
                    ));
                }
                if data_line == b".\r\n" {
                    writer.write_all(b"250 queued\r\n").await?;
                    return Ok(message);
                }
                message.extend_from_slice(&data_line);
            }
        } else {
            writer.write_all(b"500 unexpected command\r\n").await?;
        }
    }
}
