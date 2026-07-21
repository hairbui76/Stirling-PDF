use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use chrono::{Local, NaiveDate};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, runtime_config::RuntimeConfig, security_policy::LicenseTier,
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;

mod support;

use support::reviewed_security_app_at_tier;

#[tokio::test]
async fn reviewed_audit_surface_filters_aggregates_exports_and_cleans()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app) = audit_app()?;
    let denied = app
        .clone()
        .oneshot(Request::get("/api/v1/audit/data").body(Body::empty())?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    let admin_token = login_token(&app, "admin@example.test", "test-only-password").await?;
    seed_audit_events(&app, &admin_token).await?;
    assert_dashboard_routes(&app, &admin_token).await?;
    assert_ui_data_routes(&app, &admin_token).await?;
    assert_non_admin_is_forbidden(&app, &admin_token).await?;
    assert_cleanup_and_clear(&app, &admin_token).await?;
    Ok(())
}

fn audit_app() -> Result<(TempDir, axum::Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n",
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, config_directory.join("missing.yml"));
    let app = reviewed_security_app_at_tier(
        1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
        LicenseTier::Enterprise,
    )?;
    Ok((directory, app))
}

async fn seed_audit_events(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let completed =
        authorized_empty_post(app, "/api/v1/user/complete-initial-setup", token).await?;
    assert_eq!(completed.status(), StatusCode::OK);
    let settings = authorized_json_post(
        app,
        "/api/v1/user/updateUserSettings",
        token,
        serde_json::json!({ "theme": "dark" }),
    )
    .await?;
    assert_eq!(settings.status(), StatusCode::OK);
    Ok(())
}

async fn assert_dashboard_routes(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = authorized_get(
        app,
        "/api/v1/audit/data?type=USER_PROFILE_UPDATE&principal=ADMIN&page=0&size=2",
        token,
    )
    .await?;
    assert_eq!(data.status(), StatusCode::OK);
    let data = response_json(data).await?;
    assert_eq!(data["totalElements"], 2);
    assert_eq!(data["content"].as_array().map(Vec::len), Some(2));
    assert_eq!(data["content"][0]["principal"], "admin@example.test");
    assert_eq!(data["content"][0]["source"], "WEB");
    let details: Value = serde_json::from_str(
        data["content"][0]["data"]
            .as_str()
            .ok_or("missing audit data")?,
    )?;
    assert!(
        details["path"]
            .as_str()
            .is_some_and(|path| path.starts_with("/api/v1/user/"))
    );

    let stats =
        response_json(authorized_get(app, "/api/v1/audit/stats?days=1", token).await?).await?;
    assert_eq!(stats["totalEvents"], 4);
    assert_eq!(stats["eventsByType"]["USER_PROFILE_UPDATE"], 2);
    assert_eq!(stats["eventsByType"]["HTTP_REQUEST"], 1);
    let types = response_json(authorized_get(app, "/api/v1/audit/types", token).await?).await?;
    assert!(types.as_array().is_some_and(|types| {
        types.contains(&Value::String("USER_PROFILE_UPDATE".to_owned()))
            && types.contains(&Value::String("USER_LOGIN".to_owned()))
    }));

    let csv = authorized_get(
        app,
        "/api/v1/audit/export/csv?type=USER_PROFILE_UPDATE",
        token,
    )
    .await?;
    assert_eq!(csv.status(), StatusCode::OK);
    assert_eq!(
        csv.headers()[header::CONTENT_TYPE],
        "text/csv;charset=UTF-8"
    );
    let csv = String::from_utf8(to_bytes(csv.into_body(), 1024 * 1024).await?.to_vec())?;
    assert!(csv.starts_with("ID,Principal,Type,Timestamp,Data\n"));
    assert!(csv.contains("admin@example.test"));

    let json_export =
        authorized_get(app, "/api/v1/audit/export/json?principal=admin", token).await?;
    assert_eq!(json_export.status(), StatusCode::OK);
    assert_eq!(
        response_json(json_export).await?.as_array().map(Vec::len),
        Some(6)
    );
    Ok(())
}

async fn assert_ui_data_routes(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let events = response_json(
        authorized_get(
            app,
            "/api/v1/proprietary/ui-data/audit-events?eventType=USER_PROFILE_UPDATE&username=admin%40example.test&pageSize=10",
            token,
        )
        .await?,
    )
    .await?;
    assert_eq!(events["totalEvents"], 2);
    assert_eq!(events["events"][0]["eventType"], "USER_PROFILE_UPDATE");
    assert_eq!(events["events"][0]["username"], "admin@example.test");

    let charts = response_json(
        authorized_get(
            app,
            "/api/v1/proprietary/ui-data/audit-charts?period=day",
            token,
        )
        .await?,
    )
    .await?;
    assert!(
        charts["eventsByType"]["labels"]
            .as_array()
            .is_some_and(|labels| {
                labels.contains(&Value::String("USER_PROFILE_UPDATE".to_owned()))
            })
    );
    let stats = response_json(
        authorized_get(
            app,
            "/api/v1/proprietary/ui-data/audit-stats?period=day",
            token,
        )
        .await?,
    )
    .await?;
    assert_eq!(stats["totalEvents"], 10);
    assert_eq!(stats["successRate"], 100.0);
    assert_eq!(stats["errorCount"], 0);

    let users =
        response_json(authorized_get(app, "/api/v1/proprietary/ui-data/audit-users", token).await?)
            .await?;
    assert_eq!(users, serde_json::json!(["admin@example.test", "system"]));
    let export = authorized_get(
        app,
        "/api/v1/proprietary/ui-data/audit-export?fields=eventType,tool,username",
        token,
    )
    .await?;
    let export = String::from_utf8(to_bytes(export.into_body(), 1024 * 1024).await?.to_vec())?;
    assert!(export.starts_with("Username,Tool,Event Type\n"));
    assert!(export.contains("complete-initial-setup"));
    Ok(())
}

async fn assert_non_admin_is_forbidden(
    app: &axum::Router,
    admin_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let created = authorized_multipart(
        app,
        "/api/v1/user/admin/saveUser",
        admin_token,
        &[
            ("username", "audit-user@example.test"),
            ("password", "audit-user-password"),
            ("role", "ROLE_USER"),
            ("authType", "WEB"),
        ],
    )
    .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let user_token = login_token(app, "audit-user@example.test", "audit-user-password").await?;
    let forbidden = authorized_get(app, "/api/v1/audit/data", &user_token).await?;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    Ok(())
}

async fn assert_cleanup_and_clear(
    app: &axum::Router,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let future = Local::now()
        .date_naive()
        .succ_opt()
        .ok_or("missing next date")?;
    let invalid = authorized_delete(
        app,
        &format!("/api/v1/audit/cleanup/before?date={future}"),
        token,
    )
    .await?;
    assert_eq!(invalid.status(), StatusCode::OK);
    assert!(response_json(invalid).await?["error"].is_string());

    let past = NaiveDate::from_ymd_opt(1970, 1, 1).ok_or("invalid past date")?;
    let cleanup = authorized_delete(
        app,
        &format!("/api/v1/audit/cleanup/before?date={past}"),
        token,
    )
    .await?;
    assert_eq!(cleanup.status(), StatusCode::OK);
    assert_eq!(response_json(cleanup).await?["deleted"], 0);

    let cleared =
        authorized_empty_post(app, "/api/v1/proprietary/ui-data/audit-clear-all", token).await?;
    assert_eq!(cleared.status(), StatusCode::OK);
    let remaining = response_json(authorized_get(app, "/api/v1/audit/data", token).await?).await?;
    assert_eq!(remaining["totalElements"], 1);
    assert_eq!(remaining["content"][0]["type"], "PDF_PROCESS");
    Ok(())
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

async fn authorized_delete(
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

async fn authorized_empty_post(
    app: &axum::Router,
    path: &str,
    token: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::post(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn authorized_json_post(
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

async fn authorized_multipart(
    app: &axum::Router,
    path: &str,
    token: &str,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-security-audit-boundary";
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
