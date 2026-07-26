use std::fs;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;

const ADMIN_USERNAME: &str = "admin@example.test";
const ADMIN_PASSWORD: &str = "test-only-password";
const USER_USERNAME: &str = "member@example.test";
const USER_PASSWORD: &str = "member-test-password";

#[tokio::test]
async fn grants_require_admin_validate_principals_normalize_portal_and_upsert()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, user_id) = configured_app()?;
    let admin_token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let user_token = login(&app, USER_USERNAME, USER_PASSWORD).await?;

    let denied = json_request(
        &app,
        Method::POST,
        "/api/v1/admin/access/grants",
        &user_token,
        json!({
            "resourceType":"PORTAL",
            "principalType":"USER",
            "principalId":user_id
        }),
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let missing = json_request(
        &app,
        Method::POST,
        "/api/v1/admin/access/grants",
        &admin_token,
        json!({"resourceType":"INTEGRATION_CONFIG","principalType":"USER","principalId":user_id}),
    )
    .await?;
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(missing).await?["error"],
        "resourceId is required for INTEGRATION_CONFIG"
    );

    let nonexistent = json_request(
        &app,
        Method::POST,
        "/api/v1/admin/access/grants",
        &admin_token,
        json!({"resourceType":"PORTAL","principalType":"USER","principalId":9_999_999}),
    )
    .await?;
    assert_eq!(nonexistent.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(nonexistent).await?["error"],
        "User 9999999 does not exist"
    );

    let created = json_request(
        &app,
        Method::POST,
        "/api/v1/admin/access/grants",
        &admin_token,
        json!({
            "resourceType":"PORTAL",
            "resourceId":"must-be-normalized-away",
            "principalType":"USER",
            "principalId":user_id
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await?;
    let grant_id = created["id"].as_i64().ok_or("grant ID missing")?;
    assert_eq!(created["resourceId"], "");
    assert_eq!(created["permission"], "USE");
    assert!(created["createdAt"].as_str().is_some());

    let upgraded = json_request(
        &app,
        Method::POST,
        "/api/v1/admin/access/grants",
        &admin_token,
        json!({
            "resourceType":"PORTAL",
            "principalType":"USER",
            "principalId":user_id,
            "permission":"MANAGE"
        }),
    )
    .await?;
    let upgraded = response_json(upgraded).await?;
    assert_eq!(upgraded["id"], grant_id);
    assert_eq!(upgraded["permission"], "MANAGE");

    let listed = authorized_request(
        &app,
        Method::GET,
        &format!(
            "/api/v1/admin/access/grants/by-principal?principalType=USER&principalId={user_id}"
        ),
        &admin_token,
        None,
    )
    .await?;
    let listed = response_json(listed).await?;
    assert_eq!(listed.as_array().map(Vec::len), Some(1));

    let revoked = authorized_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/admin/access/grants/{grant_id}"),
        &admin_token,
        None,
    )
    .await?;
    assert_eq!(revoked.status(), StatusCode::OK);
    assert_eq!(response_json(revoked).await?["message"], "Grant revoked");
    Ok(())
}

#[tokio::test]
async fn integrations_enforce_portal_ownership_and_preserve_masked_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, user_id) = configured_app()?;
    let admin_token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let user_token = login(&app, USER_USERNAME, USER_PASSWORD).await?;

    let denied =
        authorized_request(&app, Method::GET, "/api/v1/integrations", &user_token, None).await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    grant_portal(&app, &admin_token, user_id).await?;
    let created = json_request(
        &app,
        Method::POST,
        "/api/v1/integrations",
        &user_token,
        json!({
            "integrationType":"MCP",
            "name":"Personal MCP",
            "config":{
                "apiToken":"top-secret",
                "endpoint":"https://api.example.test",
                "nested":{"password":"nested-secret","keep":"old"}
            }
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::OK);
    let created = response_json(created).await?;
    let integration_id = created["id"].as_i64().ok_or("integration ID missing")?;
    assert_eq!(created["scope"], "USER");
    assert_eq!(created["ownerUserId"], user_id);
    assert_eq!(created["config"]["apiToken"], "********");
    assert_eq!(created["config"]["nested"]["password"], "********");
    assert_eq!(created["canManage"], true);

    let updated = json_request(
        &app,
        Method::PUT,
        &format!("/api/v1/integrations/{integration_id}"),
        &user_token,
        json!({
            "name":"Updated API",
            "integrationType":"S3",
            "scope":"SERVER",
            "config":{
                "apiToken":"********",
                "nested":{"password":"********","new":"value"}
            }
        }),
    )
    .await?;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = response_json(updated).await?;
    assert_eq!(updated["integrationType"], "MCP");
    assert_eq!(updated["scope"], "USER");
    assert_eq!(updated["config"]["apiToken"], "********");
    assert_eq!(updated["config"]["nested"]["password"], "********");
    assert_eq!(updated["config"]["nested"]["new"], "value");
    assert!(updated["config"].get("endpoint").is_none());

    let listed =
        authorized_request(&app, Method::GET, "/api/v1/integrations", &user_token, None).await?;
    assert_eq!(
        response_json(listed).await?.as_array().map(Vec::len),
        Some(1)
    );

    let deleted = authorized_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/integrations/{integration_id}"),
        &user_token,
        None,
    )
    .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let missing = authorized_request(
        &app,
        Method::GET,
        &format!("/api/v1/integrations/{integration_id}"),
        &admin_token,
        None,
    )
    .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(missing).await?["error"],
        "Integration not found"
    );
    Ok(())
}

#[tokio::test]
async fn team_ownership_locked_overrides_and_disabled_resources_follow_java_rules()
-> Result<(), Box<dyn std::error::Error>> {
    let (directory, app, user_id) = configured_app()?;
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    let team_id = store.create_team("Connection Owners")?;
    store.assign_user_to_team(user_id, team_id)?;
    store.set_team_owner(team_id, user_id, true)?;

    let admin_token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let user_token = login(&app, USER_USERNAME, USER_PASSWORD).await?;
    grant_portal(&app, &admin_token, user_id).await?;

    let team_owned = json_request(
        &app,
        Method::POST,
        "/api/v1/integrations",
        &user_token,
        json!({
            "integrationType":"MCP",
            "name":"Team MCP",
            "scope":"TEAM",
            "locked":true,
            "config":{}
        }),
    )
    .await?;
    assert_eq!(team_owned.status(), StatusCode::OK);
    let team_owned = response_json(team_owned).await?;
    let team_owned_id = team_owned["id"].as_i64().ok_or("team config ID missing")?;
    assert_eq!(team_owned["ownerTeamId"], team_id);

    let locked_owner = json_request(
        &app,
        Method::PUT,
        &format!("/api/v1/integrations/{team_owned_id}"),
        &user_token,
        json!({"name":"blocked"}),
    )
    .await?;
    assert_eq!(locked_owner.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(locked_owner).await?["error"],
        "This integration is locked by an administrator"
    );
    // Java's current contract applies the lock to update, but not delete.
    let deleted = authorized_request(
        &app,
        Method::DELETE,
        &format!("/api/v1/integrations/{team_owned_id}"),
        &user_token,
        None,
    )
    .await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    Ok(())
}

#[tokio::test]
async fn server_lock_blocks_personal_override_and_disabled_config_ignores_grants()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app, user_id) = configured_app()?;
    let admin_token = login(&app, ADMIN_USERNAME, ADMIN_PASSWORD).await?;
    let user_token = login(&app, USER_USERNAME, USER_PASSWORD).await?;
    grant_portal(&app, &admin_token, user_id).await?;

    let server = json_request(
        &app,
        Method::POST,
        "/api/v1/integrations",
        &admin_token,
        json!({
            "integrationType":"MCP",
            "name":"Locked server MCP",
            "scope":"SERVER",
            "locked":true,
            "config":{}
        }),
    )
    .await?;
    let server = response_json(server).await?;
    let server_id = server["id"].as_i64().ok_or("server config ID missing")?;
    let grant = json_request(
        &app,
        Method::POST,
        "/api/v1/admin/access/grants",
        &admin_token,
        json!({
            "resourceType":"INTEGRATION_CONFIG",
            "resourceId":server_id.to_string(),
            "principalType":"USER",
            "principalId":user_id,
            "permission":"MANAGE"
        }),
    )
    .await?;
    assert_eq!(grant.status(), StatusCode::OK);

    let personal_override = json_request(
        &app,
        Method::POST,
        "/api/v1/integrations",
        &user_token,
        json!({"integrationType":"MCP","name":"Personal override","config":{}}),
    )
    .await?;
    assert_eq!(personal_override.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json(personal_override).await?["error"],
        "This is locked to the server configuration by an administrator"
    );

    let disabled = json_request(
        &app,
        Method::PUT,
        &format!("/api/v1/integrations/{server_id}"),
        &admin_token,
        json!({"enabled":false}),
    )
    .await?;
    assert_eq!(disabled.status(), StatusCode::OK);
    let denied = authorized_request(
        &app,
        Method::GET,
        &format!("/api/v1/integrations/{server_id}"),
        &user_token,
        None,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    Ok(())
}

fn configured_app() -> Result<(TempDir, Router, i64), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n  portal:\n    defaultAccess: EXPLICIT_ONLY\n",
    )?;
    let database_path = config_directory.join("security.db");
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
    let store = SecurityStore::open(&database_path)?;
    let user_id = store.create_local_user(USER_USERNAME, USER_PASSWORD, ["ROLE_USER"], None)?;
    Ok((directory, app, user_id))
}

async fn grant_portal(
    app: &Router,
    admin_token: &str,
    user_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = json_request(
        app,
        Method::POST,
        "/api/v1/admin/access/grants",
        admin_token,
        json!({
            "resourceType":"PORTAL",
            "principalType":"USER",
            "principalId":user_id
        }),
    )
    .await?;
    if response.status() != StatusCode::OK {
        return Err("portal grant failed".into());
    }
    Ok(())
}

async fn login(
    app: &Router,
    username: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json!({
                    "username":username,
                    "password":password
                }))?))?,
        )
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("login failed for {username}").into());
    }
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "access token missing".into())
}

async fn json_request(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    authorized_request(app, method, path, token, Some(body)).await
}

async fn authorized_request(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    let body = if let Some(body) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&body)?)
    } else {
        Body::empty()
    };
    Ok(app.clone().oneshot(request.body(body)?).await?)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024).await?,
    )?)
}
