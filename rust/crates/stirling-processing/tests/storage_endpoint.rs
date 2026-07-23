use std::{error::Error, fs};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

const BODY_LIMIT: usize = 4 * 1024 * 1024;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn storage_files_shares_links_and_folders_are_owner_scoped() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let app = storage_router(
        directory.path(),
        "storage:\n  enabled: true\n  provider: local\n  sharing:\n    enabled: true\n    linkEnabled: true\n",
        2 * 1024 * 1024,
    )?;

    let unauthenticated = app
        .clone()
        .oneshot(Request::get("/api/v1/storage/files").body(Body::empty())?)
        .await?;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let admin_token = login(&app, "admin", "test-only-password").await?;
    create_user(&app, &admin_token, "member", "member-password").await?;
    let member_token = login(&app, "member", "member-password").await?;

    let config =
        authorized_empty(&app, Method::GET, "/api/v1/config/app-config", &admin_token).await?;
    assert_eq!(config.status(), StatusCode::OK);
    let config = response_json(config).await?;
    assert_eq!(config["enableLogin"], true);
    assert_eq!(config["activeSecurity"], true);
    assert_eq!(config["storageEnabled"], true);
    assert_eq!(config["storageSharingEnabled"], true);
    assert_eq!(config["storageShareLinksEnabled"], true);

    let upload = authorized_multipart(
        &app,
        Method::POST,
        "/api/v1/storage/files",
        &admin_token,
        file_multipart("storage-upload", "document.pdf", b"owner-data"),
    )
    .await?;
    assert_eq!(upload.status(), StatusCode::OK);
    let uploaded = response_json(upload).await?;
    let file_id = uploaded["id"].as_i64().ok_or("missing stored file id")?;
    assert_eq!(uploaded["fileName"], "document.pdf");
    assert_eq!(uploaded["owner"], "admin");
    assert_eq!(uploaded["ownedByCurrentUser"], true);
    assert_eq!(uploaded["accessRole"], "editor");
    assert_eq!(uploaded["sizeBytes"], 10);

    let traversal_upload = authorized_multipart(
        &app,
        Method::POST,
        "/api/v1/storage/files",
        &admin_token,
        file_multipart("safe-filename", "../../outside.pdf", b"safe"),
    )
    .await?;
    assert_eq!(traversal_upload.status(), StatusCode::OK);
    let traversal_upload = response_json(traversal_upload).await?;
    assert_eq!(traversal_upload["fileName"], "outside.pdf");
    let traversal_id = traversal_upload["id"]
        .as_i64()
        .ok_or("missing traversal-safe file id")?;
    assert!(!directory.path().join("outside.pdf").exists());
    let traversal_delete = authorized_empty(
        &app,
        Method::DELETE,
        &format!("/api/v1/storage/files/{traversal_id}"),
        &admin_token,
    )
    .await?;
    assert_eq!(traversal_delete.status(), StatusCode::NO_CONTENT);

    let denied = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/files/{file_id}"),
        &member_token,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::NOT_FOUND);

    let shared = authorized_json(
        &app,
        Method::POST,
        &format!("/api/v1/storage/files/{file_id}/shares/users"),
        &admin_token,
        json!({"username": "member", "accessRole": "VIEWER"}),
    )
    .await?;
    assert_eq!(shared.status(), StatusCode::OK);
    let shared = response_json(shared).await?;
    assert_eq!(shared["sharedUsers"][0]["username"], "member");
    assert_eq!(shared["sharedUsers"][0]["accessRole"], "viewer");

    let member_metadata = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/files/{file_id}"),
        &member_token,
    )
    .await?;
    assert_eq!(member_metadata.status(), StatusCode::OK);
    let member_metadata = response_json(member_metadata).await?;
    assert_eq!(member_metadata["ownedByCurrentUser"], false);
    assert_eq!(member_metadata["accessRole"], "viewer");
    assert_eq!(member_metadata["sharedUsers"], json!([]));

    let member_update = authorized_multipart(
        &app,
        Method::PUT,
        &format!("/api/v1/storage/files/{file_id}"),
        &member_token,
        file_multipart("member-update", "changed.pdf", b"changed"),
    )
    .await?;
    assert_eq!(member_update.status(), StatusCode::NOT_FOUND);

    let member_download = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/files/{file_id}/download"),
        &member_token,
    )
    .await?;
    assert_eq!(member_download.status(), StatusCode::OK);
    assert_eq!(
        &to_bytes(member_download.into_body(), BODY_LIMIT).await?[..],
        b"owner-data"
    );

    let left = authorized_empty(
        &app,
        Method::DELETE,
        &format!("/api/v1/storage/files/{file_id}/shares/self"),
        &member_token,
    )
    .await?;
    assert_eq!(left.status(), StatusCode::NO_CONTENT);
    let denied_after_leave = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/files/{file_id}"),
        &member_token,
    )
    .await?;
    assert_eq!(denied_after_leave.status(), StatusCode::NOT_FOUND);

    let share_link = authorized_json(
        &app,
        Method::POST,
        &format!("/api/v1/storage/files/{file_id}/shares/links"),
        &admin_token,
        json!({"accessRole": "viewer"}),
    )
    .await?;
    assert_eq!(share_link.status(), StatusCode::OK);
    let share_link = response_json(share_link).await?;
    let share_token = share_link["token"]
        .as_str()
        .ok_or("missing share token")?
        .to_owned();

    let public_attempt = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/storage/share-links/{share_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(public_attempt.status(), StatusCode::UNAUTHORIZED);

    let link_download = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/share-links/{share_token}"),
        &member_token,
    )
    .await?;
    assert_eq!(link_download.status(), StatusCode::OK);
    assert_eq!(
        &to_bytes(link_download.into_body(), BODY_LIMIT).await?[..],
        b"owner-data"
    );

    let link_metadata = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/share-links/{share_token}/metadata"),
        &member_token,
    )
    .await?;
    assert_eq!(link_metadata.status(), StatusCode::OK);
    let link_metadata = response_json(link_metadata).await?;
    assert_eq!(link_metadata["fileId"], file_id);
    assert_eq!(link_metadata["owner"], "admin");
    assert!(link_metadata["lastAccessedAt"].is_string());

    let accessed = authorized_empty(
        &app,
        Method::GET,
        "/api/v1/storage/share-links/accessed",
        &member_token,
    )
    .await?;
    assert_eq!(accessed.status(), StatusCode::OK);
    let accessed = response_json(accessed).await?;
    assert_eq!(accessed.as_array().map(Vec::len), Some(1));
    assert_eq!(accessed[0]["shareToken"], share_token);

    let access_log = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/files/{file_id}/shares/links/{share_token}/accesses"),
        &admin_token,
    )
    .await?;
    assert_eq!(access_log.status(), StatusCode::OK);
    let access_log = response_json(access_log).await?;
    assert_eq!(access_log[0]["username"], "member");
    assert_eq!(access_log[0]["accessType"], "DOWNLOAD");

    exercise_folder_contract(&app, &admin_token, &member_token, file_id).await?;

    let revoked = authorized_empty(
        &app,
        Method::DELETE,
        &format!("/api/v1/storage/files/{file_id}/shares/links/{share_token}"),
        &admin_token,
    )
    .await?;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let revoked_download = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/storage/share-links/{share_token}"),
        &member_token,
    )
    .await?;
    assert_eq!(revoked_download.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn leaving_a_share_gives_the_same_response_for_a_foreign_and_a_nonexistent_file_id()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let app = storage_router(
        directory.path(),
        "storage:\n  enabled: true\n  provider: local\n  sharing:\n    enabled: true\n",
        2 * 1024 * 1024,
    )?;

    let admin_token = login(&app, "admin", "test-only-password").await?;
    create_user(&app, &admin_token, "member", "member-password").await?;
    let member_token = login(&app, "member", "member-password").await?;

    let upload = authorized_multipart(
        &app,
        Method::POST,
        "/api/v1/storage/files",
        &admin_token,
        file_multipart("storage-upload", "foreign.pdf", b"admin-only-data"),
    )
    .await?;
    assert_eq!(upload.status(), StatusCode::OK);
    let uploaded = response_json(upload).await?;
    let foreign_file_id = uploaded["id"].as_i64().ok_or("missing stored file id")?;

    // `member` was never shared this file - this must be indistinguishable from
    // a file_id that never existed, not leak that a foreign-owned file exists.
    let foreign_attempt = authorized_empty(
        &app,
        Method::DELETE,
        &format!("/api/v1/storage/files/{foreign_file_id}/shares/self"),
        &member_token,
    )
    .await?;
    let foreign_status = foreign_attempt.status();
    let foreign_body = to_bytes(foreign_attempt.into_body(), BODY_LIMIT).await?;

    let missing_attempt = authorized_empty(
        &app,
        Method::DELETE,
        "/api/v1/storage/files/999999999/shares/self",
        &member_token,
    )
    .await?;
    let missing_status = missing_attempt.status();
    let missing_body = to_bytes(missing_attempt.into_body(), BODY_LIMIT).await?;

    assert_eq!(foreign_status, StatusCode::NOT_FOUND);
    assert_eq!(foreign_status, missing_status);
    assert_eq!(foreign_body, missing_body);
    Ok(())
}

#[tokio::test]
async fn storage_disabled_and_file_quota_fail_closed() -> Result<(), Box<dyn Error>> {
    let disabled_directory = tempdir()?;
    let disabled = storage_router(disabled_directory.path(), "", 2 * 1024 * 1024)?;
    let disabled_token = login(&disabled, "admin", "test-only-password").await?;
    let denied = authorized_empty(
        &disabled,
        Method::GET,
        "/api/v1/storage/files",
        &disabled_token,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let quota_directory = tempdir()?;
    let quota = storage_router(
        quota_directory.path(),
        "storage:\n  enabled: true\n  quotas:\n    maxFileMb: 1\n",
        2 * 1024 * 1024,
    )?;
    let quota_token = login(&quota, "admin", "test-only-password").await?;
    let oversized = vec![b'x'; 1024 * 1024 + 1];
    let rejected = authorized_multipart(
        &quota,
        Method::POST,
        "/api/v1/storage/files",
        &quota_token,
        file_multipart("quota-upload", "large.pdf", &oversized),
    )
    .await?;
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn exercise_folder_contract(
    app: &Router,
    admin_token: &str,
    member_token: &str,
    file_id: i64,
) -> Result<(), Box<dyn Error>> {
    let root_id = "11111111-1111-4111-8111-111111111111";
    let child_id = "22222222-2222-4222-8222-222222222222";
    let root = authorized_json(
        app,
        Method::POST,
        "/api/v1/storage/folders",
        admin_token,
        json!({"id": root_id, "name": "Root", "color": "#112233", "icon": "folder"}),
    )
    .await?;
    assert_eq!(root.status(), StatusCode::CREATED);
    assert_eq!(
        root.headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/api/v1/storage/folders/11111111-1111-4111-8111-111111111111")
    );
    assert_eq!(response_json(root).await?["name"], "Root");

    let idempotent = authorized_json(
        app,
        Method::POST,
        "/api/v1/storage/folders",
        admin_token,
        json!({"id": root_id, "name": "Ignored replacement"}),
    )
    .await?;
    assert_eq!(idempotent.status(), StatusCode::CREATED);
    assert_eq!(response_json(idempotent).await?["name"], "Root");

    let child = authorized_json(
        app,
        Method::POST,
        "/api/v1/storage/folders",
        admin_token,
        json!({"id": child_id, "name": "Child", "parentFolderId": root_id}),
    )
    .await?;
    assert_eq!(child.status(), StatusCode::CREATED);

    let member_folders =
        authorized_empty(app, Method::GET, "/api/v1/storage/folders", member_token).await?;
    assert_eq!(member_folders.status(), StatusCode::OK);
    assert_eq!(response_json(member_folders).await?, json!([]));

    let moved = authorized_json(
        app,
        Method::PATCH,
        &format!("/api/v1/storage/files/{file_id}/folder"),
        admin_token,
        json!({"folderId": child_id}),
    )
    .await?;
    assert_eq!(moved.status(), StatusCode::NO_CONTENT);

    let foreign_move = authorized_json(
        app,
        Method::PATCH,
        &format!("/api/v1/storage/files/{file_id}/folder"),
        member_token,
        json!({"folderId": root_id}),
    )
    .await?;
    assert_eq!(foreign_move.status(), StatusCode::NOT_FOUND);

    let partial_bulk = authorized_json(
        app,
        Method::PATCH,
        "/api/v1/storage/files/folder",
        admin_token,
        json!({"folderId": null, "fileIds": [file_id, 9_999_999]}),
    )
    .await?;
    assert_eq!(partial_bulk.status(), StatusCode::MULTI_STATUS);
    let partial_bulk = response_json(partial_bulk).await?;
    assert_eq!(partial_bulk["movedFileIds"], json!([file_id]));
    assert_eq!(partial_bulk["skippedFileIds"], json!([9_999_999]));

    let moved_back = authorized_json(
        app,
        Method::PATCH,
        &format!("/api/v1/storage/files/{file_id}/folder"),
        admin_token,
        json!({"folderId": child_id}),
    )
    .await?;
    assert_eq!(moved_back.status(), StatusCode::NO_CONTENT);

    let cycle = authorized_json(
        app,
        Method::PATCH,
        &format!("/api/v1/storage/folders/{root_id}"),
        admin_token,
        json!({"reparent": true, "parentFolderId": child_id}),
    )
    .await?;
    assert_eq!(cycle.status(), StatusCode::BAD_REQUEST);

    let deleted = authorized_empty(
        app,
        Method::DELETE,
        &format!("/api/v1/storage/folders/{root_id}"),
        admin_token,
    )
    .await?;
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted = response_json(deleted).await?;
    let removed = deleted["removedFolderIds"]
        .as_array()
        .ok_or("missing removed folder ids")?;
    assert_eq!(removed.len(), 2);
    assert!(removed.iter().any(|value| value == root_id));
    assert!(removed.iter().any(|value| value == child_id));

    let file = authorized_empty(
        app,
        Method::GET,
        &format!("/api/v1/storage/files/{file_id}"),
        admin_token,
    )
    .await?;
    assert_eq!(file.status(), StatusCode::OK);
    assert!(response_json(file).await?["folderId"].is_null());
    Ok(())
}

fn storage_router(
    root: &std::path::Path,
    storage_settings: &str,
    max_upload_bytes: usize,
) -> Result<Router, Box<dyn Error>> {
    let config_directory = root.join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        format!(
            "security:\n  initialLogin:\n    username: admin\n    password: test-only-password\n{storage_settings}"
        ),
    )?;
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    Ok(app_with_reviewed_security(
        max_upload_bytes,
        TimestampSettings::default(),
        runtime_config,
    )?)
}

async fn login(app: &Router, username: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"username": username, "password": password}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn create_user(
    app: &Router,
    admin_token: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let boundary = "create-user";
    let body = text_multipart(
        boundary,
        &[
            ("username", username),
            ("password", password),
            ("role", "ROLE_USER"),
            ("authType", "WEB"),
        ],
    );
    let response = authorized_multipart(
        app,
        Method::POST,
        "/api/v1/user/admin/saveUser",
        admin_token,
        (boundary.to_owned(), body),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

async fn authorized_empty(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
) -> Result<Response, Box<dyn Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn authorized_json(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    body: Value,
) -> Result<Response, Box<dyn Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?)
}

async fn authorized_multipart(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    multipart: (String, Vec<u8>),
) -> Result<Response, Box<dyn Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={}", multipart.0),
                )
                .body(Body::from(multipart.1))?,
        )
        .await?)
}

fn text_multipart(boundary: &str, fields: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

fn file_multipart(boundary: &str, filename: &str, contents: &[u8]) -> (String, Vec<u8>) {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(contents);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (boundary.to_owned(), body)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), BODY_LIMIT).await?,
    )?)
}
