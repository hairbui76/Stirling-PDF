use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn transfers_uploaded_files_then_removes_the_session()
-> Result<(), Box<dyn std::error::Error>> {
    let app = test_app("")?;
    let created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/mobile-scanner/create-session/desktop-42")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::OK);
    assert_eq!(response_json(created).await?["success"], true);

    let uploaded = app
        .clone()
        .oneshot(upload_request("desktop-42", b"scan data", "scan one.jpg")?)
        .await?;
    assert_eq!(uploaded.status(), StatusCode::OK);
    assert_eq!(response_json(uploaded).await?["filesUploaded"], 1);

    let files = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/mobile-scanner/files/desktop-42")
                .body(Body::empty())?,
        )
        .await?;
    let files = response_json(files).await?;
    assert_eq!(files["count"], 1);
    assert_eq!(files["files"][0]["filename"], "scan_one.jpg");

    let downloaded = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/mobile-scanner/download/desktop-42/scan_one.jpg")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert!(
        downloaded.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("scan_one.jpg")
    );
    assert_eq!(response_bytes(downloaded).await?, b"scan data");

    let files_after_download = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/mobile-scanner/files/desktop-42")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response_json(files_after_download).await?["count"], 0);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_sessions_and_honours_feature_disablement()
-> Result<(), Box<dyn std::error::Error>> {
    let app = test_app("")?;
    let invalid = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/mobile-scanner/create-session/bad_session")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let disabled = test_app("system:\n  enableMobileScanner: false\n")?
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/mobile-scanner/create-session/desktop-42")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(disabled.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(disabled).await?["enabled"], false);
    Ok(())
}

fn upload_request(
    session_id: &str,
    content: &[u8],
    filename: &str,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let boundary = "stirling-mobile-scanner-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"files\"; filename=\"{filename}\"\r\nContent-Type: image/jpeg\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(Request::builder()
        .method("POST")
        .uri(format!("/api/v1/mobile-scanner/upload/{session_id}"))
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))?)
}

fn test_app(settings: &str) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings_path = directory.path().join("settings.yml");
    std::fs::write(&settings_path, settings)?;
    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        RuntimeConfig::from_files(&settings_path, directory.path().join("custom.yml")),
    ))
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&response_bytes(response).await?)?)
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}
