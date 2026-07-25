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
async fn reports_legacy_status_and_tracks_request_metrics() -> Result<(), Box<dyn std::error::Error>>
{
    let app = test_app("")?;
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/status")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(status.status(), StatusCode::OK);
    let status_json = response_json(status).await?;
    assert_eq!(status_json["status"], "UP");
    assert_eq!(status_json["version"], "2.14.2");

    let operation = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/general/edit-text")
                .header(header::COOKIE, "JSESSIONID=metrics-test")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(operation.status(), StatusCode::BAD_REQUEST);

    let count = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/requests?endpoint=%2Fapi%2Fv1%2Fgeneral%2Fedit-text")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(count.status(), StatusCode::OK);
    assert_eq!(response_json(count).await?, Value::from(1.0));

    let unique = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/requests/unique?endpoint=%2Fapi%2Fv1%2Fgeneral%2Fedit-text")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(unique.status(), StatusCode::OK);
    assert_eq!(response_json(unique).await?, Value::from(1.0));
    Ok(())
}

#[tokio::test]
async fn reports_wau_only_when_no_login_is_configured() -> Result<(), Box<dyn std::error::Error>> {
    let app = test_app("")?;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("x-browser-id", "browser-one")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let wau = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/wau")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(wau.status(), StatusCode::OK);
    let wau = response_json(wau).await?;
    assert_eq!(wau["weeklyActiveUsers"], 1);
    assert_eq!(wau["totalUniqueBrowsers"], 1);
    assert!(
        wau["trackingSince"]
            .as_str()
            .is_some_and(|value| value.ends_with('Z'))
    );

    let login_app = test_app("security:\n  enableLogin: true\n")?;
    let unavailable = login_app
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/wau")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(unavailable.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn respects_metrics_enabled_configuration() -> Result<(), Box<dyn std::error::Error>> {
    let app = test_app("metrics:\n  enabled: false\n")?;
    let disabled = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/requests")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(disabled.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_bytes(disabled).await?,
        b"This endpoint is disabled."
    );

    let status = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/info/health")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(status.status(), StatusCode::OK);
    Ok(())
}

fn test_app(settings: &str) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings_path = directory.path().join("settings.yml");
    std::fs::write(&settings_path, settings)?;
    let runtime_config =
        RuntimeConfig::from_files(&settings_path, directory.path().join("custom.yml"));
    Ok(app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        runtime_config,
    ))
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&response_bytes(response).await?)?)
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}
