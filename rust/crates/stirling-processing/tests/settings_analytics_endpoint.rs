use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::TempDir;
use tower::ServiceExt;

#[tokio::test]
async fn persists_the_first_multipart_analytics_choice() -> Result<(), Box<dyn std::error::Error>> {
    let (app, _directory, settings_path) = test_app("system:\n  defaultLocale: en-US\n")?;
    let updated = app.clone().oneshot(multipart_request("false")?).await?;
    assert_eq!(updated.status(), StatusCode::OK);
    assert_eq!(response_json(updated).await?["message"], "Updated");
    assert!(std::fs::read_to_string(&settings_path)?.contains("enableAnalytics: false"));

    let config = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/config/app-config")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response_json(config).await?["enableAnalytics"], false);

    let repeated = app.oneshot(urlencoded_request("enabled=true")?).await?;
    assert_eq!(repeated.status(), StatusCode::ALREADY_REPORTED);
    assert_eq!(
        response_json(repeated).await?["message"],
        format!(
            "Setting has already been set, To adjust please edit {}",
            settings_path.display()
        )
    );
    Ok(())
}

#[tokio::test]
async fn refuses_to_overwrite_an_existing_analytics_choice()
-> Result<(), Box<dyn std::error::Error>> {
    let initial = "system:\n  enableAnalytics: true\n";
    let (app, _directory, settings_path) = test_app(initial)?;
    let response = app.oneshot(urlencoded_request("enabled=false")?).await?;
    assert_eq!(response.status(), StatusCode::ALREADY_REPORTED);
    assert_eq!(std::fs::read_to_string(settings_path)?, initial);
    Ok(())
}

fn test_app(
    settings: &str,
) -> Result<(axum::Router, TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let settings_path = directory.path().join("settings.yml");
    std::fs::write(&settings_path, settings)?;
    let app = app_with_runtime_config(
        2 * 1024 * 1024,
        TimestampSettings::default(),
        RuntimeConfig::from_files(&settings_path, directory.path().join("custom.yml")),
    );
    Ok((app, directory, settings_path))
}

fn multipart_request(enabled: &str) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let boundary = "stirling-settings-boundary";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"enabled\"\r\n\r\n{enabled}\r\n--{boundary}--\r\n"
    );
    Ok(Request::builder()
        .method("POST")
        .uri("/api/v1/settings/update-enable-analytics")
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))?)
}

fn urlencoded_request(body: &str) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    Ok(Request::builder()
        .method("POST")
        .uri("/api/v1/settings/update-enable-analytics")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_owned()))?)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}
