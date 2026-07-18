use std::fs;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::Response,
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn ui_data_routes_read_the_java_compatible_runtime_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let configs = directory.path().join("configs");
    let pipeline = directory.path().join("pipeline/defaultWebUIConfigs/nested");
    let tessdata = directory.path().join("tessdata");
    let signatures = directory.path().join("customFiles/signatures/ALL_USERS");
    let custom_fonts = directory.path().join("customFiles/static/fonts");
    fs::create_dir_all(&configs)?;
    fs::create_dir_all(&pipeline)?;
    fs::create_dir_all(&tessdata)?;
    fs::create_dir_all(&signatures)?;
    fs::create_dir_all(&custom_fonts)?;
    fs::write(
        configs.join("settings.yml"),
        format!(
            "system:\n  enableAnalytics: true\n  tessdataDir: {}\nlegal:\n  termsAndConditions: https://terms.example.test\n  privacyPolicy: https://privacy.example.test\n  accessibilityStatement: https://accessibility.example.test\n  cookiePolicy: https://cookies.example.test\n  impressum: https://impressum.example.test\n",
            yaml_path(&tessdata)
        ),
    )?;
    fs::write(
        pipeline.join("preloaded.json"),
        r#"{"name":"Preloaded pipeline","operations":[]}"#,
    )?;
    fs::write(tessdata.join("eng.traineddata"), "test")?;
    fs::write(tessdata.join("deu.traineddata"), "test")?;
    fs::write(tessdata.join("OSD.traineddata"), "test")?;
    fs::write(signatures.join("shared-signature.PNG"), "image")?;
    fs::write(custom_fonts.join("Custom.ttf"), "font")?;

    let runtime_config = RuntimeConfig::from_files(
        configs.join("settings.yml"),
        configs.join("custom_settings.yml"),
    );
    let app = app_with_runtime_config(1024 * 1024, TimestampSettings::default(), runtime_config);

    let footer = response_json(request(&app, "/api/v1/ui-data/footer-info").await?).await?;
    assert_eq!(footer["analyticsEnabled"], true);
    assert_eq!(footer["termsAndConditions"], "https://terms.example.test");
    assert_eq!(footer["privacyPolicy"], "https://privacy.example.test");

    let home = response_json(request(&app, "/api/v1/ui-data/home").await?).await?;
    assert!(home["showSurveyFromDocker"].is_boolean());

    let licenses = response_json(request(&app, "/api/v1/ui-data/licenses").await?).await?;
    assert!(
        licenses["dependencies"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    assert!(licenses["dependencies"].as_array().is_some_and(|items| {
        items.iter().any(|dependency| {
            dependency["moduleName"] == "axum" && dependency["moduleVersion"] == "0.8.9"
        })
    }));
    assert!(licenses["dependencies"].as_array().is_some_and(|items| {
        items
            .iter()
            .all(|dependency| dependency["moduleName"] != "ch.qos.logback:logback-classic")
    }));

    let pipeline = response_json(request(&app, "/api/v1/ui-data/pipeline").await?).await?;
    assert_eq!(
        pipeline["pipelineConfigs"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(
        pipeline["pipelineConfigsWithNames"][0]["name"],
        "Preloaded pipeline"
    );

    let ocr = response_json(request(&app, "/api/v1/ui-data/ocr-pdf").await?).await?;
    assert_eq!(ocr["languages"], serde_json::json!(["deu", "eng"]));

    let sign = response_json(request(&app, "/api/v1/ui-data/sign").await?).await?;
    assert_eq!(sign["signatures"][0]["fileName"], "shared-signature.PNG");
    assert_eq!(sign["signatures"][0]["category"], "Shared");
    assert!(sign["fonts"].as_array().is_some_and(|fonts| {
        fonts.iter().any(|font| {
            font["name"] == "Custom" && font["extension"] == "ttf" && font["type"] == "truetype"
        })
    }));

    assert_shared_signature_image_routes(&app).await?;
    Ok(())
}

#[tokio::test]
async fn pipeline_metadata_returns_the_legacy_placeholder_without_templates()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let configs = directory.path().join("configs");
    fs::create_dir_all(&configs)?;
    let settings = configs.join("settings.yml");
    fs::write(&settings, "")?;
    let runtime_config = RuntimeConfig::from_files(&settings, configs.join("custom_settings.yml"));
    let app = app_with_runtime_config(1024 * 1024, TimestampSettings::default(), runtime_config);

    let response = response_json(request(&app, "/api/v1/ui-data/pipeline").await?).await?;
    assert_eq!(response["pipelineConfigs"], serde_json::json!([]));
    assert_eq!(response["pipelineConfigsWithNames"][0]["json"], "");
    assert_eq!(
        response["pipelineConfigsWithNames"][0]["name"],
        "No preloaded configs found"
    );
    Ok(())
}

async fn request(app: &axum::Router, uri: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(response)
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    let body = to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn assert_shared_signature_image_routes(
    app: &axum::Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let signature_image = request(app, "/api/v1/general/signatures/shared-signature.PNG").await?;
    assert_eq!(
        signature_image
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("image/png")
    );
    assert_eq!(
        to_bytes(signature_image.into_body(), 1024).await?.as_ref(),
        b"image"
    );
    assert_eq!(
        raw_request(app, "/api/v1/general/signatures/missing.png")
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        raw_request(app, "/api/v1/general/signatures/unsafe..png")
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

async fn raw_request(
    app: &axum::Router,
    uri: &str,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty())?)
        .await?)
}

fn yaml_path(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
