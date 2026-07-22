use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn hardware_signing_capabilities_are_read_only_and_explicit()
-> Result<(), Box<dyn std::error::Error>> {
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/cert-sign/hardware/capabilities")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
    for field in [
        "desktop",
        "osName",
        "windowsStoreSupported",
        "pkcs11Supported",
        "detectedLibraries",
    ] {
        assert!(body.get(field).is_some(), "missing {field}");
    }
    assert_eq!(body["windowsStoreSupported"], false);
    assert_eq!(body["pkcs11Supported"], false);
    Ok(())
}

#[tokio::test]
async fn windows_certificate_enumeration_rejects_non_desktop_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .uri("/api/v1/security/cert-sign/hardware/windows-certificates")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    assert!(String::from_utf8_lossy(&body).contains("desktop app"));
    Ok(())
}

#[tokio::test]
async fn pkcs11_certificate_enumeration_rejects_non_desktop_runtime_without_echoing_pin()
-> Result<(), Box<dyn std::error::Error>> {
    let pin = "never-echo-this-pin";
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/cert-sign/hardware/pkcs11-certificates")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"libraryPath":"C:\\not-a-driver.dll","pin":"{pin}"}}"#
                )))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("desktop app"));
    assert!(!body.contains(pin));
    Ok(())
}
