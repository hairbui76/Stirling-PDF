use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use serde_json::Value;
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

/// PKCS#11 enumeration is POST + a plain JSON body (no multipart), so it can
/// use the same generic `?async=true` job wrapper as the ported processing
/// endpoints (see `rust/contracts/job-management.md`) without any change to
/// the route handler itself — the middleware persists/replays the request
/// transparently regardless of content type. There is no real PKCS#11
/// hardware in this sandbox, so this proves the async plumbing (job
/// submission, polling, and the failure path carrying the same rejection the
/// synchronous call above produces) rather than real token enumeration.
#[tokio::test]
async fn pkcs11_certificate_enumeration_async_job_can_be_polled_without_echoing_pin()
-> Result<(), Box<dyn std::error::Error>> {
    let router = app(1024 * 1024);
    let pin = "never-echo-this-pin";
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/cert-sign/hardware/pkcs11-certificates?async=true")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(format!(
                    r#"{{"libraryPath":"C:\\not-a-driver.dll","pin":"{pin}"}}"#
                )))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let started: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    let job_id = started["jobId"].as_str().ok_or("jobId missing")?;

    let mut completed = None;
    for _ in 0..100 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/general/job/{job_id}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let status: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        if status["complete"] == Value::Bool(true) {
            completed = Some(status);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let completed = completed.ok_or("job did not complete")?;
    assert_eq!(completed["progress"], 100);
    let error = completed["error"].as_str().ok_or("expected job to fail")?;
    assert!(error.contains("desktop app"), "{error}");
    assert!(!error.contains(pin), "{error}");
    Ok(())
}
