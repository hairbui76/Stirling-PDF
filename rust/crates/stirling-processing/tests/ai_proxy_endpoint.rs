use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Extension,
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use stirling_processing::{
    TimestampSettings, app_with_runtime_config,
    runtime_config::RuntimeConfig,
    security::{AuthContext, AuthenticationSource},
};
use tempfile::{TempDir, tempdir};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
};
use tower::ServiceExt as _;

const AI_HEALTH_PATH: &str = "/api/v1/ai/health";
const AI_PDF_EDIT_PATH: &str = "/api/v1/ai/pdf/edit";

#[tokio::test]
async fn health_is_a_json_proxy_and_forwards_only_trusted_user_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let engine_body = r#"{"status":"ok","smart_model":"smart","fast_model":"fast"}"#;
    let engine = MockEngine::start(200, engine_body).await?;
    let (_directory, app) = configured_app(&engine.url, "")?;
    let app = app.layer(Extension(trusted_auth_context()));

    let response = app
        .oneshot(
            Request::get(AI_HEALTH_PATH)
                .header("X-User-Id", "caller-controlled@example.test")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        &to_bytes(response.into_body(), usize::MAX).await?[..],
        engine_body.as_bytes()
    );

    let captured = engine.finish().await?;
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.path, "/health");
    assert_eq!(captured.header("accept"), Some("application/json"));
    assert_eq!(
        captured.header("x-user-id"),
        Some("trusted-user@example.test")
    );
    Ok(())
}

#[tokio::test]
async fn pdf_edit_overwrites_client_endpoints_with_the_enabled_server_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    let engine_body = r#"{"outcome":"plan","steps":[]}"#;
    let engine = MockEngine::start(200, engine_body).await?;
    let (_directory, app) =
        configured_app(&engine.url, "endpoints:\n  toRemove:\n    - rotate-pdf\n")?;
    let app = app.layer(Extension(trusted_auth_context()));
    let caller_body = serde_json::json!({
        "userMessage": "rotate this file",
        "enabled_endpoints": ["/api/v1/evil"],
    });

    let response = app
        .oneshot(
            Request::post(AI_PDF_EDIT_PATH)
                .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
                .header("X-User-Id", "caller-controlled@example.test")
                .body(Body::from(serde_json::to_vec(&caller_body)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &to_bytes(response.into_body(), usize::MAX).await?[..],
        engine_body.as_bytes()
    );

    let captured = engine.finish().await?;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/pdf/edit");
    assert_eq!(captured.header("accept"), Some("application/json"));
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(
        captured.header("x-user-id"),
        Some("trusted-user@example.test")
    );
    let forwarded: Value = serde_json::from_slice(&captured.body)?;
    assert_eq!(forwarded["userMessage"], "rotate this file");
    let enabled = forwarded["enabled_endpoints"]
        .as_array()
        .ok_or("enabled_endpoints was not an array")?;
    assert!(
        enabled
            .iter()
            .any(|endpoint| endpoint == "/api/v1/general/merge-pdfs")
    );
    assert!(
        !enabled
            .iter()
            .any(|endpoint| endpoint == "/api/v1/general/rotate-pdf")
    );
    assert!(!enabled.iter().any(|endpoint| endpoint == "/api/v1/evil"));
    Ok(())
}

#[tokio::test]
async fn proxy_preserves_java_status_mapping_for_disabled_and_failed_engines()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, disabled) = disabled_app()?;
    let disabled_response = disabled
        .oneshot(Request::get(AI_HEALTH_PATH).body(Body::empty())?)
        .await?;
    assert_problem(
        disabled_response,
        StatusCode::SERVICE_UNAVAILABLE,
        "AI engine is not enabled",
        AI_HEALTH_PATH,
    )
    .await?;

    let engine = MockEngine::start(503, r#"{"detail":"provider down"}"#).await?;
    let (_directory, app) = configured_app(&engine.url, "")?;
    let failed_response = app
        .oneshot(Request::get(AI_HEALTH_PATH).body(Body::empty())?)
        .await?;
    assert_problem(
        failed_response,
        StatusCode::BAD_GATEWAY,
        "AI engine returned error: 503",
        AI_HEALTH_PATH,
    )
    .await?;
    let _captured = engine.finish().await?;
    Ok(())
}

#[tokio::test]
async fn pdf_edit_rejects_invalid_json_and_non_object_bodies_before_proxying()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, app) = configured_app("http://127.0.0.1:1", "")?;
    for (body, detail) in [
        ("{", "Request body is not valid JSON"),
        ("[]", "Request body must be a JSON object"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post(AI_PDF_EDIT_PATH)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))?,
            )
            .await?;
        assert_problem(response, StatusCode::BAD_REQUEST, detail, AI_PDF_EDIT_PATH).await?;
    }
    Ok(())
}

fn configured_app(
    engine_url: &str,
    additional_settings: &str,
) -> Result<(TempDir, Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings_path = directory.path().join("settings.yml");
    fs::write(
        &settings_path,
        format!(
            "aiEngine:\n  enabled: true\n  url: {engine_url}\n  timeoutSeconds: 5\n{additional_settings}"
        ),
    )?;
    let config = RuntimeConfig::from_files(settings_path, directory.path().join("missing.yml"));
    Ok((
        directory,
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), config),
    ))
}

fn disabled_app() -> Result<(TempDir, Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let settings_path = directory.path().join("settings.yml");
    fs::write(&settings_path, "aiEngine:\n  enabled: false\n")?;
    let config = RuntimeConfig::from_files(settings_path, directory.path().join("missing.yml"));
    Ok((
        directory,
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), config),
    ))
}

fn trusted_auth_context() -> AuthContext {
    AuthContext {
        user_id: 42,
        username: "trusted-user@example.test".to_owned(),
        authentication_source: AuthenticationSource::AccessToken,
        authentication_type: "web".to_owned(),
        roles: ["ROLE_USER".to_owned()].into_iter().collect(),
        team_id: Some(7),
        permissions: BTreeSet::default(),
        external_subject: None,
        force_password_change: false,
        session_id: "trusted-session".to_owned(),
        correlation_id: "test-request".to_owned(),
    }
}

async fn assert_problem(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_detail: &str,
    expected_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/problem+json")
    );
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(body["status"], expected_status.as_u16());
    assert_eq!(body["detail"], expected_detail);
    assert_eq!(body["path"], expected_path);
    assert_eq!(
        body["type"],
        format!("/errors/{}", expected_status.as_u16())
    );
    Ok(())
}

struct CapturedRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

struct MockEngine {
    url: String,
    captured: oneshot::Receiver<CapturedRequest>,
    server: JoinHandle<io::Result<()>>,
}

impl MockEngine {
    async fn start(status: u16, response_body: &str) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let response_body = response_body.to_owned();
        let (sender, captured) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let captured_request = read_request(&mut stream).await?;
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            let _ignored = sender.send(captured_request);
            Ok(())
        });
        Ok(Self {
            url: format!("http://{address}"),
            captured,
            server,
        })
    }

    async fn finish(self) -> Result<CapturedRequest, Box<dyn std::error::Error>> {
        self.server.await??;
        Ok(self.captured.await?)
    }
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> io::Result<CapturedRequest> {
    let mut bytes = Vec::new();
    let (header_end, content_length) = loop {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request ended before its headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = header_end + 4;
            let headers = std::str::from_utf8(&bytes[..header_end])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            break (header_end, content_length);
        }
    };
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 1024];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request ended before its body",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "request line was missing"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let path = request_parts.next().unwrap_or_default().to_owned();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Ok(CapturedRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}
