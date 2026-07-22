use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU16, Ordering},
    },
};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::stream;
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
    security::SecurityStore,
};
use tempfile::{TempDir, tempdir};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tower::ServiceExt as _;

const USERNAME: &str = "Canonical.User@Example.Test";
const PASSWORD: &str = "mcp-test-password";

#[tokio::test]
async fn mcp_enforces_api_key_auth_json_rpc_and_request_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app(&engine.url, true, "apikey", true, 1024)?;

    let unauthorized = rpc(&app, None, json!({"jsonrpc":"2.0","id":1,"method":"ping"})).await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer realm=\"Stirling MCP (API key)\"")
    );
    let unauthorized = response_json(unauthorized).await?;
    assert_eq!(unauthorized["error"], "unauthorized");

    let wrong_header_wins = app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json")
                .header("X-API-KEY", "wrong-key")
                .header(header::AUTHORIZATION, format!("Bearer {api_key}"))
                .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))?,
        )
        .await?;
    assert_eq!(wrong_header_wins.status(), StatusCode::UNAUTHORIZED);

    assert_initialize_negotiation(&app, &api_key).await?;

    let ping = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
    )
    .await?;
    assert!(response_json(ping).await?["result"].is_object());

    let notification = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","method":"unknown-notification"}),
    )
    .await?;
    assert_eq!(notification.status(), StatusCode::NO_CONTENT);
    assert!(to_bytes(notification.into_body(), 1).await?.is_empty());

    let malformed = raw_rpc(&app, &api_key, Body::from("{"), None).await?;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(malformed).await?["error"]["code"], -32700);

    let invalid = raw_rpc(&app, &api_key, Body::from("[]"), None).await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response_json(invalid).await?["error"]["code"], -32600);

    let unknown = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":4,"method":"no/such/method"}),
    )
    .await?;
    assert_eq!(response_json(unknown).await?["error"]["code"], -32601);

    let invalid_call = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}),
    )
    .await?;
    assert_eq!(response_json(invalid_call).await?["error"]["code"], -32602);

    let declared = raw_rpc(&app, "wrong-key", Body::from(vec![b'x'; 1025]), Some(1025)).await?;
    assert_payload_too_large(declared, 1024).await?;

    let chunks = stream::iter([
        Ok::<Bytes, Infallible>(Bytes::from(vec![b'x'; 600])),
        Ok(Bytes::from(vec![b'y'; 600])),
    ]);
    let chunked = raw_rpc(&app, "wrong-key", Body::from_stream(chunks), None).await?;
    assert_payload_too_large(chunked, 1024).await?;

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_lists_only_the_ai_slice_and_forwards_only_parameters_with_trusted_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    let (_directory, app, api_key) = configured_app(&engine.url, true, "apikey", true, 4096)?;

    let listed = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await?;
    let listed = response_json(listed).await?;
    let tools = listed["result"]["tools"]
        .as_array()
        .ok_or("tools result was not an array")?;
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0]["name"], "stirling_describe_operation");
    assert_eq!(tools[1]["name"], "stirling_ai");
    assert_eq!(
        tools[1]["inputSchema"]["properties"]["operation"]["enum"],
        json!(["agent-draft"])
    );
    assert!(
        tools[1]["inputSchema"]["properties"]
            .get("fileId")
            .is_some()
    );
    for omitted in [
        "stirling_upload",
        "stirling_download",
        "stirling_pages",
        "stirling_convert",
        "stirling_misc",
        "stirling_security",
    ] {
        assert!(!tools.iter().any(|tool| tool["name"] == omitted));
    }

    let described = tool_call(
        &app,
        &api_key,
        2,
        "stirling_describe_operation",
        json!({"operation":"agent-draft"}),
    )
    .await?;
    let described = response_json(described).await?;
    let description: Value = serde_json::from_str(
        described["result"]["content"][0]["text"]
            .as_str()
            .ok_or("describe result was not text")?,
    )?;
    assert_eq!(description["operation"], "agent-draft");
    assert_eq!(description["category"], "stirling_ai");
    assert_eq!(description["endpoint"], "/api/v1/agents/draft");
    assert_eq!(description["requiredScope"], "mcp.tools.write");
    assert_eq!(
        description["parametersSchema"]["required"],
        json!(["prompt"])
    );

    let invoked = tool_call(
        &app,
        &api_key,
        3,
        "stirling_ai",
        json!({
            "operation":"agent-draft",
            "fileId":"top-level-file-id-must-not-be-forwarded",
            "parameters":{"prompt":"write it","fileId":"nested-parameter-is-owned-by-engine"}
        }),
    )
    .await?;
    let invoked = response_json(invoked).await?;
    assert_eq!(invoked["result"]["isError"], Value::Null);
    assert_eq!(
        invoked["result"]["content"][0]["text"],
        r#"{"accepted":true}"#
    );

    let captured = engine.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].path, "/api/v1/agents/draft");
    assert_eq!(captured[0].header("x-user-id"), Some(USERNAME));
    assert_eq!(
        captured[0].body,
        json!({
            "prompt":"write it",
            "fileId":"nested-parameter-is-owned-by-engine"
        })
    );

    engine.execute_status.store(500, Ordering::Relaxed);
    let failed = tool_call(
        &app,
        &api_key,
        4,
        "stirling_ai",
        json!({"operation":"agent-draft","parameters":{}}),
    )
    .await?;
    assert_eq!(response_json(failed).await?["result"]["isError"], true);

    engine.stop().await?;
    Ok(())
}

#[tokio::test]
async fn mcp_is_absent_when_disabled_or_configured_for_oauth_and_rejects_disabled_users()
-> Result<(), Box<dyn std::error::Error>> {
    let engine = MockEngine::start().await?;
    for (enabled, mode) in [(false, "apikey"), (true, "oauth")] {
        let (_directory, app, api_key) = configured_app(&engine.url, enabled, mode, true, 4096)?;
        let response = rpc(
            &app,
            Some(&api_key),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    let (directory, app, api_key) = configured_app(&engine.url, true, "apikey", false, 4096)?;
    let store = SecurityStore::open(&directory.path().join("configs/security.db"))?;
    store.set_user_enabled(USERNAME, false, 1_700_000_000)?;
    let denied = rpc(
        &app,
        Some(&api_key),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);

    engine.stop().await?;
    Ok(())
}

fn configured_app(
    engine_url: &str,
    mcp_enabled: bool,
    auth_mode: &str,
    ai_enabled: bool,
    max_request_bytes: usize,
) -> Result<(TempDir, Router, String), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    fs::write(
        &settings_path,
        format!(
            "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\nmcp:\n  enabled: {mcp_enabled}\n  auth:\n    mode: {auth_mode}\n  maxRequestBytes: {max_request_bytes}\n  allowedOperations: [agent-draft, blocked-agent]\n  blockedOperations: [blocked-agent]\naiEngine:\n  enabled: {ai_enabled}\n  url: '{engine_url}'\n  timeoutSeconds: 5\n"
        ),
    )?;
    let database_path = config_directory.join("security.db");
    let config = RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app = app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), config)?;
    let store = SecurityStore::open(&database_path)?;
    let user_id = store.create_local_user(USERNAME, PASSWORD, ["ROLE_USER"], None)?;
    let api_key = store.create_api_key(user_id, 1_700_000_000)?.to_string();
    Ok((directory, app, api_key))
}

async fn rpc(
    app: &Router,
    api_key: Option<&str>,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::post("/mcp").header(header::CONTENT_TYPE, "application/json");
    if let Some(api_key) = api_key {
        request = request.header("X-API-KEY", api_key);
    }
    Ok(app
        .clone()
        .oneshot(request.body(Body::from(serde_json::to_vec(&body)?))?)
        .await?)
}

async fn rpc_bearer(
    app: &Router,
    api_key: &str,
    body: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::post("/mcp")
                .header(header::CONTENT_TYPE, "application/json; charset=UTF-8")
                .header(header::AUTHORIZATION, format!("bEaReR {api_key}"))
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?)
}

async fn assert_initialize_negotiation(
    app: &Router,
    api_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let initialize = rpc_bearer(
        app,
        api_key,
        json!({
            "jsonrpc":"2.0",
            "id":"init",
            "method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}
        }),
    )
    .await?;
    assert_eq!(initialize.status(), StatusCode::OK);
    let initialize = response_json(initialize).await?;
    assert_eq!(initialize["id"], "init");
    assert_eq!(initialize["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(
        initialize["result"]["serverInfo"]["name"],
        "stirling-pdf-mcp"
    );
    assert!(initialize["result"]["serverInfo"]["version"].is_string());
    assert!(initialize["result"]["capabilities"]["tools"].is_object());

    let fallback = rpc(
        app,
        Some(api_key),
        json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"initialize",
            "params":{"protocolVersion":"unsupported"}
        }),
    )
    .await?;
    assert_eq!(
        response_json(fallback).await?["result"]["protocolVersion"],
        "2025-06-18"
    );
    Ok(())
}

async fn raw_rpc(
    app: &Router,
    api_key: &str,
    body: Body,
    content_length: Option<usize>,
) -> Result<Response, Box<dyn std::error::Error>> {
    let mut request = Request::post("/mcp")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-API-KEY", api_key);
    if let Some(content_length) = content_length {
        request = request.header(header::CONTENT_LENGTH, content_length);
    }
    Ok(app.clone().oneshot(request.body(body)?).await?)
}

async fn tool_call(
    app: &Router,
    api_key: &str,
    id: i64,
    name: &str,
    arguments: Value,
) -> Result<Response, Box<dyn std::error::Error>> {
    rpc(
        app,
        Some(api_key),
        json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":name,"arguments":arguments}
        }),
    )
    .await
}

async fn response_json(response: Response) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 8 * 1024 * 1024).await?,
    )?)
}

async fn assert_payload_too_large(
    response: Response,
    maximum: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response_json(response).await?;
    assert_eq!(body["error"], "payload_too_large");
    assert_eq!(
        body["message"],
        format!("MCP request body exceeds the configured limit of {maximum} bytes.")
    );
    Ok(())
}

#[derive(Clone)]
struct MockState {
    execute_status: Arc<AtomicU16>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
}

struct CapturedRequest {
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

impl CapturedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

struct MockEngine {
    url: String,
    execute_status: Arc<AtomicU16>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<std::io::Result<()>>,
}

impl MockEngine {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let execute_status = Arc::new(AtomicU16::new(200));
        let captured = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            execute_status: Arc::clone(&execute_status),
            captured: Arc::clone(&captured),
        };
        let router = Router::new()
            .route("/api/v1/agents/capabilities", get(manifest))
            .route("/api/v1/agents/draft", post(execute))
            .with_state(state);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        Ok(Self {
            url: format!("http://{address}"),
            execute_status,
            captured,
            shutdown: Some(shutdown),
            task,
        })
    }

    fn captured(&self) -> Vec<CapturedRequest> {
        self.captured
            .lock()
            .map(|mut captured| captured.drain(..).collect())
            .unwrap_or_default()
    }

    async fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await??;
        Ok(())
    }
}

async fn manifest() -> Json<Value> {
    Json(json!({
        "capabilities":[
            {
                "id":"agent-draft",
                "description":"Draft content",
                "input_schema":{"type":"object","properties":{"prompt":{"type":"string"}},"required":["prompt"]},
                "required_scope":"mcp.tools.write",
                "route":"/api/v1/agents/draft"
            },
            {
                "id":"blocked-agent",
                "description":"Must remain hidden",
                "input_schema":{"type":"object"},
                "route":"/api/v1/agents/draft"
            },
            {
                "id":"unsafe-agent",
                "input_schema":{"type":"object"},
                "route":"https://example.test/steal"
            }
        ]
    }))
}

async fn execute(State(state): State<MockState>, headers: HeaderMap, body: Bytes) -> Response {
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let headers = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    if let Ok(mut captured) = state.captured.lock() {
        captured.push(CapturedRequest {
            path: "/api/v1/agents/draft".to_owned(),
            headers,
            body,
        });
    }
    let status = StatusCode::from_u16(state.execute_status.load(Ordering::Relaxed))
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if status.is_success() {
        (status, r#"{"accepted":true}"#).into_response()
    } else {
        (status, r#"{"error":"engine failed"}"#).into_response()
    }
}
