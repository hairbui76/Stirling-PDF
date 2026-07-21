//! API-key-authenticated MCP JSON-RPC boundary.
//!
//! This first vertical slice intentionally exposes only the Rust AI-engine
//! catalog. PDF category tools and reusable file artifacts stay hidden until
//! their storage and internal-dispatch contracts are ported together.

use std::{
    collections::BTreeMap,
    io::Read as _,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use reqwest::blocking::Client;
use serde_json::{Map, Value, json};
use tokio::task;
use tracing::warn;
use zeroize::Zeroizing;

use crate::{
    pdf_ai_comments::AiCommentEngineSettings,
    runtime_config::McpConfig,
    runtime_metrics::application_version,
    security::{AuthContext, SecurityError, SecurityStore},
};

const MCP_PATH: &str = "/mcp";
const CAPABILITIES_PATH: &str = "/api/v1/agents/capabilities";
const PREFERRED_PROTOCOL_VERSION: &str = "2025-06-18";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
const READ_SCOPE: &str = "mcp.tools.read";
const WRITE_SCOPE: &str = "mcp.tools.write";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ENGINE_RESULT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CAPABILITIES: usize = 256;
const MAX_CAPABILITY_ID_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 4096;
const MAX_SCOPE_BYTES: usize = 128;
const MAX_ROUTE_BYTES: usize = 512;
const MAX_SCHEMA_BYTES: usize = 128 * 1024;

#[derive(Clone)]
struct McpState {
    config: McpConfig,
    store: Arc<SecurityStore>,
    catalog: Arc<AiCapabilityCatalog>,
}

#[derive(Clone)]
struct EngineConnection {
    enabled: bool,
    base_url: String,
    timeout: Duration,
    shared_secret: Option<String>,
}

impl EngineConnection {
    fn from_settings(settings: &AiCommentEngineSettings) -> Self {
        Self {
            enabled: settings.enabled(),
            base_url: settings.base_url().to_owned(),
            timeout: settings.timeout(),
            shared_secret: settings.shared_secret().map(ToOwned::to_owned),
        }
    }
}

#[derive(Clone, Debug)]
struct AiCapability {
    id: String,
    description: String,
    input_schema: Value,
    required_scope: String,
    route: Option<String>,
}

struct AiCapabilityCatalog {
    connection: EngineConnection,
    refresh_interval: Duration,
    cache: Mutex<CapabilityCache>,
}

#[derive(Default)]
struct CapabilityCache {
    operations: BTreeMap<String, AiCapability>,
    last_attempt: Option<Instant>,
    refreshing: bool,
}

impl AiCapabilityCatalog {
    fn new(connection: EngineConnection, refresh_minutes: u64) -> Self {
        Self {
            connection,
            refresh_interval: Duration::from_secs(refresh_minutes.max(1).saturating_mul(60)),
            cache: Mutex::new(CapabilityCache::default()),
        }
    }

    async fn snapshot(&self) -> BTreeMap<String, AiCapability> {
        if !self.connection.enabled {
            if let Ok(mut cache) = self.cache.lock() {
                cache.operations.clear();
                cache.last_attempt = Some(Instant::now());
                cache.refreshing = false;
            }
            return BTreeMap::new();
        }

        let should_refresh = match self.cache.lock() {
            Ok(mut cache) => {
                let due = cache.last_attempt.is_none_or(|last| {
                    Instant::now().saturating_duration_since(last) >= self.refresh_interval
                });
                if due && !cache.refreshing {
                    cache.refreshing = true;
                    cache.last_attempt = Some(Instant::now());
                    true
                } else {
                    false
                }
            }
            Err(_) => return BTreeMap::new(),
        };

        if should_refresh {
            let connection = self.connection.clone();
            let refreshed = task::spawn_blocking(move || fetch_manifest(&connection)).await;
            if let Ok(mut cache) = self.cache.lock() {
                cache.refreshing = false;
                match refreshed {
                    Ok(Ok(operations)) => cache.operations = operations,
                    Ok(Err(error)) => {
                        warn!(%error, "MCP AI capability refresh failed; retaining last known manifest");
                    }
                    Err(error) => warn!(%error, "MCP AI capability refresh worker failed"),
                }
            }
        }

        self.cache
            .lock()
            .map(|cache| cache.operations.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, thiserror::Error)]
enum EngineError {
    #[error("AI engine URL is invalid")]
    InvalidUrl,
    #[error("AI engine client could not be created")]
    Client,
    #[error("AI engine request failed")]
    Request,
    #[error("AI engine returned HTTP {0}")]
    Status(u16),
    #[error("AI engine response exceeded its configured safety limit")]
    ResponseTooLarge,
    #[error("AI engine response could not be read")]
    ResponseRead,
    #[error("AI capability manifest is invalid")]
    InvalidManifest,
}

/// Builds the API-key MCP router. OAuth mode deliberately remains unmounted.
pub(crate) fn routes(
    config: McpConfig,
    store: Arc<SecurityStore>,
    engine_settings: &AiCommentEngineSettings,
) -> Router {
    if !config.enabled || !config.auth.mode.trim().eq_ignore_ascii_case("apikey") {
        return Router::new();
    }
    let catalog = Arc::new(AiCapabilityCatalog::new(
        EngineConnection::from_settings(engine_settings),
        config.engine_capability_refresh_minutes,
    ));
    let state = Arc::new(McpState {
        config,
        store,
        catalog,
    });
    Router::new()
        .route(MCP_PATH, post(handle))
        .with_state(state)
}

async fn handle(State(state): State<Arc<McpState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !is_json_content_type(&parts.headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    if declared_body_too_large(&parts.headers, state.config.max_request_bytes) {
        return payload_too_large(state.config.max_request_bytes);
    }
    let Ok(body) = to_bytes(body, state.config.max_request_bytes).await else {
        return payload_too_large(state.config.max_request_bytes);
    };
    let context = match authenticate_api_key(&state.store, &parts.headers).await {
        Ok(context) => context,
        Err(AuthFailure::Unauthorized) => return unauthorized(),
        Err(AuthFailure::Unavailable) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            rpc_failure(Value::Null, -32700, "Request body is not valid JSON"),
        );
    };
    let Some(request) = decode_request(&body) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            rpc_failure(
                Value::Null,
                -32600,
                "Body is not a valid JSON-RPC 2.0 request",
            ),
        );
    };
    if request.notification {
        return StatusCode::NO_CONTENT.into_response();
    }
    let result = dispatch(&state, &context, &request).await;
    json_response(StatusCode::OK, result)
}

struct RpcRequest {
    id: Value,
    method: String,
    params: Option<Value>,
    notification: bool,
}

fn decode_request(body: &Value) -> Option<RpcRequest> {
    let object = body.as_object()?;
    if object.get("jsonrpc")?.as_str()? != "2.0" {
        return None;
    }
    let method = object.get("method")?.as_str()?.to_owned();
    let id = object.get("id").cloned().unwrap_or(Value::Null);
    Some(RpcRequest {
        notification: id.is_null(),
        id,
        method,
        params: object.get("params").cloned(),
    })
}

async fn dispatch(state: &McpState, context: &AuthContext, request: &RpcRequest) -> Value {
    match request.method.as_str() {
        "initialize" => rpc_success(
            request.id.clone(),
            initialize_result(request.params.as_ref()),
        ),
        "tools/list" => {
            let operations = visible_operations(state).await;
            rpc_success(request.id.clone(), tools_list_result(&operations))
        }
        "tools/call" => handle_tools_call(state, context, request).await,
        "ping" | "notifications/initialized" => {
            rpc_success(request.id.clone(), Value::Object(Map::new()))
        }
        method => rpc_failure(
            request.id.clone(),
            -32601,
            &format!("Method not found: {method}"),
        ),
    }
}

fn initialize_result(params: Option<&Value>) -> Value {
    let requested = params
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str);
    let negotiated = requested
        .filter(|requested| SUPPORTED_PROTOCOL_VERSIONS.contains(requested))
        .unwrap_or(PREFERRED_PROTOCOL_VERSION);
    json!({
        "protocolVersion": negotiated,
        "capabilities": {"tools": {}},
        "serverInfo": {
            "name": "stirling-pdf-mcp",
            "version": application_version(),
        }
    })
}

async fn handle_tools_call(state: &McpState, context: &AuthContext, request: &RpcRequest) -> Value {
    let Some(params) = request.params.as_ref().and_then(Value::as_object) else {
        return rpc_failure(request.id.clone(), -32602, "Missing params for tools/call");
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return rpc_failure(request.id.clone(), -32602, "Missing tool name");
    };
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let operations = visible_operations(state).await;
    let result = match name {
        "stirling_describe_operation" => describe_operation(&arguments, &operations),
        "stirling_ai" => call_ai(state, context, &arguments, &operations).await,
        _ => {
            return rpc_failure(request.id.clone(), -32602, &format!("Unknown tool: {name}"));
        }
    };
    rpc_success(request.id.clone(), result)
}

async fn visible_operations(state: &McpState) -> BTreeMap<String, AiCapability> {
    state
        .catalog
        .snapshot()
        .await
        .into_iter()
        .filter(|(id, _)| operation_allowed(&state.config, id))
        .collect()
}

fn operation_allowed(config: &McpConfig, id: &str) -> bool {
    if config
        .blocked_operations
        .iter()
        .any(|blocked| blocked == id)
    {
        return false;
    }
    config.allowed_operations.is_empty()
        || config
            .allowed_operations
            .iter()
            .any(|allowed| allowed == id)
}

fn tools_list_result(operations: &BTreeMap<String, AiCapability>) -> Value {
    json!({
        "tools": [
            {
                "name": "stirling_describe_operation",
                "description": "Return the full JSON Schema for one Stirling operation's parameters. Call this before invoking stirling_ai to learn the exact shape of `parameters`.",
                "inputSchema": describe_schema(),
            },
            {
                "name": "stirling_ai",
                "description": "Invoke a Stirling AI agent capability. Call stirling_describe_operation with the chosen capability id before invoking this tool.",
                "inputSchema": ai_tool_schema(operations),
            }
        ]
    })
}

fn describe_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "operation": {
                "type": "string",
                "description": "AI capability id from the stirling_ai operation enum."
            }
        },
        "required": ["operation"]
    })
}

fn ai_tool_schema(operations: &BTreeMap<String, AiCapability>) -> Value {
    let ids = operations
        .keys()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    let mut description =
        String::from("Capability id from the engine manifest. Available capabilities:");
    for operation in operations.values() {
        description.push_str("\n- ");
        description.push_str(&operation.id);
        description.push_str(" - ");
        description.push_str(&operation.description);
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "operation": {"type": "string", "enum": ids, "description": description},
            "parameters": {"type": "object", "description": "Per-capability parameters.", "additionalProperties": true},
            "fileId": {
                "type": "string",
                "description": "Reference to a previously-uploaded PDF in Stirling's job store. Required for capabilities that consume a document."
            }
        },
        "required": ["operation"]
    })
}

fn describe_operation(arguments: &Value, operations: &BTreeMap<String, AiCapability>) -> Value {
    let Some(operation_id) = text_argument(arguments, "operation") else {
        return tool_error("Missing required argument: operation");
    };
    let Some(operation) = operations.get(operation_id) else {
        return tool_error(&format!("Unknown or disabled operation: {operation_id}"));
    };
    tool_text(
        &json!({
            "operation": operation.id,
            "category": "stirling_ai",
            "summary": operation.description,
            "endpoint": operation.route,
            "requiredScope": operation.required_scope,
            "parametersSchema": operation.input_schema,
        })
        .to_string(),
    )
}

async fn call_ai(
    state: &McpState,
    context: &AuthContext,
    arguments: &Value,
    operations: &BTreeMap<String, AiCapability>,
) -> Value {
    let Some(operation_id) = text_argument(arguments, "operation") else {
        return tool_error("Missing required argument: operation");
    };
    let Some(operation) = operations.get(operation_id) else {
        return tool_error(&format!(
            "Unknown AI capability '{operation_id}'. The engine manifest may not be loaded yet - retry shortly or confirm the engine is reachable."
        ));
    };
    if state.config.scopes_enabled
        && !matches!(operation.required_scope.as_str(), READ_SCOPE | WRITE_SCOPE)
    {
        return tool_error(&format!(
            "Insufficient scope: this capability requires '{}'.",
            operation.required_scope
        ));
    }
    let Some(route) = operation.route.clone() else {
        return tool_error(&format!(
            "Capability '{operation_id}' has no route configured in the engine manifest."
        ));
    };
    let parameters = arguments
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let connection = state.catalog.connection.clone();
    let username = context.username.clone();
    match task::spawn_blocking(move || post_engine(&connection, &route, &parameters, &username))
        .await
    {
        Ok(Ok(response)) => tool_text(&response),
        Ok(Err(error)) => {
            warn!(%error, operation = operation_id, "MCP AI capability request failed");
            tool_error(&format!(
                "Engine request failed for capability '{operation_id}'."
            ))
        }
        Err(error) => {
            warn!(%error, operation = operation_id, "MCP AI capability worker failed");
            tool_error(&format!(
                "Engine request failed for capability '{operation_id}'."
            ))
        }
    }
}

fn fetch_manifest(
    connection: &EngineConnection,
) -> Result<BTreeMap<String, AiCapability>, EngineError> {
    let endpoint = engine_endpoint(connection, CAPABILITIES_PATH)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| EngineError::Client)?;
    let mut request = client
        .get(endpoint)
        .header(header::ACCEPT.as_str(), "application/json");
    if let Some(secret) = &connection.shared_secret {
        request = request.header("X-Engine-Auth", secret);
    }
    let response = request.send().map_err(|_| EngineError::Request)?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(EngineError::Status(response.status().as_u16()));
    }
    let body = read_bounded(response, MAX_MANIFEST_BYTES)?;
    parse_manifest(&body)
}

fn post_engine(
    connection: &EngineConnection,
    route: &str,
    parameters: &Value,
    username: &str,
) -> Result<String, EngineError> {
    if !is_safe_relative_route(route) {
        return Err(EngineError::InvalidUrl);
    }
    let endpoint = engine_endpoint(connection, route)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(5).min(connection.timeout))
        .timeout(connection.timeout)
        .build()
        .map_err(|_| EngineError::Client)?;
    let body = serde_json::to_vec(parameters).map_err(|_| EngineError::InvalidManifest)?;
    let mut request = client
        .post(endpoint)
        .header(header::CONTENT_TYPE.as_str(), "application/json")
        .header(header::ACCEPT.as_str(), "application/json")
        .header("X-User-Id", username)
        .body(body);
    if let Some(secret) = &connection.shared_secret {
        request = request.header("X-Engine-Auth", secret);
    }
    let response = request.send().map_err(|_| EngineError::Request)?;
    if !response.status().is_success() {
        return Err(EngineError::Status(response.status().as_u16()));
    }
    let body = read_bounded(response, MAX_ENGINE_RESULT_BYTES)?;
    String::from_utf8(body).map_err(|_| EngineError::ResponseRead)
}

fn engine_endpoint(connection: &EngineConnection, path: &str) -> Result<reqwest::Url, EngineError> {
    let base = connection.base_url.trim().trim_end_matches('/');
    let endpoint =
        reqwest::Url::parse(&format!("{base}{path}")).map_err(|_| EngineError::InvalidUrl)?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.username() != ""
        || endpoint.password().is_some()
    {
        return Err(EngineError::InvalidUrl);
    }
    Ok(endpoint)
}

fn read_bounded(
    response: reqwest::blocking::Response,
    maximum: u64,
) -> Result<Vec<u8>, EngineError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum)
    {
        return Err(EngineError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    response
        .take(maximum + 1)
        .read_to_end(&mut body)
        .map_err(|_| EngineError::ResponseRead)?;
    if body.len() as u64 > maximum {
        return Err(EngineError::ResponseTooLarge);
    }
    Ok(body)
}

fn parse_manifest(body: &[u8]) -> Result<BTreeMap<String, AiCapability>, EngineError> {
    let root = serde_json::from_slice::<Value>(body).map_err(|_| EngineError::InvalidManifest)?;
    let capabilities = root
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(EngineError::InvalidManifest)?;
    if capabilities.len() > MAX_CAPABILITIES {
        return Err(EngineError::InvalidManifest);
    }
    let mut operations = BTreeMap::new();
    for entry in capabilities {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(input_schema) = entry
            .get("input_schema")
            .filter(|schema| schema.is_object())
        else {
            continue;
        };
        let description = entry
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or(id);
        let required_scope = entry
            .get("required_scope")
            .and_then(Value::as_str)
            .filter(|scope| !scope.trim().is_empty())
            .unwrap_or(WRITE_SCOPE);
        let route = entry.get("route").and_then(Value::as_str);
        if id.len() > MAX_CAPABILITY_ID_BYTES
            || description.len() > MAX_DESCRIPTION_BYTES
            || required_scope.len() > MAX_SCOPE_BYTES
            || route.is_some_and(|route| {
                route.len() > MAX_ROUTE_BYTES || !is_safe_relative_route(route)
            })
            || serde_json::to_vec(input_schema)
                .map_or(true, |schema| schema.len() > MAX_SCHEMA_BYTES)
        {
            continue;
        }
        operations.insert(
            id.to_owned(),
            AiCapability {
                id: id.to_owned(),
                description: description.to_owned(),
                input_schema: input_schema.clone(),
                required_scope: required_scope.to_owned(),
                route: route.map(ToOwned::to_owned),
            },
        );
    }
    Ok(operations)
}

fn is_safe_relative_route(route: &str) -> bool {
    route.starts_with("/api/")
        && !route.starts_with("//")
        && !route.contains("..")
        && !route.contains('@')
        && !route.contains('\\')
        && !route.contains(':')
        && !route.chars().any(|character| character <= ' ')
}

enum AuthFailure {
    Unauthorized,
    Unavailable,
}

async fn authenticate_api_key(
    store: &Arc<SecurityStore>,
    headers: &HeaderMap,
) -> Result<AuthContext, AuthFailure> {
    let key = extract_api_key(headers).ok_or(AuthFailure::Unauthorized)?;
    let key = Zeroizing::new(key);
    let store = Arc::clone(store);
    let correlation = mcp_request_id();
    match task::spawn_blocking(move || store.authenticate_api_key(&key, &correlation)).await {
        Ok(Ok(context)) => Ok(context),
        Ok(Err(SecurityError::Storage(_) | SecurityError::Poisoned)) | Err(_) => {
            Err(AuthFailure::Unavailable)
        }
        Ok(Err(_)) => Err(AuthFailure::Unauthorized),
    }
}

fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    if let Some(key) = headers
        .get("X-API-KEY")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|key| !key.is_empty())
    {
        return Some(key.to_owned());
    }
    let authorization = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, key) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || key.trim().is_empty() {
        return None;
    }
    Some(key.trim().to_owned())
}

fn mcp_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    format!("mcp-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn declared_body_too_large(headers: &HeaderMap, maximum: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > maximum as u64)
}

fn payload_too_large(maximum: usize) -> Response {
    json_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        json!({
            "error": "payload_too_large",
            "message": format!("MCP request body exceeds the configured limit of {maximum} bytes.")
        }),
    )
}

fn unauthorized() -> Response {
    let mut response = json_response(
        StatusCode::UNAUTHORIZED,
        json!({
            "error": "unauthorized",
            "message": "Provide a valid Stirling API key via the X-API-KEY header (or Authorization: Bearer <key>)."
        }),
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Bearer realm=\"Stirling MCP (API key)\""),
    );
    response
}

fn rpc_success(id: Value, result: Value) -> Value {
    Value::Object(Map::from_iter([
        ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
        ("id".to_owned(), id),
        ("result".to_owned(), result),
    ]))
}

fn rpc_failure(id: Value, code: i32, message: &str) -> Value {
    Value::Object(Map::from_iter([
        ("jsonrpc".to_owned(), Value::String("2.0".to_owned())),
        ("id".to_owned(), id),
        ("error".to_owned(), json!({"code":code, "message":message})),
    ]))
}

fn tool_text(text: &str) -> Value {
    json!({"content":[{"type":"text", "text":text}]})
}

fn tool_error(message: &str) -> Value {
    json!({"content":[{"type":"text", "text":message}], "isError":true})
}

fn text_argument<'a>(arguments: &'a Value, name: &str) -> Option<&'a str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn json_response(status: StatusCode, body: Value) -> Response {
    (status, axum::Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        AiCapability, AiCapabilityCatalog, EngineConnection, EngineError, MAX_CAPABILITIES,
        extract_api_key, is_safe_relative_route, operation_allowed, parse_manifest,
    };
    use crate::runtime_config::{McpAuthConfig, McpConfig};
    use axum::http::{HeaderMap, HeaderValue, header};
    use serde_json::json;
    use std::{
        collections::BTreeMap,
        io::{self, Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    #[test]
    fn manifest_is_bounded_and_unsafe_routes_are_skipped() {
        let manifest = serde_json::json!({"capabilities":[
            {"id":"good","description":"ok","input_schema":{"type":"object"},"required_scope":"","route":"/api/v1/pdf/questions"},
            {"id":"absolute","input_schema":{"type":"object"},"route":"https://evil.test/x"},
            {"id":"escape","input_schema":{"type":"object"},"route":"/api/../secret"},
            {"id":"missing-route","input_schema":{"type":"object"}}
        ]});
        let parsed =
            parse_manifest(&serde_json::to_vec(&manifest).unwrap_or_default()).unwrap_or_default();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed["good"].required_scope, "mcp.tools.write");
        assert!(parsed["missing-route"].route.is_none());
        assert!(!is_safe_relative_route("//evil.test/x"));
        assert!(!is_safe_relative_route("/api/v1/x y"));
    }

    #[test]
    fn manifest_rejects_excessive_entry_count() {
        let capabilities = (0..=MAX_CAPABILITIES)
            .map(|index| serde_json::json!({"id":index.to_string(),"input_schema":{}}))
            .collect::<Vec<_>>();
        let error = parse_manifest(
            &serde_json::to_vec(&serde_json::json!({"capabilities":capabilities}))
                .unwrap_or_default(),
        );
        assert!(matches!(error, Err(EngineError::InvalidManifest)));
    }

    #[test]
    fn api_key_header_wins_and_bearer_is_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-KEY", HeaderValue::from_static("header-key"));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("bearer bearer-key"),
        );
        assert_eq!(extract_api_key(&headers).as_deref(), Some("header-key"));
        headers.remove("X-API-KEY");
        assert_eq!(extract_api_key(&headers).as_deref(), Some("bearer-key"));
    }

    #[test]
    fn allow_and_block_filters_match_java_precedence() {
        let mut config = McpConfig {
            enabled: true,
            scopes_enabled: true,
            engine_capability_refresh_minutes: 5,
            allowed_operations: vec!["allowed".to_owned()],
            blocked_operations: Vec::new(),
            max_request_bytes: 1024,
            max_inline_response_bytes: 1024,
            auth: McpAuthConfig {
                mode: "apikey".to_owned(),
                issuer_uri: String::new(),
                jwks_uri: String::new(),
                resource_id: String::new(),
                accepted_audiences: Vec::new(),
                username_claim: "sub".to_owned(),
                require_existing_account: true,
            },
        };
        assert!(operation_allowed(&config, "allowed"));
        assert!(!operation_allowed(&config, "other"));
        config.blocked_operations.push("allowed".to_owned());
        assert!(!operation_allowed(&config, "allowed"));
    }

    #[test]
    fn engine_requests_send_the_shared_secret_and_only_the_provided_parameters()
    -> Result<(), Box<dyn std::error::Error>> {
        let manifest = json!({"capabilities":[{
            "id":"agent-draft",
            "input_schema":{"type":"object"},
            "route":"/api/v1/agents/draft"
        }]})
        .to_string();
        let (manifest_url, manifest_request, manifest_server) = mock_http_response(200, &manifest)?;
        let connection = EngineConnection {
            enabled: true,
            base_url: manifest_url,
            timeout: Duration::from_secs(1),
            shared_secret: Some("secret".to_owned()),
        };
        let fetched = super::fetch_manifest(&connection).unwrap_or_default();
        assert!(fetched.contains_key("agent-draft"));
        let request = manifest_request
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        assert!(request.starts_with("GET /api/v1/agents/capabilities HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-engine-auth: secret\r\n")
        );
        let _ = manifest_server.join();

        let (post_url, post_request, post_server) =
            mock_http_response(200, r#"{"accepted":true}"#)?;
        let connection = EngineConnection {
            enabled: true,
            base_url: post_url,
            timeout: Duration::from_secs(1),
            shared_secret: Some("secret".to_owned()),
        };
        let response = super::post_engine(
            &connection,
            "/api/v1/agents/draft",
            &json!({"prompt":"draft","fileId":"nested-only"}),
            "Canonical.User@Example.Test",
        )
        .unwrap_or_default();
        assert_eq!(response, r#"{"accepted":true}"#);
        let request = post_request
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default();
        assert!(request.starts_with("POST /api/v1/agents/draft HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-engine-auth: secret\r\n")
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-user-id: canonical.user@example.test\r\n")
        );
        assert!(request.ends_with(r#"{"fileId":"nested-only","prompt":"draft"}"#));
        let _ = post_server.join();
        Ok(())
    }

    #[tokio::test]
    async fn failed_refresh_retains_last_known_good_manifest_and_disabled_engine_clears_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let (url, request, server) = mock_http_response(500, r#"{"error":"unavailable"}"#)?;
        let catalog = AiCapabilityCatalog::new(
            EngineConnection {
                enabled: true,
                base_url: url,
                timeout: Duration::from_secs(1),
                shared_secret: None,
            },
            1,
        );
        if let Ok(mut cache) = catalog.cache.lock() {
            cache.operations = BTreeMap::from([(
                "cached-agent".to_owned(),
                AiCapability {
                    id: "cached-agent".to_owned(),
                    description: "last known good".to_owned(),
                    input_schema: json!({"type":"object"}),
                    required_scope: "mcp.tools.write".to_owned(),
                    route: Some("/api/v1/agents/draft".to_owned()),
                },
            )]);
            cache.last_attempt = None;
        }
        assert!(catalog.snapshot().await.contains_key("cached-agent"));
        let _ = request.recv_timeout(Duration::from_secs(2));
        let _ = server.join();

        let disabled = AiCapabilityCatalog::new(
            EngineConnection {
                enabled: false,
                base_url: "http://127.0.0.1:1".to_owned(),
                timeout: Duration::from_secs(1),
                shared_secret: None,
            },
            1,
        );
        let cached = catalog.snapshot().await;
        if let Ok(mut cache) = disabled.cache.lock() {
            cache.operations = cached;
        }
        assert!(disabled.snapshot().await.is_empty());
        assert!(
            disabled
                .cache
                .lock()
                .map(|cache| cache.operations.is_empty())
                .unwrap_or(false)
        );
        Ok(())
    }

    fn mock_http_response(
        status: u16,
        body: &str,
    ) -> io::Result<(String, mpsc::Receiver<String>, thread::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let body = body.to_owned();
        let (request_tx, request_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut request = Vec::new();
            let mut expected_length = None;
            loop {
                let mut chunk = [0_u8; 4096];
                let Ok(read) = stream.read(&mut chunk) else {
                    break;
                };
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if expected_length.is_none()
                    && let Some(header_end) =
                        request.windows(4).position(|part| part == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let length = headers.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    expected_length = Some((header_end + 4, length.unwrap_or(0)));
                }
                if expected_length
                    .is_some_and(|(header_end, length)| request.len() >= header_end + length)
                {
                    break;
                }
            }
            let _ = request_tx.send(String::from_utf8_lossy(&request).into_owned());
            let reason = if status == 200 { "OK" } else { "Error" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        Ok((format!("http://{address}"), request_rx, server))
    }
}
