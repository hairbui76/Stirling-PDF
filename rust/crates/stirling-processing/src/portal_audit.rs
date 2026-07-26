//! Enterprise portal surfaces derived from the durable audit store.
//!
//! Ports the proprietary Java `PortalDocumentsController` /
//! `PortalDocumentsService` and `PortalInfraAuditController` /
//! `PortalInfraAuditService` read-only endpoints. Both shape recent
//! `audit_events` into portal DTOs, are Enterprise-gated, and resolve a per
//! caller audit scope (admin sees the whole server; a team leader sees their
//! team; everyone else is denied).
//!
//! The `tier` query parameter is accepted for mock-seam symmetry with the Java
//! controllers and is ignored (neither surface is tier-scoped).

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::task;

use crate::security::{
    AuthContext, SecurityAuditEvent, SecurityAuditFilter, SecurityError, SecurityStore,
};

/// Portal Documents review queue. Java's `PortalDocumentsController` is a
/// `@ProprietaryUiDataApi`, so the class-level `/api/v1/proprietary/ui-data`
/// prefix is part of the route.
pub(crate) const DOCUMENTS_PATH: &str = "/api/v1/proprietary/ui-data/documents";
/// Portal Infrastructure -> Audit tab (same `@ProprietaryUiDataApi` prefix).
pub(crate) const INFRA_AUDIT_LOG_PATH: &str =
    "/api/v1/proprietary/ui-data/infrastructure/audit-log";

/// Rows returned to each surface after filtering (mirrors Java `RETURN_LIMIT`).
const RETURN_LIMIT: usize = 40;
/// Newest rows scanned per scope before each surface filters them down
/// (mirrors Java `PortalAuditReadService.SCAN_LIMIT`).
const SCAN_LIMIT: usize = 400;
/// The reviewed audit store caps a single query page at 200 rows.
const QUERY_PAGE_SIZE: usize = 200;

/// Every standard audit type except the read/polling noise (`UI_DATA`,
/// `HTTP_REQUEST`). Java excludes the two noise types with a `NOT IN` query;
/// the reviewed store filter only expresses a positive `IN`, so the equivalent
/// allow-list of the seven meaningful standard types is used instead.
const NON_NOISE_EVENT_TYPES: [&str; 7] = [
    "USER_LOGIN",
    "USER_LOGOUT",
    "USER_FAILED_LOGIN",
    "USER_PROFILE_UPDATE",
    "SETTINGS_CHANGED",
    "FILE_OPERATION",
    "PDF_PROCESS",
];

pub(crate) fn routes() -> Router {
    Router::new()
        .route(DOCUMENTS_PATH, get(documents))
        .route(INFRA_AUDIT_LOG_PATH, get(infrastructure_audit_log))
}

// ---------------------------------------------------------------------------
// DTOs (camelCase JSON parity with the Java model classes)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortalDocumentsResponse {
    summary: PortalDocumentsSummary,
    documents: Vec<PortalReviewDocument>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortalDocumentsSummary {
    total_in_queue: usize,
    processed: usize,
    errors: usize,
    processed_today: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortalReviewDocument {
    id: String,
    name: String,
    #[serde(rename = "type")]
    doc_type: String,
    product: String,
    action: String,
    user: String,
    status: String,
    source: String,
    confidence: Option<f64>,
    fields_extracted: u32,
    time: String,
    sensitive: bool,
    extractions: Vec<Value>,
    audit: Vec<PortalDocAuditEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortalDocAuditEvent {
    id: String,
    kind: String,
    time: String,
    actor: String,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfraAuditLogResponse {
    summary: InfraAuditSummary,
    events: Vec<InfraAuditEvent>,
    full_server: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfraAuditSummary {
    total_events: usize,
    policy: usize,
    processing: usize,
    elevation: usize,
    config: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InfraAuditEvent {
    id: String,
    timestamp: String,
    category: String,
    action: String,
    actor: String,
    target: String,
    status: String,
    latency_ms: i64,
}

// ---------------------------------------------------------------------------
// Scope resolution + event fetch
// ---------------------------------------------------------------------------

/// Resolved audit visibility for the calling principal.
enum PortalAuditScope {
    /// Whole-server view (admins).
    Server,
    /// Team-scoped view: events by the given principals (team leaders).
    Team(Vec<String>),
}

/// Resolves which slice of the audit log the caller may see.
///
/// Mirrors the combined Java behavior of `DefaultPortalAuditScopeResolver`
/// (admin -> server) and `SaasPortalAuditScopeResolver` (team leader ->
/// team-scoped). `Ok(None)` denies the caller (HTTP 403).
fn resolve_scope(
    store: &SecurityStore,
    context: &AuthContext,
) -> Result<Option<PortalAuditScope>, SecurityError> {
    if context.has_role("ROLE_ADMIN") {
        return Ok(Some(PortalAuditScope::Server));
    }
    let Some(team_id) = context.team_id else {
        return Ok(None);
    };
    if !store.is_team_owner(context.user_id, team_id)? {
        return Ok(None);
    }
    let principals = store
        .list_users(Utc::now().timestamp())?
        .into_iter()
        .filter(|user| user.team_id == Some(team_id))
        .map(|user| user.username)
        .collect::<Vec<_>>();
    Ok(Some(PortalAuditScope::Team(principals)))
}

/// Reads recent non-noise events for a scope, newest-first, up to `SCAN_LIMIT`.
///
/// Mirrors `PortalAuditReadService`: the server view is unfiltered by principal;
/// a team scope with no principals yields an empty log.
fn fetch_events(
    store: &SecurityStore,
    scope: &PortalAuditScope,
) -> Result<Vec<SecurityAuditEvent>, SecurityError> {
    let principals = match scope {
        PortalAuditScope::Server => Vec::new(),
        PortalAuditScope::Team(principals) => {
            if principals.is_empty() {
                return Ok(Vec::new());
            }
            principals.clone()
        }
    };
    let filter = SecurityAuditFilter {
        event_types: NON_NOISE_EVENT_TYPES
            .iter()
            .map(|event_type| (*event_type).to_owned())
            .collect(),
        principals,
        ..SecurityAuditFilter::default()
    };
    let mut events = Vec::new();
    let mut offset = 0;
    while events.len() < SCAN_LIMIT {
        let page_size = QUERY_PAGE_SIZE.min(SCAN_LIMIT - events.len());
        let page = store.query_audit_events(&filter, offset, page_size)?;
        let fetched = page.events.len();
        events.extend(page.events);
        if fetched < page_size {
            break;
        }
        offset += fetched;
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn documents(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    let result = task::spawn_blocking(move || {
        let Some(scope) = resolve_scope(&store, &context)? else {
            return Ok(None);
        };
        let events = fetch_events(&store, &scope)?;
        Ok::<_, SecurityError>(Some(build_documents(&events)))
    })
    .await;
    match result {
        Ok(Ok(Some(body))) => Json(body).into_response(),
        Ok(Ok(None)) => forbidden(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn infrastructure_audit_log(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    let result = task::spawn_blocking(move || {
        let Some(scope) = resolve_scope(&store, &context)? else {
            return Ok(None);
        };
        let full_server = matches!(scope, PortalAuditScope::Server);
        let events = fetch_events(&store, &scope)?;
        Ok::<_, SecurityError>(Some(build_infra_audit_log(&events, full_server)))
    })
    .await;
    match result {
        Ok(Ok(Some(body))) => Json(body).into_response(),
        Ok(Ok(None)) => forbidden(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

fn forbidden() -> Response {
    StatusCode::FORBIDDEN.into_response()
}

fn service_unavailable() -> Response {
    StatusCode::SERVICE_UNAVAILABLE.into_response()
}

// ---------------------------------------------------------------------------
// Documents shaping (ports PortalDocumentsService)
// ---------------------------------------------------------------------------

fn build_documents(events: &[SecurityAuditEvent]) -> PortalDocumentsResponse {
    let now = Utc::now().timestamp();
    let day_ago = now - 86_400;
    let mut documents = Vec::new();
    let mut processed_today = 0;

    for event in events {
        if documents.len() >= RETURN_LIMIT {
            break;
        }
        if !is_file_bearing(&event.event_type) {
            continue;
        }
        let data = parse_data(event);
        let Some(files) = data.get("files").and_then(Value::as_array) else {
            continue;
        };
        let path = as_string(data.get("path"));
        // Pipeline steps run over an internal loopback (API-key auth), so the
        // origin alone reads as "API". The automation marker distinguishes a
        // policy-run step from real API traffic.
        let automation = is_automation(&data);
        let policy_name = as_string(data.get("policyName"));
        let source = if automation {
            match policy_name.as_deref() {
                Some(name) if !name.trim().is_empty() => format!("Policy: {name}"),
                _ => "Policy automation".to_owned(),
            }
        } else {
            // Java reads a `__origin` data key; the reviewed store carries the
            // same request origin in the durable `source` column instead.
            source_label(&event.source)
        };
        let product = if automation {
            "Automation".to_owned()
        } else {
            product_label(&source)
        };
        let action = documents_pretty_tool(path.as_deref());
        let failed = is_failure(&data);
        let timestamp = event.timestamp;

        let mut index = 0;
        for file in files {
            if documents.len() >= RETURN_LIMIT {
                break;
            }
            let Some(file) = file.as_object() else {
                continue;
            };
            let Some(name) = as_string(file.get("name")) else {
                continue;
            };
            if name.trim().is_empty() {
                continue;
            }
            let row_id = format!("{}-{index}", event.id);
            index += 1;
            documents.push(to_document(
                &row_id,
                &name,
                as_string(file.get("type")).as_deref(),
                &product,
                &action,
                &event.principal,
                failed,
                &source,
                timestamp,
                now,
            ));
            if !failed && timestamp > day_ago {
                processed_today += 1;
            }
        }
    }

    let processed = documents
        .iter()
        .filter(|document| document.status == "processed")
        .count();
    let errors = documents.len() - processed;

    PortalDocumentsResponse {
        summary: PortalDocumentsSummary {
            total_in_queue: documents.len(),
            processed,
            errors,
            processed_today,
        },
        documents,
    }
}

#[allow(clippy::too_many_arguments)]
fn to_document(
    row_id: &str,
    name: &str,
    content_type: Option<&str>,
    product: &str,
    action: &str,
    user: &str,
    failed: bool,
    source: &str,
    timestamp: i64,
    now: i64,
) -> PortalReviewDocument {
    let time = relative_time(timestamp, now);
    let detail = if failed {
        format!("{action} failed")
    } else {
        format!("{action} via {source}")
    };
    let op = PortalDocAuditEvent {
        id: format!("{row_id}-op"),
        kind: if failed { "flagged" } else { "extracted" }.to_owned(),
        time: time.clone(),
        actor: user.to_owned(),
        detail,
    };
    PortalReviewDocument {
        id: format!("doc-{row_id}"),
        name: name.to_owned(),
        doc_type: doc_type(content_type, name).to_owned(),
        product: product.to_owned(),
        action: action.to_owned(),
        user: user.to_owned(),
        status: if failed { "error" } else { "processed" }.to_owned(),
        source: source.to_owned(),
        confidence: None,
        fields_extracted: 0,
        time,
        // Audit events don't reveal content sensitivity, so never guess it.
        sensitive: false,
        extractions: Vec::new(),
        audit: vec![op],
    }
}

fn is_file_bearing(event_type: &str) -> bool {
    event_type == "PDF_PROCESS" || event_type == "FILE_OPERATION"
}

fn is_failure(data: &Map<String, Value>) -> bool {
    if let Some(Value::String(status)) = data.get("status")
        && status.eq_ignore_ascii_case("failure")
    {
        return true;
    }
    as_integer(data.get("statusCode")).is_some_and(|code| code >= 400)
}

fn source_label(origin: &str) -> String {
    match origin {
        "API" => "API integration",
        "SYSTEM" => "System",
        _ => "Web upload",
    }
    .to_owned()
}

fn product_label(source: &str) -> String {
    if source == "API integration" {
        "API"
    } else {
        "Editor"
    }
    .to_owned()
}

fn doc_type(content_type: Option<&str>, name: &str) -> &'static str {
    let content_type = content_type
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if content_type.contains("pdf") || extension == "pdf" {
        return "PDF";
    }
    if content_type.starts_with("image/")
        || matches!(
            extension.as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "tif" | "tiff"
        )
    {
        return "Image";
    }
    if content_type.contains("word") || matches!(extension.as_str(), "doc" | "docx") {
        return "Word";
    }
    "Document"
}

/// Documents-tab tool label: title-cases the last path segment, recognizes
/// `/convert/{from}/{to}` endpoints, and defaults to "Processed".
fn documents_pretty_tool(path: Option<&str>) -> String {
    let Some(path) = path.filter(|value| !value.trim().is_empty()) else {
        return "Processed".to_owned();
    };
    let parts = java_split_slash(path);
    for index in 0..parts.len().saturating_sub(2) {
        if parts[index] == "convert" && !parts[index + 1].is_empty() && !parts[index + 2].is_empty()
        {
            return format!(
                "Convert {} to {}",
                documents_pretty_words(parts[index + 1]),
                documents_pretty_words(parts[index + 2])
            );
        }
    }
    let last = parts.last().copied().unwrap_or(path);
    let pretty = documents_pretty_words(last);
    if pretty.is_empty() {
        "Processed".to_owned()
    } else {
        pretty
    }
}

/// Title-case a hyphenated path segment for the documents tab, upper-casing the
/// acronyms the Java documents service recognizes.
fn documents_pretty_words(segment: &str) -> String {
    let mut words = Vec::new();
    for word in segment.split('-') {
        if word.is_empty() {
            continue;
        }
        let mapped = match word.to_ascii_lowercase().as_str() {
            "pdf" => "PDF".to_owned(),
            "pdfs" => "PDFs".to_owned(),
            "ocr" => "OCR".to_owned(),
            "img" => "Image".to_owned(),
            "csv" => "CSV".to_owned(),
            _ => capitalize(word),
        };
        words.push(mapped);
    }
    words.join(" ")
}

fn relative_time(timestamp: i64, now: i64) -> String {
    let seconds = now - timestamp;
    if seconds < 60 {
        return "just now".to_owned();
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return format!("{minutes}m ago");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    format!("{}d ago", hours / 24)
}

// ---------------------------------------------------------------------------
// Infrastructure audit shaping (ports PortalInfraAuditService)
// ---------------------------------------------------------------------------

fn build_infra_audit_log(
    events: &[SecurityAuditEvent],
    full_server: bool,
) -> InfraAuditLogResponse {
    let events = events
        .iter()
        .filter(|event| is_infra_relevant(&event.event_type))
        .map(infra_event)
        .take(RETURN_LIMIT)
        .collect::<Vec<_>>();

    let count_category = |category: &str| {
        events
            .iter()
            .filter(|event| event.category == category)
            .count()
    };
    let summary = InfraAuditSummary {
        total_events: events.len(),
        policy: count_category("policy"),
        processing: count_category("processing"),
        elevation: count_category("elevation"),
        config: count_category("config"),
    };

    InfraAuditLogResponse {
        summary,
        events,
        full_server,
    }
}

/// `UI_DATA` and `HTTP_REQUEST` are read/polling noise - excluded from the view.
fn is_infra_relevant(event_type: &str) -> bool {
    event_type != "UI_DATA" && event_type != "HTTP_REQUEST"
}

fn infra_event(event: &SecurityAuditEvent) -> InfraAuditEvent {
    let data = parse_data(event);
    let path = as_string(data.get("path"));
    let policy_name = as_string(data.get("policyName"));
    let automation = is_automation(&data);
    // Classify a dispatch by its real run-path URI, not a policyName: the latter
    // can be spoofed via a header to make a direct call pose as a policy row.
    let policy_dispatch = is_policy_run_path(path.as_deref()) && !automation;
    let category = if policy_dispatch {
        "policy".to_owned()
    } else {
        category_for(&event.event_type, path.as_deref()).to_owned()
    };

    InfraAuditEvent {
        id: event.id.to_string(),
        timestamp: infra_timestamp(event.timestamp),
        action: action_for(
            &event.event_type,
            path.as_deref(),
            policy_name.as_deref(),
            automation,
        ),
        target: target_for(&category, path.as_deref(), &data, policy_dispatch),
        status: status_for(&event.event_type, &category, &data).to_owned(),
        category,
        actor: event.principal.clone(),
        latency_ms: as_long(data.get("latencyMs")),
    }
}

fn infra_timestamp(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0).map_or_else(String::new, |value| {
        value.format("%Y-%m-%d %H:%M:%S").to_string()
    })
}

fn category_for(event_type: &str, path: Option<&str>) -> &'static str {
    match event_type {
        "USER_LOGIN" | "USER_LOGOUT" | "USER_FAILED_LOGIN" => "auth",
        "SETTINGS_CHANGED" | "USER_PROFILE_UPDATE" => "config",
        "PDF_PROCESS" | "FILE_OPERATION" => {
            if is_security_path(path) {
                "security"
            } else {
                "processing"
            }
        }
        _ => "processing",
    }
}

fn is_security_path(path: Option<&str>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let path = path.to_ascii_lowercase();
    path.contains("/security/")
        || path.contains("password")
        || path.contains("watermark")
        || path.contains("sign")
        || path.contains("cert")
        || path.contains("redact")
}

fn action_for(
    event_type: &str,
    path: Option<&str>,
    policy_name: Option<&str>,
    automation: bool,
) -> String {
    if !automation && is_policy_run_path(path) {
        // A run with no name (ad-hoc pipeline) still reads better than "run".
        return policy_name.map_or_else(|| "Policy run".to_owned(), ToOwned::to_owned);
    }
    let base = base_action_for(event_type, path);
    if automation {
        return match policy_name {
            Some(name) => format!("{base} (policy: {name})"),
            None => format!("{base} (automation)"),
        };
    }
    base
}

fn is_policy_run_path(path: Option<&str>) -> bool {
    path.is_some_and(|path| {
        path.contains("/policies/") && (path.ends_with("/run") || path.ends_with("/run/stream"))
    })
}

fn base_action_for(event_type: &str, path: Option<&str>) -> String {
    match event_type {
        "USER_LOGIN" => "User signed in".to_owned(),
        "USER_LOGOUT" => "User signed out".to_owned(),
        "USER_FAILED_LOGIN" => "Failed sign-in attempt".to_owned(),
        "USER_PROFILE_UPDATE" => "Profile settings updated".to_owned(),
        "SETTINGS_CHANGED" => "Admin settings changed".to_owned(),
        _ => infra_pretty_tool(path),
    }
}

/// Infrastructure-tab tool label: title-cases the last path segment with a
/// broader acronym map and defaults to "PDF operation".
fn infra_pretty_tool(path: Option<&str>) -> String {
    let Some(path) = path.filter(|value| !value.trim().is_empty()) else {
        return "PDF operation".to_owned();
    };
    let parts = java_split_slash(path);
    let last = parts.last().copied().unwrap_or(path);
    let mut words = Vec::new();
    for word in last.split('-') {
        if word.is_empty() {
            continue;
        }
        let mapped = match word.to_ascii_lowercase().as_str() {
            "pdf" => "PDF".to_owned(),
            "pdfs" => "PDFs".to_owned(),
            "ocr" => "OCR".to_owned(),
            "img" => "Image".to_owned(),
            "csv" => "CSV".to_owned(),
            "html" => "HTML".to_owned(),
            "url" => "URL".to_owned(),
            "xml" => "XML".to_owned(),
            _ => capitalize(word),
        };
        words.push(mapped);
    }
    if words.is_empty() {
        "PDF operation".to_owned()
    } else {
        words.join(" ")
    }
}

/// "Auto Redact, Compress PDF" from the run's step endpoints; first three,
/// then "+N more".
fn pretty_step_list(steps: Option<&Value>) -> Option<String> {
    let steps = steps?.as_array()?;
    if steps.is_empty() {
        return None;
    }
    let shown = steps.len().min(3);
    let labels = steps
        .iter()
        .take(shown)
        .map(|step| infra_pretty_tool(as_string(Some(step)).as_deref()))
        .collect::<Vec<_>>()
        .join(", ");
    if steps.len() > shown {
        Some(format!("{labels} +{} more", steps.len() - shown))
    } else {
        Some(labels)
    }
}

fn target_for(
    category: &str,
    path: Option<&str>,
    data: &Map<String, Value>,
    policy_dispatch: bool,
) -> String {
    if policy_dispatch {
        // The run touches no single file at this level; show the tools instead.
        return pretty_step_list(data.get("policySteps")).unwrap_or_else(|| "Pipeline".to_owned());
    }
    if category == "auth" {
        // Auth events don't act on a resource; the session is the closest thing.
        return "Web session".to_owned();
    }
    if category == "config" {
        return non_blank(path).map_or_else(|| "System settings".to_owned(), ToOwned::to_owned);
    }
    // processing / security: prefer the first affected file name.
    if let Some(file) = first_file_name(data) {
        return file;
    }
    non_blank(path).map_or_else(
        || "Document".to_owned(),
        |path| infra_pretty_tool(Some(path)),
    )
}

fn status_for(event_type: &str, category: &str, data: &Map<String, Value>) -> &'static str {
    if event_type == "USER_FAILED_LOGIN" {
        return "danger";
    }
    let status = as_string(data.get("status"));
    let code = as_integer(data.get("statusCode"));
    if status.is_some_and(|status| status.eq_ignore_ascii_case("failure"))
        || code.is_some_and(|code| code >= 500)
    {
        return "danger";
    }
    if code.is_some_and(|code| code >= 400) {
        return "warning";
    }
    if category == "config" {
        return "info";
    }
    "success"
}

fn first_file_name(data: &Map<String, Value>) -> Option<String> {
    let first = data.get("files")?.as_array()?.first()?.as_object()?;
    as_string(first.get("name"))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Parses the event `data` document into an object map, treating a null payload
/// or any parse failure as an empty map (matches the Java services).
fn parse_data(event: &SecurityAuditEvent) -> Map<String, Value> {
    if event.data.is_empty() {
        return Map::new();
    }
    match serde_json::from_str::<Value>(&event.data) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

fn is_automation(data: &Map<String, Value>) -> bool {
    match data.get("automation") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Java's `asString`: null/absent -> `None`; otherwise a string form of the
/// value (`String.valueOf`).
fn as_string(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        Some(Value::Number(value)) => Some(value.to_string()),
        Some(other) => Some(other.to_string()),
    }
}

/// Java's numeric coercion: only a JSON number yields a value (a string never
/// does), matching `instanceof Number`.
fn as_integer(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

fn as_long(value: Option<&Value>) -> i64 {
    as_integer(value).unwrap_or(0)
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

/// Upper-cases the first character and preserves the remainder, matching Java's
/// `Character.toUpperCase(charAt(0)) + substring(1)`.
fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Splits on `/` like Java's `String.split("/")` with the default limit:
/// trailing empty segments are dropped, interior empties are kept.
fn java_split_slash(value: &str) -> Vec<&str> {
    let mut parts = value.split('/').collect::<Vec<_>>();
    while parts.last() == Some(&"") {
        parts.pop();
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::{
        SecurityAuditEvent, build_documents, build_infra_audit_log, category_for, doc_type,
        documents_pretty_tool, infra_pretty_tool, status_for,
    };
    use serde_json::{Map, Value};

    fn event(
        id: i64,
        event_type: &str,
        source: &str,
        data: &str,
        timestamp: i64,
    ) -> SecurityAuditEvent {
        SecurityAuditEvent {
            id,
            principal: "alice@example.test".to_owned(),
            event_type: event_type.to_owned(),
            source: source.to_owned(),
            data: data.to_owned(),
            timestamp,
        }
    }

    fn data_of(json: &str) -> Map<String, Value> {
        match serde_json::from_str::<Value>(json) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        }
    }

    #[test]
    fn documents_tool_label_recognizes_convert_and_acronyms() {
        assert_eq!(
            documents_pretty_tool(Some("/api/v1/misc/compress-pdf")),
            "Compress PDF"
        );
        assert_eq!(
            documents_pretty_tool(Some("/api/v1/convert/pdf/word")),
            "Convert PDF to Word"
        );
        assert_eq!(
            documents_pretty_tool(Some("/api/v1/security/auto-redact")),
            "Auto Redact"
        );
        assert_eq!(documents_pretty_tool(None), "Processed");
    }

    #[test]
    fn infra_tool_label_does_not_expand_convert_and_defaults_to_pdf_operation() {
        assert_eq!(infra_pretty_tool(Some("/api/v1/convert/pdf/word")), "Word");
        assert_eq!(
            infra_pretty_tool(Some("/api/v1/misc/merge-pdfs")),
            "Merge PDFs"
        );
        assert_eq!(infra_pretty_tool(Some("   ")), "PDF operation");
    }

    #[test]
    fn security_path_and_config_drive_category_and_status() {
        assert_eq!(
            category_for("PDF_PROCESS", Some("/api/v1/security/auto-redact")),
            "security"
        );
        assert_eq!(
            category_for("PDF_PROCESS", Some("/api/v1/misc/compress-pdf")),
            "processing"
        );
        assert_eq!(category_for("SETTINGS_CHANGED", None), "config");
        assert_eq!(
            status_for("USER_FAILED_LOGIN", "auth", &Map::new()),
            "danger"
        );
        assert_eq!(
            status_for(
                "PDF_PROCESS",
                "processing",
                &data_of("{\"statusCode\":500}")
            ),
            "danger"
        );
        assert_eq!(
            status_for(
                "PDF_PROCESS",
                "processing",
                &data_of("{\"statusCode\":422}")
            ),
            "warning"
        );
        assert_eq!(
            status_for("SETTINGS_CHANGED", "config", &Map::new()),
            "info"
        );
    }

    #[test]
    fn doc_type_uses_content_type_and_extension() {
        assert_eq!(doc_type(Some("application/pdf"), "a.bin"), "PDF");
        assert_eq!(doc_type(None, "photo.PNG"), "Image");
        assert_eq!(doc_type(Some("application/msword"), "letter.bin"), "Word");
        assert_eq!(doc_type(None, "notes.txt"), "Document");
    }

    #[test]
    fn infra_summary_counts_categories_and_excludes_noise_newest_first() {
        let now = 1_900_000_000;
        let events = vec![
            event(9, "HTTP_REQUEST", "WEB", "{\"path\":\"/health\"}", now - 5),
            event(
                8,
                "PDF_PROCESS",
                "SYSTEM",
                "{\"path\":\"/api/v1/policies/run\",\"policyName\":\"Nightly\",\"policySteps\":[\"/api/v1/security/auto-redact\",\"/api/v1/misc/compress-pdf\"],\"statusCode\":202,\"latencyMs\":7}",
                now - 10,
            ),
            event(
                7,
                "PDF_PROCESS",
                "API",
                "{\"path\":\"/api/v1/misc/compress-pdf\",\"files\":[{\"name\":\"a.pdf\"}],\"statusCode\":200}",
                now - 20,
            ),
            event(
                6,
                "SETTINGS_CHANGED",
                "WEB",
                "{\"path\":\"/api/v1/admin/settings\"}",
                now - 30,
            ),
            event(5, "USER_LOGIN", "WEB", "{}", now - 40),
        ];
        let response = build_infra_audit_log(&events, true);
        assert!(response.full_server);
        assert_eq!(response.events.len(), 4);
        // Noise (HTTP_REQUEST) excluded, newest-first.
        assert_eq!(response.events[0].id, "8");
        assert_eq!(response.events[0].category, "policy");
        assert_eq!(response.events[0].action, "Nightly");
        assert_eq!(response.events[0].target, "Auto Redact, Compress PDF");
        assert_eq!(response.events[1].category, "processing");
        assert_eq!(response.events[1].target, "a.pdf");
        assert_eq!(response.summary.total_events, 4);
        assert_eq!(response.summary.policy, 1);
        assert_eq!(response.summary.processing, 1);
        assert_eq!(response.summary.config, 1);
        assert_eq!(response.summary.elevation, 0);
    }

    #[test]
    fn documents_label_automation_and_direct_api_from_source_column() {
        let now = 1_900_000_000;
        let automation = build_documents(&[event(
            1,
            "PDF_PROCESS",
            "API",
            "{\"path\":\"/api/v1/security/auto-redact\",\"automation\":true,\"files\":[{\"name\":\"mushroom life.pdf\",\"type\":\"application/pdf\"}],\"statusCode\":200}",
            now - 10,
        )]);
        let doc = &automation.documents[0];
        assert_eq!(doc.name, "mushroom life.pdf");
        assert_eq!(doc.action, "Auto Redact");
        assert_eq!(doc.product, "Automation");
        assert_eq!(doc.source, "Policy automation");

        let direct = build_documents(&[event(
            2,
            "PDF_PROCESS",
            "API",
            "{\"path\":\"/api/v1/misc/compress-pdf\",\"files\":[{\"name\":\"a.pdf\",\"type\":\"application/pdf\"}],\"statusCode\":200}",
            now - 10,
        )]);
        let doc = &direct.documents[0];
        assert_eq!(doc.product, "API");
        assert_eq!(doc.source, "API integration");
    }
}
