//! Administrator-only HTTP compatibility for the proprietary audit APIs.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Json, Router,
    extract::{Extension, RawQuery},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, Local, NaiveDate, SecondsFormat, TimeZone, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::task;

use crate::security::{
    SecurityAuditEvent, SecurityAuditFilter, SecurityAuditPage, SecurityAuditUsageScope,
    SecurityError, SecurityStore,
};

const STANDARD_EVENT_TYPES: [&str; 9] = [
    "FILE_OPERATION",
    "HTTP_REQUEST",
    "PDF_PROCESS",
    "SETTINGS_CHANGED",
    "UI_DATA",
    "USER_FAILED_LOGIN",
    "USER_LOGIN",
    "USER_LOGOUT",
    "USER_PROFILE_UPDATE",
];
const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_QUERY_PAIRS: usize = 128;
const DEFAULT_PAGE_SIZE: usize = 30;

pub(crate) fn routes() -> Router {
    Router::new()
        .route("/api/v1/audit/data", get(dashboard_data))
        .route("/api/v1/audit/stats", get(dashboard_stats))
        .route("/api/v1/audit/types", get(audit_types))
        .route("/api/v1/audit/export/csv", get(dashboard_export_csv))
        .route("/api/v1/audit/export/json", get(dashboard_export_json))
        .route("/api/v1/audit/cleanup/before", delete(cleanup_before))
        .route(
            "/api/v1/proprietary/ui-data/audit-events",
            get(ui_audit_events),
        )
        .route(
            "/api/v1/proprietary/ui-data/audit-charts",
            get(ui_audit_charts),
        )
        .route(
            "/api/v1/proprietary/ui-data/audit-event-types",
            get(audit_types),
        )
        .route("/api/v1/proprietary/ui-data/audit-users", get(audit_users))
        .route(
            "/api/v1/proprietary/ui-data/audit-stats",
            get(ui_audit_stats),
        )
        .route(
            "/api/v1/proprietary/ui-data/audit-export",
            get(ui_audit_export),
        )
        .route(
            "/api/v1/proprietary/ui-data/audit-clear-all",
            post(clear_all),
        )
        .route(
            "/api/v1/proprietary/ui-data/usage-endpoint-statistics",
            get(endpoint_usage_statistics),
        )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardDataResponse {
    content: Vec<PersistentAuditEventResponse>,
    total_pages: usize,
    total_elements: usize,
    current_page: usize,
}

#[derive(Serialize)]
struct PersistentAuditEventResponse {
    id: i64,
    principal: String,
    #[serde(rename = "type")]
    event_type: String,
    source: String,
    data: String,
    timestamp: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardStatsResponse {
    events_by_type: BTreeMap<String, u64>,
    events_by_principal: BTreeMap<String, u64>,
    events_by_day: BTreeMap<String, u64>,
    total_events: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventsResponse {
    events: Vec<AuditEventDto>,
    total_events: usize,
    page: usize,
    page_size: usize,
    total_pages: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventDto {
    id: String,
    timestamp: String,
    event_type: String,
    username: String,
    ip_address: String,
    details: Map<String, Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditChartsData {
    #[serde(rename = "eventsByType")]
    by_type: ChartData,
    #[serde(rename = "eventsByUser")]
    by_user: ChartData,
    #[serde(rename = "eventsOverTime")]
    over_time: ChartData,
}

#[derive(Serialize)]
struct ChartData {
    labels: Vec<String>,
    values: Vec<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditStatsData {
    total_events: usize,
    prev_total_events: usize,
    unique_users: usize,
    prev_unique_users: usize,
    success_rate: f64,
    prev_success_rate: f64,
    avg_latency_ms: f64,
    prev_avg_latency_ms: f64,
    error_count: u64,
    top_event_type: String,
    top_user: String,
    events_by_type: BTreeMap<String, u64>,
    events_by_user: BTreeMap<String, u64>,
    top_tools: BTreeMap<String, u64>,
    hourly_distribution: BTreeMap<String, u64>,
}

#[derive(Default)]
struct AuditMetrics {
    total_events: usize,
    unique_users: usize,
    success_rate: f64,
    avg_latency_ms: f64,
    error_count: u64,
    top_event_type: String,
    top_user: String,
    events_by_type: BTreeMap<String, u64>,
    events_by_user: BTreeMap<String, u64>,
    top_tools: BTreeMap<String, u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EndpointUsageStatistics {
    endpoints: Vec<EndpointUsage>,
    total_endpoints: i32,
    total_visits: i32,
}

#[derive(Serialize)]
struct EndpointUsage {
    endpoint: String,
    visits: i32,
    percentage: f64,
}

#[derive(Clone, Copy)]
enum EndpointUsageDataType {
    All,
    Ui,
    Api,
    Unknown,
}

struct EndpointUsageQuery {
    limit: Option<usize>,
    data_type: EndpointUsageDataType,
    days: i32,
}

#[derive(Default)]
struct QueryValues(BTreeMap<String, Vec<String>>);

#[derive(Clone, Copy)]
struct AuditQueryError(&'static str);

type AuditQueryResult<T> = Result<T, AuditQueryError>;

impl IntoResponse for AuditQueryError {
    fn into_response(self) -> Response {
        bad_request(self.0)
    }
}

impl QueryValues {
    fn parse(raw: Option<String>) -> AuditQueryResult<Self> {
        let raw = raw.unwrap_or_default();
        if raw.len() > MAX_QUERY_BYTES {
            return Err(AuditQueryError("Query is too large"));
        }
        let mut values = BTreeMap::<String, Vec<String>>::new();
        for (index, pair) in raw.split('&').filter(|pair| !pair.is_empty()).enumerate() {
            if index >= MAX_QUERY_PAIRS {
                return Err(AuditQueryError("Too many query parameters"));
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = decode_query_component(key)?;
            let value = decode_query_component(value)?;
            let key = key.strip_suffix("[]").unwrap_or(&key).to_owned();
            values.entry(key).or_default().push(value);
        }
        Ok(Self(values))
    }

    fn optional(&self, name: &str) -> AuditQueryResult<Option<String>> {
        let Some(values) = self.0.get(name) else {
            return Ok(None);
        };
        if values.len() != 1 {
            return Err(AuditQueryError("Ambiguous query parameter"));
        }
        let value = values[0].trim();
        Ok((!value.is_empty()).then(|| value.to_owned()))
    }

    fn optional_raw(&self, name: &str) -> AuditQueryResult<Option<String>> {
        let Some(values) = self.0.get(name) else {
            return Ok(None);
        };
        if values.len() != 1 {
            return Err(AuditQueryError("Ambiguous query parameter"));
        }
        Ok((!values[0].is_empty()).then(|| values[0].clone()))
    }

    fn many(&self, name: &str) -> Vec<String> {
        self.0
            .get(name)
            .into_iter()
            .flatten()
            .flat_map(|value| value.split(','))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }
}

async fn dashboard_data(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let (page, size) = match pagination(&query, "size") {
        Ok(pagination) => pagination,
        Err(error) => return error.into_response(),
    };
    let filter = match dashboard_filter(&query) {
        Ok(filter) => filter,
        Err(error) => return error.into_response(),
    };
    let Some(offset) = page.checked_mul(size) else {
        return bad_request("Invalid pagination");
    };
    let result =
        task::spawn_blocking(move || store.query_audit_events(&filter, offset, size)).await;
    match result {
        Ok(Ok(events)) => Json(dashboard_page(events, page, size)).into_response(),
        Ok(Err(SecurityError::InvalidInput)) => bad_request("Invalid audit query"),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn dashboard_stats(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let days = match bounded_days(&query, "days", 7) {
        Ok(days) => days,
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().timestamp();
    let filter = SecurityAuditFilter {
        start_at: Some(now.saturating_sub(i64::from(days) * 86_400)),
        end_at: Some(now.saturating_add(1)),
        ..SecurityAuditFilter::default()
    };
    let result = task::spawn_blocking(move || store.export_audit_events(&filter)).await;
    match result {
        Ok(Ok(events)) => Json(simple_stats(&events)).into_response(),
        Ok(Err(SecurityError::InvalidInput)) => export_too_large(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn audit_types(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    let result = task::spawn_blocking(move || store.audit_event_types()).await;
    match result {
        Ok(Ok(stored)) => {
            let mut types = stored
                .into_iter()
                .chain(STANDARD_EVENT_TYPES.into_iter().map(ToOwned::to_owned))
                .collect::<Vec<_>>();
            types.sort();
            types.dedup();
            Json(types).into_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn audit_users(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    match task::spawn_blocking(move || store.audit_principals()).await {
        Ok(Ok(users)) => Json(users).into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn endpoint_usage_statistics(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let query = match endpoint_usage_query(&query) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let scope = match query.data_type {
        EndpointUsageDataType::All => SecurityAuditUsageScope::All,
        EndpointUsageDataType::Ui => SecurityAuditUsageScope::Ui,
        EndpointUsageDataType::Api => SecurityAuditUsageScope::Api,
        EndpointUsageDataType::Unknown => {
            return Json(empty_endpoint_usage_statistics()).into_response();
        }
    };
    let cutoff = Utc::now()
        .timestamp()
        .saturating_sub(i64::from(query.days) * 86_400);
    let result = task::spawn_blocking(move || {
        let data = store.endpoint_usage_audit_data(cutoff, scope)?;
        Ok::<_, SecurityError>(aggregate_endpoint_usage(&data, query.limit))
    })
    .await;
    match result {
        Ok(Ok(statistics)) => Json(statistics).into_response(),
        Ok(Err(SecurityError::AuditEventLimitExceeded)) => endpoint_usage_too_large(),
        Ok(Err(_)) | Err(_) => endpoint_usage_internal_error(),
    }
}

async fn dashboard_export_csv(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    export_dashboard(store, raw, ExportFormat::Csv).await
}

async fn dashboard_export_json(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    export_dashboard(store, raw, ExportFormat::Json).await
}

async fn export_dashboard(
    store: Arc<SecurityStore>,
    raw: Option<String>,
    format: ExportFormat,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let filter = match dashboard_filter(&query) {
        Ok(filter) => filter,
        Err(error) => return error.into_response(),
    };
    let result = task::spawn_blocking(move || store.export_audit_events(&filter)).await;
    match result {
        Ok(Ok(events)) => match format {
            ExportFormat::Csv => csv_response(default_csv(&events), "audit_export.csv"),
            ExportFormat::Json => json_export_response(&events),
        },
        Ok(Err(SecurityError::InvalidInput)) => export_too_large(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn cleanup_before(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let date = match query.optional("date") {
        Ok(Some(date)) => date,
        Ok(None) => return bad_request("date is required"),
        Err(error) => return error.into_response(),
    };
    let Ok(date) = NaiveDate::parse_from_str(&date, "%Y-%m-%d") else {
        return invalid_cleanup_date();
    };
    if date > Local::now().date_naive() {
        return invalid_cleanup_date();
    }
    let cutoff = match local_midnight(date) {
        Ok(cutoff) => cutoff,
        Err(error) => return error.into_response(),
    };
    let result = task::spawn_blocking(move || store.delete_audit_events_before(cutoff)).await;
    match result {
        Ok(Ok(deleted)) => Json(json!({
            "deleted": deleted,
            "cutoffDate": date.to_string(),
        }))
        .into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn ui_audit_events(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let (page, page_size) = match pagination(&query, "pageSize") {
        Ok(pagination) => pagination,
        Err(error) => return error.into_response(),
    };
    let filter = match ui_filter(&query) {
        Ok(filter) => filter,
        Err(error) => return error.into_response(),
    };
    let Some(offset) = page.checked_mul(page_size) else {
        return bad_request("Invalid pagination");
    };
    let result =
        task::spawn_blocking(move || store.query_audit_events(&filter, offset, page_size)).await;
    match result {
        Ok(Ok(events)) => Json(ui_page(&events, page, page_size)).into_response(),
        Ok(Err(SecurityError::InvalidInput)) => bad_request("Invalid audit query"),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn ui_audit_charts(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let days = match period_days(&query) {
        Ok(days) => days,
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().timestamp();
    let filter = audit_period_filter(now, days);
    let result = task::spawn_blocking(move || store.export_audit_events(&filter)).await;
    match result {
        Ok(Ok(events)) => Json(charts(&events)).into_response(),
        Ok(Err(SecurityError::InvalidInput)) => export_too_large(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn ui_audit_stats(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let days = match period_days(&query) {
        Ok(days) => days,
        Err(error) => return error.into_response(),
    };
    let now = Utc::now().timestamp();
    let seconds = i64::from(days) * 86_400;
    let current_filter = audit_period_filter(now, days);
    let previous_filter = SecurityAuditFilter {
        start_at: Some(now.saturating_sub(seconds.saturating_mul(2))),
        end_at: Some(now.saturating_sub(seconds)),
        ..SecurityAuditFilter::default()
    };
    let result = task::spawn_blocking(move || {
        Ok::<_, SecurityError>((
            store.export_audit_events(&current_filter)?,
            store.export_audit_events(&previous_filter)?,
        ))
    })
    .await;
    match result {
        Ok(Ok((current, previous))) => Json(detailed_stats(&current, &previous)).into_response(),
        Ok(Err(SecurityError::InvalidInput)) => export_too_large(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn ui_audit_export(
    Extension(store): Extension<Arc<SecurityStore>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match QueryValues::parse(raw) {
        Ok(query) => query,
        Err(error) => return error.into_response(),
    };
    let filter = match ui_filter(&query) {
        Ok(filter) => filter,
        Err(error) => return error.into_response(),
    };
    let format = match query.optional("format") {
        Ok(Some(format)) if format.eq_ignore_ascii_case("json") => ExportFormat::Json,
        Ok(_) => ExportFormat::Csv,
        Err(error) => return error.into_response(),
    };
    let fields = match query.optional("fields") {
        Ok(fields) => fields,
        Err(error) => return error.into_response(),
    };
    let result = task::spawn_blocking(move || store.export_audit_events(&filter)).await;
    match result {
        Ok(Ok(events)) => match format {
            ExportFormat::Json => json_export_response(&events),
            ExportFormat::Csv => {
                let csv = fields.map_or_else(
                    || default_csv(&events),
                    |fields| selected_csv(&events, &fields),
                );
                csv_response(csv, "audit_export.csv")
            }
        },
        Ok(Err(SecurityError::InvalidInput)) => export_too_large(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

async fn clear_all(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    match task::spawn_blocking(move || store.clear_audit_events()).await {
        Ok(Ok(_)) => Json(json!({
            "message": "All audit data has been cleared successfully",
        }))
        .into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

fn dashboard_filter(query: &QueryValues) -> AuditQueryResult<SecurityAuditFilter> {
    let (start_at, end_at) = date_range(query)?;
    Ok(SecurityAuditFilter {
        event_types: query.optional("type")?.into_iter().collect(),
        principal_contains: query.optional("principal")?,
        start_at,
        end_at,
        ..SecurityAuditFilter::default()
    })
}

fn ui_filter(query: &QueryValues) -> AuditQueryResult<SecurityAuditFilter> {
    let (start_at, end_at) = date_range(query)?;
    Ok(SecurityAuditFilter {
        event_types: query.many("eventType"),
        principals: query.many("username"),
        start_at,
        end_at,
        ..SecurityAuditFilter::default()
    })
}

fn endpoint_usage_query(query: &QueryValues) -> AuditQueryResult<EndpointUsageQuery> {
    let limit = query.optional("limit")?.map_or(Ok(None), |value| {
        let value = value
            .parse::<i32>()
            .map_err(|_| AuditQueryError("Invalid limit"))?;
        if value > 0 {
            usize::try_from(value)
                .map(Some)
                .map_err(|_| AuditQueryError("Invalid limit"))
        } else {
            Ok(None)
        }
    })?;
    let data_type = match query.optional_raw("dataType")?.as_deref() {
        None => EndpointUsageDataType::All,
        Some(value) if value.eq_ignore_ascii_case("all") => EndpointUsageDataType::All,
        Some(value) if value.eq_ignore_ascii_case("ui") => EndpointUsageDataType::Ui,
        Some(value) if value.eq_ignore_ascii_case("api") => EndpointUsageDataType::Api,
        Some(_) => EndpointUsageDataType::Unknown,
    };
    let days = query.optional("days")?.map_or(Ok(30), |value| {
        value
            .parse::<i32>()
            .map_err(|_| AuditQueryError("Invalid days"))
    })?;
    Ok(EndpointUsageQuery {
        limit,
        data_type,
        days: days.clamp(1, 365),
    })
}

fn aggregate_endpoint_usage(
    event_data: &[String],
    limit: Option<usize>,
) -> EndpointUsageStatistics {
    let mut counts = BTreeMap::<String, i32>::new();
    for data in event_data {
        if let Some(endpoint) = endpoint_from_audit_data(data) {
            *counts.entry(endpoint).or_default() += 1;
        }
    }
    let total_endpoints = i32::try_from(counts.len()).unwrap_or(i32::MAX);
    let total_visits = counts.values().copied().sum::<i32>();
    let mut endpoints = counts
        .into_iter()
        .map(|(endpoint, visits)| EndpointUsage {
            endpoint,
            visits,
            percentage: if total_visits == 0 {
                0.0
            } else {
                (f64::from(visits) * 1_000.0 / f64::from(total_visits)).round() / 10.0
            },
        })
        .collect::<Vec<_>>();
    endpoints.sort_by(|left, right| {
        right
            .visits
            .cmp(&left.visits)
            .then_with(|| left.endpoint.cmp(&right.endpoint))
    });
    if let Some(limit) = limit {
        endpoints.truncate(limit);
    }
    EndpointUsageStatistics {
        endpoints,
        total_endpoints,
        total_visits,
    }
}

fn empty_endpoint_usage_statistics() -> EndpointUsageStatistics {
    EndpointUsageStatistics {
        endpoints: Vec::new(),
        total_endpoints: 0,
        total_visits: 0,
    }
}

fn endpoint_from_audit_data(data: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let value = serde_json::from_str::<Value>(data).ok()?;
    let object = value.as_object()?;
    let raw = ["endpoint", "path", "requestUri"]
        .into_iter()
        .find_map(|key| object.get(key).filter(|value| !value.is_null()))
        .map(java_json_string)?;
    let path = raw.split_once('?').map_or(raw.as_str(), |(path, _)| path);
    Some(if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    })
}

fn java_json_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(java_json_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(key, value)| format!("{key}={}", java_json_string(value)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn pagination(query: &QueryValues, size_name: &str) -> AuditQueryResult<(usize, usize)> {
    let page = parse_usize(query.optional("page")?, 0)?;
    let size = parse_usize(query.optional(size_name)?, DEFAULT_PAGE_SIZE)?;
    if size == 0 || size > 200 {
        return Err(AuditQueryError("Page size must be between 1 and 200"));
    }
    Ok((page, size))
}

fn parse_usize(value: Option<String>, default: usize) -> AuditQueryResult<usize> {
    value.map_or(Ok(default), |value| {
        value
            .parse::<usize>()
            .map_err(|_| AuditQueryError("Invalid numeric query parameter"))
    })
}

fn bounded_days(query: &QueryValues, name: &str, default: u16) -> AuditQueryResult<u16> {
    let days = query.optional(name)?.map_or(Ok(default), |value| {
        value
            .parse::<u16>()
            .map_err(|_| AuditQueryError("Invalid period"))
    })?;
    if !(1..=3_650).contains(&days) {
        return Err(AuditQueryError("Period must be between 1 and 3650 days"));
    }
    Ok(days)
}

fn period_days(query: &QueryValues) -> AuditQueryResult<u16> {
    Ok(match query.optional("period")?.as_deref() {
        Some(period) if period.eq_ignore_ascii_case("day") => 1,
        Some(period) if period.eq_ignore_ascii_case("month") => 30,
        _ => 7,
    })
}

fn date_range(query: &QueryValues) -> AuditQueryResult<(Option<i64>, Option<i64>)> {
    let start = query.optional("startDate")?;
    let end = query.optional("endDate")?;
    let (Some(start), Some(end)) = (start, end) else {
        return Ok((None, None));
    };
    let start = NaiveDate::parse_from_str(&start, "%Y-%m-%d")
        .map_err(|_| AuditQueryError("Invalid startDate"))?;
    let end = NaiveDate::parse_from_str(&end, "%Y-%m-%d")
        .map_err(|_| AuditQueryError("Invalid endDate"))?;
    if start > end {
        return Err(AuditQueryError("startDate must not be after endDate"));
    }
    let end_exclusive = end.succ_opt().ok_or(AuditQueryError("Invalid endDate"))?;
    Ok((
        Some(local_midnight(start)?),
        Some(local_midnight(end_exclusive)?),
    ))
}

fn local_midnight(date: NaiveDate) -> AuditQueryResult<i64> {
    let local = date
        .and_hms_opt(0, 0, 0)
        .and_then(|time| Local.from_local_datetime(&time).earliest())
        .ok_or(AuditQueryError("Invalid local date"))?;
    Ok(local.timestamp())
}

fn audit_period_filter(now: i64, days: u16) -> SecurityAuditFilter {
    SecurityAuditFilter {
        start_at: Some(now.saturating_sub(i64::from(days) * 86_400)),
        end_at: Some(now.saturating_add(1)),
        ..SecurityAuditFilter::default()
    }
}

fn dashboard_page(
    page: SecurityAuditPage,
    current_page: usize,
    size: usize,
) -> DashboardDataResponse {
    DashboardDataResponse {
        content: page
            .events
            .into_iter()
            .map(PersistentAuditEventResponse::from)
            .collect(),
        total_pages: total_pages(page.total_events, size),
        total_elements: page.total_events,
        current_page,
    }
}

fn ui_page(page: &SecurityAuditPage, current_page: usize, page_size: usize) -> AuditEventsResponse {
    AuditEventsResponse {
        events: page.events.iter().map(audit_event_dto).collect(),
        total_events: page.total_events,
        page: current_page,
        page_size,
        total_pages: total_pages(page.total_events, page_size),
    }
}

fn total_pages(total: usize, size: usize) -> usize {
    total.saturating_add(size - 1) / size
}

impl From<SecurityAuditEvent> for PersistentAuditEventResponse {
    fn from(event: SecurityAuditEvent) -> Self {
        Self {
            id: event.id,
            principal: event.principal,
            event_type: event.event_type,
            source: event.source,
            data: event.data,
            timestamp: timestamp_string(event.timestamp),
        }
    }
}

fn audit_event_dto(event: &SecurityAuditEvent) -> AuditEventDto {
    let details = event_details(event);
    let ip_address = details
        .get("clientIp")
        .or_else(|| details.get("__ipAddress"))
        .map(json_scalar)
        .unwrap_or_default();
    AuditEventDto {
        id: event.id.to_string(),
        timestamp: timestamp_string(event.timestamp),
        event_type: event.event_type.clone(),
        username: event.principal.clone(),
        ip_address,
        details,
    }
}

fn event_details(event: &SecurityAuditEvent) -> Map<String, Value> {
    match serde_json::from_str::<Value>(&event.data) {
        Ok(Value::Object(details)) => details,
        _ => Map::from_iter([("rawData".to_owned(), Value::String(event.data.clone()))]),
    }
}

fn simple_stats(events: &[SecurityAuditEvent]) -> DashboardStatsResponse {
    let mut events_by_type = BTreeMap::new();
    let mut events_by_principal = BTreeMap::new();
    let mut events_by_day = BTreeMap::new();
    for event in events {
        increment(&mut events_by_type, &event.event_type);
        increment(&mut events_by_principal, &event.principal);
        increment(&mut events_by_day, &local_day(event.timestamp));
    }
    DashboardStatsResponse {
        events_by_type,
        events_by_principal,
        events_by_day,
        total_events: events.len(),
    }
}

fn charts(events: &[SecurityAuditEvent]) -> AuditChartsData {
    let stats = simple_stats(events);
    AuditChartsData {
        by_type: chart_data(stats.events_by_type),
        by_user: chart_data(stats.events_by_principal),
        over_time: chart_data(stats.events_by_day),
    }
}

fn chart_data(values: BTreeMap<String, u64>) -> ChartData {
    let (labels, values) = values.into_iter().unzip();
    ChartData { labels, values }
}

fn detailed_stats(
    current_events: &[SecurityAuditEvent],
    previous_events: &[SecurityAuditEvent],
) -> AuditStatsData {
    let current = compute_metrics(current_events);
    let previous = compute_metrics(previous_events);
    let mut hourly_distribution = (0..24)
        .map(|hour| (format!("{hour:02}"), 0))
        .collect::<BTreeMap<_, _>>();
    for event in current_events {
        increment(&mut hourly_distribution, &local_hour(event.timestamp));
    }
    AuditStatsData {
        total_events: current.total_events,
        prev_total_events: previous.total_events,
        unique_users: current.unique_users,
        prev_unique_users: previous.unique_users,
        success_rate: current.success_rate,
        prev_success_rate: previous.success_rate,
        avg_latency_ms: current.avg_latency_ms,
        prev_avg_latency_ms: previous.avg_latency_ms,
        error_count: current.error_count,
        top_event_type: current.top_event_type,
        top_user: current.top_user,
        events_by_type: current.events_by_type,
        events_by_user: current.events_by_user,
        top_tools: current.top_tools,
        hourly_distribution,
    }
}

fn compute_metrics(events: &[SecurityAuditEvent]) -> AuditMetrics {
    if events.is_empty() {
        return AuditMetrics::default();
    }
    let mut metrics = AuditMetrics {
        total_events: events.len(),
        ..AuditMetrics::default()
    };
    let mut successes = 0_u64;
    let mut failures = 0_u64;
    let mut total_latency = 0_u64;
    let mut latency_count = 0_u64;
    for event in events {
        increment(&mut metrics.events_by_type, &event.event_type);
        increment(&mut metrics.events_by_user, &event.principal);
        let details = event_details(event);
        let outcome = details.get("status").or_else(|| details.get("outcome"));
        match outcome.map(json_scalar).as_deref() {
            Some("success") => successes += 1,
            Some("failure") => {
                failures += 1;
                metrics.error_count += 1;
            }
            _ if details
                .get("statusCode")
                .and_then(json_i64)
                .is_some_and(|status| status >= 400) =>
            {
                metrics.error_count += 1;
            }
            _ => {}
        }
        if let Some(latency) = details.get("latencyMs").and_then(json_u64) {
            total_latency = total_latency.saturating_add(latency);
            latency_count += 1;
        }
        if let Some(tool) = details.get("path").map(json_scalar).and_then(|path| {
            path.rsplit('/')
                .find(|part| !part.is_empty())
                .map(ToOwned::to_owned)
        }) {
            increment(&mut metrics.top_tools, &tool);
        }
    }
    metrics.unique_users = metrics.events_by_user.len();
    let total_outcomes = successes + failures;
    if total_outcomes > 0 {
        metrics.success_rate = u64_to_f64(successes) * 100.0 / u64_to_f64(total_outcomes);
    }
    if latency_count > 0 {
        metrics.avg_latency_ms = u64_to_f64(total_latency) / u64_to_f64(latency_count);
    }
    metrics.top_event_type = top_key(&metrics.events_by_type);
    metrics.top_user = top_key(&metrics.events_by_user);
    metrics.top_tools = top_ten(metrics.top_tools);
    metrics
}

fn top_key(values: &BTreeMap<String, u64>) -> String {
    values
        .iter()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
        .map_or_else(String::new, |(key, _)| key.clone())
}

fn top_ten(values: BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    values.truncate(10);
    values.into_iter().collect()
}

fn increment(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_owned()).or_default() += 1;
}

enum ExportFormat {
    Csv,
    Json,
}

fn default_csv(events: &[SecurityAuditEvent]) -> String {
    let mut csv = String::from("ID,Principal,Type,Timestamp,Data\n");
    for event in events {
        csv.push_str(&event.id.to_string());
        csv.push(',');
        csv.push_str(&escape_csv(&event.principal));
        csv.push(',');
        csv.push_str(&escape_csv(&event.event_type));
        csv.push(',');
        csv.push_str(&timestamp_string(event.timestamp));
        csv.push(',');
        csv.push_str(&escape_csv(&event.data));
        csv.push('\n');
    }
    csv
}

fn selected_csv(events: &[SecurityAuditEvent], fields: &str) -> String {
    const FIELD_ORDER: [(&str, &str); 10] = [
        ("date", "Date"),
        ("username", "Username"),
        ("ipaddress", "IP Address"),
        ("tool", "Tool"),
        ("documentname", "Document Name"),
        ("outcome", "Outcome"),
        ("author", "Author"),
        ("filehash", "File Hash"),
        ("operationresults", "Operation Results"),
        ("eventtype", "Event Type"),
    ];
    let requested = fields
        .split(',')
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let fields = FIELD_ORDER
        .into_iter()
        .filter(|(field, _)| requested.iter().any(|requested| requested == field))
        .collect::<Vec<_>>();
    let mut csv = fields
        .iter()
        .map(|(_, title)| *title)
        .collect::<Vec<_>>()
        .join(",");
    csv.push('\n');
    for event in events {
        let row = selected_row(event);
        csv.push_str(
            &fields
                .iter()
                .map(|(field, _)| escape_csv(row.get(*field).map_or("", String::as_str)))
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    csv
}

fn selected_row(event: &SecurityAuditEvent) -> BTreeMap<&'static str, String> {
    let details = event_details(event);
    let path = details.get("path").map(json_scalar).unwrap_or_default();
    let files = details
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| files.first())
        .and_then(Value::as_object);
    BTreeMap::from([
        ("date", timestamp_string(event.timestamp)),
        ("username", event.principal.clone()),
        (
            "ipaddress",
            details
                .get("clientIp")
                .or_else(|| details.get("__ipAddress"))
                .map(json_scalar)
                .unwrap_or_default(),
        ),
        (
            "tool",
            path.rsplit('/')
                .find(|part| !part.is_empty())
                .unwrap_or("")
                .to_owned(),
        ),
        ("documentname", file_value(files, "name")),
        (
            "outcome",
            details
                .get("outcome")
                .or_else(|| details.get("status"))
                .map(json_scalar)
                .unwrap_or_default(),
        ),
        ("author", file_value(files, "pdfAuthor")),
        ("filehash", file_value(files, "fileHash")),
        (
            "operationresults",
            details.get("result").map(json_scalar).unwrap_or_default(),
        ),
        ("eventtype", event.event_type.clone()),
    ])
}

fn file_value(files: Option<&Map<String, Value>>, key: &str) -> String {
    files
        .and_then(|file| file.get(key))
        .map(json_scalar)
        .unwrap_or_default()
}

fn json_export_response(events: &[SecurityAuditEvent]) -> Response {
    let events = events
        .iter()
        .cloned()
        .map(PersistentAuditEventResponse::from)
        .collect::<Vec<_>>();
    let mut response = Json(events).into_response();
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"audit_export.json\""),
    );
    response
}

fn csv_response(csv: String, filename: &'static str) -> Response {
    let mut response = csv.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv;charset=UTF-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    response
}

fn escape_csv(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn timestamp_string(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0).map_or_else(String::new, |timestamp| {
        timestamp.to_rfc3339_opts(SecondsFormat::Secs, true)
    })
}

fn local_day(timestamp: i64) -> String {
    Local
        .timestamp_opt(timestamp, 0)
        .single()
        .map_or_else(String::new, |timestamp| {
            timestamp.format("%Y-%m-%d").to_string()
        })
}

fn local_hour(timestamp: i64) -> String {
    Local
        .timestamp_opt(timestamp, 0)
        .single()
        .map_or_else(String::new, |timestamp| timestamp.format("%H").to_string())
}

fn json_scalar(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn json_i64(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_str()?.parse().ok())
}

fn json_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str()?.parse().ok())
}

fn u64_to_f64(value: u64) -> f64 {
    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & u64::from(u32::MAX)).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

fn decode_query_component(value: &str) -> AuditQueryResult<String> {
    let value = value.replace('+', " ");
    urlencoding::decode(&value)
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| AuditQueryError("Malformed query encoding"))
}

fn invalid_cleanup_date() -> Response {
    Json(json!({
        "error": "Invalid date format. Use ISO date format (YYYY-MM-DD). Date must be in the past."
    }))
    .into_response()
}

fn export_too_large() -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "Audit export exceeds the 50000-event safety limit",
    )
}

fn endpoint_usage_too_large() -> Response {
    error_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "Endpoint usage query exceeds the 50000-event safety limit",
    )
}

fn endpoint_usage_internal_error() -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Could not calculate endpoint usage statistics",
    )
}

fn bad_request(message: &'static str) -> Response {
    error_response(StatusCode::BAD_REQUEST, message)
}

fn service_unavailable() -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, "Audit service unavailable")
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": status.canonical_reason().unwrap_or("Request rejected"),
            "message": message,
            "status": status.as_u16(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{aggregate_endpoint_usage, endpoint_from_audit_data, escape_csv, selected_csv};
    use crate::security::SecurityAuditEvent;

    #[test]
    fn selected_export_uses_java_field_order_and_csv_escaping() {
        let event = SecurityAuditEvent {
            id: 7,
            principal: "admin,one".to_owned(),
            event_type: "PDF_PROCESS".to_owned(),
            source: "WEB".to_owned(),
            data: r#"{"path":"/api/v1/misc/compress-pdf","outcome":"success","files":[{"name":"a\"b.pdf"}]}"#.to_owned(),
            timestamp: 1_700_000_000,
        };
        let csv = selected_csv(&[event], "eventType,documentName,username");
        assert_eq!(
            csv.lines().next(),
            Some("Username,Document Name,Event Type")
        );
        assert!(csv.contains("\"admin,one\""));
        assert!(csv.contains("\"a\"\"b.pdf\""));
        assert_eq!(escape_csv("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn endpoint_usage_extracts_java_key_precedence_and_normalization() {
        assert_eq!(
            endpoint_from_audit_data(
                r#"{"endpoint":null,"path":"api/v1/test?a=1","requestUri":"ignored"}"#,
            )
            .as_deref(),
            Some("/api/v1/test")
        );
        assert_eq!(
            endpoint_from_audit_data(r#"{"endpoint":123}"#).as_deref(),
            Some("/123")
        );
        assert_eq!(
            endpoint_from_audit_data(r#"{"requestUri":"?query"}"#).as_deref(),
            Some("/")
        );
        assert!(endpoint_from_audit_data(r#"["not","a","map"]"#).is_none());
        assert!(endpoint_from_audit_data("not-json").is_none());
    }

    #[test]
    fn endpoint_usage_totals_precede_limit_and_percentages_use_all_visits() {
        let data = [
            r#"{"path":"/merge"}"#.to_owned(),
            r#"{"path":"/merge?again=true"}"#.to_owned(),
            r#"{"path":"split"}"#.to_owned(),
        ];
        let statistics = aggregate_endpoint_usage(&data, Some(1));
        assert_eq!(statistics.total_endpoints, 2);
        assert_eq!(statistics.total_visits, 3);
        assert_eq!(statistics.endpoints.len(), 1);
        assert_eq!(statistics.endpoints[0].endpoint, "/merge");
        assert_eq!(statistics.endpoints[0].visits, 2);
        assert!((statistics.endpoints[0].percentage - 66.7).abs() < 0.000_001);
    }
}
