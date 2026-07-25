//! Java-compatible HTTP surface for resource grants and integration configs.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Extension, Multipart, Path, Query, multipart::MultipartError,
        rejection::JsonRejection,
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::json;
use tokio::task;

use crate::{
    integration_config::{
        IntegrationConfigRequest, IntegrationConfigService, IntegrationFailure, IntegrationType,
        parse_connection_id_param,
    },
    proprietary_external_api::{
        ApiConnectionSettings, ExternalApiCallRequest, ExternalApiCallResult, ExternalApiCaller,
        ExternalApiError, RunFacts,
    },
    resource_access::{AccessPermission, PrincipalType, ResourceType},
    security::AuthContext,
};

/// Header carrying the structured step report alongside the returned document.
/// Mirrors Java `AiToolResponseHeaders.TOOL_REPORT`; the pipeline already parses it.
const TOOL_REPORT_HEADER: &str = "X-Stirling-Tool-Report";

/// Request header naming the policy that dispatched the step. Mirrors Java
/// `InternalApiClient.POLICY_NAME_HEADER`.
const POLICY_NAME_HEADER: &str = "X-Stirling-Policy-Name";

/// Request header carrying the automation run id. Mirrors Java
/// `AutomationRunContext.RUN_ID_HEADER`.
const RUN_ID_HEADER: &str = "X-Stirling-Run-Id";

pub(crate) fn routes(
    service: Arc<IntegrationConfigService>,
    caller: Arc<ExternalApiCaller>,
    max_upload_bytes: usize,
) -> Router {
    let json_routes = Router::new()
        .route(
            "/api/v1/admin/access/grants",
            get(list_grants).post(create_grant),
        )
        .route(
            "/api/v1/admin/access/grants/by-principal",
            get(list_grants_by_principal),
        )
        .route("/api/v1/admin/access/grants/{id}", delete(revoke_grant))
        .route(
            "/api/v1/integrations",
            get(list_integrations).post(create_integration),
        )
        .route(
            "/api/v1/integrations/capabilities",
            get(integration_capabilities),
        )
        .route(
            "/api/v1/integrations/{id}",
            get(get_integration)
                .put(update_integration)
                .delete(delete_integration),
        )
        .layer(Extension(Arc::clone(&service)));

    // The external-API-call step uploads the document, so it gets the multipart body
    // limit (kept off the small JSON routes above). The connection is resolved by id
    // through the same service, then the ported SSRF-safe caller runs the call.
    let external_api = Router::new()
        .route(
            "/api/v1/integration/external-api-call",
            post(external_api_call),
        )
        .layer(DefaultBodyLimit::max(max_upload_bytes))
        .layer(Extension(caller))
        .layer(Extension(service));

    json_routes.merge(external_api)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantListQuery {
    resource_type: ResourceType,
    #[serde(default)]
    resource_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalGrantQuery {
    principal_type: PrincipalType,
    principal_id: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantRequest {
    resource_type: Option<ResourceType>,
    resource_id: Option<String>,
    principal_type: Option<PrincipalType>,
    principal_id: Option<i64>,
    permission: Option<AccessPermission>,
}

async fn list_grants(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<GrantListQuery>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match service
        .access()
        .list_grants(query.resource_type, &query.resource_id)
    {
        Ok(grants) => Json(grants).into_response(),
        Err(_) => internal_error(),
    }
}

async fn list_grants_by_principal(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<PrincipalGrantQuery>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match service
        .access()
        .list_grants_for_principal(query.principal_type, query.principal_id)
    {
        Ok(grants) => Json(grants).into_response(),
        Err(_) => internal_error(),
    }
}

async fn create_grant(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<GrantRequest>, JsonRejection>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    let Ok(Json(request)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid request payload");
    };
    let (Some(resource_type), Some(principal_type), Some(principal_id)) = (
        request.resource_type,
        request.principal_type,
        request.principal_id,
    ) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "resourceType, principalType and principalId are required",
        );
    };
    let resource_id = if resource_type == ResourceType::Portal {
        String::new()
    } else {
        let Some(resource_id) = request.resource_id.filter(|id| !id.trim().is_empty()) else {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("resourceId is required for {}", resource_type.as_str()),
            );
        };
        resource_id
    };
    match service
        .access()
        .principal_exists(principal_type, principal_id)
    {
        Ok(true) => {}
        Ok(false) => {
            let label = match principal_type {
                PrincipalType::User => "User",
                PrincipalType::Team => "Team",
            };
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("{label} {principal_id} does not exist"),
            );
        }
        Err(_) => return internal_error(),
    }
    match service.access().grant(
        resource_type,
        &resource_id,
        principal_type,
        principal_id,
        request.permission.unwrap_or(AccessPermission::Use),
        context.user_id,
    ) {
        Ok(grant) => Json(grant).into_response(),
        Err(_) => internal_error(),
    }
}

async fn revoke_grant(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match service.access().revoke(id) {
        Ok(()) => Json(json!({"message":"Grant revoked"})).into_response(),
        Err(_) => internal_error(),
    }
}

async fn list_integrations(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    match service.list(&context) {
        Ok(integrations) => Json(integrations).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn create_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<IntegrationConfigRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    let Ok(Json(request)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid config payload");
    };
    match service.create(request, &context) {
        Ok(integration) => Json(integration).into_response(),
        Err(error) => integration_error(error),
    }
}

/// Reports what the authenticated caller may set up so the portal UI offers the
/// free-form "custom API" option only to those who can actually use it. Portal
/// access is required (as for every integrations route); the answer is computed
/// server-side because it is an authorization decision, not a presentation one.
/// Mirrors Java's `IntegrationConfigController.capabilities`.
async fn integration_capabilities(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    Json(json!({"customApi": service.can_author_custom_api(&context)})).into_response()
}

async fn get_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    match service.get(id, &context) {
        Ok(integration) => Json(integration).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn update_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
    request: Result<Json<IntegrationConfigRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    let Ok(Json(request)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid config payload");
    };
    match service.update(id, request, &context) {
        Ok(integration) => Json(integration).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn delete_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    match service.delete(id, &context) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => integration_error(error),
    }
}

/// Posts the document flowing through a policy to a third-party HTTP API and folds
/// the answer back into the run. Mirrors Java `ExternalApiCallController.call`: the
/// step names a stored `API` connection by id (resolved here, so the ownership check
/// runs while the caller's identity is available), never a host; the connection owns
/// the base URL and the credentials. All network work is blocking, so it runs on a
/// blocking thread.
async fn external_api_call(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(caller): Extension<Arc<ExternalApiCaller>>,
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let form = match ExternalApiForm::read(multipart).await {
        Ok(form) => form,
        Err(response) => return response,
    };
    // Resolve the connection first (auth check + config), matching the controller's
    // ordering so a bad connection is reported before the call is assembled.
    let id = match parse_connection_id_param(&form.connection_id) {
        Ok(id) => id,
        Err(error) => return integration_error(error),
    };
    let config = match service.resolve_config(id, IntegrationType::Api, &context) {
        Ok(config) => config,
        Err(error) => return integration_error(error),
    };
    let settings = match ApiConnectionSettings::from_options(&config.into_iter().collect()) {
        Ok(settings) => settings,
        Err(error) => return external_api_error(&error),
    };

    // Policy/run facts ride in as request headers, not form fields (the pipeline sets
    // them); the timestamp is the wall clock, matching Java `Instant.now()`.
    let policy_name = header_string(&headers, POLICY_NAME_HEADER);
    let run_id = header_string(&headers, RUN_ID_HEADER);
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true);

    let outcome = task::spawn_blocking(move || {
        let request = ExternalApiCallRequest {
            file_content: &form.file,
            original_filename: form.filename.as_deref(),
            file_content_type: form.content_type.as_deref(),
            path: form.path.as_deref(),
            method: form.method.as_deref(),
            body_mode: form.body_mode.as_deref(),
            file_field_name: &form.file_field_name,
            response_mode: form.response_mode.as_deref(),
            result_url_path: form.result_url_path.as_deref(),
            result_url_header: form.result_url_header.as_deref(),
            response_select: form.response_select.as_deref(),
            require_true: form.require_true.as_deref(),
            fields: form.fields.as_deref(),
            body_template: form.body_template.as_deref(),
            headers: form.headers.as_deref(),
            include_context: form.include_context,
            include_file: form.include_file,
            run: RunFacts {
                policy_name: policy_name.as_deref(),
                run_id: run_id.as_deref(),
                timestamp: &timestamp,
            },
        };
        caller.call(&settings, &request)
    })
    .await;

    match outcome {
        Ok(Ok(result)) => external_api_success(result),
        Ok(Err(error)) => external_api_error(&error),
        Err(_) => internal_error(),
    }
}

/// Build the document response the pipeline consumes: the returned bytes with a
/// `Content-Disposition`, and — in report mode — the answer in the report header.
fn external_api_success(result: ExternalApiCallResult) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&result.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    if let Ok(disposition) = attachment_disposition(&result.filename) {
        headers.insert(header::CONTENT_DISPOSITION, disposition);
    }
    if let Some(report) = result.report.as_deref()
        && let Ok(value) = HeaderValue::from_str(report)
    {
        headers.insert(TOOL_REPORT_HEADER, value);
    }
    (headers, Body::from(result.body)).into_response()
}

fn external_api_error(error: &ExternalApiError) -> Response {
    // Every failure here fails the step (fail-closed): the message is the operator's
    // to read, and any non-2xx stops the pipeline from delivering the document.
    json_error(StatusCode::BAD_REQUEST, &error.to_string())
}

fn attachment_disposition(filename: &str) -> Result<HeaderValue, ()> {
    let encoded = urlencoding::encode(filename).replace('+', "%20");
    HeaderValue::from_str(&format!("attachment; filename=\"{encoded}\"")).map_err(|_| ())
}

fn header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The multipart form of an external-API-call step. Optional fields left `None` are
/// defaulted by the orchestration (`method`→POST, `bodyMode`→multipart,
/// `responseMode`→report), matching Spring's `defaultValue`; `fileFieldName`,
/// `includeFile` and `includeContext` carry their defaults here.
struct ExternalApiForm {
    file: Vec<u8>,
    filename: Option<String>,
    content_type: Option<String>,
    connection_id: String,
    path: Option<String>,
    method: Option<String>,
    body_mode: Option<String>,
    file_field_name: String,
    response_mode: Option<String>,
    result_url_path: Option<String>,
    result_url_header: Option<String>,
    response_select: Option<String>,
    require_true: Option<String>,
    fields: Option<String>,
    body_template: Option<String>,
    headers: Option<String>,
    include_context: bool,
    include_file: bool,
}

impl ExternalApiForm {
    async fn read(mut multipart: Multipart) -> Result<Self, Response> {
        let mut file = None;
        let mut filename = None;
        let mut content_type = None;
        let mut connection_id = None;
        let mut path = None;
        let mut method = None;
        let mut body_mode = None;
        let mut file_field_name = None;
        let mut response_mode = None;
        let mut result_url_path = None;
        let mut result_url_header = None;
        let mut response_select = None;
        let mut require_true = None;
        let mut fields = None;
        let mut body_template = None;
        let mut header_json = None;
        let mut include_context = None;
        let mut include_file = None;

        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(multipart_bad_request)?
        {
            let name = field.name().unwrap_or_default().to_owned();
            match name.as_str() {
                "fileInput" => {
                    filename = field.file_name().map(ToOwned::to_owned);
                    content_type = field.content_type().map(ToOwned::to_owned);
                    file = Some(field.bytes().await.map_err(multipart_bad_request)?.to_vec());
                }
                "connectionId" => connection_id = Some(text(field).await?),
                "path" => path = Some(text(field).await?),
                "method" => method = Some(text(field).await?),
                "bodyMode" => body_mode = Some(text(field).await?),
                "fileFieldName" => file_field_name = Some(text(field).await?),
                "responseMode" => response_mode = Some(text(field).await?),
                "resultUrlPath" => result_url_path = Some(text(field).await?),
                "resultUrlHeader" => result_url_header = Some(text(field).await?),
                "responseSelect" => response_select = Some(text(field).await?),
                "requireTrue" => require_true = Some(text(field).await?),
                "fields" => fields = Some(text(field).await?),
                "bodyTemplate" => body_template = Some(text(field).await?),
                "headers" => header_json = Some(text(field).await?),
                "includeContext" => include_context = Some(parse_bool(&text(field).await?, false)),
                "includeFile" => include_file = Some(parse_bool(&text(field).await?, true)),
                _ => {
                    field.bytes().await.map_err(multipart_bad_request)?;
                }
            }
        }

        Ok(Self {
            file: file
                .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "'fileInput' is required"))?,
            filename,
            content_type,
            connection_id: connection_id
                .ok_or_else(|| json_error(StatusCode::BAD_REQUEST, "'connectionId' is required"))?,
            path,
            method,
            body_mode,
            file_field_name: file_field_name.unwrap_or_else(|| "file".to_owned()),
            response_mode,
            result_url_path,
            result_url_header,
            response_select,
            require_true,
            fields,
            body_template,
            headers: header_json,
            include_context: include_context.unwrap_or(false),
            include_file: include_file.unwrap_or(true),
        })
    }
}

async fn text(field: axum::extract::multipart::Field<'_>) -> Result<String, Response> {
    field.text().await.map_err(multipart_bad_request)
}

/// A form boolean, defaulting when absent/blank/unrecognised (the frontend sends
/// `true`/`false`).
fn parse_bool(value: &str, default: bool) -> bool {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => default,
    }
}

fn multipart_bad_request(_: MultipartError) -> Response {
    json_error(StatusCode::BAD_REQUEST, "Invalid request payload")
}

fn is_admin(context: &AuthContext) -> bool {
    context.has_role("ROLE_ADMIN")
}

fn integration_error(error: IntegrationFailure) -> Response {
    match error {
        IntegrationFailure::BadRequest(message) => json_error(StatusCode::BAD_REQUEST, &message),
        IntegrationFailure::Forbidden(message) => json_error(StatusCode::FORBIDDEN, &message),
        IntegrationFailure::NotFound(message) => json_error(StatusCode::NOT_FOUND, &message),
        IntegrationFailure::Conflict(message) => json_error(StatusCode::CONFLICT, &message),
        IntegrationFailure::Storage(_) | IntegrationFailure::Access(_) => internal_error(),
    }
}

fn internal_error() -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Integration service unavailable",
    )
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error":message}))).into_response()
}
