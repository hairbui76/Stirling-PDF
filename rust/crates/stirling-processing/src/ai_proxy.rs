//! Java-compatible HTTP boundary for the separately deployed AI engine.
//!
//! This module owns transparent proxy operations and shared engine transport
//! helpers. The multipart workflow state machine lives in `ai_workflow`.

use std::sync::Arc;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::Extension,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{SecondsFormat, Utc};
use reqwest::{Client, Method};
use serde::Serialize;
use serde_json::Value;

use crate::{
    pdf_ai_comments::AiCommentEngineSettings, runtime_config::RuntimeConfig, security::AuthContext,
};

pub(crate) const AI_HEALTH_PATH: &str = "/api/v1/ai/health";
pub(crate) const AI_PDF_EDIT_PATH: &str = "/api/v1/ai/pdf/edit";
const ENGINE_HEALTH_PATH: &str = "/health";
const ENGINE_PDF_EDIT_PATH: &str = "/api/v1/pdf/edit";
const ENGINE_AUTH_HEADER: &str = "X-Engine-Auth";
const USER_ID_HEADER: &str = "X-User-Id";

// This is the intersection of the Rust processing router's PDF operation
// surface and the engine's generated operation catalog. Java discovers every
// `/api/v1/**` mapping and the engine drops unknown values; sending the
// intersection is observably equivalent while keeping non-tool/admin routes
// out of an AI prompt.
pub(crate) const PDF_EDIT_ENDPOINTS: &[&str] = &[
    "/api/v1/convert/cbr/pdf",
    "/api/v1/convert/cbz/pdf",
    "/api/v1/convert/ebook/pdf",
    "/api/v1/convert/eml/pdf",
    "/api/v1/convert/file/pdf",
    "/api/v1/convert/html/pdf",
    "/api/v1/convert/img/pdf",
    "/api/v1/convert/markdown/pdf",
    "/api/v1/convert/pdf/cbr",
    "/api/v1/convert/pdf/cbz",
    "/api/v1/convert/pdf/csv",
    "/api/v1/convert/pdf/epub",
    "/api/v1/convert/pdf/html",
    "/api/v1/convert/pdf/img",
    "/api/v1/convert/pdf/markdown",
    "/api/v1/convert/pdf/pdfa",
    "/api/v1/convert/pdf/presentation",
    "/api/v1/convert/pdf/text",
    "/api/v1/convert/pdf/vector",
    "/api/v1/convert/pdf/word",
    "/api/v1/convert/pdf/xlsx",
    "/api/v1/convert/pdf/xml",
    "/api/v1/convert/svg/pdf",
    "/api/v1/convert/url/pdf",
    "/api/v1/convert/vector/pdf",
    "/api/v1/general/booklet-imposition",
    "/api/v1/general/crop",
    "/api/v1/general/edit-table-of-contents",
    "/api/v1/general/edit-text",
    "/api/v1/general/merge-pdfs",
    "/api/v1/general/multi-page-layout",
    "/api/v1/general/pdf-to-single-page",
    "/api/v1/general/rearrange-pages",
    "/api/v1/general/remove-image-pdf",
    "/api/v1/general/remove-pages",
    "/api/v1/general/rotate-pdf",
    "/api/v1/general/scale-pages",
    "/api/v1/general/split-by-size-or-count",
    "/api/v1/general/split-for-poster-print",
    "/api/v1/general/split-pages",
    "/api/v1/general/split-pdf-by-chapters",
    "/api/v1/general/split-pdf-by-sections",
    "/api/v1/misc/add-comments",
    "/api/v1/misc/add-page-numbers",
    "/api/v1/misc/add-stamp",
    "/api/v1/misc/auto-rename",
    "/api/v1/misc/auto-split-pdf",
    "/api/v1/misc/compress-pdf",
    "/api/v1/misc/delete-attachment",
    "/api/v1/misc/extract-attachments",
    "/api/v1/misc/extract-image-scans",
    "/api/v1/misc/extract-images",
    "/api/v1/misc/flatten",
    "/api/v1/misc/ocr-pdf",
    "/api/v1/misc/remove-blanks",
    "/api/v1/misc/rename-attachment",
    "/api/v1/misc/repair",
    "/api/v1/misc/replace-invert-pdf",
    "/api/v1/misc/scanner-effect",
    "/api/v1/misc/unlock-pdf-forms",
    "/api/v1/misc/update-metadata",
    "/api/v1/security/add-password",
    "/api/v1/security/add-watermark",
    "/api/v1/security/auto-redact",
    "/api/v1/security/redact",
    "/api/v1/security/redact-execute",
    "/api/v1/security/remove-cert-sign",
    "/api/v1/security/remove-password",
    "/api/v1/security/sanitize-pdf",
    "/api/v1/security/timestamp-pdf",
];

pub(crate) fn routes() -> Router {
    Router::new()
        .route(AI_HEALTH_PATH, get(ai_health))
        .route(AI_PDF_EDIT_PATH, post(pdf_edit))
}

async fn ai_health(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    auth: Option<Extension<AuthContext>>,
) -> Response {
    proxy_request(
        &settings,
        auth.as_ref().map(|Extension(context)| context),
        Method::GET,
        ENGINE_HEALTH_PATH,
        None,
        AI_HEALTH_PATH,
    )
    .await
}

async fn pdf_edit(
    Extension(settings): Extension<Arc<AiCommentEngineSettings>>,
    Extension(runtime_config): Extension<Arc<RuntimeConfig>>,
    auth: Option<Extension<AuthContext>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_json_content_type(&headers) {
        return ProxyError::unsupported_media_type(headers.get(header::CONTENT_TYPE))
            .into_response();
    }
    let mut body: Value = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return ProxyError::new(
                StatusCode::BAD_REQUEST,
                "Request body is not valid JSON",
                AI_PDF_EDIT_PATH,
            )
            .into_response();
        }
    };
    let Some(object) = body.as_object_mut() else {
        return ProxyError::new(
            StatusCode::BAD_REQUEST,
            "Request body must be a JSON object",
            AI_PDF_EDIT_PATH,
        )
        .into_response();
    };
    object.insert(
        "enabled_endpoints".to_owned(),
        Value::Array(
            enabled_pdf_edit_endpoints(&runtime_config)
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    let forwarded_body = match serde_json::to_vec(&body) {
        Ok(body) => body,
        Err(error) => {
            return ProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                error.to_string(),
                AI_PDF_EDIT_PATH,
            )
            .into_response();
        }
    };
    proxy_request(
        &settings,
        auth.as_ref().map(|Extension(context)| context),
        Method::POST,
        ENGINE_PDF_EDIT_PATH,
        Some(forwarded_body),
        AI_PDF_EDIT_PATH,
    )
    .await
}

async fn proxy_request(
    settings: &AiCommentEngineSettings,
    auth: Option<&AuthContext>,
    method: Method,
    engine_path: &str,
    body: Option<Vec<u8>>,
    public_path: &'static str,
) -> Response {
    if !settings.enabled() {
        return ProxyError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AI engine is not enabled",
            public_path,
        )
        .into_response();
    }
    let endpoint = match engine_endpoint(settings, engine_path, public_path) {
        Ok(endpoint) => endpoint,
        Err(error) => return error.into_response(),
    };
    let client = match proxy_client(settings.timeout(), public_path) {
        Ok(client) => client,
        Err(error) => return error.into_response(),
    };
    let mut request = client
        .request(method, endpoint)
        .header(header::ACCEPT.as_str(), "application/json");
    if let Some(secret) = settings.shared_secret() {
        request = request.header(ENGINE_AUTH_HEADER, secret);
    }
    if let Some(auth) = auth.filter(|auth| !auth.username.trim().is_empty()) {
        request = request.header(USER_ID_HEADER, &auth.username);
    }
    if let Some(body) = body {
        request = request
            .header(header::CONTENT_TYPE.as_str(), "application/json")
            .body(body);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => return transport_error(&error, public_path).into_response(),
    };
    let upstream_status = response.status();
    let response_body = match response.text().await {
        Ok(body) => body,
        Err(error) => return transport_error(&error, public_path).into_response(),
    };
    if upstream_status.is_server_error() {
        return ProxyError::new(
            StatusCode::BAD_GATEWAY,
            format!("AI engine returned error: {}", upstream_status.as_u16()),
            public_path,
        )
        .into_response();
    }
    if upstream_status.is_client_error() {
        return ProxyError::new(
            StatusCode::from_u16(upstream_status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            format!("AI engine returned client error: {response_body}"),
            public_path,
        )
        .into_response();
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(response_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub(crate) fn enabled_pdf_edit_endpoints(runtime_config: &RuntimeConfig) -> Vec<String> {
    PDF_EDIT_ENDPOINTS
        .iter()
        .filter(|path| runtime_config.is_endpoint_enabled_for_uri(path))
        .map(|path| (*path).to_owned())
        .collect()
}

pub(crate) fn engine_endpoint(
    settings: &AiCommentEngineSettings,
    engine_path: &str,
    public_path: &'static str,
) -> Result<reqwest::Url, ProxyError> {
    let endpoint = format!("{}{}", settings.base_url().trim_end(), engine_path);
    match reqwest::Url::parse(&endpoint) {
        Ok(endpoint) if matches!(endpoint.scheme(), "http" | "https") => Ok(endpoint),
        Ok(endpoint) => Err(ProxyError::new(
            StatusCode::BAD_REQUEST,
            format!("invalid URI scheme {}", endpoint.scheme()),
            public_path,
        )),
        Err(error) => Err(ProxyError::new(
            StatusCode::BAD_REQUEST,
            error.to_string(),
            public_path,
        )),
    }
}

pub(crate) fn proxy_client(
    timeout: std::time::Duration,
    public_path: &'static str,
) -> Result<Client, ProxyError> {
    Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| {
            ProxyError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("AI engine unreachable: {error}"),
                public_path,
            )
        })
}

pub(crate) fn transport_error(error: &reqwest::Error, public_path: &'static str) -> ProxyError {
    if error.is_timeout() {
        ProxyError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "AI engine timed out",
            public_path,
        )
    } else {
        ProxyError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("AI engine unreachable: {error}"),
            public_path,
        )
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|media_type| {
                media_type.trim().eq_ignore_ascii_case("application/json")
            })
        })
}

#[derive(Serialize)]
struct ProblemDetail {
    r#type: String,
    title: String,
    status: u16,
    detail: String,
    timestamp: String,
    path: &'static str,
    #[serde(skip_serializing_if = "Option::is_none", rename = "contentType")]
    content_type: Option<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "supportedMediaTypes"
    )]
    supported_media_types: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hints: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "actionRequired")]
    action_required: Option<&'static str>,
}

pub(crate) struct ProxyError {
    status: StatusCode,
    detail: String,
    path: &'static str,
    problem_type: Option<&'static str>,
    unsupported_content_type: Option<String>,
}

impl ProxyError {
    pub(crate) fn new(status: StatusCode, detail: impl Into<String>, path: &'static str) -> Self {
        Self {
            status,
            detail: detail.into(),
            path,
            problem_type: None,
            unsupported_content_type: None,
        }
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }

    fn unsupported_media_type(content_type: Option<&axum::http::HeaderValue>) -> Self {
        let content_type = content_type
            .and_then(|value| value.to_str().ok())
            .unwrap_or("null");
        Self {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            detail: format!(
                "Media type '{content_type}' is not supported. Supported media types: [application/json]"
            ),
            path: AI_PDF_EDIT_PATH,
            problem_type: Some("/errors/unsupported-media-type"),
            unsupported_content_type: Some(content_type.to_owned()),
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let title = self
            .status
            .canonical_reason()
            .unwrap_or("HTTP Error")
            .to_owned();
        let problem = ProblemDetail {
            r#type: self.problem_type.map_or_else(
                || format!("/errors/{}", self.status.as_u16()),
                str::to_owned,
            ),
            title,
            status: self.status.as_u16(),
            detail: self.detail,
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
            path: self.path,
            content_type: self.unsupported_content_type.clone(),
            supported_media_types: self
                .unsupported_content_type
                .as_ref()
                .map(|_| vec!["application/json"]),
            hints: self.unsupported_content_type.as_ref().map(|_| {
                vec![
                    "Set the Content-Type header to a supported media type.",
                    "When sending JSON, use 'application/json'.",
                    "Check that the request body matches the declared Content-Type.",
                ]
            }),
            action_required: self
                .unsupported_content_type
                .as_ref()
                .map(|_| "Change the Content-Type to a supported value."),
        };
        (
            self.status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            axum::Json(problem),
        )
            .into_response()
    }
}
