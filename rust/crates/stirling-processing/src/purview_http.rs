//! Reviewed secured-mode HTTP boundary for the Microsoft Purview label steps.
//!
//! Two policy steps, both fully local (a sensitivity label is metadata, so applying
//! and reading one involves no call to Microsoft):
//!
//! - `POST /api/v1/integration/purview-apply-label` writes the label metadata onto the
//!   PDF and returns the **re-saved** document.
//! - `POST /api/v1/integration/purview-read-label` reports the labels a PDF already
//!   carries via the `X-Stirling-Tool-Report` header and returns the document
//!   **byte-for-byte unchanged**, so a read never perturbs the file it inspected.
//!
//! Ported from the Java `PurviewLabelController` (+ `ApiConnectionResolver` for the
//! connection lookup and `AiToolResponseHeaders` for the report header name).

use std::{path::Path, sync::Arc, time::SystemTime};

use axum::{
    Json, Router,
    body::Body,
    extract::{
        Extension, Multipart,
        multipart::{Field, MultipartError},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{DateTime, SecondsFormat, Utc};
use lopdf::Document;
use serde_json::{Map, Value, json};
use tokio::task;

use crate::{
    integration_config::{
        IntegrationConfigService, IntegrationFailure, IntegrationType, parse_connection_id_param,
    },
    purview::{
        AssignmentMethod, PdfLabelError, PdfSensitivityLabels, PurviewConnectionSettings,
        SensitivityLabel, SensitivityLabelError,
    },
    security::AuthContext,
};

/// Header carrying the structured label report alongside the returned PDF. Mirrors
/// Java `AiToolResponseHeaders.TOOL_REPORT`; the pipeline already parses this header.
const TOOL_REPORT_HEADER: &str = "X-Stirling-Tool-Report";

/// Default output filename when the upload carries none. Matches Java `safeFileName`.
const DEFAULT_FILENAME: &str = "labelled.pdf";

pub(crate) fn routes(service: Arc<IntegrationConfigService>) -> Router {
    Router::new()
        .route("/api/v1/integration/purview-apply-label", post(apply_label))
        .route("/api/v1/integration/purview-read-label", post(read_label))
        .layer(Extension(service))
}

// ---- handlers -----------------------------------------------------------------------

async fn apply_label(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Result<Response, StepError> {
    let form = ApplyLabelForm::read(multipart).await?;
    // Resolve the connection first, then parse the method — matching the Java
    // controller's ordering, so a bad connection is reported before a bad method.
    let settings = resolve_settings(&service, &context, &form.connection_id)?;
    let method = parse_method(form.method.as_deref())?;
    let label = SensitivityLabel::new(
        form.label_id.trim().to_owned(),
        form.label_name,
        settings.tenant_id().to_owned(),
        Some(method),
        Some(now()),
        form.content_bits,
    )?;

    let file = form.file;
    let saved = task::spawn_blocking(move || apply_label_to_pdf(&file, &label))
        .await
        .map_err(|_| StepError::internal())??;
    pdf_response(saved, &safe_file_name(form.filename.as_deref()), None)
}

async fn read_label(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Result<Response, StepError> {
    let form = ReadLabelForm::read(multipart).await?;
    let settings = resolve_settings(&service, &context, &form.connection_id)?;

    // Move the bytes into the blocking read and hand them back out so the document is
    // returned byte-for-byte, without cloning the whole upload.
    let file = form.file;
    let (labels, file) = task::spawn_blocking(move || {
        let labels = read_labels_from_pdf(&file);
        (labels, file)
    })
    .await
    .map_err(|_| StepError::internal())?;
    let labels = labels?;

    let report = build_report(&labels, &settings);
    let report = serde_json::to_string(&report).map_err(|_| StepError::internal())?;
    pdf_response(
        file,
        &safe_file_name(form.filename.as_deref()),
        Some(&report),
    )
}

// ---- connection / label plumbing ----------------------------------------------------

fn resolve_settings(
    service: &IntegrationConfigService,
    context: &AuthContext,
    connection_id: &str,
) -> Result<PurviewConnectionSettings, StepError> {
    let id = parse_connection_id_param(connection_id)?;
    let config = service.resolve_config(id, IntegrationType::Purview, context)?;
    let settings = PurviewConnectionSettings::from(&config).map_err(IntegrationFailure::from)?;
    Ok(settings)
}

/// The wall-clock instant for a freshly applied label. `std::time::SystemTime` is the
/// real clock (mirrors Java `Instant.now()`); it is converted into the `chrono` type
/// the label carries.
fn now() -> DateTime<Utc> {
    DateTime::<Utc>::from(SystemTime::now())
}

/// Parses the assignment method, defaulting to `STANDARD` only when the field is
/// absent (matching Spring's `defaultValue`); a present-but-unrecognised value is a
/// client error naming both accepted values, as in Java `parseMethod`.
fn parse_method(value: Option<&str>) -> Result<AssignmentMethod, StepError> {
    let raw = value.unwrap_or("STANDARD");
    AssignmentMethod::parse(Some(raw)).ok_or_else(|| {
        StepError::bad_request(format!(
            "'method' must be STANDARD (applied automatically) or PRIVILEGED (chosen by a \
             person); got {raw}"
        ))
    })
}

fn apply_label_to_pdf(bytes: &[u8], label: &SensitivityLabel) -> Result<Vec<u8>, StepError> {
    let mut document = Document::load_mem(bytes)
        .map_err(|_| StepError::bad_request("could not read the input PDF"))?;
    PdfSensitivityLabels::apply(&mut document, label)?;
    let mut saved = Vec::new();
    document
        .save_to(&mut saved)
        .map_err(|_| StepError::internal())?;
    Ok(saved)
}

fn read_labels_from_pdf(bytes: &[u8]) -> Result<Vec<SensitivityLabel>, StepError> {
    let document = Document::load_mem(bytes)
        .map_err(|_| StepError::bad_request("could not read the input PDF"))?;
    Ok(PdfSensitivityLabels::read_all(&document))
}

/// Builds the structured label report. Ported from Java `buildReport`: `labelled` plus
/// this tenant's label (case-insensitive `siteId == tenantId`), and every other
/// tenant's label id/site so a policy can still see them. The per-label fields are
/// omitted entirely when this tenant has no label, matching Java's `ifPresent`.
fn build_report(labels: &[SensitivityLabel], settings: &PurviewConnectionSettings) -> Value {
    let tenant = settings.tenant_id();
    let own = labels
        .iter()
        .find(|label| label.site_id().eq_ignore_ascii_case(tenant));

    let mut report = Map::new();
    report.insert("labelled".to_owned(), Value::Bool(own.is_some()));
    if let Some(label) = own {
        report.insert(
            "labelId".to_owned(),
            Value::String(label.label_id().to_owned()),
        );
        report.insert("labelName".to_owned(), string_or_null(label.name()));
        report.insert(
            "method".to_owned(),
            string_or_null(label.method().map(method_name)),
        );
        let set_date = label.set_date().map(format_set_date);
        report.insert("setDate".to_owned(), string_or_null(set_date.as_deref()));
        report.insert(
            "contentBits".to_owned(),
            label
                .content_bits()
                .map_or(Value::Null, |bits| Value::Number(bits.into())),
        );
        report.insert("protected".to_owned(), Value::Bool(label.is_protected()));
    }

    let others = labels
        .iter()
        .filter(|label| !label.site_id().eq_ignore_ascii_case(tenant))
        .map(|label| {
            let mut node = Map::new();
            node.insert(
                "labelId".to_owned(),
                Value::String(label.label_id().to_owned()),
            );
            node.insert(
                "siteId".to_owned(),
                Value::String(label.site_id().to_owned()),
            );
            Value::Object(node)
        })
        .collect();
    report.insert("otherTenantLabels".to_owned(), Value::Array(others));

    Value::Object(report)
}

/// The Java enum constant name (`STANDARD`/`PRIVILEGED`), which is what `buildReport`
/// writes via `method().name()` — deliberately the constant name, not the MIP wire
/// form (`Standard`/`Privileged`).
fn method_name(method: AssignmentMethod) -> &'static str {
    match method {
        AssignmentMethod::Standard => "STANDARD",
        AssignmentMethod::Privileged => "PRIVILEGED",
    }
}

/// The report's `setDate`, matching Java `Instant.toString()`: ISO-8601 in UTC with a
/// `Z` suffix and only as many fractional digits as needed.
fn format_set_date(set_date: DateTime<Utc>) -> String {
    set_date.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn string_or_null(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.to_owned()))
}

// ---- responses ----------------------------------------------------------------------

fn pdf_response(
    bytes: Vec<u8>,
    filename: &str,
    report: Option<&str>,
) -> Result<Response, StepError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        attachment_disposition(filename)?,
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&bytes.len().to_string()).map_err(|_| StepError::internal())?,
    );
    if let Some(report) = report {
        headers.insert(
            TOOL_REPORT_HEADER,
            HeaderValue::from_str(report).map_err(|_| StepError::internal())?,
        );
    }
    Ok((headers, Body::from(bytes)).into_response())
}

fn attachment_disposition(filename: &str) -> Result<HeaderValue, StepError> {
    let encoded = urlencoding::encode(filename).replace('+', "%20");
    HeaderValue::from_str(&format!("attachment; filename=\"{encoded}\""))
        .map_err(|_| StepError::internal())
}

/// The upload's basename, or the default. Mirrors Java `safeFileName`: strip any path
/// component and fall back when the result is blank.
fn safe_file_name(filename: Option<&str>) -> String {
    filename
        .and_then(|name| Path::new(name).file_name())
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_FILENAME)
        .to_owned()
}

// ---- multipart forms ----------------------------------------------------------------

struct ApplyLabelForm {
    file: Vec<u8>,
    filename: Option<String>,
    connection_id: String,
    label_id: String,
    label_name: Option<String>,
    method: Option<String>,
    content_bits: Option<i32>,
}

impl ApplyLabelForm {
    async fn read(mut multipart: Multipart) -> Result<Self, StepError> {
        let mut file = None;
        let mut filename = None;
        let mut connection_id = None;
        let mut label_id = None;
        let mut label_name = None;
        let mut method = None;
        let mut content_bits = None;
        while let Some(field) = multipart.next_field().await? {
            let name = field.name().unwrap_or_default().to_owned();
            match name.as_str() {
                "fileInput" => {
                    filename = field.file_name().map(ToOwned::to_owned);
                    file = Some(field.bytes().await?.to_vec());
                }
                "connectionId" => connection_id = Some(field.text().await?),
                "labelId" => label_id = Some(field.text().await?),
                "labelName" => label_name = Some(field.text().await?),
                "method" => method = Some(field.text().await?),
                "contentBits" => content_bits = parse_content_bits(&field.text().await?)?,
                _ => drain(field).await?,
            }
        }
        Ok(Self {
            file: file.ok_or_else(required_file)?,
            filename,
            connection_id: connection_id.ok_or_else(required_connection_id)?,
            label_id: label_id.ok_or_else(|| StepError::bad_request("'labelId' is required"))?,
            label_name,
            method,
            content_bits,
        })
    }
}

struct ReadLabelForm {
    file: Vec<u8>,
    filename: Option<String>,
    connection_id: String,
}

impl ReadLabelForm {
    async fn read(mut multipart: Multipart) -> Result<Self, StepError> {
        let mut file = None;
        let mut filename = None;
        let mut connection_id = None;
        while let Some(field) = multipart.next_field().await? {
            let name = field.name().unwrap_or_default().to_owned();
            match name.as_str() {
                "fileInput" => {
                    filename = field.file_name().map(ToOwned::to_owned);
                    file = Some(field.bytes().await?.to_vec());
                }
                "connectionId" => connection_id = Some(field.text().await?),
                _ => drain(field).await?,
            }
        }
        Ok(Self {
            file: file.ok_or_else(required_file)?,
            filename,
            connection_id: connection_id.ok_or_else(required_connection_id)?,
        })
    }
}

fn required_file() -> StepError {
    StepError::bad_request("'fileInput' is required")
}

fn required_connection_id() -> StepError {
    StepError::bad_request("'connectionId' is required")
}

/// An absent field means `None`; a present-but-blank field is treated as absent (so a
/// stray empty part does not become a bad-integer error); anything else must parse.
fn parse_content_bits(value: &str) -> Result<Option<i32>, StepError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<i32>()
        .map(Some)
        .map_err(|_| StepError::bad_request("'contentBits' must be an integer"))
}

/// Consume an unexpected field so the multipart stream advances to the next one.
async fn drain(field: Field<'_>) -> Result<(), StepError> {
    field.bytes().await?;
    Ok(())
}

// ---- errors -------------------------------------------------------------------------

/// A rejected label step. The body shape (`{"error": message}`) mirrors the sibling
/// integration HTTP surface.
enum StepError {
    BadRequest(String),
    Forbidden(String),
    Internal,
}

impl StepError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn internal() -> Self {
        Self::Internal
    }
}

impl IntoResponse for StepError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Purview label step failed".to_owned(),
            ),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<IntegrationFailure> for StepError {
    fn from(error: IntegrationFailure) -> Self {
        match error {
            IntegrationFailure::BadRequest(message)
            | IntegrationFailure::NotFound(message)
            | IntegrationFailure::Conflict(message) => Self::BadRequest(message),
            IntegrationFailure::Forbidden(message) => Self::Forbidden(message),
            IntegrationFailure::Storage(_) | IntegrationFailure::Access(_) => Self::Internal,
        }
    }
}

impl From<SensitivityLabelError> for StepError {
    fn from(error: SensitivityLabelError) -> Self {
        Self::BadRequest(error.to_string())
    }
}

impl From<PdfLabelError> for StepError {
    fn from(error: PdfLabelError) -> Self {
        match error {
            // A protected (encryption) label cannot be honoured, and an oversized XMP
            // packet is a hostile/malformed input — both are the caller's problem.
            PdfLabelError::ProtectedLabel | PdfLabelError::XmpTooLarge(_) => {
                Self::BadRequest(error.to_string())
            }
            PdfLabelError::PdfJson(_) | PdfLabelError::Pdf(_) => Self::Internal,
        }
    }
}

impl From<MultipartError> for StepError {
    fn from(error: MultipartError) -> Self {
        Self::BadRequest(error.body_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration_config::NewIntegrationConfig;
    use crate::resource_access::{DefaultAccessPolicy, OwnerScope};
    use crate::security::{AuthenticationSource, SecurityStore};
    use axum::body::to_bytes;
    use axum::http::Request;
    use lopdf::dictionary;
    use std::collections::BTreeSet;
    use tower::ServiceExt as _;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Fixture<T> = Result<T, Box<dyn std::error::Error>>;

    const TENANT: &str = "cb46c030-1825-4e81-a295-151c039dbf02";
    const OTHER_TENANT: &str = "99999999-8888-7777-6666-555555555555";
    const LABEL: &str = "11111111-2222-3333-4444-555555555555";
    const OTHER_LABEL: &str = "22222222-3333-4444-5555-666666666666";
    const BOUNDARY: &str = "purview-test-boundary";
    const APPLY: &str = "/api/v1/integration/purview-apply-label";
    const READ: &str = "/api/v1/integration/purview-read-label";
    const OPAQUE: &str = "unknown or inaccessible purview connection";

    fn admin() -> AuthContext {
        AuthContext {
            user_id: 1,
            username: "user".to_owned(),
            authentication_source: AuthenticationSource::AccessToken,
            authentication_type: "web".to_owned(),
            roles: ["ROLE_ADMIN"]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
            team_id: Some(1),
            permissions: BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        }
    }

    fn service() -> Fixture<Arc<IntegrationConfigService>> {
        Ok(Arc::new(IntegrationConfigService::new(
            Arc::new(SecurityStore::in_memory()?),
            DefaultAccessPolicy::ExplicitOnly,
            false,
            false,
            false,
            false,
        )))
    }

    fn router(service: Arc<IntegrationConfigService>) -> Router {
        routes(service).layer(Extension(admin()))
    }

    fn connection(
        service: &IntegrationConfigService,
        integration_type: IntegrationType,
        config: Value,
        enabled: bool,
    ) -> Fixture<i64> {
        let config = match config {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        let created =
            service
                .access()
                .store()
                .create_integration_config(&NewIntegrationConfig {
                    integration_type,
                    name: "conn".to_owned(),
                    scope: OwnerScope::Server,
                    owner_user_id: None,
                    owner_team_id: None,
                    enabled,
                    locked: false,
                    default_access: DefaultAccessPolicy::ExplicitOnly,
                    config,
                })?;
        Ok(created.id)
    }

    fn purview_connection(service: &IntegrationConfigService, enabled: bool) -> Fixture<i64> {
        connection(
            service,
            IntegrationType::Purview,
            json!({ "tenantId": TENANT }),
            enabled,
        )
    }

    fn blank_pdf() -> Fixture<Vec<u8>> {
        save(&mut base_document())
    }

    fn labelled_pdf() -> Fixture<Vec<u8>> {
        let mut document = base_document();
        PdfSensitivityLabels::apply(
            &mut document,
            &label(LABEL, TENANT, AssignmentMethod::Privileged)?,
        )?;
        PdfSensitivityLabels::apply(
            &mut document,
            &label(OTHER_LABEL, OTHER_TENANT, AssignmentMethod::Standard)?,
        )?;
        save(&mut document)
    }

    fn base_document() -> Document {
        let mut document = Document::with_version("1.7");
        let catalog = document.add_object(dictionary! { "Type" => "Catalog" });
        document.trailer.set("Root", catalog);
        document
    }

    fn save(document: &mut Document) -> Fixture<Vec<u8>> {
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    fn label(label_id: &str, site_id: &str, method: AssignmentMethod) -> Fixture<SensitivityLabel> {
        // FOOTER (not ENCRYPT), so applying is allowed and `protected` reads false.
        Ok(SensitivityLabel::new(
            label_id.to_owned(),
            Some("Confidential".to_owned()),
            site_id.to_owned(),
            Some(method),
            Some(now()),
            Some(SensitivityLabel::CONTENT_BITS_FOOTER),
        )?)
    }

    fn multipart(fields: &[(&str, &str)], file: Option<&[u8]>) -> (String, Vec<u8>) {
        let mut body = Vec::new();
        for (name, value) in fields {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
                )
                .as_bytes(),
            );
        }
        if let Some(file) = file {
            body.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"input.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(file);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={BOUNDARY}"), body)
    }

    async fn send(
        app: Router,
        path: &str,
        content_type: String,
        body: Vec<u8>,
    ) -> Fixture<Response> {
        Ok(app
            .oneshot(
                Request::post(path)
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?)
    }

    async fn error_message(response: Response) -> Fixture<String> {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        Ok(value["error"].as_str().unwrap_or_default().to_owned())
    }

    async fn apply_error(
        service: &Arc<IntegrationConfigService>,
        connection_id: &str,
    ) -> Fixture<(StatusCode, String)> {
        let (content_type, body) = multipart(
            &[("connectionId", connection_id), ("labelId", LABEL)],
            Some(&blank_pdf()?),
        );
        let response = send(router(Arc::clone(service)), APPLY, content_type, body).await?;
        let status = response.status();
        Ok((status, error_message(response).await?))
    }

    #[tokio::test]
    async fn apply_writes_the_label_and_returns_the_re_saved_pdf() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?;
        let (content_type, body) = multipart(
            &[
                ("connectionId", &id.to_string()),
                ("labelId", LABEL),
                ("method", "PRIVILEGED"),
            ],
            Some(&blank_pdf()?),
        );
        let response = send(router(service), APPLY, content_type, body).await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/pdf")
        );
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024).await?;
        let document = Document::load_mem(&bytes)?;
        let read = PdfSensitivityLabels::read(&document).ok_or("expected a label on the output")?;
        assert_eq!(read.label_id(), LABEL);
        assert_eq!(read.site_id(), TENANT);
        assert_eq!(read.method(), Some(AssignmentMethod::Privileged));
        Ok(())
    }

    #[tokio::test]
    async fn read_returns_the_pdf_unchanged_with_a_tenant_report() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?;
        let input = labelled_pdf()?;
        let (content_type, body) = multipart(&[("connectionId", &id.to_string())], Some(&input));
        let response = send(router(service), READ, content_type, body).await?;

        assert_eq!(response.status(), StatusCode::OK);
        let report = response
            .headers()
            .get(TOOL_REPORT_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or("expected a tool-report header")?
            .to_owned();
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024).await?;
        // The read must return the document byte-for-byte, never re-saved.
        assert_eq!(bytes.as_ref(), input.as_slice());

        let report: Value = serde_json::from_str(&report)?;
        assert_eq!(report["labelled"], Value::Bool(true));
        assert_eq!(report["labelId"], Value::String(LABEL.to_owned()));
        assert_eq!(report["method"], Value::String("PRIVILEGED".to_owned()));
        assert_eq!(report["protected"], Value::Bool(false));
        let others = report["otherTenantLabels"]
            .as_array()
            .ok_or("expected an otherTenantLabels array")?;
        assert_eq!(others.len(), 1);
        assert_eq!(others[0]["labelId"], Value::String(OTHER_LABEL.to_owned()));
        assert_eq!(others[0]["siteId"], Value::String(OTHER_TENANT.to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn apply_rejects_an_unknown_method() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?;
        let (content_type, body) = multipart(
            &[
                ("connectionId", &id.to_string()),
                ("labelId", LABEL),
                ("method", "AUTOMATIC"),
            ],
            Some(&blank_pdf()?),
        );
        let response = send(router(service), APPLY, content_type, body).await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let message = error_message(response).await?;
        assert!(
            message.contains("STANDARD") && message.contains("PRIVILEGED"),
            "{message}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn apply_rejects_an_encryption_label() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?;
        let (content_type, body) = multipart(
            &[
                ("connectionId", &id.to_string()),
                ("labelId", LABEL),
                ("contentBits", "8"),
            ],
            Some(&blank_pdf()?),
        );
        let response = send(router(service), APPLY, content_type, body).await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(error_message(response).await?.contains("cannot protect"));
        Ok(())
    }

    #[tokio::test]
    async fn unknown_wrong_type_and_disabled_connections_collapse_to_one_error() -> TestResult {
        let service = service()?;
        let disabled = purview_connection(&service, false)?.to_string();
        let wrong_type = connection(&service, IntegrationType::Api, json!({}), true)?.to_string();
        let missing = "999999".to_owned();

        for id in [&disabled, &wrong_type, &missing] {
            let (status, message) = apply_error(&service, id).await?;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id={id}");
            // Anti-enumeration: every failure mode yields the identical opaque message.
            assert_eq!(message.as_str(), OPAQUE, "id={id}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_blank_or_absent_connection_id_is_rejected_as_required() -> TestResult {
        let service = service()?;
        purview_connection(&service, true)?;

        for fields in [
            vec![("connectionId", ""), ("labelId", LABEL)],
            vec![("labelId", LABEL)],
        ] {
            let (content_type, body) = multipart(&fields, Some(&blank_pdf()?));
            let response = send(router(Arc::clone(&service)), APPLY, content_type, body).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(error_message(response).await?, "'connectionId' is required");
        }
        Ok(())
    }

    #[tokio::test]
    async fn apply_rejects_a_non_guid_label_id() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?;
        let (content_type, body) = multipart(
            &[("connectionId", &id.to_string()), ("labelId", "not-a-guid")],
            Some(&blank_pdf()?),
        );
        let response = send(router(service), APPLY, content_type, body).await?;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(error_message(response).await?.contains("labelId"));
        Ok(())
    }

    // ---- tester-added adversarial coverage (WI-4 sign-off) --------------------------

    /// A non-numeric or overflowing connectionId is a client error naming the parameter,
    /// distinct from the "required" case (blank/absent) and never a 500 or a lookup.
    #[tokio::test]
    async fn apply_rejects_a_malformed_connection_id() -> TestResult {
        let service = service()?;
        purview_connection(&service, true)?;
        for reference in ["abc", "9999999999999999999999", "1e3", "1; DROP TABLE"] {
            let (content_type, body) = multipart(
                &[("connectionId", reference), ("labelId", LABEL)],
                Some(&blank_pdf()?),
            );
            let response = send(router(Arc::clone(&service)), APPLY, content_type, body).await?;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "ref={reference}"
            );
            let message = error_message(response).await?;
            assert!(
                message.contains("not a valid connection reference"),
                "ref={reference}: {message}"
            );
        }
        Ok(())
    }

    /// A multipart with no `fileInput` part is rejected as required, on both endpoints.
    #[tokio::test]
    async fn a_missing_file_input_is_rejected_as_required() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?.to_string();
        for (path, fields) in [
            (
                APPLY,
                vec![("connectionId", id.as_str()), ("labelId", LABEL)],
            ),
            (READ, vec![("connectionId", id.as_str())]),
        ] {
            let (content_type, body) = multipart(&fields, None);
            let response = send(router(Arc::clone(&service)), path, content_type, body).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "path={path}");
            assert_eq!(error_message(response).await?, "'fileInput' is required");
        }
        Ok(())
    }

    /// Full HTTP apply -> HTTP read round-trip: the label written by apply is the one read
    /// back, and the read returns the apply output byte-for-byte (proving no re-save).
    #[tokio::test]
    async fn apply_then_read_round_trips_through_http() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?.to_string();

        let (content_type, body) = multipart(
            &[
                ("connectionId", &id),
                ("labelId", LABEL),
                ("method", "STANDARD"),
            ],
            Some(&blank_pdf()?),
        );
        let applied = send(router(Arc::clone(&service)), APPLY, content_type, body).await?;
        assert_eq!(applied.status(), StatusCode::OK);
        let applied_bytes = to_bytes(applied.into_body(), 8 * 1024 * 1024)
            .await?
            .to_vec();

        let (content_type, body) = multipart(&[("connectionId", &id)], Some(&applied_bytes));
        let read = send(router(service), READ, content_type, body).await?;
        assert_eq!(read.status(), StatusCode::OK);
        let report = read
            .headers()
            .get(TOOL_REPORT_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or("expected a tool-report header")?
            .to_owned();
        let echoed = to_bytes(read.into_body(), 8 * 1024 * 1024).await?;
        // Read echoes the apply output unchanged.
        assert_eq!(echoed.as_ref(), applied_bytes.as_slice());

        let report: Value = serde_json::from_str(&report)?;
        assert_eq!(report["labelled"], Value::Bool(true));
        assert_eq!(report["labelId"], Value::String(LABEL.to_owned()));
        assert_eq!(report["method"], Value::String("STANDARD".to_owned()));
        // No other tenants involved: the array is present and empty.
        assert_eq!(
            report["otherTenantLabels"].as_array().map(Vec::len),
            Some(0)
        );
        Ok(())
    }

    /// Applying this tenant's label onto a PDF that already carries another tenant's label
    /// leaves the other tenant's label intact, and the read report surfaces it under
    /// `otherTenantLabels` with exactly `labelId` + `siteId` (no name/method leak).
    #[tokio::test]
    async fn apply_preserves_other_tenant_labels_and_report_shape() -> TestResult {
        let service = service()?;
        let id = purview_connection(&service, true)?.to_string();

        // A PDF pre-seeded with only the OTHER tenant's label.
        let mut document = base_document();
        PdfSensitivityLabels::apply(
            &mut document,
            &label(OTHER_LABEL, OTHER_TENANT, AssignmentMethod::Standard)?,
        )?;
        let seeded = save(&mut document)?;

        let (content_type, body) =
            multipart(&[("connectionId", &id), ("labelId", LABEL)], Some(&seeded));
        let applied = send(router(Arc::clone(&service)), APPLY, content_type, body).await?;
        assert_eq!(applied.status(), StatusCode::OK);
        let applied_bytes = to_bytes(applied.into_body(), 8 * 1024 * 1024)
            .await?
            .to_vec();

        // Both labels survive on the output document.
        let output = Document::load_mem(&applied_bytes)?;
        let labels = PdfSensitivityLabels::read_all(&output);
        assert!(
            labels
                .iter()
                .any(|l| l.label_id() == LABEL && l.site_id() == TENANT)
        );
        assert!(
            labels
                .iter()
                .any(|l| l.label_id() == OTHER_LABEL && l.site_id() == OTHER_TENANT)
        );

        // The read report exposes the other tenant's label with only id + site.
        let (content_type, body) = multipart(&[("connectionId", &id)], Some(&applied_bytes));
        let read = send(router(service), READ, content_type, body).await?;
        let report: Value = serde_json::from_str(
            read.headers()
                .get(TOOL_REPORT_HEADER)
                .and_then(|value| value.to_str().ok())
                .ok_or("expected a tool-report header")?,
        )?;
        let others = report["otherTenantLabels"]
            .as_array()
            .ok_or("expected otherTenantLabels")?;
        assert_eq!(others.len(), 1);
        let entry = others[0].as_object().ok_or("expected an object entry")?;
        let mut keys = entry.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["labelId", "siteId"]);
        assert_eq!(entry["labelId"], Value::String(OTHER_LABEL.to_owned()));
        assert_eq!(entry["siteId"], Value::String(OTHER_TENANT.to_owned()));
        Ok(())
    }
}
