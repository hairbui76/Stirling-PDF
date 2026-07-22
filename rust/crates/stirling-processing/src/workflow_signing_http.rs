//! HTTP compatibility surface for collaborative signing workflows.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Extension, Multipart, Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::Value;
use tokio::{io::AsyncWriteExt as _, task};
use tokio_util::io::ReaderStream;

use crate::{
    security::{AuthContext, SecurityAuditContext},
    storage::{PendingFileBundle, PendingObject, StorageError, StorageService, StoredFileObject},
    workflow_signing::{
        CertificateValidationResponse, ParticipantRequest, SignatureSubmission, WetSignature,
        WorkflowCreation, WorkflowSessionResponse, WorkflowSigningError, WorkflowSigningService,
    },
};

const MAX_FORM_VALUE_BYTES: usize = 5 * 1024 * 1024;
const MAX_SIGNING_MATERIAL_BYTES: usize = 32 * 1024 * 1024;

pub(crate) fn owner_routes(max_upload_bytes: usize) -> Router {
    Router::new()
        .route(
            "/api/v1/security/cert-sign/sessions",
            get(list_sessions).post(create_session),
        )
        .route(
            "/api/v1/security/cert-sign/sessions/{session_id}",
            get(get_session).delete(delete_session),
        )
        .route(
            "/api/v1/security/cert-sign/sessions/{session_id}/participants",
            post(add_participants),
        )
        .route(
            "/api/v1/security/cert-sign/sessions/{session_id}/participants/{participant_id}",
            axum::routing::delete(remove_participant),
        )
        .route(
            "/api/v1/security/cert-sign/sessions/{session_id}/pdf",
            get(get_session_pdf),
        )
        .route(
            "/api/v1/security/cert-sign/sessions/{session_id}/finalize",
            post(finalize_session),
        )
        .route(
            "/api/v1/security/cert-sign/sessions/{session_id}/signed-pdf",
            get(get_signed_pdf),
        )
        .route(
            "/api/v1/security/cert-sign/sign-requests",
            get(list_sign_requests),
        )
        .route(
            "/api/v1/security/cert-sign/sign-requests/{session_id}",
            get(get_sign_request),
        )
        .route(
            "/api/v1/security/cert-sign/sign-requests/{session_id}/document",
            get(get_sign_request_document),
        )
        .route(
            "/api/v1/security/cert-sign/sign-requests/{session_id}/sign",
            post(sign_request),
        )
        .route(
            "/api/v1/security/cert-sign/sign-requests/{session_id}/decline",
            post(decline_sign_request),
        )
        .route(
            "/api/v1/security/cert-sign/validate-certificate",
            post(validate_certificate),
        )
        .layer(DefaultBodyLimit::max(max_upload_bytes))
}

pub(crate) fn participant_routes(max_upload_bytes: usize) -> Router {
    Router::new()
        .route(
            "/api/v1/workflow/participant/session",
            get(participant_session),
        )
        .route(
            "/api/v1/workflow/participant/details",
            get(participant_details),
        )
        .route(
            "/api/v1/workflow/participant/submit-signature",
            post(participant_submit),
        )
        .route(
            "/api/v1/workflow/participant/decline",
            post(participant_decline),
        )
        .route(
            "/api/v1/workflow/participant/document",
            get(participant_document),
        )
        .route(
            "/api/v1/workflow/participant/validate-certificate",
            post(participant_validate_certificate),
        )
        .layer(DefaultBodyLimit::max(max_upload_bytes))
}

async fn list_sessions(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<WorkflowSessionResponse>>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.list_sessions(context.user_id)).await?,
    ))
}

async fn create_session(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(storage): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Result<Json<WorkflowSessionResponse>, WorkflowApiError> {
    let (mut bundle, mut request) =
        read_creation_form(&storage, context.user_id, multipart).await?;
    Ok(Json(
        blocking(move || {
            service.create_session(
                context.user_id,
                &context.username,
                &mut bundle,
                &mut request,
            )
        })
        .await?,
    ))
}

async fn get_session(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Json<WorkflowSessionResponse>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.owner_session(context.user_id, &session_id)).await?,
    ))
}

async fn delete_session(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, WorkflowApiError> {
    blocking(move || service.delete_session(context.user_id, &session_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_participants(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
    Json(requests): Json<Vec<ParticipantRequest>>,
) -> Result<Json<WorkflowSessionResponse>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.add_participants(context.user_id, &session_id, &requests)).await?,
    ))
}

async fn remove_participant(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path((session_id, participant_id)): Path<(String, i64)>,
) -> Result<StatusCode, WorkflowApiError> {
    blocking(move || service.remove_participant(context.user_id, &session_id, participant_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_session_pdf(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Response, WorkflowApiError> {
    let stored =
        blocking(move || service.owner_document(context.user_id, &session_id, false)).await?;
    stream_file(stored, false).await
}

async fn finalize_session(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Response, WorkflowApiError> {
    let stored = blocking(move || service.finalize(context.user_id, &session_id)).await?;
    stream_file(stored, false).await
}

async fn get_signed_pdf(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Response, WorkflowApiError> {
    let stored =
        blocking(move || service.owner_document(context.user_id, &session_id, true)).await?;
    stream_file(stored, false).await
}

async fn list_sign_requests(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<crate::workflow_signing::SignRequestSummary>>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.list_sign_requests(context.user_id)).await?,
    ))
}

async fn get_sign_request(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Json<crate::workflow_signing::SignRequestDetail>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.sign_request_detail(context.user_id, &session_id)).await?,
    ))
}

async fn get_sign_request_document(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<Response, WorkflowApiError> {
    let stored =
        blocking(move || service.sign_request_document(context.user_id, &session_id)).await?;
    stream_file(stored, false).await
}

async fn sign_request(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
    multipart: Multipart,
) -> Result<StatusCode, WorkflowApiError> {
    let submission = read_submission_form(multipart).await?;
    blocking(move || service.submit_for_user(context.user_id, &session_id, submission)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn decline_sign_request(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Extension(context): Extension<AuthContext>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, WorkflowApiError> {
    blocking(move || service.decline_for_user(context.user_id, &session_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn validate_certificate(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    multipart: Multipart,
) -> Result<Json<CertificateValidationResponse>, WorkflowApiError> {
    let submission = read_submission_form(multipart).await?;
    validation_response(blocking(move || service.validate_certificate(&submission)).await)
}

#[derive(Deserialize)]
struct TokenQuery {
    token: String,
}

#[derive(Deserialize)]
struct DeclineQuery {
    token: String,
    reason: Option<String>,
}

async fn participant_session(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Query(query): Query<TokenQuery>,
) -> Result<Json<WorkflowSessionResponse>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.token_session(&query.token)).await?,
    ))
}

async fn participant_details(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Query(query): Query<TokenQuery>,
) -> Result<Json<crate::workflow_signing::ParticipantResponse>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.token_participant(&query.token)).await?,
    ))
}

async fn participant_submit(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    multipart: Multipart,
) -> Result<Json<crate::workflow_signing::ParticipantResponse>, WorkflowApiError> {
    let (token, submission) = read_token_submission_form(multipart).await?;
    Ok(Json(
        blocking(move || service.submit_for_token(&token, submission)).await?,
    ))
}

async fn participant_decline(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Query(query): Query<DeclineQuery>,
) -> Result<Json<crate::workflow_signing::ParticipantResponse>, WorkflowApiError> {
    Ok(Json(
        blocking(move || service.decline_for_token(&query.token, query.reason.as_deref())).await?,
    ))
}

async fn participant_document(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, WorkflowApiError> {
    let stored = blocking(move || service.token_document(&query.token)).await?;
    stream_file(stored, false).await
}

async fn participant_validate_certificate(
    Extension(service): Extension<Arc<WorkflowSigningService>>,
    multipart: Multipart,
) -> Result<Json<CertificateValidationResponse>, WorkflowApiError> {
    let (token, submission) = read_token_submission_form(multipart).await?;
    validation_response(
        blocking(move || service.validate_certificate_for_token(&token, &submission)).await,
    )
}

fn validation_response(
    result: Result<CertificateValidationResponse, WorkflowApiError>,
) -> Result<Json<CertificateValidationResponse>, WorkflowApiError> {
    match result {
        Ok(response) => Ok(Json(response)),
        Err(WorkflowApiError::Workflow(
            WorkflowSigningError::Certificate(_)
            | WorkflowSigningError::InvalidInput
            | WorkflowSigningError::DigitalSignature(_),
        )) => Ok(Json(CertificateValidationResponse {
            valid: false,
            subject_name: None,
            issuer_name: None,
            not_after: None,
            not_before: None,
            self_signed: false,
            error: Some("Certificate validation failed".to_owned()),
        })),
        Err(error) => Err(error),
    }
}

async fn read_creation_form(
    storage: &StorageService,
    owner_id: i64,
    mut multipart: Multipart,
) -> Result<(PendingFileBundle, WorkflowCreation), WorkflowApiError> {
    let mut bundle = PendingFileBundle::default();
    let mut workflow_type = None;
    let mut document_name = None;
    let mut owner_email = None;
    let mut message = None;
    let mut due_date = None;
    let mut participant_user_ids = Vec::new();
    let mut participant_emails = Vec::new();
    let mut workflow_metadata = serde_json::json!({});
    let mut total_bytes = 0_u64;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| WorkflowSigningError::InvalidInput)?
    {
        let name = field.name().unwrap_or_default().to_owned();
        if name == "file" {
            if bundle.file.is_some() {
                return Err(WorkflowSigningError::InvalidInput.into());
            }
            let filename = field.file_name().map(ToOwned::to_owned);
            let content_type = field.content_type().map(ToString::to_string);
            let object = stream_object(
                storage,
                owner_id,
                filename.as_deref(),
                content_type.as_deref(),
                &mut field,
                &mut total_bytes,
            )
            .await?;
            if object.size_bytes == 0 {
                return Err(WorkflowSigningError::InvalidInput.into());
            }
            bundle.file = Some(object);
            continue;
        }
        let value = read_text_field(
            &mut field,
            &name,
            MAX_FORM_VALUE_BYTES,
            &mut total_bytes,
            storage.max_upload_bytes(),
        )
        .await?;
        match name.as_str() {
            "workflowType" => workflow_type = Some(value),
            "documentName" => document_name = Some(value),
            "ownerEmail" => owner_email = Some(value),
            "message" => message = Some(value),
            "dueDate" => due_date = Some(value),
            "workflowMetadata" => {
                workflow_metadata = serde_json::from_str::<Value>(&value)
                    .map_err(|_| WorkflowSigningError::InvalidInput)?;
            }
            "participantUserIds" => participant_user_ids.push(parse_i64(&value)?),
            "participantEmails" => participant_emails.push(value),
            _ if indexed_field(&name, "participantUserIds") => {
                participant_user_ids.push(parse_i64(&value)?);
            }
            _ if indexed_field(&name, "participantEmails") => participant_emails.push(value),
            _ => {}
        }
    }
    if bundle.file.is_none() {
        return Err(WorkflowSigningError::InvalidInput.into());
    }
    Ok((
        bundle,
        WorkflowCreation {
            workflow_type: workflow_type.ok_or(WorkflowSigningError::InvalidInput)?,
            document_name,
            owner_email,
            message,
            due_date,
            participant_user_ids,
            participant_emails,
            workflow_metadata,
        },
    ))
}

fn indexed_field(name: &str, base: &str) -> bool {
    name.strip_prefix(base).is_some_and(|suffix| {
        suffix.starts_with('[')
            && suffix.ends_with(']')
            && suffix[1..suffix.len() - 1]
                .bytes()
                .all(|byte| byte.is_ascii_digit())
    })
}

async fn read_submission_form(
    multipart: Multipart,
) -> Result<SignatureSubmission, WorkflowApiError> {
    let (_, submission) = read_submission_form_inner(multipart).await?;
    Ok(submission)
}

async fn read_token_submission_form(
    multipart: Multipart,
) -> Result<(String, SignatureSubmission), WorkflowApiError> {
    let (token, submission) = read_submission_form_inner(multipart).await?;
    let token = token
        .filter(|value| !value.trim().is_empty())
        .ok_or(WorkflowSigningError::InvalidInput)?;
    Ok((token, submission))
}

async fn read_submission_form_inner(
    mut multipart: Multipart,
) -> Result<(Option<String>, SignatureSubmission), WorkflowApiError> {
    let mut submission = SignatureSubmission::default();
    let mut participant_token = None;
    let mut total_bytes = 0_u64;
    let total_limit =
        u64::try_from(MAX_SIGNING_MATERIAL_BYTES * 4).map_err(|_| WorkflowApiError::Internal)?;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| WorkflowSigningError::InvalidInput)?
    {
        let name = field.name().unwrap_or_default().to_owned();
        match name.as_str() {
            "p12File" => {
                set_file_field(
                    &mut submission.p12_file,
                    &mut field,
                    &mut total_bytes,
                    total_limit,
                )
                .await?;
            }
            "jksFile" => {
                set_file_field(
                    &mut submission.jks_file,
                    &mut field,
                    &mut total_bytes,
                    total_limit,
                )
                .await?;
            }
            "privateKeyFile" => {
                set_file_field(
                    &mut submission.private_key_file,
                    &mut field,
                    &mut total_bytes,
                    total_limit,
                )
                .await?;
            }
            "certFile" => {
                set_file_field(
                    &mut submission.cert_file,
                    &mut field,
                    &mut total_bytes,
                    total_limit,
                )
                .await?;
            }
            _ => {
                let value = read_text_field(
                    &mut field,
                    &name,
                    MAX_FORM_VALUE_BYTES,
                    &mut total_bytes,
                    total_limit,
                )
                .await?;
                match name.as_str() {
                    "participantToken" => participant_token = Some(value),
                    "certType" => submission.cert_type = Some(value),
                    "password" => submission.password = Some(value),
                    "alias" => submission.alias = Some(value),
                    "showSignature" => submission.show_signature = Some(parse_bool(&value)?),
                    "pageNumber" => submission.page_number = Some(parse_i64(&value)?),
                    "location" => submission.location = Some(value),
                    "reason" => submission.reason = Some(value),
                    "showLogo" => submission.show_logo = Some(parse_bool(&value)?),
                    "wetSignaturesData" | "wetSignatureData" => {
                        submission.wet_signatures =
                            serde_json::from_str::<Vec<WetSignature>>(&value)
                                .map_err(|_| WorkflowSigningError::InvalidInput)?;
                    }
                    _ => {}
                }
            }
        }
    }
    Ok((participant_token, submission))
}

async fn set_file_field(
    destination: &mut Option<Vec<u8>>,
    field: &mut axum::extract::multipart::Field<'_>,
    total_bytes: &mut u64,
    total_limit: u64,
) -> Result<(), WorkflowApiError> {
    if destination.is_some() {
        return Err(WorkflowSigningError::InvalidInput.into());
    }
    let audit_filename = field.file_name().map(ToOwned::to_owned);
    let audit_content_type = field.content_type().map(ToOwned::to_owned);
    let value =
        read_bytes_field(field, MAX_SIGNING_MATERIAL_BYTES, total_bytes, total_limit).await?;
    if let Some(filename) = audit_filename {
        SecurityAuditContext::record_current_file_bytes(
            &filename,
            u64::try_from(value.len()).unwrap_or(u64::MAX),
            audit_content_type.as_deref(),
            &value,
        );
    }
    if !value.is_empty() {
        *destination = Some(value);
    }
    Ok(())
}

async fn read_text_field(
    field: &mut axum::extract::multipart::Field<'_>,
    name: &str,
    field_limit: usize,
    total_bytes: &mut u64,
    total_limit: u64,
) -> Result<String, WorkflowApiError> {
    let bytes = read_bytes_field(field, field_limit, total_bytes, total_limit).await?;
    let value = String::from_utf8(bytes).map_err(|_| WorkflowSigningError::InvalidInput)?;
    SecurityAuditContext::record_current_form_param(name, &value);
    Ok(value)
}

async fn read_bytes_field(
    field: &mut axum::extract::multipart::Field<'_>,
    field_limit: usize,
    total_bytes: &mut u64,
    total_limit: u64,
) -> Result<Vec<u8>, WorkflowApiError> {
    let mut output = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| WorkflowSigningError::InvalidInput)?
    {
        add_chunk_size(total_bytes, chunk.len(), total_limit)?;
        if output.len().saturating_add(chunk.len()) > field_limit {
            return Err(WorkflowSigningError::InvalidInput.into());
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

async fn stream_object(
    storage: &StorageService,
    owner_id: i64,
    filename: Option<&str>,
    content_type: Option<&str>,
    field: &mut axum::extract::multipart::Field<'_>,
    total_bytes: &mut u64,
) -> Result<PendingObject, WorkflowApiError> {
    let (mut object, file) = storage.prepare_object(owner_id, filename, content_type)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut object_bytes = 0_u64;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| WorkflowSigningError::InvalidInput)?
    {
        add_chunk_size(total_bytes, chunk.len(), storage.max_upload_bytes())?;
        object_bytes = object_bytes
            .checked_add(
                u64::try_from(chunk.len()).map_err(|_| WorkflowSigningError::InvalidInput)?,
            )
            .ok_or(WorkflowSigningError::InvalidInput)?;
        file.write_all(&chunk).await?;
    }
    file.sync_all().await?;
    object.set_size(object_bytes);
    SecurityAuditContext::record_current_file_path(
        &object.original_filename,
        object_bytes,
        object.content_type.as_deref(),
        object.path(),
    )
    .await;
    Ok(object)
}

fn add_chunk_size(
    total_bytes: &mut u64,
    chunk_size: usize,
    limit: u64,
) -> Result<(), WorkflowApiError> {
    *total_bytes = total_bytes
        .checked_add(u64::try_from(chunk_size).map_err(|_| WorkflowApiError::Internal)?)
        .ok_or(WorkflowApiError::Internal)?;
    if *total_bytes > limit {
        Err(WorkflowApiError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

fn parse_i64(value: &str) -> Result<i64, WorkflowApiError> {
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| WorkflowSigningError::InvalidInput.into())
}

fn parse_bool(value: &str) -> Result<bool, WorkflowApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(WorkflowSigningError::InvalidInput.into()),
    }
}

async fn stream_file(stored: StoredFileObject, inline: bool) -> Result<Response, WorkflowApiError> {
    let file = tokio::fs::File::open(&stored.path).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(stored.content_type.as_deref().unwrap_or("application/pdf"))
            .unwrap_or_else(|_| HeaderValue::from_static("application/pdf")),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&stored.size_bytes.to_string())
            .map_err(|_| WorkflowApiError::Internal)?,
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(inline, &stored.filename)?,
    );
    Ok((
        StatusCode::OK,
        headers,
        Body::from_stream(ReaderStream::new(file)),
    )
        .into_response())
}

fn content_disposition(inline: bool, filename: &str) -> Result<HeaderValue, WorkflowApiError> {
    let ascii = filename
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() && character != '"' && character != '\\' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let disposition = if inline { "inline" } else { "attachment" };
    HeaderValue::from_str(&format!(
        "{disposition}; filename=\"{ascii}\"; filename*=UTF-8''{}",
        urlencoding::encode(filename)
    ))
    .map_err(|_| WorkflowApiError::Internal)
}

async fn blocking<T, F>(function: F) -> Result<T, WorkflowApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, WorkflowSigningError> + Send + 'static,
{
    task::spawn_blocking(function)
        .await
        .map_err(|_| WorkflowApiError::Internal)?
        .map_err(WorkflowApiError::Workflow)
}

#[derive(Debug)]
enum WorkflowApiError {
    Workflow(WorkflowSigningError),
    PayloadTooLarge,
    Internal,
}

impl From<WorkflowSigningError> for WorkflowApiError {
    fn from(error: WorkflowSigningError) -> Self {
        Self::Workflow(error)
    }
}

impl From<StorageError> for WorkflowApiError {
    fn from(error: StorageError) -> Self {
        Self::Workflow(WorkflowSigningError::Storage(error))
    }
}

impl From<std::io::Error> for WorkflowApiError {
    fn from(error: std::io::Error) -> Self {
        Self::Workflow(WorkflowSigningError::Filesystem(error))
    }
}

impl IntoResponse for WorkflowApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::PayloadTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "Request is too large"),
            Self::Workflow(WorkflowSigningError::Disabled) => {
                (StatusCode::FORBIDDEN, "Group signing is disabled")
            }
            Self::Workflow(WorkflowSigningError::InvalidInput) => {
                (StatusCode::BAD_REQUEST, "Invalid workflow request")
            }
            Self::Workflow(WorkflowSigningError::NotFound) => {
                (StatusCode::NOT_FOUND, "Workflow session was not found")
            }
            Self::Workflow(WorkflowSigningError::AccessDenied) => {
                (StatusCode::FORBIDDEN, "Workflow access denied")
            }
            Self::Workflow(WorkflowSigningError::Expired) => {
                (StatusCode::FORBIDDEN, "Participant access expired")
            }
            Self::Workflow(WorkflowSigningError::Conflict) => (
                StatusCode::CONFLICT,
                "Workflow action conflicts with its current state",
            ),
            Self::Workflow(WorkflowSigningError::UnsupportedCertificate) => (
                StatusCode::NOT_IMPLEMENTED,
                "Certificate source is not available in the Rust runtime",
            ),
            Self::Workflow(WorkflowSigningError::Storage(StorageError::QuotaExceeded)) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "Storage quota exceeded")
            }
            Self::Workflow(
                WorkflowSigningError::Certificate(_)
                | WorkflowSigningError::DigitalSignature(_)
                | WorkflowSigningError::WetSignature(_),
            ) => (StatusCode::BAD_REQUEST, "Signature material is invalid"),
            Self::Workflow(
                WorkflowSigningError::Poisoned
                | WorkflowSigningError::Database(_)
                | WorkflowSigningError::Storage(_)
                | WorkflowSigningError::SecretProtection(_)
                | WorkflowSigningError::Serialization(_)
                | WorkflowSigningError::Filesystem(_)
                | WorkflowSigningError::PdfDocument(_)
                | WorkflowSigningError::Summary(_),
            )
            | Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Workflow service unavailable",
            ),
        };
        (
            status,
            Json(serde_json::json!({
                "error": status.canonical_reason().unwrap_or("Request rejected"),
                "message": message,
                "status": status.as_u16(),
            })),
        )
            .into_response()
    }
}
