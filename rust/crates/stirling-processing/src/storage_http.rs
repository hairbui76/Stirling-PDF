//! HTTP compatibility surface for secured durable storage.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Extension, Multipart, Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt as _, task};
use tokio_util::io::ReaderStream;

use crate::{
    security::{AuthContext, SecurityAuditContext},
    storage::{
        FolderResponse, PendingFileBundle, PendingObject, ShareLinkAccessResponse,
        ShareLinkMetadataResponse, ShareLinkResponse, ShareRole, StorageError, StorageService,
        StoredFileObject, StoredFileResponse,
    },
};

const JSON_BODY_LIMIT: usize = 64 * 1024;

pub(crate) fn routes(max_upload_bytes: usize) -> Router {
    let files = Router::new()
        .route("/api/v1/storage/files", get(list_files).post(upload_file))
        .route(
            "/api/v1/storage/files/{file_id}",
            get(file_metadata).put(update_file).delete(delete_file),
        )
        .route(
            "/api/v1/storage/files/{file_id}/download",
            get(download_file),
        )
        .layer(DefaultBodyLimit::max(max_upload_bytes));
    let json = Router::new()
        .route(
            "/api/v1/storage/files/{file_id}/shares/users",
            post(share_with_user),
        )
        .route(
            "/api/v1/storage/files/{file_id}/shares/users/{username}",
            axum::routing::delete(revoke_user_share),
        )
        .route(
            "/api/v1/storage/files/{file_id}/shares/self",
            axum::routing::delete(leave_user_share),
        )
        .route(
            "/api/v1/storage/files/{file_id}/shares/links",
            post(create_share_link),
        )
        .route(
            "/api/v1/storage/files/{file_id}/shares/links/{token}",
            axum::routing::delete(revoke_share_link),
        )
        .route(
            "/api/v1/storage/files/{file_id}/shares/links/{token}/accesses",
            get(list_share_accesses),
        )
        .route(
            "/api/v1/storage/share-links/accessed",
            get(accessed_share_links),
        )
        .route(
            "/api/v1/storage/share-links/{token}",
            get(download_share_link),
        )
        .route(
            "/api/v1/storage/share-links/{token}/metadata",
            get(share_link_metadata),
        )
        .route(
            "/api/v1/storage/folders",
            get(list_folders).post(create_folder),
        )
        .route(
            "/api/v1/storage/folders/{folder_id}",
            patch(update_folder).delete(delete_folder),
        )
        .route(
            "/api/v1/storage/files/{file_id}/folder",
            patch(move_file_to_folder),
        )
        .route("/api/v1/storage/files/folder", patch(bulk_move_files))
        .layer(DefaultBodyLimit::max(JSON_BODY_LIMIT));
    files.merge(json)
}

async fn upload_file(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Result<Json<crate::storage::StoredFileResponse>, StorageApiError> {
    let mut bundle = read_file_bundle(&service, context.user_id, multipart).await?;
    let response = blocking(move || service.create_file(context.user_id, &mut bundle)).await?;
    Ok(Json(response))
}

async fn update_file(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
    multipart: Multipart,
) -> Result<Json<crate::storage::StoredFileResponse>, StorageApiError> {
    let mut bundle = read_file_bundle(&service, context.user_id, multipart).await?;
    let response =
        blocking(move || service.update_file(context.user_id, file_id, &mut bundle)).await?;
    Ok(Json(response))
}

async fn list_files(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<crate::storage::StoredFileResponse>>, StorageApiError> {
    Ok(Json(
        blocking(move || service.list_files(context.user_id)).await?,
    ))
}

async fn file_metadata(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
) -> Result<Json<crate::storage::StoredFileResponse>, StorageApiError> {
    Ok(Json(
        blocking(move || service.get_file_response(context.user_id, file_id)).await?,
    ))
}

#[derive(Default, Deserialize)]
struct DownloadQuery {
    inline: Option<bool>,
}

async fn download_file(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
    Query(query): Query<DownloadQuery>,
) -> Result<Response, StorageApiError> {
    let stored = blocking(move || service.open_file(context.user_id, file_id)).await?;
    stream_stored_file(stored, query.inline.unwrap_or(false)).await
}

async fn stream_stored_file(
    stored: StoredFileObject,
    inline: bool,
) -> Result<Response, StorageApiError> {
    let file = tokio::fs::File::open(&stored.path).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(
            stored
                .content_type
                .as_deref()
                .unwrap_or("application/octet-stream"),
        )
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&stored.size_bytes.to_string())
            .map_err(|_| StorageApiError::Internal)?,
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

async fn delete_file(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
) -> Result<StatusCode, StorageApiError> {
    blocking(move || service.delete_file(context.user_id, file_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShareWithUserRequest {
    username: String,
    access_role: Option<String>,
}

async fn share_with_user(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
    Json(request): Json<ShareWithUserRequest>,
) -> Result<Json<StoredFileResponse>, StorageApiError> {
    let role = ShareRole::parse(request.access_role.as_deref())?;
    Ok(Json(
        blocking(move || {
            service.share_with_user(context.user_id, file_id, &request.username, role)
        })
        .await?,
    ))
}

async fn revoke_user_share(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path((file_id, username)): Path<(i64, String)>,
) -> Result<StatusCode, StorageApiError> {
    blocking(move || service.revoke_user_share(context.user_id, file_id, &username)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn leave_user_share(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
) -> Result<StatusCode, StorageApiError> {
    blocking(move || service.leave_user_share(context.user_id, file_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateShareLinkRequest {
    access_role: Option<String>,
}

async fn create_share_link(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
    Json(request): Json<CreateShareLinkRequest>,
) -> Result<Json<ShareLinkResponse>, StorageApiError> {
    let role = ShareRole::parse(request.access_role.as_deref())?;
    Ok(Json(
        blocking(move || service.create_share_link(context.user_id, file_id, role)).await?,
    ))
}

async fn revoke_share_link(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path((file_id, token)): Path<(i64, String)>,
) -> Result<StatusCode, StorageApiError> {
    blocking(move || service.revoke_share_link(context.user_id, file_id, &token)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn download_share_link(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(token): Path<String>,
    Query(query): Query<DownloadQuery>,
) -> Result<Response, StorageApiError> {
    let inline = query.inline.unwrap_or(false);
    let stored = blocking(move || service.open_share_link(context.user_id, &token, inline)).await?;
    stream_stored_file(stored, inline).await
}

async fn share_link_metadata(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(token): Path<String>,
) -> Result<Json<ShareLinkMetadataResponse>, StorageApiError> {
    Ok(Json(
        blocking(move || service.share_link_metadata(context.user_id, &token)).await?,
    ))
}

async fn accessed_share_links(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<ShareLinkMetadataResponse>>, StorageApiError> {
    Ok(Json(
        blocking(move || service.list_accessed_share_links(context.user_id)).await?,
    ))
}

async fn list_share_accesses(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path((file_id, token)): Path<(i64, String)>,
) -> Result<Json<Vec<ShareLinkAccessResponse>>, StorageApiError> {
    Ok(Json(
        blocking(move || service.list_share_accesses(context.user_id, file_id, &token)).await?,
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateFolderRequest {
    id: Option<String>,
    name: String,
    parent_folder_id: Option<String>,
    color: Option<String>,
    icon: Option<String>,
}

async fn list_folders(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
) -> Result<Json<Vec<FolderResponse>>, StorageApiError> {
    Ok(Json(
        blocking(move || service.list_folders(context.user_id)).await?,
    ))
}

async fn create_folder(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<CreateFolderRequest>,
) -> Result<Response, StorageApiError> {
    let response = blocking(move || {
        service.create_folder(
            context.user_id,
            request.id.as_deref(),
            &request.name,
            request.parent_folder_id.as_deref(),
            request.color.as_deref(),
            request.icon.as_deref(),
        )
    })
    .await?;
    let location = HeaderValue::from_str(&format!("/api/v1/storage/folders/{}", response.id))
        .map_err(|_| StorageApiError::Internal)?;
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(response),
    )
        .into_response())
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderRequest {
    name: Option<String>,
    reparent: Option<bool>,
    parent_folder_id: Option<String>,
    color: Option<String>,
    icon: Option<String>,
}

async fn update_folder(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(folder_id): Path<String>,
    Json(request): Json<UpdateFolderRequest>,
) -> Result<Json<FolderResponse>, StorageApiError> {
    Ok(Json(
        blocking(move || {
            service.update_folder(
                context.user_id,
                &folder_id,
                request.name.as_deref(),
                request.reparent.unwrap_or(false),
                request.parent_folder_id.as_deref(),
                request.color.as_deref(),
                request.icon.as_deref(),
            )
        })
        .await?,
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteFolderResponse {
    removed_folder_ids: Vec<String>,
}

async fn delete_folder(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(folder_id): Path<String>,
) -> Result<Json<DeleteFolderResponse>, StorageApiError> {
    Ok(Json(DeleteFolderResponse {
        removed_folder_ids: blocking(move || service.delete_folder(context.user_id, &folder_id))
            .await?,
    }))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderPlacementRequest {
    folder_id: Option<String>,
}

async fn move_file_to_folder(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Path(file_id): Path<i64>,
    Json(request): Json<FolderPlacementRequest>,
) -> Result<StatusCode, StorageApiError> {
    blocking(move || {
        service.move_file_to_folder(context.user_id, file_id, request.folder_id.as_deref())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkMoveRequest {
    folder_id: Option<String>,
    file_ids: Vec<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkMoveResponse {
    moved_file_ids: Vec<i64>,
    skipped_file_ids: Vec<i64>,
}

async fn bulk_move_files(
    Extension(service): Extension<Arc<StorageService>>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<BulkMoveRequest>,
) -> Result<Response, StorageApiError> {
    let (moved_file_ids, skipped_file_ids) = blocking(move || {
        service.bulk_move_files_to_folder(
            context.user_id,
            request.folder_id.as_deref(),
            &request.file_ids,
        )
    })
    .await?;
    let status = if skipped_file_ids.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::MULTI_STATUS
    };
    Ok((
        status,
        Json(BulkMoveResponse {
            moved_file_ids,
            skipped_file_ids,
        }),
    )
        .into_response())
}

async fn read_file_bundle(
    service: &Arc<StorageService>,
    owner_id: i64,
    mut multipart: Multipart,
) -> Result<PendingFileBundle, StorageApiError> {
    let mut bundle = PendingFileBundle::default();
    let mut total_bytes = 0_u64;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| StorageError::InvalidInput)?
    {
        let name = field.name().unwrap_or_default().to_owned();
        let target = match name.as_str() {
            "file" if bundle.file.is_none() => Some(FilePart::Main),
            "historyBundle" if bundle.history_bundle.is_none() => Some(FilePart::History),
            "auditLog" if bundle.audit_log.is_none() => Some(FilePart::Audit),
            "file" | "historyBundle" | "auditLog" => {
                return Err(StorageError::InvalidInput.into());
            }
            _ => None,
        };
        let Some(target) = target else {
            drain_field(&mut field, &mut total_bytes, service.max_upload_bytes()).await?;
            continue;
        };
        let filename = field.file_name().map(ToOwned::to_owned);
        let content_type = field.content_type().map(ToString::to_string);
        let object = stream_object(
            service,
            owner_id,
            filename.as_deref(),
            content_type.as_deref(),
            &mut field,
            &mut total_bytes,
        )
        .await?;
        if object.size_bytes == 0 {
            if target == FilePart::Main {
                return Err(StorageError::InvalidInput.into());
            }
            continue;
        }
        match target {
            FilePart::Main => bundle.file = Some(object),
            FilePart::History => bundle.history_bundle = Some(object),
            FilePart::Audit => bundle.audit_log = Some(object),
        }
    }
    if bundle.file.is_none() {
        return Err(StorageError::InvalidInput.into());
    }
    Ok(bundle)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FilePart {
    Main,
    History,
    Audit,
}

async fn stream_object(
    service: &StorageService,
    owner_id: i64,
    filename: Option<&str>,
    content_type: Option<&str>,
    field: &mut axum::extract::multipart::Field<'_>,
    total_bytes: &mut u64,
) -> Result<PendingObject, StorageApiError> {
    let (mut object, file) = service.prepare_object(owner_id, filename, content_type)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut object_bytes = 0_u64;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| StorageError::InvalidInput)?
    {
        add_chunk_size(total_bytes, chunk.len(), service.max_upload_bytes())?;
        object_bytes = object_bytes
            .checked_add(u64::try_from(chunk.len()).map_err(|_| StorageError::QuotaExceeded)?)
            .ok_or(StorageError::QuotaExceeded)?;
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

async fn drain_field(
    field: &mut axum::extract::multipart::Field<'_>,
    total_bytes: &mut u64,
    limit: u64,
) -> Result<(), StorageApiError> {
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|_| StorageError::InvalidInput)?
    {
        add_chunk_size(total_bytes, chunk.len(), limit)?;
    }
    Ok(())
}

fn add_chunk_size(total: &mut u64, chunk_size: usize, limit: u64) -> Result<(), StorageApiError> {
    *total = total
        .checked_add(u64::try_from(chunk_size).map_err(|_| StorageError::QuotaExceeded)?)
        .ok_or(StorageError::QuotaExceeded)?;
    if *total > limit {
        Err(StorageError::QuotaExceeded.into())
    } else {
        Ok(())
    }
}

async fn blocking<T, F>(function: F) -> Result<T, StorageApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StorageError> + Send + 'static,
{
    task::spawn_blocking(function)
        .await
        .map_err(|_| StorageApiError::Internal)?
        .map_err(StorageApiError::Storage)
}

fn content_disposition(inline: bool, filename: &str) -> Result<HeaderValue, StorageApiError> {
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
    .map_err(|_| StorageApiError::Internal)
}

#[derive(Debug)]
enum StorageApiError {
    Storage(StorageError),
    Internal,
}

impl From<StorageError> for StorageApiError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<std::io::Error> for StorageApiError {
    fn from(error: std::io::Error) -> Self {
        Self::Storage(StorageError::Filesystem(error))
    }
}

impl IntoResponse for StorageApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Storage(StorageError::Disabled) => (StatusCode::FORBIDDEN, "Storage is disabled"),
            Self::Storage(StorageError::SharingDisabled) => {
                (StatusCode::FORBIDDEN, "Storage sharing is disabled")
            }
            Self::Storage(StorageError::ShareLinksDisabled) => {
                (StatusCode::FORBIDDEN, "Storage share links are disabled")
            }
            Self::Storage(StorageError::InvalidInput) => {
                (StatusCode::BAD_REQUEST, "Invalid storage request")
            }
            Self::Storage(StorageError::FileNotFound) => (StatusCode::NOT_FOUND, "File not found"),
            Self::Storage(StorageError::UserNotFound) => (StatusCode::NOT_FOUND, "User not found"),
            Self::Storage(StorageError::FolderNotFound) => {
                (StatusCode::NOT_FOUND, "Folder not found")
            }
            Self::Storage(StorageError::ShareNotFound) => {
                (StatusCode::NOT_FOUND, "Share not found")
            }
            Self::Storage(StorageError::AccessDenied) => {
                (StatusCode::FORBIDDEN, "Storage access denied")
            }
            Self::Storage(StorageError::Conflict) => {
                (StatusCode::CONFLICT, "Storage state conflict")
            }
            Self::Storage(StorageError::QuotaExceeded) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "Storage quota exceeded")
            }
            Self::Storage(
                StorageError::EmailDeliveryUnavailable | StorageError::UnsupportedProvider,
            ) => (
                StatusCode::NOT_IMPLEMENTED,
                "Configured storage capability is unavailable",
            ),
            Self::Storage(
                StorageError::Poisoned | StorageError::Database(_) | StorageError::Filesystem(_),
            )
            | Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage operation failed",
            ),
        };
        (status, message).into_response()
    }
}
