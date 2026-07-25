//! Authenticated personal and administrator-managed shared signature storage.
//!
//! Java stores these assets below `customFiles/signatures`, with one directory
//! per username and `ALL_USERS` for shared assets. This module preserves that
//! on-disk and HTTP contract while rejecting links and unsafe path components.

use std::{
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path as AxumPath},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use tracing::{error, warn};

use crate::security::AuthContext;

const SIGNATURES_PATH: &str = "/api/v1/proprietary/signatures";
const SIGNATURE_LABEL_PATH: &str = "/api/v1/proprietary/signatures/{signature_id}/label";
const SIGNATURE_DELETE_PATH: &str = "/api/v1/proprietary/signatures/{signature_id}";
const ALL_USERS_DIRECTORY: &str = "ALL_USERS";
const MAX_SIGNATURES_PER_USER: usize = 20;
const MAX_SIGNATURE_SIZE_BYTES: usize = 2_000_000;
const MAX_TOTAL_USER_STORAGE_BYTES: u64 = 20_000_000;
const MAX_DATA_URL_CHARS: usize = MAX_SIGNATURE_SIZE_BYTES * 2;
const MAX_SIGNATURE_REQUEST_BYTES: usize = MAX_DATA_URL_CHARS + 64 * 1024;
const MAX_METADATA_BYTES: u64 = MAX_SIGNATURE_REQUEST_BYTES as u64;

#[derive(Clone)]
pub(crate) struct PersonalSignatureService {
    root: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SavedSignatureRequest {
    id: String,
    label: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    scope: Option<String>,
    data_url: Option<String>,
    signer_name: Option<String>,
    font_family: Option<String>,
    font_size: Option<i32>,
    text_color: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SavedSignatureResponse {
    id: String,
    label: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    scope: String,
    data_url: Option<String>,
    signer_name: Option<String>,
    font_family: Option<String>,
    font_size: Option<i32>,
    text_color: Option<String>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Deserialize)]
struct LabelRequest {
    label: Option<String>,
}

#[derive(Debug, Error)]
pub(crate) enum SignatureError {
    #[error("signature request is invalid")]
    Invalid,
    #[error("signature was not found")]
    NotFound,
    #[error("signature storage failed: {0}")]
    Storage(#[source] io::Error),
}

pub(crate) fn routes() -> Router {
    Router::new()
        .route(SIGNATURES_PATH, get(list_signatures).post(save_signature))
        .route(SIGNATURE_LABEL_PATH, post(update_signature_label))
        .route(SIGNATURE_DELETE_PATH, delete(delete_signature))
        .layer(DefaultBodyLimit::max(MAX_SIGNATURE_REQUEST_BYTES))
}

impl PersonalSignatureService {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(crate) fn personal_directory(
        &self,
        context: &AuthContext,
    ) -> Result<PathBuf, SignatureError> {
        safe_child_directory(&self.root, &context.username)
    }

    pub(crate) fn shared_directory(&self) -> PathBuf {
        self.root.join(ALL_USERS_DIRECTORY)
    }

    fn save(
        &self,
        context: &AuthContext,
        request: SavedSignatureRequest,
    ) -> Result<SavedSignatureResponse, SignatureError> {
        validate_identifier(&request.id)?;
        let scope = normalized_scope(request.scope.as_deref())?;
        let data_url = request
            .data_url
            .as_deref()
            .filter(|value| !value.is_empty());
        let data_url = data_url.ok_or(SignatureError::Invalid)?;
        let (image_bytes, extension) = decode_image_data_url(data_url)?;
        let target_directory = if scope == "shared" {
            self.shared_directory()
        } else {
            let directory = self.personal_directory(context)?;
            enforce_personal_limits(&directory, data_url)?;
            directory
        };
        ensure_directory(&self.root, &target_directory)?;

        let timestamp = current_epoch_millis()?;
        let image_filename = format!("{}.{}", request.id, extension);
        let response = SavedSignatureResponse {
            id: request.id.clone(),
            label: request.label,
            kind: request.kind.clone(),
            scope: scope.to_owned(),
            data_url: Some(format!("/api/v1/general/signatures/{image_filename}")),
            signer_name: (request.kind.as_deref() == Some("text"))
                .then_some(request.signer_name)
                .flatten(),
            font_family: (request.kind.as_deref() == Some("text"))
                .then_some(request.font_family)
                .flatten(),
            font_size: (request.kind.as_deref() == Some("text"))
                .then_some(request.font_size)
                .flatten(),
            text_color: (request.kind.as_deref() == Some("text"))
                .then_some(request.text_color)
                .flatten(),
            created_at: timestamp,
            updated_at: timestamp,
        };
        let metadata = serde_json::to_vec(&response)
            .map_err(io::Error::other)
            .map_err(SignatureError::Storage)?;
        let image_path = target_directory.join(&image_filename);
        let metadata_path = target_directory.join(format!("{}.json", request.id));

        atomic_write(&target_directory, &image_path, &image_bytes)?;
        atomic_write(&target_directory, &metadata_path, &metadata)?;
        Ok(response)
    }

    fn list(&self, context: &AuthContext) -> Result<Vec<SavedSignatureResponse>, SignatureError> {
        let personal = self.personal_directory(context)?;
        let mut signatures = load_signatures_from_directory(&personal, "personal")?;
        signatures.extend(load_signatures_from_directory(
            &self.shared_directory(),
            "shared",
        )?);
        Ok(signatures)
    }

    fn shared_signature_exists(&self, signature_id: &str) -> Result<bool, SignatureError> {
        validate_identifier(signature_id)?;
        ordinary_file_exists(&self.shared_directory().join(format!("{signature_id}.json")))
    }

    fn update_label(
        &self,
        context: &AuthContext,
        signature_id: &str,
        label: String,
    ) -> Result<(), SignatureError> {
        validate_identifier(signature_id)?;
        let personal_path = self
            .personal_directory(context)?
            .join(format!("{signature_id}.json"));
        if ordinary_file_exists(&personal_path)? {
            return update_metadata_label(&personal_path, label);
        }
        let shared_path = self.shared_directory().join(format!("{signature_id}.json"));
        if ordinary_file_exists(&shared_path)? {
            return update_metadata_label(&shared_path, label);
        }
        Err(SignatureError::NotFound)
    }

    fn delete_personal(
        &self,
        context: &AuthContext,
        signature_id: &str,
    ) -> Result<bool, SignatureError> {
        validate_identifier(signature_id)?;
        delete_matching_files(&self.personal_directory(context)?, signature_id)
    }

    fn delete_shared(&self, signature_id: &str) -> Result<bool, SignatureError> {
        validate_identifier(signature_id)?;
        delete_matching_files(&self.shared_directory(), signature_id)
    }
}

async fn save_signature(
    Extension(service): Extension<Arc<PersonalSignatureService>>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<SavedSignatureRequest>,
) -> Response {
    if request.scope.as_deref() == Some("shared") && !context.has_role("ROLE_ADMIN") {
        return StatusCode::FORBIDDEN.into_response();
    }
    signature_result(service.save(&context, request), |signature| {
        Json(signature).into_response()
    })
}

async fn list_signatures(
    Extension(service): Extension<Arc<PersonalSignatureService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    signature_result(service.list(&context), |signatures| {
        Json(signatures).into_response()
    })
}

async fn update_signature_label(
    Extension(service): Extension<Arc<PersonalSignatureService>>,
    Extension(context): Extension<AuthContext>,
    AxumPath(signature_id): AxumPath<String>,
    Json(request): Json<LabelRequest>,
) -> Response {
    let Some(label) = request.label.filter(|label| !label.trim().is_empty()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match service.shared_signature_exists(&signature_id) {
        Ok(true) if !context.has_role("ROLE_ADMIN") => StatusCode::FORBIDDEN.into_response(),
        Ok(_) => signature_result(service.update_label(&context, &signature_id, label), |()| {
            StatusCode::NO_CONTENT.into_response()
        }),
        Err(error) => signature_error_response(error),
    }
}

async fn delete_signature(
    Extension(service): Extension<Arc<PersonalSignatureService>>,
    Extension(context): Extension<AuthContext>,
    AxumPath(signature_id): AxumPath<String>,
) -> Response {
    match service.delete_personal(&context, &signature_id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) if context.has_role("ROLE_ADMIN") => {
            signature_result(service.delete_shared(&signature_id), |deleted| {
                if deleted {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::NOT_FOUND
                }
                .into_response()
            })
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => signature_error_response(error),
    }
}

fn signature_result<T>(
    result: Result<T, SignatureError>,
    success: impl FnOnce(T) -> Response,
) -> Response {
    match result {
        Ok(value) => success(value),
        Err(error) => signature_error_response(error),
    }
}

fn signature_error_response(error: SignatureError) -> Response {
    match error {
        SignatureError::Invalid => StatusCode::BAD_REQUEST.into_response(),
        SignatureError::NotFound => StatusCode::NOT_FOUND.into_response(),
        SignatureError::Storage(error) => {
            error!(%error, "saved signature storage failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn normalized_scope(scope: Option<&str>) -> Result<&'static str, SignatureError> {
    match scope.unwrap_or("personal") {
        "" | "personal" => Ok("personal"),
        "shared" => Ok("shared"),
        _ => Err(SignatureError::Invalid),
    }
}

fn decode_image_data_url(data_url: &str) -> Result<(Vec<u8>, &'static str), SignatureError> {
    if data_url.len() > MAX_DATA_URL_CHARS {
        return Err(SignatureError::Invalid);
    }
    let (header, encoded) = data_url.split_once(',').ok_or(SignatureError::Invalid)?;
    let media_type = header
        .strip_prefix("data:")
        .and_then(|value| value.split(';').next())
        .ok_or(SignatureError::Invalid)?;
    let extension = match media_type.to_ascii_lowercase().as_str() {
        "image/png" => "png",
        "image/jpg" => "jpg",
        "image/jpeg" => "jpeg",
        _ => return Err(SignatureError::Invalid),
    };
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| SignatureError::Invalid)?;
    if bytes.len() > MAX_SIGNATURE_SIZE_BYTES {
        return Err(SignatureError::Invalid);
    }
    Ok((bytes, extension))
}

fn enforce_personal_limits(directory: &Path, data_url: &str) -> Result<(), SignatureError> {
    let Some(entries) = directory_entries(directory)? else {
        return Ok(());
    };
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    for entry in entries {
        let entry = entry.map_err(SignatureError::Storage)?;
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => continue,
            Err(error) => return Err(SignatureError::Storage(error)),
        };
        if is_image_path(&path) {
            count = count.saturating_add(1);
            total_bytes = total_bytes.saturating_add(metadata.len());
        }
    }
    let estimated_new_bytes = u64::try_from(data_url.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(3)
        / 4;
    if count >= MAX_SIGNATURES_PER_USER
        || total_bytes.saturating_add(estimated_new_bytes) > MAX_TOTAL_USER_STORAGE_BYTES
    {
        return Err(SignatureError::Invalid);
    }
    Ok(())
}

fn load_signatures_from_directory(
    directory: &Path,
    scope: &str,
) -> Result<Vec<SavedSignatureResponse>, SignatureError> {
    let Some(entries) = directory_entries(directory)? else {
        return Ok(Vec::new());
    };
    let mut signatures = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, "ignoring unreadable saved signature directory entry");
                continue;
            }
        };
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() || !is_image_path(&path) {
            continue;
        }
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(id) = path.file_stem().and_then(|name| name.to_str()) else {
            continue;
        };
        let metadata_path = directory.join(format!("{id}.json"));
        if let Some(saved) = read_saved_metadata(&metadata_path) {
            signatures.push(saved);
            continue;
        }
        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .unwrap_or_default();
        signatures.push(SavedSignatureResponse {
            id: id.to_owned(),
            label: Some(id.to_owned()),
            kind: Some("image".to_owned()),
            scope: scope.to_owned(),
            data_url: Some(format!("/api/v1/general/signatures/{filename}")),
            signer_name: None,
            font_family: None,
            font_size: None,
            text_color: None,
            created_at: modified_at,
            updated_at: modified_at,
        });
    }
    Ok(signatures)
}

fn read_saved_metadata(path: &Path) -> Option<SavedSignatureResponse> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_METADATA_BYTES
    {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(saved) => Some(saved),
        Err(error) => {
            warn!(path = %path.display(), %error, "ignoring invalid saved signature metadata");
            None
        }
    }
}

fn update_metadata_label(path: &Path, label: String) -> Result<(), SignatureError> {
    let mut metadata = read_saved_metadata(path).ok_or(SignatureError::NotFound)?;
    metadata.label = Some(label);
    metadata.updated_at = current_epoch_millis()?;
    let bytes = serde_json::to_vec(&metadata)
        .map_err(io::Error::other)
        .map_err(SignatureError::Storage)?;
    let directory = path.parent().ok_or(SignatureError::Invalid)?;
    atomic_write(directory, path, &bytes)
}

fn delete_matching_files(directory: &Path, signature_id: &str) -> Result<bool, SignatureError> {
    let Some(entries) = directory_entries(directory)? else {
        return Ok(false);
    };
    let prefix = format!("{signature_id}.");
    let mut deleted = false;
    for entry in entries {
        let entry = entry.map_err(SignatureError::Storage)?;
        let path = entry.path();
        let Some(filename) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !filename.starts_with(&prefix) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(SignatureError::Storage)?;
        if metadata.is_file() || metadata.file_type().is_symlink() {
            fs::remove_file(path).map_err(SignatureError::Storage)?;
            deleted = true;
        }
    }
    Ok(deleted)
}

fn safe_child_directory(root: &Path, child: &str) -> Result<PathBuf, SignatureError> {
    let mut components = Path::new(child).components();
    let is_direct_child =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if child.is_empty()
        || child.eq_ignore_ascii_case(ALL_USERS_DIRECTORY)
        || matches!(child, "." | "..")
        || child.contains('/')
        || child.contains('\\')
        || child.chars().any(char::is_control)
        || !is_direct_child
    {
        return Err(SignatureError::Invalid);
    }
    Ok(root.join(child))
}

fn validate_identifier(value: &str) -> Result<(), SignatureError> {
    if value.is_empty()
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(SignatureError::Invalid);
    }
    Ok(())
}

fn ensure_directory(root: &Path, directory: &Path) -> Result<(), SignatureError> {
    fs::create_dir_all(root).map_err(SignatureError::Storage)?;
    reject_link(root)?;
    fs::create_dir_all(directory).map_err(SignatureError::Storage)?;
    reject_link(directory)
}

fn reject_link(path: &Path) -> Result<(), SignatureError> {
    let metadata = fs::symlink_metadata(path).map_err(SignatureError::Storage)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SignatureError::Invalid);
    }
    Ok(())
}

fn directory_entries(directory: &Path) -> Result<Option<fs::ReadDir>, SignatureError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(SignatureError::Invalid)
        }
        Ok(_) => fs::read_dir(directory)
            .map(Some)
            .map_err(SignatureError::Storage),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SignatureError::Storage(error)),
    }
}

fn ordinary_file_exists(path: &Path) -> Result<bool, SignatureError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.is_file() && !metadata.file_type().is_symlink()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(SignatureError::Storage(error)),
    }
}

fn atomic_write(directory: &Path, destination: &Path, bytes: &[u8]) -> Result<(), SignatureError> {
    let mut temporary = NamedTempFile::new_in(directory).map_err(SignatureError::Storage)?;
    temporary
        .write_all(bytes)
        .map_err(SignatureError::Storage)?;
    temporary.flush().map_err(SignatureError::Storage)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(SignatureError::Storage)?;
    temporary
        .persist(destination)
        .map_err(|error| SignatureError::Storage(error.error))?;
    Ok(())
}

fn is_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("png")
                || extension.eq_ignore_ascii_case("jpg")
                || extension.eq_ignore_ascii_case("jpeg")
        })
}

fn current_epoch_millis() -> Result<i64, SignatureError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)
        .map_err(SignatureError::Storage)?;
    i64::try_from(duration.as_millis()).map_err(|_| SignatureError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SIGNATURES_PER_USER, PersonalSignatureService, SavedSignatureRequest,
        decode_image_data_url,
    };
    use crate::security::{AuthContext, AuthenticationSource};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::collections::BTreeSet;
    use tempfile::tempdir;

    #[test]
    fn saves_lists_updates_and_deletes_personal_signatures()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let service = PersonalSignatureService::new(directory.path().to_path_buf());
        let context = context("alice@example.test", ["ROLE_USER"]);
        let saved = service.save(&context, image_request("sig1", "personal"))?;
        assert_eq!(saved.id, "sig1");
        assert_eq!(service.list(&context)?.len(), 1);
        service.update_label(&context, "sig1", "Renamed".to_owned())?;
        assert_eq!(service.list(&context)?[0].label.as_deref(), Some("Renamed"));
        assert!(service.delete_personal(&context, "sig1")?);
        assert!(service.list(&context)?.is_empty());
        Ok(())
    }

    #[test]
    fn enforces_personal_count_limit() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let service = PersonalSignatureService::new(directory.path().to_path_buf());
        let context = context("alice@example.test", ["ROLE_USER"]);
        let personal = service.personal_directory(&context)?;
        std::fs::create_dir_all(&personal)?;
        for index in 0..MAX_SIGNATURES_PER_USER {
            std::fs::write(personal.join(format!("sig{index}.png")), [1])?;
        }
        assert!(
            service
                .save(&context, image_request("overflow", "personal"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn rejects_unsafe_ids_and_unsupported_images() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = STANDARD.encode(b"gif");
        assert!(decode_image_data_url(&format!("data:image/gif;base64,{encoded}")).is_err());
        let request = image_request("../escape", "personal");
        let directory = tempdir()?;
        let service = PersonalSignatureService::new(directory.path().to_path_buf());
        assert!(
            service
                .save(&context("alice", ["ROLE_USER"]), request)
                .is_err()
        );
        for username in ["", ".", "..", "nested/user", "nested\\user", "ALL_USERS"] {
            assert!(
                service
                    .personal_directory(&context(username, ["ROLE_USER"]))
                    .is_err()
            );
        }
        Ok(())
    }

    fn image_request(id: &str, scope: &str) -> SavedSignatureRequest {
        SavedSignatureRequest {
            id: id.to_owned(),
            label: Some("My Signature".to_owned()),
            kind: Some("image".to_owned()),
            scope: Some(scope.to_owned()),
            data_url: Some(format!(
                "data:image/png;base64,{}",
                STANDARD.encode(b"not-a-real-image-but-java-compatible")
            )),
            signer_name: None,
            font_family: None,
            font_size: None,
            text_color: None,
        }
    }

    fn context<const N: usize>(username: &str, roles: [&str; N]) -> AuthContext {
        AuthContext {
            user_id: 1,
            username: username.to_owned(),
            authentication_source: AuthenticationSource::AccessToken,
            authentication_type: "web".to_owned(),
            roles: roles
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
}
