//! Administrator-only commercial license lifecycle endpoints.
//!
//! These routes intentionally share the verified license state, live
//! configuration, and settings-file writer used by the secured runtime. A
//! configured key is never treated as an entitlement until verification
//! succeeds.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Multipart},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::NamedTempFile;
use tokio::task;
use zeroize::Zeroizing;

use crate::{
    admin_settings::AdminSettingsService,
    license::{
        LicenseConfig, LicenseConfigState, LicenseError, LicenseState, LicenseVerification,
        LicenseVerifier, generate_machine_fingerprint,
    },
    security::SecurityAuditContext,
};

const MAX_LICENSE_FILE_BYTES: usize = 1024 * 1024;
const MAX_MULTIPART_OVERHEAD_BYTES: usize = 64 * 1024;
const LICENSE_ADMIN_BODY_LIMIT: usize = MAX_LICENSE_FILE_BYTES + MAX_MULTIPART_OVERHEAD_BYTES;

type FingerprintProvider = dyn Fn() -> Result<String, String> + Send + Sync;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveLicenseKeyRequest {
    license_key: Option<String>,
}

struct UploadedLicenseFile {
    filename: String,
    bytes: Vec<u8>,
}

pub(crate) struct LicenseAdminService {
    verifier: LicenseVerifier,
    config: Arc<LicenseConfigState>,
    state: Arc<LicenseState>,
    settings: Arc<AdminSettingsService>,
    config_directory: PathBuf,
    mutation_lock: Mutex<()>,
    fingerprint: Arc<FingerprintProvider>,
}

enum LicenseAdminError {
    BadRequest(String),
    Activation(LicenseError),
    Settings,
    Io(std::io::Error),
    Unavailable,
}

impl LicenseAdminService {
    #[must_use]
    pub(crate) fn new(
        verifier: LicenseVerifier,
        config: Arc<LicenseConfigState>,
        state: Arc<LicenseState>,
        settings: Arc<AdminSettingsService>,
        config_directory: PathBuf,
    ) -> Self {
        Self {
            verifier,
            config,
            state,
            settings,
            config_directory,
            mutation_lock: Mutex::new(()),
            fingerprint: Arc::new(|| Ok(generate_machine_fingerprint())),
        }
    }

    fn installation_id(&self) -> Result<String, LicenseAdminError> {
        (self.fingerprint)().map_err(|_| LicenseAdminError::Unavailable)
    }

    fn save_key(&self, submitted: &str) -> Result<Value, LicenseAdminError> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| LicenseAdminError::Unavailable)?;
        let key = java_trim(submitted).to_owned();
        let prior = self.state.current();
        let config = LicenseConfig {
            enabled: true,
            key: Zeroizing::new(key.clone()),
            initial_max_users: prior.max_users,
        };

        // Java updates the live property and persists the key before it tries
        // verification. Preserve that observable failure ordering.
        self.config.replace(config.clone());
        self.persist_values(BTreeMap::from([(
            "premium.key".to_owned(),
            Value::String(key),
        )]))?;

        let verification = self
            .verifier
            .verify_config(&config, prior.max_users)
            .map_err(LicenseAdminError::Activation)?;
        self.state.replace(verification);
        self.config.replace(LicenseConfig {
            enabled: true,
            key: config.key,
            initial_max_users: verification.max_users,
        });

        let mut updates = BTreeMap::from([(
            "premium.enabled".to_owned(),
            Value::Bool(verification.running_pro_or_higher()),
        )]);
        if verification.running_pro_or_higher() {
            updates.insert(
                "premium.maxUsers".to_owned(),
                Value::from(verification.max_users),
            );
        }
        self.persist_values(updates)?;

        Ok(json!({
            "success": true,
            "licenseType": verification.tier_name(),
            // The Java controller leaves the live enabled property true even
            // when it writes false for an invalid key.
            "enabled": true,
            "maxUsers": verification.max_users,
            "requiresRestart": false,
            "message": "License key saved and activated",
        }))
    }

    fn resync(&self) -> Result<Value, LicenseAdminError> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| LicenseAdminError::Unavailable)?;
        let config = self.config.current();
        if java_trim(config.key.as_str()).is_empty() {
            return Err(LicenseAdminError::BadRequest(
                "No license key configured".to_owned(),
            ));
        }
        let prior = self.state.current();
        let verification = self
            .verifier
            .verify_config(&config, prior.max_users)
            .map_err(LicenseAdminError::Activation)?;
        self.state.replace(verification);
        self.config.replace(LicenseConfig {
            enabled: config.enabled,
            key: config.key,
            initial_max_users: verification.max_users,
        });
        Ok(json!({
            "success": true,
            "licenseType": verification.tier_name(),
            "enabled": config.enabled,
            "maxUsers": verification.max_users,
            "message": "License resynced successfully",
        }))
    }

    fn info(&self) -> Result<Value, LicenseAdminError> {
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| LicenseAdminError::Unavailable)?;
        let config = self.config.current();
        let verification = self.state.current();
        let has_key = !java_trim(config.key.as_str()).is_empty();
        let mut response = json!({
            "licenseType": verification.tier_name(),
            "enabled": config.enabled,
            "maxUsers": verification.max_users,
            "hasKey": has_key,
        });
        if has_key {
            response["licenseKey"] = Value::String(config.key.as_str().to_owned());
        }
        Ok(response)
    }

    fn upload(&self, upload: &UploadedLicenseFile) -> Result<Value, LicenseAdminError> {
        validate_upload(upload)?;
        let _guard = self
            .mutation_lock
            .lock()
            .map_err(|_| LicenseAdminError::Unavailable)?;
        self.write_uploaded_file(upload)?;
        let file_reference = format!("file:configs/{}", upload.filename);
        let prior = self.state.current();
        let config = LicenseConfig {
            enabled: true,
            key: Zeroizing::new(file_reference.clone()),
            initial_max_users: prior.max_users,
        };

        self.config.replace(config.clone());
        self.persist_values(BTreeMap::from([(
            "premium.key".to_owned(),
            Value::String(file_reference),
        )]))?;
        let verification = self
            .verifier
            .verify_config(&config, prior.max_users)
            .map_err(LicenseAdminError::Activation)?;
        self.state.replace(verification);
        self.config.replace(LicenseConfig {
            enabled: true,
            key: config.key,
            initial_max_users: verification.max_users,
        });

        let file_path = format!("configs/{}", upload.filename);
        Ok(upload_response(verification, &upload.filename, &file_path))
    }

    fn persist_values(&self, updates: BTreeMap<String, Value>) -> Result<(), LicenseAdminError> {
        self.settings
            .persist_immediate(updates)
            .map_err(|_| LicenseAdminError::Settings)
    }

    fn write_uploaded_file(&self, upload: &UploadedLicenseFile) -> Result<(), LicenseAdminError> {
        ensure_directory(&self.config_directory)?;
        let config_directory =
            std::path::absolute(&self.config_directory).map_err(LicenseAdminError::Io)?;
        let target = config_directory.join(&upload.filename);
        if !target.starts_with(&config_directory) {
            return Err(LicenseAdminError::BadRequest(
                "Invalid file path".to_owned(),
            ));
        }
        if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(LicenseAdminError::BadRequest(
                "Invalid file path".to_owned(),
            ));
        }
        if target.exists() {
            let backup_directory = config_directory.join("backup");
            ensure_directory(&backup_directory)?;
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let backup = backup_directory.join(format!("{}.bak.{timestamp}", upload.filename));
            fs::copy(&target, backup).map_err(LicenseAdminError::Io)?;
        }

        let mut temporary =
            NamedTempFile::new_in(&config_directory).map_err(LicenseAdminError::Io)?;
        temporary
            .write_all(&upload.bytes)
            .map_err(LicenseAdminError::Io)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(LicenseAdminError::Io)?;
        temporary
            .persist(&target)
            .map_err(|error| LicenseAdminError::Io(error.error))?;
        Ok(())
    }
}

pub(crate) fn routes(service: Arc<LicenseAdminService>) -> Router {
    Router::new()
        .route("/api/v1/admin/installation-id", get(installation_id))
        .route("/api/v1/admin/license-key", post(save_license_key))
        .route("/api/v1/admin/license/resync", post(resync_license))
        .route("/api/v1/admin/license-info", get(license_info))
        .route("/api/v1/admin/license-file", post(upload_license_file))
        .layer(DefaultBodyLimit::max(LICENSE_ADMIN_BODY_LIMIT))
        .layer(Extension(service))
}

async fn installation_id(Extension(service): Extension<Arc<LicenseAdminService>>) -> Response {
    match task::spawn_blocking(move || service.installation_id()).await {
        Ok(Ok(installation_id)) => {
            Json(json!({ "installationId": installation_id })).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to generate installation ID" })),
        )
            .into_response(),
    }
}

async fn save_license_key(
    Extension(service): Extension<Arc<LicenseAdminService>>,
    Json(request): Json<SaveLicenseKeyRequest>,
) -> Response {
    let Some(key) = request.license_key else {
        return license_error(StatusCode::BAD_REQUEST, "License key is required");
    };
    match task::spawn_blocking(move || service.save_key(&key)).await {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(error)) => activation_error(error, "Failed to activate license"),
        Err(_) => activation_error(LicenseAdminError::Unavailable, "Failed to activate license"),
    }
}

async fn resync_license(Extension(service): Extension<Arc<LicenseAdminService>>) -> Response {
    match task::spawn_blocking(move || service.resync()).await {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(LicenseAdminError::BadRequest(error))) => {
            license_error(StatusCode::BAD_REQUEST, &error)
        }
        Ok(Err(error)) => activation_error(error, "Failed to resync license"),
        Err(_) => activation_error(LicenseAdminError::Unavailable, "Failed to resync license"),
    }
}

async fn license_info(Extension(service): Extension<Arc<LicenseAdminService>>) -> Response {
    match task::spawn_blocking(move || service.info()).await {
        Ok(Ok(response)) => Json(response).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to retrieve license information" })),
        )
            .into_response(),
    }
}

async fn upload_license_file(
    Extension(service): Extension<Arc<LicenseAdminService>>,
    mut multipart: Multipart,
) -> Response {
    let upload = match read_upload(&mut multipart).await {
        Ok(upload) => upload,
        Err(error) => return license_error(StatusCode::BAD_REQUEST, &error),
    };
    match task::spawn_blocking(move || service.upload(&upload)).await {
        Ok(Ok(response)) => Json(response).into_response(),
        Ok(Err(LicenseAdminError::BadRequest(error))) => {
            license_error(StatusCode::BAD_REQUEST, &error)
        }
        Ok(Err(LicenseAdminError::Io(_) | LicenseAdminError::Settings)) => license_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to save license file",
        ),
        Ok(Err(error)) => activation_error(error, "Failed to activate license"),
        Err(_) => activation_error(LicenseAdminError::Unavailable, "Failed to activate license"),
    }
}

async fn read_upload(multipart: &mut Multipart) -> Result<UploadedLicenseFile, String> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| "File is empty".to_owned())?
    {
        if field.name() != Some("file") {
            continue;
        }
        let filename = field.file_name().unwrap_or_default().to_owned();
        let content_type = field.content_type().map(ToOwned::to_owned);
        let bytes = field
            .bytes()
            .await
            .map_err(|_| "File is empty".to_owned())?;
        SecurityAuditContext::record_current_file_bytes(
            &filename,
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            content_type.as_deref(),
            &bytes,
        );
        return Ok(UploadedLicenseFile {
            filename,
            bytes: bytes.to_vec(),
        });
    }
    Err("File is empty".to_owned())
}

fn validate_upload(upload: &UploadedLicenseFile) -> Result<(), LicenseAdminError> {
    if upload.bytes.is_empty() {
        return Err(LicenseAdminError::BadRequest("File is empty".to_owned()));
    }
    if upload.filename.trim().is_empty() {
        return Err(LicenseAdminError::BadRequest("Invalid filename".to_owned()));
    }
    if upload.filename.contains("..")
        || upload.filename.contains('/')
        || upload.filename.contains('\\')
    {
        return Err(LicenseAdminError::BadRequest(
            "Filename must not contain path separators or '..'".to_owned(),
        ));
    }
    let valid_extension = Path::new(&upload.filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("lic") || extension.eq_ignore_ascii_case("cert")
        });
    if !valid_extension {
        return Err(LicenseAdminError::BadRequest(
            "Invalid file type. Expected .lic or .cert".to_owned(),
        ));
    }
    if upload.bytes.len() > MAX_LICENSE_FILE_BYTES {
        return Err(LicenseAdminError::BadRequest(
            "File too large. Maximum 1MB allowed".to_owned(),
        ));
    }
    if !java_trim(&String::from_utf8_lossy(&upload.bytes))
        .starts_with("-----BEGIN LICENSE FILE-----")
    {
        return Err(LicenseAdminError::BadRequest(
            "Invalid license certificate format".to_owned(),
        ));
    }
    Ok(())
}

fn upload_response(verification: LicenseVerification, filename: &str, file_path: &str) -> Value {
    json!({
        "success": true,
        "licenseType": verification.tier_name(),
        "filename": filename,
        "filePath": file_path,
        "enabled": true,
        "maxUsers": verification.max_users,
        "message": "License file uploaded and activated",
    })
}

fn ensure_directory(path: &Path) -> Result<(), LicenseAdminError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(
            LicenseAdminError::BadRequest("Invalid file path".to_owned()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(LicenseAdminError::Io)?;
            let metadata = fs::symlink_metadata(path).map_err(LicenseAdminError::Io)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                Err(LicenseAdminError::BadRequest(
                    "Invalid file path".to_owned(),
                ))
            } else {
                Ok(())
            }
        }
        Err(error) => Err(LicenseAdminError::Io(error)),
    }
}

fn activation_error(error: LicenseAdminError, prefix: &str) -> Response {
    let (status, detail) = match error {
        LicenseAdminError::BadRequest(detail) => (StatusCode::BAD_REQUEST, detail),
        LicenseAdminError::Activation(error) => {
            let status = if prefix.contains("resync") {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, error.to_string())
        }
        LicenseAdminError::Settings => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "settings could not be saved".to_owned(),
        ),
        LicenseAdminError::Io(error) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
        LicenseAdminError::Unavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "license service is unavailable".to_owned(),
        ),
    };
    license_error(status, &format!("{prefix}: {detail}"))
}

fn license_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "success": false, "error": error }))).into_response()
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| u32::from(character) <= 0x20)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_validation_matches_java_bounds_and_filename_rules() {
        let valid = UploadedLicenseFile {
            filename: "offline.LIC".to_owned(),
            bytes: b" \n-----BEGIN LICENSE FILE-----\ninvalid\n".to_vec(),
        };
        assert!(validate_upload(&valid).is_ok());

        for filename in ["../offline.lic", "folder/offline.lic", "offline.txt"] {
            let upload = UploadedLicenseFile {
                filename: filename.to_owned(),
                bytes: valid.bytes.clone(),
            };
            assert!(matches!(
                validate_upload(&upload),
                Err(LicenseAdminError::BadRequest(_))
            ));
        }
        let too_large = UploadedLicenseFile {
            filename: "offline.cert".to_owned(),
            bytes: vec![b'x'; MAX_LICENSE_FILE_BYTES + 1],
        };
        assert!(matches!(
            validate_upload(&too_large),
            Err(LicenseAdminError::BadRequest(_))
        ));
    }
}
