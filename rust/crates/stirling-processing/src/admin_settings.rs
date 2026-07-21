//! Administrator-only settings inspection and restart-pending mutation.
//!
//! The live runtime remains immutable: successful writes update the YAML file
//! and a process-local delta, then take effect after restart. Secret-like values
//! are masked on every read and are never emitted by this module.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path as AxumPath, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use thiserror::Error;

const ADMIN_SETTINGS_BODY_LIMIT: usize = 256 * 1024;
const SETTINGS_FILE_LIMIT: u64 = 2 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 256;
const MAX_KEY_PARTS: usize = 10;
const MAX_VALUE_DEPTH: usize = 10;
const MAX_COLLECTION_ITEMS: usize = 2_048;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MASK: &str = "********";

const VALID_SECTIONS: &[&str] = &[
    "security",
    "system",
    "ui",
    "endpoints",
    "metrics",
    "mail",
    "storage",
    "premium",
    "processexecutor",
    "autopipeline",
    "legal",
    "telegram",
    "aiengine",
    "mcp",
];

const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "password",
    "dbpassword",
    "mailpassword",
    "smtppassword",
    "clientsecret",
    "apisecret",
    "secret",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "token",
    "key",
    "enterprisekey",
    "licensekey",
];

#[derive(Debug)]
pub(crate) struct AdminSettingsService {
    settings_path: PathBuf,
    loaded_settings: Value,
    pending: Mutex<BTreeMap<String, Value>>,
    write_lock: Mutex<()>,
}

#[derive(Debug, Error)]
pub(crate) enum AdminSettingsError {
    #[error("invalid setting key or value")]
    Invalid,
    #[error("the requested setting was not found")]
    Missing,
    #[error("settings state is unavailable")]
    Poisoned,
    #[error("failed to save settings to configuration file")]
    Io(#[from] std::io::Error),
    #[error("failed to parse or serialize settings")]
    Serialization,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IncludePendingQuery {
    #[serde(default)]
    include_pending: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    settings: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingValueRequest {
    value: Value,
}

impl AdminSettingsService {
    #[must_use]
    pub(crate) fn new(settings_path: PathBuf, loaded_settings: Value) -> Self {
        Self {
            settings_path,
            loaded_settings,
            pending: Mutex::new(BTreeMap::new()),
            write_lock: Mutex::new(()),
        }
    }

    fn all_settings(&self, include_pending: bool) -> Result<Value, AdminSettingsError> {
        let mut settings = self.loaded_settings.clone();
        if include_pending {
            for (key, value) in self.pending()?.iter() {
                set_dot_value(&mut settings, key, value.clone())?;
            }
        }
        Ok(mask_sensitive_value(&settings, ""))
    }

    fn delta(&self) -> Result<Value, AdminSettingsError> {
        let pending = self.pending()?;
        let masked = pending
            .iter()
            .map(|(key, value)| {
                let masked = if is_sensitive_path(key) {
                    mask_scalar(value)
                } else {
                    mask_sensitive_value(value, key)
                };
                (key.clone(), masked)
            })
            .collect::<Map<_, _>>();
        Ok(json!({
            "pendingChanges": masked,
            "hasPendingChanges": !pending.is_empty(),
            "count": pending.len(),
        }))
    }

    fn section(&self, section: &str, include_pending: bool) -> Result<Value, AdminSettingsError> {
        let canonical = canonical_section(section).ok_or(AdminSettingsError::Invalid)?;
        let section_value = self
            .loaded_settings
            .as_object()
            .and_then(|settings| get_case_insensitive(settings, canonical))
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        let mut section_map = section_value
            .as_object()
            .cloned()
            .ok_or(AdminSettingsError::Invalid)?;
        if include_pending {
            let prefix = format!("{canonical}.");
            let mut section_pending = Value::Object(Map::new());
            for (key, value) in self.pending()?.iter() {
                if let Some(path) = strip_prefix_case_insensitive(key, &prefix) {
                    set_dot_value(&mut section_pending, path, value.clone())?;
                }
            }
            if section_pending
                .as_object()
                .is_some_and(|map| !map.is_empty())
            {
                section_map.insert("_pending".to_owned(), section_pending);
            }
        }
        Ok(mask_sensitive_value(&Value::Object(section_map), canonical))
    }

    fn setting(&self, key: &str) -> Result<Value, AdminSettingsError> {
        let key = normalize_setting_key(key)?;
        let value =
            get_dot_value(&self.loaded_settings, &key).ok_or(AdminSettingsError::Missing)?;
        Ok(if is_sensitive_path(&key) {
            mask_scalar(value)
        } else {
            mask_sensitive_value(value, &key)
        })
    }

    fn update_many(&self, updates: BTreeMap<String, Value>) -> Result<usize, AdminSettingsError> {
        if updates.is_empty() {
            return Err(AdminSettingsError::Invalid);
        }
        let normalized = updates
            .into_iter()
            .map(|(key, value)| {
                let key = normalize_setting_key(&key)?;
                validate_update(&key, &value)?;
                Ok((key, value))
            })
            .collect::<Result<BTreeMap<_, _>, AdminSettingsError>>()?;
        self.persist_updates(&normalized)?;
        let count = normalized.len();
        self.pending()?.extend(normalized);
        Ok(count)
    }

    /// Persists live runtime-owned settings through the same serialized writer
    /// as restart-pending administrator edits, without adding them to the
    /// pending-restart delta. License activation uses this path because Java
    /// applies those values immediately.
    pub(crate) fn persist_immediate(
        &self,
        updates: BTreeMap<String, Value>,
    ) -> Result<(), AdminSettingsError> {
        if updates.is_empty() {
            return Err(AdminSettingsError::Invalid);
        }
        let normalized = updates
            .into_iter()
            .map(|(key, value)| {
                let key = normalize_setting_key(&key)?;
                validate_update(&key, &value)?;
                Ok((key, value))
            })
            .collect::<Result<BTreeMap<_, _>, AdminSettingsError>>()?;
        self.persist_updates(&normalized)
    }

    fn update_section(
        &self,
        section: &str,
        mut values: Map<String, Value>,
    ) -> Result<usize, AdminSettingsError> {
        let section = canonical_section(section).ok_or(AdminSettingsError::Invalid)?;
        if values.is_empty() {
            return Err(AdminSettingsError::Invalid);
        }
        if section == "premium"
            && values
                .get("key")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        {
            values.insert("enabled".to_owned(), Value::Bool(true));
        }
        let updates = values
            .into_iter()
            .map(|(key, value)| (format!("{section}.{key}"), value))
            .collect();
        self.update_many(updates)
    }

    fn persist_updates(&self, updates: &BTreeMap<String, Value>) -> Result<(), AdminSettingsError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| AdminSettingsError::Poisoned)?;
        let mut settings = read_settings(&self.settings_path)?;
        for (key, value) in updates {
            set_dot_value(&mut settings, key, value.clone())?;
        }
        write_settings(&self.settings_path, &settings)
    }

    fn pending(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, Value>>, AdminSettingsError> {
        self.pending
            .lock()
            .map_err(|_| AdminSettingsError::Poisoned)
    }
}

pub(crate) fn routes() -> Router {
    Router::new()
        .route(
            "/api/v1/admin/settings",
            get(get_settings).put(update_settings),
        )
        .route("/api/v1/admin/settings/delta", get(get_delta))
        .route(
            "/api/v1/admin/settings/section/{section}",
            get(get_section).put(update_section),
        )
        .route(
            "/api/v1/admin/settings/key/{key}",
            get(get_setting).put(update_setting),
        )
        .route("/api/v1/admin/settings/restart", post(restart))
        .layer(DefaultBodyLimit::max(ADMIN_SETTINGS_BODY_LIMIT))
}

async fn get_settings(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
    Query(query): Query<IncludePendingQuery>,
) -> Response {
    settings_result(service.all_settings(query.include_pending))
}

async fn get_delta(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
) -> Response {
    settings_result(service.delta())
}

async fn update_settings(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
    Json(request): Json<UpdateSettingsRequest>,
) -> Response {
    match service.update_many(request.settings) {
        Ok(count) => Json(json!({
            "message": format!(
                "Successfully updated {count} setting(s). Changes will take effect on application restart."
            )
        }))
        .into_response(),
        Err(error) => settings_error_response(&error),
    }
}

async fn get_section(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
    AxumPath(section): AxumPath<String>,
    Query(query): Query<IncludePendingQuery>,
) -> Response {
    settings_result(service.section(&section, query.include_pending))
}

async fn update_section(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
    AxumPath(section): AxumPath<String>,
    Json(values): Json<Map<String, Value>>,
) -> Response {
    match service.update_section(&section, values) {
        Ok(count) => Json(json!({
            "message": format!(
                "Successfully updated {count} setting(s) in section '{section}'. Changes will take effect on application restart."
            )
        }))
        .into_response(),
        Err(error) => settings_error_response(&error),
    }
}

async fn get_setting(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
    AxumPath(key): AxumPath<String>,
) -> Response {
    match service.setting(&key) {
        Ok(value) => Json(json!({ "key": key, "value": value })).into_response(),
        Err(error) => settings_error_response(&error),
    }
}

async fn update_setting(
    Extension(service): Extension<std::sync::Arc<AdminSettingsService>>,
    AxumPath(key): AxumPath<String>,
    Json(request): Json<UpdateSettingValueRequest>,
) -> Response {
    match service.update_many(BTreeMap::from([(key.clone(), request.value)])) {
        Ok(_) => format!(
            "Successfully updated setting '{key}'. Changes will take effect on application restart."
        )
        .into_response(),
        Err(error) => settings_error_response(&error),
    }
}

async fn restart() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": "In-process restart is unavailable. Restart the Rust service through its supervisor."
        })),
    )
        .into_response()
}

fn settings_result(result: Result<Value, AdminSettingsError>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => settings_error_response(&error),
    }
}

fn settings_error_response(error: &AdminSettingsError) -> Response {
    let status = match error {
        AdminSettingsError::Invalid | AdminSettingsError::Missing => StatusCode::BAD_REQUEST,
        AdminSettingsError::Poisoned
        | AdminSettingsError::Io(_)
        | AdminSettingsError::Serialization => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": error.to_string() }))).into_response()
}

fn normalize_setting_key(key: &str) -> Result<String, AdminSettingsError> {
    let key = key.trim();
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
    {
        return Err(AdminSettingsError::Invalid);
    }
    let mut parts = key.split('.').collect::<Vec<_>>();
    if parts.len() < 2 || parts.len() > MAX_KEY_PARTS || parts.iter().any(|part| part.is_empty()) {
        return Err(AdminSettingsError::Invalid);
    }
    parts[0] = canonical_section(parts[0]).ok_or(AdminSettingsError::Invalid)?;
    Ok(parts.join("."))
}

fn canonical_section(section: &str) -> Option<&'static str> {
    let normalized = section.trim().to_ascii_lowercase();
    if !VALID_SECTIONS.contains(&normalized.as_str()) {
        return None;
    }
    Some(match normalized.as_str() {
        "processexecutor" => "processExecutor",
        "autopipeline" => "autoPipeline",
        "aiengine" => "aiEngine",
        section => VALID_SECTIONS
            .iter()
            .copied()
            .find(|candidate| *candidate == section)?,
    })
}

fn validate_update(key: &str, value: &Value) -> Result<(), AdminSettingsError> {
    validate_value(value, 0)?;
    if is_sensitive_path(key) && value.as_str() == Some(MASK) {
        return Err(AdminSettingsError::Invalid);
    }
    if key.eq_ignore_ascii_case("system.customPaths.pipeline.watchedFoldersDirs") {
        validate_pipeline_paths(value)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize) -> Result<(), AdminSettingsError> {
    if depth > MAX_VALUE_DEPTH {
        return Err(AdminSettingsError::Invalid);
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => Err(AdminSettingsError::Invalid),
        Value::Array(values) if values.len() > MAX_COLLECTION_ITEMS => {
            Err(AdminSettingsError::Invalid)
        }
        Value::Array(values) => values
            .iter()
            .try_for_each(|value| validate_value(value, depth + 1)),
        Value::Object(values) if values.len() > MAX_COLLECTION_ITEMS => {
            Err(AdminSettingsError::Invalid)
        }
        Value::Object(values) => values.iter().try_for_each(|(key, value)| {
            if key.is_empty() || key.len() > MAX_KEY_BYTES || key.chars().any(char::is_control) {
                return Err(AdminSettingsError::Invalid);
            }
            validate_value(value, depth + 1)
        }),
        _ => Ok(()),
    }
}

fn validate_pipeline_paths(value: &Value) -> Result<(), AdminSettingsError> {
    let values = value.as_array().ok_or(AdminSettingsError::Invalid)?;
    let mut paths = BTreeSet::new();
    for value in values {
        let path = value.as_str().ok_or(AdminSettingsError::Invalid)?.trim();
        if path.is_empty() {
            continue;
        }
        let path = std::path::absolute(path).map_err(|_| AdminSettingsError::Invalid)?;
        if !paths.insert(path) {
            return Err(AdminSettingsError::Invalid);
        }
    }
    for path in &paths {
        if paths
            .iter()
            .any(|other| path != other && (path.starts_with(other) || other.starts_with(path)))
        {
            return Err(AdminSettingsError::Invalid);
        }
    }
    Ok(())
}

fn read_settings(path: &Path) -> Result<Value, AdminSettingsError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > SETTINGS_FILE_LIMIT
            {
                return Err(AdminSettingsError::Invalid);
            }
            let contents = fs::read_to_string(path)?;
            if contents.trim().is_empty() {
                Ok(Value::Object(Map::new()))
            } else {
                serde_yaml::from_str(&contents).map_err(|_| AdminSettingsError::Serialization)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Value::Object(Map::new())),
        Err(error) => Err(AdminSettingsError::Io(error)),
    }
}

fn write_settings(path: &Path, settings: &Value) -> Result<(), AdminSettingsError> {
    let contents =
        serde_yaml::to_string(settings).map_err(|_| AdminSettingsError::Serialization)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > SETTINGS_FILE_LIMIT {
        return Err(AdminSettingsError::Invalid);
    }
    let parent = path.parent().ok_or(AdminSettingsError::Invalid)?;
    fs::create_dir_all(parent)?;
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(AdminSettingsError::Invalid);
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn get_dot_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(root, |current, part| {
        current
            .as_object()
            .and_then(|map| get_case_insensitive(map, part))
    })
}

fn get_case_insensitive<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).or_else(|| {
        map.iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    })
}

fn set_dot_value(root: &mut Value, path: &str, value: Value) -> Result<(), AdminSettingsError> {
    let parts = path.split('.').collect::<Vec<_>>();
    let Some((last, parents)) = parts.split_last() else {
        return Err(AdminSettingsError::Invalid);
    };
    let mut current = root;
    for part in parents {
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        let map = current.as_object_mut().ok_or(AdminSettingsError::Invalid)?;
        current = map
            .entry((*part).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if !current.is_object() {
        *current = Value::Object(Map::new());
    }
    current
        .as_object_mut()
        .ok_or(AdminSettingsError::Invalid)?
        .insert((*last).to_owned(), value);
    Ok(())
}

fn is_sensitive_path(path: &str) -> bool {
    let field = path.rsplit('.').next().unwrap_or(path).to_ascii_lowercase();
    if field == "key" && path.eq_ignore_ascii_case("premium.key") {
        return false;
    }
    SENSITIVE_FIELD_NAMES.contains(&field.as_str())
        || field.contains("password")
        || field.contains("secret")
}

fn mask_sensitive_value(value: &Value, path: &str) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    let masked = if is_sensitive_path(&child_path) {
                        mask_scalar(value)
                    } else {
                        mask_sensitive_value(value, &child_path)
                    };
                    (key.clone(), masked)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| mask_sensitive_value(value, path))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn mask_scalar(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        Value::String(value) if value.trim().is_empty() => Value::String(value.clone()),
        _ => Value::String(MASK.to_owned()),
    }
}

fn strip_prefix_case_insensitive<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .and_then(|_| value.get(prefix.len()..))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use serde_json::json;
    use tempfile::tempdir;

    use super::{AdminSettingsError, AdminSettingsService, MASK};

    #[test]
    fn writes_nested_deltas_and_masks_secrets_without_changing_live_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("settings.yml");
        fs::write(
            &path,
            "security:\n  oauth2:\n    clientSecret: old-secret\nui:\n  appName: Old\n",
        )?;
        let loaded = serde_yaml::from_str(&fs::read_to_string(&path)?)?;
        let service = AdminSettingsService::new(path.clone(), loaded);
        service.update_many(BTreeMap::from([
            ("ui.appName".to_owned(), json!("New")),
            (
                "security.oauth2.clientSecret".to_owned(),
                json!("new-secret"),
            ),
        ]))?;

        assert_eq!(service.setting("ui.appName")?, json!("Old"));
        assert_eq!(
            service.setting("security.oauth2.clientSecret")?,
            json!(MASK)
        );
        let merged = service.all_settings(true)?;
        assert_eq!(merged["ui"]["appName"], "New");
        assert_eq!(merged["security"]["oauth2"]["clientSecret"], MASK);
        let persisted: serde_json::Value = serde_yaml::from_str(&fs::read_to_string(path)?)?;
        assert_eq!(persisted["ui"]["appName"], "New");
        assert_eq!(
            persisted["security"]["oauth2"]["clientSecret"],
            "new-secret"
        );
        Ok(())
    }

    #[test]
    fn rejects_unsafe_keys_mask_placeholders_and_overlapping_pipeline_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let path = directory.path().join("settings.yml");
        fs::write(&path, "{}\n")?;
        let service = AdminSettingsService::new(path, json!({}));
        for (key, value) in [
            ("../security.password", json!("value")),
            ("unknown.value", json!("value")),
            ("security.password", json!(MASK)),
        ] {
            assert!(matches!(
                service.update_many(BTreeMap::from([(key.to_owned(), value)])),
                Err(AdminSettingsError::Invalid)
            ));
        }
        let root = directory.path().join("root");
        assert!(matches!(
            service.update_many(BTreeMap::from([(
                "system.customPaths.pipeline.watchedFoldersDirs".to_owned(),
                json!([root, root.join("child")]),
            )])),
            Err(AdminSettingsError::Invalid)
        ));
        Ok(())
    }
}
