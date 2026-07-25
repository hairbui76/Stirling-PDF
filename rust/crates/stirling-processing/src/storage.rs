//! Durable owner-scoped storage used by secured file and signing workflows.

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    path::{Component, Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use chrono::{DateTime, SecondsFormat, Utc};
use rand::RngExt as _;
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior, params};
use serde::Serialize;
use thiserror::Error;

const MAX_FILENAME_BYTES: usize = 1_024;
const MAX_CONTENT_TYPE_BYTES: usize = 255;
const MAX_STORAGE_KEY_BYTES: usize = 1_280;
const MAX_FOLDER_NAME_LENGTH: usize = 255;
const MAX_FOLDERS_PER_USER: i64 = 5_000;
const MAX_FOLDER_DEPTH: usize = 64;
const MAX_BULK_MOVE_FILES: usize = 1_000;

#[derive(Clone, Debug)]
pub(crate) struct StorageConfig {
    pub(crate) enabled: bool,
    pub(crate) provider: String,
    pub(crate) base_path: PathBuf,
    pub(crate) database_path: PathBuf,
    pub(crate) sharing: StorageSharingConfig,
    pub(crate) max_file_bytes: Option<u64>,
    pub(crate) max_user_bytes: Option<u64>,
    pub(crate) max_total_bytes: Option<u64>,
    pub(crate) max_upload_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct StorageSharingConfig {
    pub(crate) enabled: bool,
    pub(crate) link_enabled: bool,
    pub(crate) email_enabled: bool,
    pub(crate) link_expiration_days: u64,
}

/// Resolved storage feature flags surfaced to the frontend through
/// `/api/v1/config/app-config`. Mirrors Java's `ConfigController` gating so the
/// UI only advertises storage capabilities that are actually reachable.
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct StorageAppConfig {
    pub(crate) enabled: bool,
    pub(crate) sharing_enabled: bool,
    pub(crate) share_links_enabled: bool,
    pub(crate) share_email_enabled: bool,
    pub(crate) group_signing_enabled: bool,
}

impl StorageAppConfig {
    pub(crate) fn apply_to_app_config(&self, config: &mut serde_json::Value) {
        let Some(config) = config.as_object_mut() else {
            return;
        };
        config.insert("storageEnabled".to_owned(), self.enabled.into());
        config.insert(
            "storageSharingEnabled".to_owned(),
            self.sharing_enabled.into(),
        );
        config.insert(
            "storageShareLinksEnabled".to_owned(),
            self.share_links_enabled.into(),
        );
        config.insert(
            "storageShareEmailEnabled".to_owned(),
            self.share_email_enabled.into(),
        );
        config.insert(
            "storageGroupSigningEnabled".to_owned(),
            self.group_signing_enabled.into(),
        );
    }
}

pub(crate) struct StorageService {
    connection: Mutex<Connection>,
    config: StorageConfig,
    base_path: PathBuf,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("storage is disabled")]
    Disabled,
    #[error("storage sharing is disabled")]
    SharingDisabled,
    #[error("storage share links are disabled")]
    ShareLinksDisabled,
    #[error("the configured storage provider is not supported by this Rust runtime")]
    UnsupportedProvider,
    #[error("storage input is invalid")]
    InvalidInput,
    #[error("stored file was not found")]
    FileNotFound,
    #[error("storage user was not found")]
    UserNotFound,
    #[error("storage folder was not found")]
    FolderNotFound,
    #[error("storage share was not found")]
    ShareNotFound,
    #[error("storage access is denied")]
    AccessDenied,
    #[error("storage state conflicts with an existing record")]
    Conflict,
    #[error("stored content exceeds an configured limit")]
    QuotaExceeded,
    #[error("email delivery for storage shares is not available")]
    EmailDeliveryUnavailable,
    #[error("storage state is unavailable")]
    Poisoned,
    #[error("storage database operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("storage filesystem operation failed")]
    Filesystem(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShareRole {
    Editor,
    Commenter,
    Viewer,
}

impl ShareRole {
    pub(crate) fn parse(value: Option<&str>) -> Result<Self, StorageError> {
        match value.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::Editor),
            Some(value) if value.eq_ignore_ascii_case("EDITOR") => Ok(Self::Editor),
            Some(value) if value.eq_ignore_ascii_case("COMMENTER") => Ok(Self::Commenter),
            Some(value) if value.eq_ignore_ascii_case("VIEWER") => Ok(Self::Viewer),
            Some(_) => Err(StorageError::InvalidInput),
        }
    }

    fn database_value(self) -> &'static str {
        match self {
            Self::Editor => "EDITOR",
            Self::Commenter => "COMMENTER",
            Self::Viewer => "VIEWER",
        }
    }

    fn response_value(self) -> &'static str {
        match self {
            Self::Editor => "editor",
            Self::Commenter => "commenter",
            Self::Viewer => "viewer",
        }
    }

    fn from_database(value: &str) -> Self {
        if value.eq_ignore_ascii_case("EDITOR") {
            Self::Editor
        } else if value.eq_ignore_ascii_case("COMMENTER") {
            Self::Commenter
        } else {
            Self::Viewer
        }
    }
}

pub(crate) struct PendingObject {
    storage_key: String,
    pub(crate) original_filename: String,
    pub(crate) content_type: Option<String>,
    path: PathBuf,
    pub(crate) size_bytes: u64,
    committed: bool,
}

impl PendingObject {
    pub(crate) fn set_size(&mut self, size_bytes: u64) {
        self.size_bytes = size_bytes;
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingObject {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Default)]
pub(crate) struct PendingFileBundle {
    pub(crate) file: Option<PendingObject>,
    pub(crate) history_bundle: Option<PendingObject>,
    pub(crate) audit_log: Option<PendingObject>,
}

impl PendingFileBundle {
    fn uploaded_bytes(&self) -> u64 {
        self.file.as_ref().map_or(0, |file| file.size_bytes)
            + self
                .history_bundle
                .as_ref()
                .map_or(0, |file| file.size_bytes)
            + self.audit_log.as_ref().map_or(0, |file| file.size_bytes)
    }

    fn commit(&mut self) {
        if let Some(file) = self.file.as_mut() {
            file.commit();
        }
        if let Some(file) = self.history_bundle.as_mut() {
            file.commit();
        }
        if let Some(file) = self.audit_log.as_mut() {
            file.commit();
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct StoredFileObject {
    pub(crate) filename: String,
    pub(crate) content_type: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredFileResponse {
    pub(crate) id: i64,
    pub(crate) file_name: String,
    pub(crate) content_type: Option<String>,
    pub(crate) size_bytes: u64,
    pub(crate) owner: String,
    pub(crate) owned_by_current_user: bool,
    pub(crate) access_role: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) shared_with_users: Vec<String>,
    pub(crate) shared_users: Vec<SharedUserResponse>,
    pub(crate) share_links: Vec<ShareLinkResponse>,
    pub(crate) file_purpose: Option<String>,
    pub(crate) folder_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SharedUserResponse {
    pub(crate) username: String,
    pub(crate) access_role: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShareLinkResponse {
    pub(crate) token: String,
    pub(crate) access_role: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShareLinkMetadataResponse {
    pub(crate) share_token: String,
    pub(crate) file_id: i64,
    pub(crate) file_name: String,
    pub(crate) owner: String,
    pub(crate) owned_by_current_user: bool,
    pub(crate) access_role: String,
    pub(crate) created_at: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) last_accessed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShareLinkAccessResponse {
    pub(crate) username: String,
    pub(crate) access_type: String,
    pub(crate) accessed_at: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FolderResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) parent_folder_id: Option<String>,
    pub(crate) color: Option<String>,
    pub(crate) icon: Option<String>,
    pub(crate) version: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

#[derive(Clone, Debug)]
struct StoredFileRow {
    id: i64,
    owner_id: i64,
    owner_username: String,
    original_filename: String,
    content_type: Option<String>,
    size_bytes: u64,
    storage_key: String,
    history_filename: Option<String>,
    history_content_type: Option<String>,
    history_size_bytes: Option<u64>,
    history_storage_key: Option<String>,
    audit_filename: Option<String>,
    audit_content_type: Option<String>,
    audit_size_bytes: Option<u64>,
    audit_storage_key: Option<String>,
    purpose: Option<String>,
    folder_id: Option<String>,
    created_at: i64,
    updated_at: i64,
    access_role: ShareRole,
}

struct ShareRow {
    share_id: i64,
    file_id: i64,
    owner_id: i64,
    shared_with_user_id: Option<i64>,
    token: String,
    role: ShareRole,
    created_at: i64,
    expires_at: Option<i64>,
}

impl StoredFileRow {
    fn total_bytes(&self) -> u64 {
        self.size_bytes
            .saturating_add(self.history_size_bytes.unwrap_or(0))
            .saturating_add(self.audit_size_bytes.unwrap_or(0))
    }
}

impl StorageService {
    pub(crate) fn open(config: StorageConfig) -> Result<Self, StorageError> {
        let provider = config.provider.trim();
        if config.enabled && !provider.eq_ignore_ascii_case("local") {
            return Err(StorageError::UnsupportedProvider);
        }
        let base_path = if config.enabled {
            prepare_storage_directory(&config.base_path)?
        } else {
            config.base_path.clone()
        };
        let connection = Connection::open(&config.database_path)?;
        initialize_storage_connection(&connection)?;
        let service = Self {
            connection: Mutex::new(connection),
            config,
            base_path,
        };
        if service.config.enabled {
            service.drain_cleanup_queue()?;
        }
        Ok(service)
    }

    #[must_use]
    pub(crate) fn max_upload_bytes(&self) -> u64 {
        self.config.max_upload_bytes
    }

    pub(crate) fn prepare_object(
        &self,
        owner_id: i64,
        filename: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(PendingObject, fs::File), StorageError> {
        self.ensure_enabled()?;
        let filename = sanitize_filename(filename);
        let content_type = normalize_content_type(content_type)?;
        let owner_directory = self.base_path.join(owner_id.to_string());
        create_safe_directory(&owner_directory)?;
        let storage_key = format!("{owner_id}/{}_{}", random_uuid(), filename);
        if storage_key.len() > MAX_STORAGE_KEY_BYTES {
            return Err(StorageError::InvalidInput);
        }
        let path = checked_object_path(&self.base_path, &storage_key)?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        Ok((
            PendingObject {
                storage_key,
                original_filename: filename,
                content_type,
                path,
                size_bytes: 0,
                committed: false,
            },
            file,
        ))
    }

    pub(crate) fn create_file(
        &self,
        owner_id: i64,
        bundle: &mut PendingFileBundle,
    ) -> Result<StoredFileResponse, StorageError> {
        self.ensure_enabled()?;
        let new_bytes = bundle.uploaded_bytes();
        let mut connection = self.lock()?;
        let file = bundle.file.as_ref().ok_or(StorageError::InvalidInput)?;
        let file_size = sqlite_size(file.size_bytes)?;
        let history_size = bundle
            .history_bundle
            .as_ref()
            .map(|value| sqlite_size(value.size_bytes))
            .transpose()?;
        let audit_size = bundle
            .audit_log
            .as_ref()
            .map(|value| sqlite_size(value.size_bytes))
            .transpose()?;
        let now = Utc::now().timestamp();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.enforce_quotas(&transaction, owner_id, new_bytes, 0)?;
        transaction.execute(
            "INSERT INTO storage_files
             (owner_id, original_filename, content_type, size_bytes, storage_key,
              history_filename, history_content_type, history_size_bytes, history_storage_key,
              audit_filename, audit_content_type, audit_size_bytes, audit_storage_key,
              created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?14)",
            params![
                owner_id,
                file.original_filename,
                file.content_type,
                file_size,
                file.storage_key,
                bundle
                    .history_bundle
                    .as_ref()
                    .map(|value| value.original_filename.as_str()),
                bundle
                    .history_bundle
                    .as_ref()
                    .and_then(|value| value.content_type.as_deref()),
                history_size,
                bundle
                    .history_bundle
                    .as_ref()
                    .map(|value| value.storage_key.as_str()),
                bundle
                    .audit_log
                    .as_ref()
                    .map(|value| value.original_filename.as_str()),
                bundle
                    .audit_log
                    .as_ref()
                    .and_then(|value| value.content_type.as_deref()),
                audit_size,
                bundle
                    .audit_log
                    .as_ref()
                    .map(|value| value.storage_key.as_str()),
                now,
            ],
        )?;
        let file_id = transaction.last_insert_rowid();
        transaction.commit()?;
        bundle.commit();
        self.file_response_locked(&connection, file_id, owner_id)
    }

    pub(crate) fn update_file(
        &self,
        owner_id: i64,
        file_id: i64,
        bundle: &mut PendingFileBundle,
    ) -> Result<StoredFileResponse, StorageError> {
        self.ensure_enabled()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_owned_file(&transaction, file_id, owner_id)?;
        let file = bundle.file.as_ref().ok_or(StorageError::InvalidInput)?;
        let history_bytes = bundle
            .history_bundle
            .as_ref()
            .map_or(existing.history_size_bytes.unwrap_or(0), |value| {
                value.size_bytes
            });
        let audit_bytes = bundle
            .audit_log
            .as_ref()
            .map_or(existing.audit_size_bytes.unwrap_or(0), |value| {
                value.size_bytes
            });
        let new_bytes = file
            .size_bytes
            .saturating_add(history_bytes)
            .saturating_add(audit_bytes);
        self.enforce_quotas(&transaction, owner_id, new_bytes, existing.total_bytes())?;
        update_file_row(
            &transaction,
            &existing,
            file_id,
            bundle,
            Utc::now().timestamp(),
        )?;
        queue_replaced_objects(&transaction, &existing, bundle)?;
        transaction.commit()?;
        bundle.commit();
        let response = self.file_response_locked(&connection, file_id, owner_id)?;
        drop(connection);
        self.drain_cleanup_queue()?;
        Ok(response)
    }

    pub(crate) fn list_files(&self, user_id: i64) -> Result<Vec<StoredFileResponse>, StorageError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT DISTINCT f.file_id
             FROM storage_files f
             LEFT JOIN storage_shares s
               ON s.file_id = f.file_id AND s.shared_with_user_id = ?1
             WHERE f.owner_id = ?1 OR s.share_id IS NOT NULL
             ORDER BY f.created_at DESC, f.file_id DESC",
        )?;
        let ids = statement
            .query_map([user_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|file_id| self.file_response_locked(&connection, file_id, user_id))
            .collect()
    }

    pub(crate) fn get_file_response(
        &self,
        user_id: i64,
        file_id: i64,
    ) -> Result<StoredFileResponse, StorageError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        self.file_response_locked(&connection, file_id, user_id)
    }

    pub(crate) fn open_file(
        &self,
        user_id: i64,
        file_id: i64,
    ) -> Result<StoredFileObject, StorageError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let row = load_accessible_file(&connection, file_id, user_id)?;
        let path = checked_existing_object_path(&self.base_path, &row.storage_key)?;
        Ok(StoredFileObject {
            filename: row.original_filename,
            content_type: row.content_type,
            size_bytes: row.size_bytes,
            path,
        })
    }

    pub(crate) fn link_workflow_file(
        &self,
        owner_id: i64,
        file_id: i64,
        workflow_session_id: i64,
        purpose: &str,
    ) -> Result<(), StorageError> {
        self.ensure_enabled()?;
        if !matches!(purpose, "SIGNING_ORIGINAL" | "SIGNING_SIGNED") {
            return Err(StorageError::InvalidInput);
        }
        let connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let updated = connection.execute(
            "UPDATE storage_files
             SET workflow_session_id = ?1, file_purpose = ?2, updated_at = ?3
             WHERE file_id = ?4 AND owner_id = ?5",
            params![
                workflow_session_id,
                purpose,
                Utc::now().timestamp(),
                file_id,
                owner_id
            ],
        )?;
        if updated == 1 {
            Ok(())
        } else {
            Err(StorageError::FileNotFound)
        }
    }

    pub(crate) fn delete_file(&self, owner_id: i64, file_id: i64) -> Result<(), StorageError> {
        self.ensure_enabled()?;
        let mut connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM storage_files WHERE file_id = ?1", [file_id])?;
        transaction.commit()?;
        drop(connection);
        self.drain_cleanup_queue()
    }

    pub(crate) fn share_with_user(
        &self,
        owner_id: i64,
        file_id: i64,
        username: &str,
        role: ShareRole,
    ) -> Result<StoredFileResponse, StorageError> {
        self.ensure_sharing_enabled()?;
        let username = username.trim();
        if username.is_empty() || username.len() > 320 || username.chars().any(char::is_control) {
            return Err(StorageError::InvalidInput);
        }
        if looks_like_email(username) {
            if !self.config.sharing.email_enabled {
                return Err(StorageError::InvalidInput);
            }
            return Err(StorageError::EmailDeliveryUnavailable);
        }
        let mut connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let target_id = connection
            .query_row(
                "SELECT user_id FROM security_users WHERE username = ?1 COLLATE NOCASE",
                [username],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StorageError::UserNotFound)?;
        if target_id == owner_id {
            return Err(StorageError::InvalidInput);
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO storage_shares
             (file_id, shared_with_user_id, access_role, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(file_id, shared_with_user_id)
             DO UPDATE SET access_role = excluded.access_role",
            params![
                file_id,
                target_id,
                role.database_value(),
                Utc::now().timestamp()
            ],
        )?;
        transaction.commit()?;
        self.file_response_locked(&connection, file_id, owner_id)
    }

    pub(crate) fn revoke_user_share(
        &self,
        owner_id: i64,
        file_id: i64,
        username: &str,
    ) -> Result<(), StorageError> {
        self.ensure_sharing_enabled()?;
        let connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let target_id = connection
            .query_row(
                "SELECT user_id FROM security_users WHERE username = ?1 COLLATE NOCASE",
                [username.trim()],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StorageError::UserNotFound)?;
        connection.execute(
            "DELETE FROM storage_shares
             WHERE file_id = ?1 AND shared_with_user_id = ?2",
            params![file_id, target_id],
        )?;
        Ok(())
    }

    /// Removes the caller's own share of `file_id`, if one exists.
    ///
    /// A missing file, a file the caller owns instead of having been shared
    /// with them, and a file that exists but was never shared with the caller
    /// all collapse into the same [`StorageError::FileNotFound`] - mirroring
    /// [`load_accessible_file`]/[`load_owned_file`] - so this endpoint cannot
    /// be used to enumerate which numeric file IDs exist or who owns them.
    pub(crate) fn leave_user_share(&self, user_id: i64, file_id: i64) -> Result<(), StorageError> {
        self.ensure_sharing_enabled()?;
        let connection = self.lock()?;
        let deleted = connection.execute(
            "DELETE FROM storage_shares
             WHERE file_id = ?1 AND shared_with_user_id = ?2",
            params![file_id, user_id],
        )?;
        if deleted == 0 {
            Err(StorageError::FileNotFound)
        } else {
            Ok(())
        }
    }

    pub(crate) fn create_share_link(
        &self,
        owner_id: i64,
        file_id: i64,
        role: ShareRole,
    ) -> Result<ShareLinkResponse, StorageError> {
        self.ensure_share_links_enabled()?;
        let connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let token = random_uuid();
        let now = Utc::now().timestamp();
        let expiration_seconds = self
            .config
            .sharing
            .link_expiration_days
            .checked_mul(86_400)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(StorageError::InvalidInput)?;
        let expires_at = now
            .checked_add(expiration_seconds)
            .ok_or(StorageError::InvalidInput)?;
        connection.execute(
            "INSERT INTO storage_shares
             (file_id, share_token, access_role, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![file_id, token, role.database_value(), expires_at, now],
        )?;
        Ok(ShareLinkResponse {
            token,
            access_role: role.response_value().to_owned(),
            created_at: format_timestamp(now),
            expires_at: Some(format_timestamp(expires_at)),
        })
    }

    pub(crate) fn revoke_share_link(
        &self,
        owner_id: i64,
        file_id: i64,
        token: &str,
    ) -> Result<(), StorageError> {
        self.ensure_share_links_enabled()?;
        let token = validate_uuid(token).ok_or(StorageError::ShareNotFound)?;
        let connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let deleted = connection.execute(
            "DELETE FROM storage_shares
             WHERE file_id = ?1 AND share_token = ?2",
            params![file_id, token],
        )?;
        if deleted == 0 {
            Err(StorageError::ShareNotFound)
        } else {
            Ok(())
        }
    }

    pub(crate) fn open_share_link(
        &self,
        user_id: i64,
        token: &str,
        inline: bool,
    ) -> Result<StoredFileObject, StorageError> {
        self.ensure_share_links_enabled()?;
        let connection = self.lock()?;
        let share = load_live_share(&connection, token)?;
        if share
            .shared_with_user_id
            .is_some_and(|intended| intended != user_id && share.owner_id != user_id)
        {
            return Err(StorageError::AccessDenied);
        }
        let row = load_owned_file(&connection, share.file_id, share.owner_id)?;
        let path = checked_existing_object_path(&self.base_path, &row.storage_key)?;
        connection.execute(
            "INSERT INTO storage_share_accesses
             (share_id, user_id, access_type, accessed_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                share.share_id,
                user_id,
                if inline { "VIEW" } else { "DOWNLOAD" },
                Utc::now().timestamp()
            ],
        )?;
        Ok(StoredFileObject {
            filename: row.original_filename,
            content_type: row.content_type,
            size_bytes: row.size_bytes,
            path,
        })
    }

    pub(crate) fn share_link_metadata(
        &self,
        user_id: i64,
        token: &str,
    ) -> Result<ShareLinkMetadataResponse, StorageError> {
        self.ensure_share_links_enabled()?;
        let connection = self.lock()?;
        let share = load_live_share(&connection, token)?;
        if share
            .shared_with_user_id
            .is_some_and(|intended| intended != user_id && share.owner_id != user_id)
        {
            return Err(StorageError::AccessDenied);
        }
        let file = load_owned_file(&connection, share.file_id, share.owner_id)?;
        Ok(ShareLinkMetadataResponse {
            share_token: share.token,
            file_id: file.id,
            file_name: file.original_filename,
            owner: file.owner_username,
            owned_by_current_user: file.owner_id == user_id,
            access_role: share.role.response_value().to_owned(),
            created_at: format_timestamp(share.created_at),
            expires_at: share.expires_at.map(format_timestamp),
            last_accessed_at: latest_share_access(&connection, share.share_id, user_id)?
                .map(format_timestamp),
        })
    }

    pub(crate) fn list_accessed_share_links(
        &self,
        user_id: i64,
    ) -> Result<Vec<ShareLinkMetadataResponse>, StorageError> {
        self.ensure_share_links_enabled()?;
        let connection = self.lock()?;
        let now = Utc::now().timestamp();
        let mut statement = connection.prepare(
            "SELECT s.share_token, f.file_id, f.original_filename, owner.username,
                    f.owner_id, s.access_role, s.created_at, s.expires_at,
                    MAX(a.accessed_at)
             FROM storage_share_accesses a
             JOIN storage_shares s ON s.share_id = a.share_id
             JOIN storage_files f ON f.file_id = s.file_id
             JOIN security_users owner ON owner.user_id = f.owner_id
             WHERE a.user_id = ?1 AND s.share_token IS NOT NULL
               AND (s.expires_at IS NULL OR s.expires_at >= ?2)
             GROUP BY s.share_id
             ORDER BY MAX(a.accessed_at) DESC",
        )?;
        statement
            .query_map(params![user_id, now], |row| {
                let role: String = row.get(5)?;
                let expires_at: Option<i64> = row.get(7)?;
                let accessed_at: i64 = row.get(8)?;
                Ok(ShareLinkMetadataResponse {
                    share_token: row.get(0)?,
                    file_id: row.get(1)?,
                    file_name: row.get(2)?,
                    owner: row.get(3)?,
                    owned_by_current_user: row.get::<_, i64>(4)? == user_id,
                    access_role: ShareRole::from_database(&role).response_value().to_owned(),
                    created_at: format_timestamp(row.get(6)?),
                    expires_at: expires_at.map(format_timestamp),
                    last_accessed_at: Some(format_timestamp(accessed_at)),
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub(crate) fn list_folders(&self, owner_id: i64) -> Result<Vec<FolderResponse>, StorageError> {
        self.ensure_enabled()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT folder_id, name, parent_folder_id, color, icon, version,
                    created_at, updated_at
             FROM storage_folders WHERE owner_id = ?1
             ORDER BY name COLLATE NOCASE, folder_id",
        )?;
        statement
            .query_map([owner_id], folder_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_folder(
        &self,
        owner_id: i64,
        requested_id: Option<&str>,
        name: &str,
        parent_folder_id: Option<&str>,
        color: Option<&str>,
        icon: Option<&str>,
    ) -> Result<FolderResponse, StorageError> {
        self.ensure_enabled()?;
        let folder_id = match requested_id {
            Some(value) => validate_uuid(value).ok_or(StorageError::InvalidInput)?,
            None => random_uuid(),
        };
        let parent_folder_id = validated_optional_uuid(parent_folder_id)?;
        if parent_folder_id.as_deref() == Some(folder_id.as_str()) {
            return Err(StorageError::InvalidInput);
        }
        let name = validate_folder_name(name)?;
        let color = validate_folder_color(color, false)?;
        let icon = validate_folder_icon(icon, false)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_folder_parent(&transaction, owner_id, parent_folder_id.as_deref(), None)?;
        if let Some(existing) = load_folder(&transaction, &folder_id, owner_id)? {
            transaction.commit()?;
            return Ok(existing);
        }
        let id_exists = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM storage_folders WHERE folder_id = ?1)",
            [&folder_id],
            |row| row.get::<_, bool>(0),
        )?;
        if id_exists {
            return Err(StorageError::Conflict);
        }
        let folder_count = transaction.query_row(
            "SELECT COUNT(*) FROM storage_folders WHERE owner_id = ?1",
            [owner_id],
            |row| row.get::<_, i64>(0),
        )?;
        if folder_count >= MAX_FOLDERS_PER_USER {
            return Err(StorageError::Conflict);
        }
        let now = Utc::now().timestamp();
        transaction.execute(
            "INSERT INTO storage_folders
             (folder_id, owner_id, parent_folder_id, name, color, icon,
              version, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7)",
            params![
                folder_id,
                owner_id,
                parent_folder_id,
                name,
                color,
                icon,
                now
            ],
        )?;
        let response =
            load_folder(&transaction, &folder_id, owner_id)?.ok_or(StorageError::FolderNotFound)?;
        transaction.commit()?;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn update_folder(
        &self,
        owner_id: i64,
        folder_id: &str,
        name: Option<&str>,
        reparent: bool,
        parent_folder_id: Option<&str>,
        color: Option<&str>,
        icon: Option<&str>,
    ) -> Result<FolderResponse, StorageError> {
        self.ensure_enabled()?;
        let folder_id = validate_uuid(folder_id).ok_or(StorageError::FolderNotFound)?;
        let name = name.map(validate_folder_name).transpose()?;
        let validated_parent_folder_id = validated_optional_uuid(parent_folder_id)?;
        let parent_folder_id = reparent.then_some(validated_parent_folder_id).flatten();
        let color = validate_folder_color(color, true)?;
        let icon = validate_folder_icon(icon, true)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if load_folder(&transaction, &folder_id, owner_id)?.is_none() {
            return Err(StorageError::FolderNotFound);
        }
        if reparent {
            validate_folder_parent(
                &transaction,
                owner_id,
                parent_folder_id.as_deref(),
                Some(&folder_id),
            )?;
        }
        transaction.execute(
            "UPDATE storage_folders SET
                 name = COALESCE(?1, name),
                 parent_folder_id = CASE WHEN ?2 THEN ?3 ELSE parent_folder_id END,
                 color = CASE WHEN ?4 THEN ?5 ELSE color END,
                 icon = CASE WHEN ?6 THEN ?7 ELSE icon END,
                 version = version + 1,
                 updated_at = ?8
             WHERE folder_id = ?9 AND owner_id = ?10",
            params![
                name,
                reparent,
                parent_folder_id,
                color.is_some(),
                color.as_deref().filter(|value| !value.is_empty()),
                icon.is_some(),
                icon.as_deref().filter(|value| !value.is_empty()),
                Utc::now().timestamp(),
                folder_id,
                owner_id,
            ],
        )?;
        let response =
            load_folder(&transaction, &folder_id, owner_id)?.ok_or(StorageError::FolderNotFound)?;
        transaction.commit()?;
        Ok(response)
    }

    pub(crate) fn delete_folder(
        &self,
        owner_id: i64,
        folder_id: &str,
    ) -> Result<Vec<String>, StorageError> {
        self.ensure_enabled()?;
        let folder_id = validate_uuid(folder_id).ok_or(StorageError::FolderNotFound)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if load_folder(&transaction, &folder_id, owner_id)?.is_none() {
            return Err(StorageError::FolderNotFound);
        }
        let removed = {
            let mut statement = transaction.prepare(
                "WITH RECURSIVE subtree(folder_id) AS (
                     SELECT folder_id FROM storage_folders
                      WHERE folder_id = ?1 AND owner_id = ?2
                     UNION
                     SELECT child.folder_id FROM storage_folders child
                     JOIN subtree parent ON child.parent_folder_id = parent.folder_id
                      WHERE child.owner_id = ?2
                 )
                 SELECT folder_id FROM subtree",
            )?;
            statement
                .query_map(params![folder_id, owner_id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.execute(
            "WITH RECURSIVE subtree(folder_id) AS (
                 SELECT folder_id FROM storage_folders
                  WHERE folder_id = ?1 AND owner_id = ?2
                 UNION
                 SELECT child.folder_id FROM storage_folders child
                 JOIN subtree parent ON child.parent_folder_id = parent.folder_id
                  WHERE child.owner_id = ?2
             )
             UPDATE storage_files SET folder_id = NULL, updated_at = ?3
              WHERE owner_id = ?2 AND folder_id IN (SELECT folder_id FROM subtree)",
            params![folder_id, owner_id, Utc::now().timestamp()],
        )?;
        transaction.execute(
            "DELETE FROM storage_folders WHERE folder_id = ?1 AND owner_id = ?2",
            params![folder_id, owner_id],
        )?;
        transaction.commit()?;
        Ok(removed)
    }

    pub(crate) fn move_file_to_folder(
        &self,
        owner_id: i64,
        file_id: i64,
        folder_id: Option<&str>,
    ) -> Result<(), StorageError> {
        self.ensure_enabled()?;
        let folder_id = validated_optional_uuid(folder_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        load_owned_file(&transaction, file_id, owner_id)?;
        validate_owned_folder_target(&transaction, owner_id, folder_id.as_deref())?;
        let updated = transaction.execute(
            "UPDATE storage_files SET folder_id = ?1, updated_at = ?2
             WHERE file_id = ?3 AND owner_id = ?4",
            params![folder_id, Utc::now().timestamp(), file_id, owner_id],
        )?;
        if updated == 0 {
            return Err(StorageError::FileNotFound);
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn bulk_move_files_to_folder(
        &self,
        owner_id: i64,
        folder_id: Option<&str>,
        file_ids: &[i64],
    ) -> Result<(Vec<i64>, Vec<i64>), StorageError> {
        self.ensure_enabled()?;
        if file_ids.is_empty() || file_ids.len() > MAX_BULK_MOVE_FILES {
            return Err(StorageError::InvalidInput);
        }
        let folder_id = validated_optional_uuid(folder_id)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_owned_folder_target(&transaction, owner_id, folder_id.as_deref())?;
        let now = Utc::now().timestamp();
        let mut seen = HashSet::with_capacity(file_ids.len());
        let mut moved = Vec::with_capacity(file_ids.len());
        let mut owned = HashSet::with_capacity(file_ids.len());
        for &file_id in file_ids {
            if !seen.insert(file_id) {
                continue;
            }
            let updated = transaction.execute(
                "UPDATE storage_files SET folder_id = ?1, updated_at = ?2
                 WHERE file_id = ?3 AND owner_id = ?4",
                params![folder_id, now, file_id, owner_id],
            )?;
            if updated != 0 {
                moved.push(file_id);
                owned.insert(file_id);
            }
        }
        let skipped = file_ids
            .iter()
            .copied()
            .filter(|file_id| !owned.contains(file_id))
            .collect();
        transaction.commit()?;
        Ok((moved, skipped))
    }

    pub(crate) fn list_share_accesses(
        &self,
        owner_id: i64,
        file_id: i64,
        token: &str,
    ) -> Result<Vec<ShareLinkAccessResponse>, StorageError> {
        self.ensure_share_links_enabled()?;
        let connection = self.lock()?;
        load_owned_file(&connection, file_id, owner_id)?;
        let share_id = connection
            .query_row(
                "SELECT share_id FROM storage_shares
                 WHERE file_id = ?1 AND share_token = ?2",
                params![file_id, token],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(StorageError::ShareNotFound)?;
        let mut statement = connection.prepare(
            "SELECT u.username, a.access_type, a.accessed_at
             FROM storage_share_accesses a
             JOIN security_users u ON u.user_id = a.user_id
             WHERE a.share_id = ?1 ORDER BY a.accessed_at DESC, a.access_id DESC",
        )?;
        statement
            .query_map([share_id], |row| {
                Ok(ShareLinkAccessResponse {
                    username: row.get(0)?,
                    access_type: row.get(1)?,
                    accessed_at: format_timestamp(row.get(2)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    fn ensure_sharing_enabled(&self) -> Result<(), StorageError> {
        self.ensure_enabled()?;
        if self.config.sharing.enabled {
            Ok(())
        } else {
            Err(StorageError::SharingDisabled)
        }
    }

    fn ensure_share_links_enabled(&self) -> Result<(), StorageError> {
        self.ensure_sharing_enabled()?;
        if self.config.sharing.link_enabled {
            Ok(())
        } else {
            Err(StorageError::ShareLinksDisabled)
        }
    }

    fn ensure_enabled(&self) -> Result<(), StorageError> {
        if self.config.enabled {
            Ok(())
        } else {
            Err(StorageError::Disabled)
        }
    }

    fn enforce_quotas(
        &self,
        connection: &Connection,
        owner_id: i64,
        new_bytes: u64,
        existing_bytes: u64,
    ) -> Result<(), StorageError> {
        if self
            .config
            .max_file_bytes
            .is_some_and(|limit| new_bytes > limit)
        {
            return Err(StorageError::QuotaExceeded);
        }
        let delta = new_bytes.saturating_sub(existing_bytes);
        if delta == 0 {
            return Ok(());
        }
        let user_bytes = storage_bytes(connection, Some(owner_id))?;
        if self
            .config
            .max_user_bytes
            .is_some_and(|limit| user_bytes.saturating_add(delta) > limit)
        {
            return Err(StorageError::QuotaExceeded);
        }
        let total_bytes = storage_bytes(connection, None)?;
        if self
            .config
            .max_total_bytes
            .is_some_and(|limit| total_bytes.saturating_add(delta) > limit)
        {
            return Err(StorageError::QuotaExceeded);
        }
        Ok(())
    }

    fn file_response_locked(
        &self,
        connection: &Connection,
        file_id: i64,
        user_id: i64,
    ) -> Result<StoredFileResponse, StorageError> {
        let file = load_accessible_file(connection, file_id, user_id)?;
        let owned = file.owner_id == user_id;
        let (shared_users, share_links) = if owned {
            (
                load_shared_users(connection, file_id)?,
                self.load_share_links(connection, file_id)?,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let shared_with_users = shared_users
            .iter()
            .map(|shared| shared.username.clone())
            .collect();
        Ok(StoredFileResponse {
            id: file.id,
            file_name: file.original_filename,
            content_type: file.content_type,
            size_bytes: file.size_bytes,
            owner: file.owner_username,
            owned_by_current_user: owned,
            access_role: if owned {
                ShareRole::Editor.response_value().to_owned()
            } else {
                file.access_role.response_value().to_owned()
            },
            created_at: format_timestamp(file.created_at),
            updated_at: format_timestamp(file.updated_at),
            shared_with_users,
            shared_users,
            share_links,
            file_purpose: file.purpose.map(|value| value.to_ascii_lowercase()),
            folder_id: file.folder_id,
        })
    }

    fn load_share_links(
        &self,
        connection: &Connection,
        file_id: i64,
    ) -> Result<Vec<ShareLinkResponse>, StorageError> {
        if !(self.config.sharing.enabled && self.config.sharing.link_enabled) {
            return Ok(Vec::new());
        }
        let now = Utc::now().timestamp();
        let mut statement = connection.prepare(
            "SELECT share_token, access_role, created_at, expires_at
             FROM storage_shares
             WHERE file_id = ?1 AND share_token IS NOT NULL
               AND (expires_at IS NULL OR expires_at >= ?2)
             ORDER BY created_at DESC, share_id DESC",
        )?;
        statement
            .query_map(params![file_id, now], |row| {
                let role: String = row.get(1)?;
                let expires_at: Option<i64> = row.get(3)?;
                Ok(ShareLinkResponse {
                    token: row.get(0)?,
                    access_role: ShareRole::from_database(&role).response_value().to_owned(),
                    created_at: format_timestamp(row.get(2)?),
                    expires_at: expires_at.map(format_timestamp),
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StorageError> {
        self.connection.lock().map_err(|_| StorageError::Poisoned)
    }

    fn drain_cleanup_queue(&self) -> Result<(), StorageError> {
        if !self.config.enabled {
            return Ok(());
        }
        let entries = {
            let connection = self.lock()?;
            let mut statement = connection.prepare(
                "SELECT cleanup_id, storage_key FROM storage_cleanup_entries
                 ORDER BY cleanup_id LIMIT 1000",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (cleanup_id, storage_key) in entries {
            let path = checked_object_path(&self.base_path, &storage_key)?;
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(StorageError::AccessDenied);
                }
                Ok(_) => fs::remove_file(path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StorageError::Filesystem(error)),
            }
            self.lock()?.execute(
                "DELETE FROM storage_cleanup_entries WHERE cleanup_id = ?1",
                [cleanup_id],
            )?;
        }
        Ok(())
    }
}

fn initialize_storage_connection(connection: &Connection) -> Result<(), StorageError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA synchronous = FULL;
         CREATE TABLE IF NOT EXISTS storage_folders (
             folder_id TEXT PRIMARY KEY,
             owner_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             parent_folder_id TEXT REFERENCES storage_folders(folder_id) ON DELETE CASCADE,
             name TEXT NOT NULL,
             color TEXT,
             icon TEXT,
             version INTEGER NOT NULL DEFAULT 0,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS storage_folders_owner_idx
             ON storage_folders(owner_id, name COLLATE NOCASE);
         CREATE INDEX IF NOT EXISTS storage_folders_parent_idx
             ON storage_folders(parent_folder_id);
         CREATE TABLE IF NOT EXISTS storage_files (
             file_id INTEGER PRIMARY KEY AUTOINCREMENT,
             owner_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             original_filename TEXT NOT NULL,
             content_type TEXT,
             size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
             storage_key TEXT NOT NULL UNIQUE,
             history_filename TEXT,
             history_content_type TEXT,
             history_size_bytes INTEGER CHECK(history_size_bytes >= 0),
             history_storage_key TEXT UNIQUE,
             audit_filename TEXT,
             audit_content_type TEXT,
             audit_size_bytes INTEGER CHECK(audit_size_bytes >= 0),
             audit_storage_key TEXT UNIQUE,
             workflow_session_id INTEGER,
             file_purpose TEXT,
             folder_id TEXT REFERENCES storage_folders(folder_id) ON DELETE SET NULL,
             created_at INTEGER NOT NULL,
             updated_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS storage_files_owner_idx
             ON storage_files(owner_id, created_at DESC);
         CREATE INDEX IF NOT EXISTS storage_files_folder_idx
             ON storage_files(folder_id);
         CREATE TABLE IF NOT EXISTS storage_shares (
             share_id INTEGER PRIMARY KEY AUTOINCREMENT,
             file_id INTEGER NOT NULL REFERENCES storage_files(file_id) ON DELETE CASCADE,
             shared_with_user_id INTEGER REFERENCES security_users(user_id) ON DELETE CASCADE,
             share_token TEXT UNIQUE,
             access_role TEXT NOT NULL CHECK(access_role IN ('EDITOR', 'COMMENTER', 'VIEWER')),
             expires_at INTEGER,
             created_at INTEGER NOT NULL,
             CHECK(shared_with_user_id IS NOT NULL OR share_token IS NOT NULL),
             UNIQUE(file_id, shared_with_user_id)
         );
         CREATE INDEX IF NOT EXISTS storage_shares_file_idx ON storage_shares(file_id);
         CREATE INDEX IF NOT EXISTS storage_shares_user_idx
             ON storage_shares(shared_with_user_id, file_id);
         CREATE TABLE IF NOT EXISTS storage_share_accesses (
             access_id INTEGER PRIMARY KEY AUTOINCREMENT,
             share_id INTEGER NOT NULL REFERENCES storage_shares(share_id) ON DELETE CASCADE,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             access_type TEXT NOT NULL CHECK(access_type IN ('VIEW', 'DOWNLOAD')),
             accessed_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS storage_share_access_idx
             ON storage_share_accesses(share_id, accessed_at DESC);
         CREATE INDEX IF NOT EXISTS storage_share_access_user_idx
             ON storage_share_accesses(user_id, accessed_at DESC);
         CREATE TABLE IF NOT EXISTS storage_cleanup_entries (
             cleanup_id INTEGER PRIMARY KEY AUTOINCREMENT,
             storage_key TEXT NOT NULL UNIQUE,
             attempt_count INTEGER NOT NULL DEFAULT 0,
             created_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TRIGGER IF NOT EXISTS storage_files_cleanup_main
         AFTER DELETE ON storage_files WHEN OLD.storage_key IS NOT NULL
         BEGIN
             INSERT OR IGNORE INTO storage_cleanup_entries(storage_key) VALUES (OLD.storage_key);
         END;
         CREATE TRIGGER IF NOT EXISTS storage_files_cleanup_history
         AFTER DELETE ON storage_files WHEN OLD.history_storage_key IS NOT NULL
         BEGIN
             INSERT OR IGNORE INTO storage_cleanup_entries(storage_key)
             VALUES (OLD.history_storage_key);
         END;
         CREATE TRIGGER IF NOT EXISTS storage_files_cleanup_audit
         AFTER DELETE ON storage_files WHEN OLD.audit_storage_key IS NOT NULL
         BEGIN
             INSERT OR IGNORE INTO storage_cleanup_entries(storage_key)
             VALUES (OLD.audit_storage_key);
         END;",
    )?;
    Ok(())
}

fn folder_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FolderResponse> {
    Ok(FolderResponse {
        id: row.get(0)?,
        name: row.get(1)?,
        parent_folder_id: row.get(2)?,
        color: row.get(3)?,
        icon: row.get(4)?,
        version: row.get(5)?,
        created_at: format_timestamp(row.get(6)?),
        updated_at: format_timestamp(row.get(7)?),
    })
}

fn load_folder(
    connection: &Connection,
    folder_id: &str,
    owner_id: i64,
) -> Result<Option<FolderResponse>, StorageError> {
    connection
        .query_row(
            "SELECT folder_id, name, parent_folder_id, color, icon, version,
                    created_at, updated_at
             FROM storage_folders WHERE folder_id = ?1 AND owner_id = ?2",
            params![folder_id, owner_id],
            folder_from_row,
        )
        .optional()
        .map_err(StorageError::from)
}

fn validate_folder_parent(
    connection: &Connection,
    owner_id: i64,
    parent_folder_id: Option<&str>,
    forbidden_folder_id: Option<&str>,
) -> Result<(), StorageError> {
    let Some(mut cursor) = parent_folder_id.map(ToOwned::to_owned) else {
        return Ok(());
    };
    let mut seen = HashSet::with_capacity(MAX_FOLDER_DEPTH);
    let mut depth = 0_usize;
    loop {
        if forbidden_folder_id == Some(cursor.as_str()) || !seen.insert(cursor.clone()) {
            return Err(StorageError::InvalidInput);
        }
        let row = connection
            .query_row(
                "SELECT owner_id, parent_folder_id FROM storage_folders WHERE folder_id = ?1",
                [&cursor],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or(StorageError::InvalidInput)?;
        if row.0 != owner_id {
            return Err(StorageError::InvalidInput);
        }
        depth += 1;
        if depth >= MAX_FOLDER_DEPTH {
            return Err(StorageError::InvalidInput);
        }
        let Some(parent) = row.1 else {
            return Ok(());
        };
        cursor = parent;
    }
}

fn validate_owned_folder_target(
    connection: &Connection,
    owner_id: i64,
    folder_id: Option<&str>,
) -> Result<(), StorageError> {
    let Some(folder_id) = folder_id else {
        return Ok(());
    };
    if load_folder(connection, folder_id, owner_id)?.is_some() {
        Ok(())
    } else {
        Err(StorageError::InvalidInput)
    }
}

fn validate_folder_name(value: &str) -> Result<String, StorageError> {
    let value = value.trim();
    if value.is_empty()
        || value.encode_utf16().count() > MAX_FOLDER_NAME_LENGTH
        || value.chars().any(char::is_control)
    {
        Err(StorageError::InvalidInput)
    } else {
        Ok(value.to_owned())
    }
}

fn validate_folder_color(
    value: Option<&str>,
    allow_empty: bool,
) -> Result<Option<String>, StorageError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if allow_empty && value.is_empty() {
        return Ok(Some(String::new()));
    }
    let bytes = value.as_bytes();
    if !matches!(bytes.len(), 7 | 9)
        || bytes.first() != Some(&b'#')
        || !bytes[1..].iter().all(u8::is_ascii_hexdigit)
    {
        return Err(StorageError::InvalidInput);
    }
    Ok(Some(value.to_owned()))
}

fn validate_folder_icon(
    value: Option<&str>,
    allow_empty: bool,
) -> Result<Option<String>, StorageError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if allow_empty && value.is_empty() {
        return Ok(Some(String::new()));
    }
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(StorageError::InvalidInput);
    }
    Ok(Some(value.to_owned()))
}

fn validated_optional_uuid(value: Option<&str>) -> Result<Option<String>, StorageError> {
    value
        .map(|value| validate_uuid(value).ok_or(StorageError::InvalidInput))
        .transpose()
}

fn update_file_row(
    transaction: &Transaction<'_>,
    existing: &StoredFileRow,
    file_id: i64,
    bundle: &PendingFileBundle,
    now: i64,
) -> Result<(), StorageError> {
    let file = bundle.file.as_ref().ok_or(StorageError::InvalidInput)?;
    let file_size = sqlite_size(file.size_bytes)?;
    let history_size = bundle
        .history_bundle
        .as_ref()
        .map_or(existing.history_size_bytes, |value| Some(value.size_bytes))
        .map(sqlite_size)
        .transpose()?;
    let audit_size = bundle
        .audit_log
        .as_ref()
        .map_or(existing.audit_size_bytes, |value| Some(value.size_bytes))
        .map(sqlite_size)
        .transpose()?;
    transaction.execute(
        "UPDATE storage_files SET
             original_filename = ?1, content_type = ?2, size_bytes = ?3, storage_key = ?4,
             history_filename = ?5, history_content_type = ?6,
             history_size_bytes = ?7, history_storage_key = ?8,
             audit_filename = ?9, audit_content_type = ?10,
             audit_size_bytes = ?11, audit_storage_key = ?12, updated_at = ?13
         WHERE file_id = ?14",
        params![
            file.original_filename,
            file.content_type,
            file_size,
            file.storage_key,
            bundle
                .history_bundle
                .as_ref()
                .map(|value| value.original_filename.as_str())
                .or(existing.history_filename.as_deref()),
            bundle
                .history_bundle
                .as_ref()
                .and_then(|value| value.content_type.as_deref())
                .or(existing.history_content_type.as_deref()),
            history_size,
            bundle
                .history_bundle
                .as_ref()
                .map(|value| value.storage_key.as_str())
                .or(existing.history_storage_key.as_deref()),
            bundle
                .audit_log
                .as_ref()
                .map(|value| value.original_filename.as_str())
                .or(existing.audit_filename.as_deref()),
            bundle
                .audit_log
                .as_ref()
                .and_then(|value| value.content_type.as_deref())
                .or(existing.audit_content_type.as_deref()),
            audit_size,
            bundle
                .audit_log
                .as_ref()
                .map(|value| value.storage_key.as_str())
                .or(existing.audit_storage_key.as_deref()),
            now,
            file_id,
        ],
    )?;
    Ok(())
}

fn queue_replaced_objects(
    transaction: &Transaction<'_>,
    existing: &StoredFileRow,
    bundle: &PendingFileBundle,
) -> Result<(), StorageError> {
    queue_cleanup(transaction, &existing.storage_key)?;
    if bundle.history_bundle.is_some()
        && let Some(key) = existing.history_storage_key.as_deref()
    {
        queue_cleanup(transaction, key)?;
    }
    if bundle.audit_log.is_some()
        && let Some(key) = existing.audit_storage_key.as_deref()
    {
        queue_cleanup(transaction, key)?;
    }
    Ok(())
}

fn queue_cleanup(transaction: &Transaction<'_>, storage_key: &str) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT OR IGNORE INTO storage_cleanup_entries(storage_key) VALUES (?1)",
        [storage_key],
    )?;
    Ok(())
}

fn load_accessible_file(
    connection: &Connection,
    file_id: i64,
    user_id: i64,
) -> Result<StoredFileRow, StorageError> {
    connection
        .query_row(
            "SELECT f.file_id, f.owner_id, owner.username, f.original_filename,
                    f.content_type, f.size_bytes, f.storage_key,
                    f.history_filename, f.history_content_type,
                    f.history_size_bytes, f.history_storage_key,
                    f.audit_filename, f.audit_content_type,
                    f.audit_size_bytes, f.audit_storage_key,
                    f.file_purpose, f.folder_id, f.created_at, f.updated_at,
                    CASE WHEN f.owner_id = ?2 THEN 'EDITOR' ELSE COALESCE(s.access_role, 'VIEWER') END
             FROM storage_files f
             JOIN security_users owner ON owner.user_id = f.owner_id
             LEFT JOIN storage_shares s
               ON s.file_id = f.file_id AND s.shared_with_user_id = ?2
             WHERE f.file_id = ?1 AND (f.owner_id = ?2 OR s.share_id IS NOT NULL)",
            params![file_id, user_id],
            stored_file_from_row,
        )
        .optional()?
        .ok_or(StorageError::FileNotFound)
}

fn load_owned_file(
    connection: &Connection,
    file_id: i64,
    owner_id: i64,
) -> Result<StoredFileRow, StorageError> {
    connection
        .query_row(
            "SELECT f.file_id, f.owner_id, owner.username, f.original_filename,
                    f.content_type, f.size_bytes, f.storage_key,
                    f.history_filename, f.history_content_type,
                    f.history_size_bytes, f.history_storage_key,
                    f.audit_filename, f.audit_content_type,
                    f.audit_size_bytes, f.audit_storage_key,
                    f.file_purpose, f.folder_id, f.created_at, f.updated_at, 'EDITOR'
             FROM storage_files f
             JOIN security_users owner ON owner.user_id = f.owner_id
             WHERE f.file_id = ?1 AND f.owner_id = ?2",
            params![file_id, owner_id],
            stored_file_from_row,
        )
        .optional()?
        .ok_or(StorageError::FileNotFound)
}

fn stored_file_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredFileRow> {
    let size_bytes = row.get::<_, i64>(5)?;
    let history_size = row.get::<_, Option<i64>>(9)?;
    let audit_size = row.get::<_, Option<i64>>(13)?;
    let role: String = row.get(19)?;
    Ok(StoredFileRow {
        id: row.get(0)?,
        owner_id: row.get(1)?,
        owner_username: row.get(2)?,
        original_filename: row.get(3)?,
        content_type: row.get(4)?,
        size_bytes: u64::try_from(size_bytes).unwrap_or(0),
        storage_key: row.get(6)?,
        history_filename: row.get(7)?,
        history_content_type: row.get(8)?,
        history_size_bytes: history_size.and_then(|value| u64::try_from(value).ok()),
        history_storage_key: row.get(10)?,
        audit_filename: row.get(11)?,
        audit_content_type: row.get(12)?,
        audit_size_bytes: audit_size.and_then(|value| u64::try_from(value).ok()),
        audit_storage_key: row.get(14)?,
        purpose: row.get(15)?,
        folder_id: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
        access_role: ShareRole::from_database(&role),
    })
}

fn load_shared_users(
    connection: &Connection,
    file_id: i64,
) -> Result<Vec<SharedUserResponse>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT u.username, s.access_role
         FROM storage_shares s
         JOIN security_users u ON u.user_id = s.shared_with_user_id
         WHERE s.file_id = ?1
         ORDER BY u.username COLLATE NOCASE",
    )?;
    statement
        .query_map([file_id], |row| {
            let role: String = row.get(1)?;
            Ok(SharedUserResponse {
                username: row.get(0)?,
                access_role: ShareRole::from_database(&role).response_value().to_owned(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StorageError::from)
}

fn load_live_share(connection: &Connection, token: &str) -> Result<ShareRow, StorageError> {
    let token = validate_uuid(token).ok_or(StorageError::ShareNotFound)?;
    let now = Utc::now().timestamp();
    connection
        .query_row(
            "SELECT s.share_id, s.file_id, f.owner_id, s.shared_with_user_id,
                    s.share_token, s.access_role, s.created_at, s.expires_at
             FROM storage_shares s
             JOIN storage_files f ON f.file_id = s.file_id
             WHERE s.share_token = ?1 AND (s.expires_at IS NULL OR s.expires_at >= ?2)",
            params![token, now],
            |row| {
                let role: String = row.get(5)?;
                Ok(ShareRow {
                    share_id: row.get(0)?,
                    file_id: row.get(1)?,
                    owner_id: row.get(2)?,
                    shared_with_user_id: row.get(3)?,
                    token: row.get(4)?,
                    role: ShareRole::from_database(&role),
                    created_at: row.get(6)?,
                    expires_at: row.get(7)?,
                })
            },
        )
        .optional()?
        .ok_or(StorageError::ShareNotFound)
}

fn latest_share_access(
    connection: &Connection,
    share_id: i64,
    user_id: i64,
) -> Result<Option<i64>, StorageError> {
    connection
        .query_row(
            "SELECT MAX(accessed_at) FROM storage_share_accesses
             WHERE share_id = ?1 AND user_id = ?2",
            params![share_id, user_id],
            |row| row.get(0),
        )
        .map_err(StorageError::from)
}

fn storage_bytes(connection: &Connection, owner_id: Option<i64>) -> Result<u64, StorageError> {
    let bytes: i64 = if let Some(owner_id) = owner_id {
        connection.query_row(
            "SELECT COALESCE(SUM(size_bytes + COALESCE(history_size_bytes, 0)
                                      + COALESCE(audit_size_bytes, 0)), 0)
             FROM storage_files WHERE owner_id = ?1",
            [owner_id],
            |row| row.get(0),
        )?
    } else {
        connection.query_row(
            "SELECT COALESCE(SUM(size_bytes + COALESCE(history_size_bytes, 0)
                                      + COALESCE(audit_size_bytes, 0)), 0)
             FROM storage_files",
            [],
            |row| row.get(0),
        )?
    };
    Ok(u64::try_from(bytes).unwrap_or(u64::MAX))
}

fn prepare_storage_directory(path: &Path) -> Result<PathBuf, StorageError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_dir())
    {
        return Err(StorageError::AccessDenied);
    }
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::AccessDenied);
    }
    Ok(fs::canonicalize(path)?)
}

fn create_safe_directory(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(StorageError::AccessDenied)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                Err(StorageError::AccessDenied)
            } else {
                Ok(())
            }
        }
        Err(error) => Err(StorageError::Filesystem(error)),
    }
}

fn checked_object_path(base_path: &Path, storage_key: &str) -> Result<PathBuf, StorageError> {
    if storage_key.is_empty() || storage_key.len() > MAX_STORAGE_KEY_BYTES {
        return Err(StorageError::InvalidInput);
    }
    let relative = Path::new(storage_key);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative.components().count() != 2
    {
        return Err(StorageError::AccessDenied);
    }
    let path = base_path.join(relative);
    if !path.starts_with(base_path) {
        return Err(StorageError::AccessDenied);
    }
    Ok(path)
}

fn checked_existing_object_path(
    base_path: &Path,
    storage_key: &str,
) -> Result<PathBuf, StorageError> {
    let path = checked_object_path(base_path, storage_key)?;
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StorageError::FileNotFound
        } else {
            StorageError::Filesystem(error)
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::AccessDenied);
    }
    Ok(path)
}

fn sanitize_filename(filename: Option<&str>) -> String {
    let candidate = filename
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    let mut sanitized = String::with_capacity(candidate.len().min(MAX_FILENAME_BYTES));
    for character in candidate.chars() {
        let replacement = if character.is_control()
            || matches!(
                character,
                '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
            ) {
            '_'
        } else {
            character
        };
        if sanitized.len() + replacement.len_utf8() > MAX_FILENAME_BYTES {
            break;
        }
        sanitized.push(replacement);
    }
    let sanitized = sanitized.trim().trim_matches(['.', ' ']);
    if sanitized.is_empty() {
        "file".to_owned()
    } else {
        sanitized.to_owned()
    }
}

fn normalize_content_type(content_type: Option<&str>) -> Result<Option<String>, StorageError> {
    let content_type = content_type
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if content_type.is_some_and(|value| {
        value.len() > MAX_CONTENT_TYPE_BYTES || value.chars().any(char::is_control)
    }) {
        return Err(StorageError::InvalidInput);
    }
    Ok(content_type.map(ToOwned::to_owned))
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain
            .rsplit_once('.')
            .is_some_and(|(host, suffix)| !host.is_empty() && suffix.len() >= 2)
}

fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn format_timestamp(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(timestamp, 0).map_or_else(
        || "1970-01-01T00:00:00Z".to_owned(),
        |value| value.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

fn sqlite_size(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::QuotaExceeded)
}

fn validate_uuid(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
        } else if !byte.is_ascii_hexdigit() {
            return None;
        }
    }
    Some(value.to_ascii_lowercase())
}
