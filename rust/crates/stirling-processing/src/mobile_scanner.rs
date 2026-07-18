//! Temporary mobile-to-desktop scan transfer sessions.
//!
//! This is the non-UI backend counterpart of the QR scanner workflow. Files are
//! kept in a private temporary directory for at most ten minutes and are removed
//! after download, session deletion, or expiry.

use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tempfile::TempDir;
use thiserror::Error;

const SESSION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const SESSION_TIMEOUT_MILLIS: u64 = 10 * 60 * 1_000;

pub struct MobileScannerService {
    workspace: TempDir,
    sessions: Mutex<HashMap<String, SessionData>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    #[serde(rename = "timeoutMs")]
    pub timeout_millis: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
}

#[derive(Debug, Error)]
pub enum MobileScannerError {
    #[error("Session ID cannot be empty")]
    EmptySessionId,
    #[error("Invalid session ID format")]
    InvalidSessionId,
    #[error("Filename cannot be empty")]
    EmptyFilename,
    #[error("Invalid filename: contains path separators or parent references")]
    UnsafeFilename,
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("mobile scanner state is unavailable")]
    StateUnavailable,
    #[error("mobile scanner storage error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug)]
struct SessionData {
    created_at: u64,
    last_access: Instant,
    last_access_at: u64,
    files: Vec<StoredFile>,
}

#[derive(Debug)]
struct StoredFile {
    metadata: FileMetadata,
    downloaded: bool,
}

impl MobileScannerService {
    /// Creates an isolated workspace that is deleted when the service shuts down.
    ///
    /// # Errors
    ///
    /// Returns an error when a temporary workspace cannot be created.
    pub fn new() -> Result<Self, MobileScannerError> {
        Ok(Self {
            workspace: TempDir::new()?,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    /// Creates or replaces a scanner session with the Java-compatible ten minute TTL.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid session IDs or unavailable process state.
    pub fn create_session(&self, session_id: &str) -> Result<SessionInfo, MobileScannerError> {
        validate_session_id(session_id)?;
        self.delete_session(session_id);
        let created_at = epoch_millis();
        let session = SessionData {
            created_at,
            last_access: Instant::now(),
            last_access_at: created_at,
            files: Vec::new(),
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| MobileScannerError::StateUnavailable)?;
        sessions.insert(session_id.to_owned(), session);
        Ok(SessionInfo {
            session_id: session_id.to_owned(),
            created_at,
            expires_at: created_at.saturating_add(SESSION_TIMEOUT_MILLIS),
            timeout_millis: SESSION_TIMEOUT_MILLIS,
        })
    }

    /// Returns a valid session and extends its inactivity timeout.
    #[must_use]
    pub fn validate_session(&self, session_id: &str) -> Option<SessionInfo> {
        let mut sessions = self.sessions.lock().ok()?;
        let session = sessions.get_mut(session_id)?;
        if session.last_access.elapsed() > SESSION_TIMEOUT {
            sessions.remove(session_id);
            drop(sessions);
            self.remove_session_directory(session_id);
            return None;
        }
        let expires_at = session
            .last_access_at
            .saturating_add(SESSION_TIMEOUT_MILLIS);
        session.last_access = Instant::now();
        session.last_access_at = epoch_millis();
        Some(SessionInfo {
            session_id: session_id.to_owned(),
            created_at: session.created_at,
            expires_at,
            timeout_millis: SESSION_TIMEOUT_MILLIS,
        })
    }

    /// Ensures an upload session exists and returns its private directory.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid session IDs or failed storage setup.
    pub fn upload_directory(&self, session_id: &str) -> Result<PathBuf, MobileScannerError> {
        validate_session_id(session_id)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| MobileScannerError::StateUnavailable)?;
        sessions
            .entry(session_id.to_owned())
            .or_insert_with(|| SessionData {
                created_at: epoch_millis(),
                last_access: Instant::now(),
                last_access_at: epoch_millis(),
                files: Vec::new(),
            });
        let session_dir = self.session_directory(session_id)?;
        fs::create_dir_all(&session_dir)?;
        Ok(session_dir)
    }

    /// Records a stored upload after it has been atomically written to disk.
    ///
    /// # Errors
    ///
    /// Returns an error when the session no longer exists or state is unavailable.
    pub fn record_upload(
        &self,
        session_id: &str,
        metadata: FileMetadata,
    ) -> Result<(), MobileScannerError> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| MobileScannerError::StateUnavailable)?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| MobileScannerError::SessionNotFound(session_id.to_owned()))?;
        session.files.push(StoredFile {
            metadata,
            downloaded: false,
        });
        session.last_access = Instant::now();
        session.last_access_at = epoch_millis();
        Ok(())
    }

    /// Lists a session's files, returning an empty list for missing sessions as Java does.
    #[must_use]
    pub fn files(&self, session_id: &str) -> Vec<FileMetadata> {
        let Ok(mut sessions) = self.sessions.lock() else {
            return Vec::new();
        };
        let Some(session) = sessions.get_mut(session_id) else {
            return Vec::new();
        };
        session.last_access = Instant::now();
        session.last_access_at = epoch_millis();
        session
            .files
            .iter()
            .map(|file| file.metadata.clone())
            .collect()
    }

    /// Resolves a downloadable file and marks the session as accessed.
    ///
    /// # Errors
    ///
    /// Returns an error for missing sessions/files or unsafe file names.
    pub fn download_path(
        &self,
        session_id: &str,
        filename: &str,
    ) -> Result<(PathBuf, Option<String>), MobileScannerError> {
        validate_download_filename(filename)?;
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| MobileScannerError::StateUnavailable)?;
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| MobileScannerError::SessionNotFound(session_id.to_owned()))?;
        let file = session
            .files
            .iter()
            .find(|file| file.metadata.filename == filename)
            .ok_or_else(|| MobileScannerError::FileNotFound(filename.to_owned()))?;
        let path = self.session_directory(session_id)?.join(filename);
        if !path.is_file() {
            return Err(MobileScannerError::FileNotFound(filename.to_owned()));
        }
        session.last_access = Instant::now();
        session.last_access_at = epoch_millis();
        Ok((path, file.metadata.content_type.clone()))
    }

    /// Removes a downloaded file and deletes the session when no files remain.
    pub fn complete_download(&self, session_id: &str, filename: &str) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        let Some(session) = sessions.get_mut(session_id) else {
            return;
        };
        if let Some(file) = session
            .files
            .iter_mut()
            .find(|file| file.metadata.filename == filename)
        {
            file.downloaded = true;
        }
        let remove_session =
            !session.files.is_empty() && session.files.iter().all(|file| file.downloaded);
        drop(sessions);
        let _ = fs::remove_file(self.workspace.path().join(session_id).join(filename));
        if remove_session {
            self.delete_session(session_id);
        }
    }

    /// Deletes a session. Missing or malformed IDs are a no-op to match Java's delete endpoint.
    pub fn delete_session(&self, session_id: &str) {
        let Ok(mut sessions) = self.sessions.lock() else {
            return;
        };
        if sessions.remove(session_id).is_none() {
            return;
        }
        drop(sessions);
        self.remove_session_directory(session_id);
    }

    #[must_use]
    pub fn sanitize_upload_filename(filename: Option<&str>) -> String {
        let filename = filename.unwrap_or_default();
        let sanitized = filename
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        if sanitized.trim().is_empty() {
            format!("upload-{}", epoch_millis())
        } else {
            sanitized
        }
    }

    fn session_directory(&self, session_id: &str) -> Result<PathBuf, MobileScannerError> {
        validate_session_id(session_id)?;
        Ok(self.workspace.path().join(session_id))
    }

    fn remove_session_directory(&self, session_id: &str) {
        if validate_session_id(session_id).is_err() {
            return;
        }
        let path = self.workspace.path().join(session_id);
        if path.starts_with(self.workspace.path()) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn validate_session_id(session_id: &str) -> Result<(), MobileScannerError> {
    if session_id.trim().is_empty() {
        return Err(MobileScannerError::EmptySessionId);
    }
    if !session_id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '-')
    {
        return Err(MobileScannerError::InvalidSessionId);
    }
    Ok(())
}

fn validate_download_filename(filename: &str) -> Result<(), MobileScannerError> {
    if filename.trim().is_empty() {
        return Err(MobileScannerError::EmptyFilename);
    }
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(MobileScannerError::UnsafeFilename);
    }
    Ok(())
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use super::{FileMetadata, MobileScannerError, MobileScannerService};

    #[test]
    fn rejects_unsafe_session_ids_and_download_names() -> Result<(), Box<dyn std::error::Error>> {
        let service = MobileScannerService::new()?;
        assert!(matches!(
            service.create_session("../outside"),
            Err(MobileScannerError::InvalidSessionId)
        ));
        service.create_session("safe-session")?;
        assert!(matches!(
            service.download_path("safe-session", "../report.png"),
            Err(MobileScannerError::UnsafeFilename)
        ));
        Ok(())
    }

    #[test]
    fn stores_metadata_and_sanitizes_uploaded_names() -> Result<(), Box<dyn std::error::Error>> {
        let service = MobileScannerService::new()?;
        let directory = service.upload_directory("scanner-1")?;
        let filename = MobileScannerService::sanitize_upload_filename(Some("scan 1?.jpg"));
        std::fs::write(directory.join(&filename), b"image")?;
        service.record_upload(
            "scanner-1",
            FileMetadata {
                filename: filename.clone(),
                size: 5,
                content_type: Some("image/jpeg".to_owned()),
            },
        )?;
        assert_eq!(service.files("scanner-1")[0].filename, filename);
        Ok(())
    }
}
