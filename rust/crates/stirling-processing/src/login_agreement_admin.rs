//! Administrator management for live login-agreement Markdown files.

use std::{
    collections::BTreeSet,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path as AxumPath},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::task;

use crate::runtime_config::is_valid_locale;

const MAX_AGREEMENT_BYTES: usize = 256 * 1024;
const MAX_AGREEMENT_BYTES_U64: u64 = 256 * 1024;
const MAX_REQUEST_BYTES: usize = MAX_AGREEMENT_BYTES + 1024;

#[derive(Debug)]
pub(crate) struct LoginAgreementAdminService {
    directory: PathBuf,
    write_lock: Mutex<()>,
}

#[derive(Debug, Error)]
enum LoginAgreementAdminError {
    #[error("invalid login-agreement locale or content")]
    Invalid,
    #[error("login-agreement storage is unavailable")]
    Poisoned,
    #[error("login-agreement storage operation failed")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Deserialize)]
struct AgreementContentRequest {
    content: Option<String>,
}

#[derive(Debug, Serialize)]
struct AgreementContentResponse {
    locale: String,
    content: String,
}

impl LoginAgreementAdminService {
    #[must_use]
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            write_lock: Mutex::new(()),
        }
    }

    fn list_locales(&self) -> Result<BTreeSet<String>, LoginAgreementAdminError> {
        let mut locales = BTreeSet::new();
        let metadata = match fs::symlink_metadata(&self.directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(locales),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LoginAgreementAdminError::Invalid);
        }
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            let Some(locale) = name.strip_suffix(".md") else {
                continue;
            };
            if is_valid_locale(locale) {
                locales.insert(locale.to_owned());
            }
        }
        Ok(locales)
    }

    fn read(&self, locale: &str) -> Result<String, LoginAgreementAdminError> {
        let path = self.locale_path(locale)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
            Err(_) => return Ok(String::new()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_AGREEMENT_BYTES_U64
        {
            return Ok(String::new());
        }
        let bytes = match fs::read(path) {
            Ok(bytes) if bytes.len() <= MAX_AGREEMENT_BYTES => bytes,
            Ok(_) | Err(_) => return Ok(String::new()),
        };
        Ok(String::from_utf8(bytes).unwrap_or_default())
    }

    fn write(&self, locale: &str, content: Option<&str>) -> Result<(), LoginAgreementAdminError> {
        let path = self.locale_path(locale)?;
        let content = content.unwrap_or_default();
        if content.len() > MAX_AGREEMENT_BYTES || content.contains('\0') {
            return Err(LoginAgreementAdminError::Invalid);
        }
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| LoginAgreementAdminError::Poisoned)?;
        if content.trim().is_empty() {
            match fs::remove_file(path) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
        ensure_safe_directory(&self.directory)?;
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(LoginAgreementAdminError::Invalid);
        }
        let mut temporary = NamedTempFile::new_in(&self.directory)?;
        temporary.write_all(content.as_bytes())?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        Ok(())
    }

    fn locale_path(&self, locale: &str) -> Result<PathBuf, LoginAgreementAdminError> {
        if !is_valid_locale(locale) {
            return Err(LoginAgreementAdminError::Invalid);
        }
        let path = self.directory.join(format!("{locale}.md"));
        path.starts_with(&self.directory)
            .then_some(path)
            .ok_or(LoginAgreementAdminError::Invalid)
    }
}

pub(crate) fn routes(service: Arc<LoginAgreementAdminService>) -> Router {
    Router::new()
        .route("/api/v1/admin/login-agreement", get(list_login_agreements))
        .route(
            "/api/v1/admin/login-agreement/{locale}",
            get(read_login_agreement).put(write_login_agreement),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(Extension(service))
}

async fn list_login_agreements(
    Extension(service): Extension<Arc<LoginAgreementAdminService>>,
) -> Response {
    match task::spawn_blocking(move || service.list_locales()).await {
        Ok(Ok(locales)) => Json(locales).into_response(),
        Ok(Err(error)) => error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn read_login_agreement(
    Extension(service): Extension<Arc<LoginAgreementAdminService>>,
    AxumPath(locale): AxumPath<String>,
) -> Response {
    let response_locale = locale.clone();
    match task::spawn_blocking(move || service.read(&locale)).await {
        Ok(Ok(content)) => Json(AgreementContentResponse {
            locale: response_locale,
            content,
        })
        .into_response(),
        Ok(Err(error)) => error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn write_login_agreement(
    Extension(service): Extension<Arc<LoginAgreementAdminService>>,
    AxumPath(locale): AxumPath<String>,
    Json(request): Json<Option<AgreementContentRequest>>,
) -> Response {
    let content = request.and_then(|request| request.content);
    match task::spawn_blocking(move || service.write(&locale, content.as_deref())).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn ensure_safe_directory(directory: &Path) -> Result<(), LoginAgreementAdminError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(LoginAgreementAdminError::Invalid)
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = directory
                .parent()
                .ok_or(LoginAgreementAdminError::Invalid)?;
            if fs::symlink_metadata(parent).is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return Err(LoginAgreementAdminError::Invalid);
            }
            fs::create_dir_all(directory)?;
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn error_response(error: &LoginAgreementAdminError) -> Response {
    match error {
        LoginAgreementAdminError::Invalid => StatusCode::BAD_REQUEST.into_response(),
        LoginAgreementAdminError::Poisoned | LoginAgreementAdminError::Io(_) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::LoginAgreementAdminService;

    #[test]
    fn writes_lists_reads_and_clears_locale_files() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let service = LoginAgreementAdminService::new(temporary.path().join("disclaimer"));

        service.write("en-US", Some("# Terms\n"))?;
        service.write("fr", Some("# Conditions\n"))?;
        assert_eq!(
            service.list_locales()?.into_iter().collect::<Vec<_>>(),
            ["en-US", "fr"]
        );
        assert_eq!(service.read("en-US")?, "# Terms\n");
        service.write("en-US", Some(" \n"))?;
        assert_eq!(service.read("en-US")?, "");
        Ok(())
    }

    #[test]
    fn rejects_invalid_locales_and_oversized_content() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        let service = LoginAgreementAdminService::new(temporary.path().join("disclaimer"));

        assert!(service.write("../en-US", Some("terms")).is_err());
        assert!(
            service
                .write("en-US", Some(&"x".repeat(256 * 1024 + 1)))
                .is_err()
        );
        assert!(!temporary.path().join("disclaimer/en-US.md").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_locale_files() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("disclaimer");
        fs::create_dir_all(&directory)?;
        let outside = temporary.path().join("outside.md");
        fs::write(&outside, "secret")?;
        symlink(&outside, directory.join("en-US.md"))?;
        let service = LoginAgreementAdminService::new(directory);

        assert_eq!(service.read("en-US")?, "");
        assert!(service.write("en-US", Some("replacement")).is_err());
        assert_eq!(fs::read_to_string(outside)?, "secret");
        Ok(())
    }
}
