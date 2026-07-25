//! Administrator-only discovery and installation of Tesseract language data.

use std::{
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use reqwest::{
    Url,
    blocking::{Client, Response as HttpResponse},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::task;

const REMOTE_INDEX_URL: &str = "https://api.github.com/repos/tesseract-ocr/tessdata/contents";
const REMOTE_DOWNLOAD_BASE_URL: &str =
    "https://raw.githubusercontent.com/tesseract-ocr/tessdata/main/";
const REMOTE_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INDEX_BYTES: usize = 4 * 1024 * 1024;
const MAX_LANGUAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_LANGUAGES_PER_REQUEST: usize = 128;
const MAX_LANGUAGE_NAME_BYTES: usize = 64;
const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct TessdataAdminService {
    directory: PathBuf,
    remote: RemoteEndpoints,
    cache: Mutex<RemoteCache>,
}

#[derive(Debug)]
struct RemoteEndpoints {
    index_url: String,
    download_base_url: String,
}

#[derive(Debug, Default)]
struct RemoteCache {
    languages: Vec<String>,
    expires_at: Option<Instant>,
}

#[derive(Debug, Deserialize)]
struct TessdataDownloadRequest {
    languages: Option<Vec<Option<String>>>,
}

#[derive(Debug, Serialize)]
struct TessdataLanguagesResponse {
    installed: Vec<String>,
    available: Vec<String>,
    writable: bool,
}

#[derive(Debug, Serialize)]
struct TessdataDownloadResponse {
    downloaded: Vec<String>,
    failed: Vec<Option<String>>,
    #[serde(rename = "tessdataDir")]
    tessdata_dir: String,
}

#[derive(Debug, Deserialize)]
struct RemoteEntry {
    name: Option<String>,
}

#[derive(Debug, Error)]
enum RemoteError {
    #[error("invalid tessdata upstream URL")]
    Url,
    #[error("tessdata upstream request failed")]
    Http(#[from] reqwest::Error),
    #[error("tessdata upstream returned HTTP {0}")]
    Status(u16),
    #[error("tessdata upstream response was too large")]
    TooLarge,
    #[error("tessdata upstream response could not be read")]
    Io(#[from] std::io::Error),
    #[error("tessdata upstream response was invalid")]
    Json(#[from] serde_json::Error),
}

impl TessdataAdminService {
    #[must_use]
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self::with_remote(
            directory,
            REMOTE_INDEX_URL.to_owned(),
            REMOTE_DOWNLOAD_BASE_URL.to_owned(),
        )
    }

    fn with_remote(directory: PathBuf, index_url: String, download_base_url: String) -> Self {
        Self {
            directory,
            remote: RemoteEndpoints {
                index_url,
                download_base_url,
            },
            cache: Mutex::new(RemoteCache::default()),
        }
    }

    fn status(&self) -> TessdataLanguagesResponse {
        TessdataLanguagesResponse {
            installed: installed_languages(&self.directory),
            available: self.remote_languages(),
            writable: writable_directory(&self.directory),
        }
    }

    fn download(&self, requested: Vec<Option<String>>) -> TessdataDownloadResponse {
        let available = self.remote_languages();
        let mut downloaded = Vec::new();
        let mut failed = Vec::new();

        for requested_language in requested {
            let Some(language) = requested_language.as_deref() else {
                failed.push(None);
                continue;
            };
            if !is_safe_language(language)
                || (!available.is_empty()
                    && available
                        .binary_search_by(|candidate| candidate.as_str().cmp(language))
                        .is_err())
            {
                failed.push(Some(language.to_owned()));
                continue;
            }
            if self.download_one(language) {
                downloaded.push(language.to_owned());
            } else {
                failed.push(Some(language.to_owned()));
            }
        }

        TessdataDownloadResponse {
            downloaded,
            failed,
            tessdata_dir: self.directory.to_string_lossy().into_owned(),
        }
    }

    fn remote_languages(&self) -> Vec<String> {
        let stale = match self.cache.lock() {
            Ok(cache) => {
                if cache
                    .expires_at
                    .is_some_and(|expires_at| Instant::now() < expires_at)
                {
                    return cache.languages.clone();
                }
                cache.languages.clone()
            }
            Err(_) => Vec::new(),
        };

        let Ok(languages) = self.fetch_remote_languages() else {
            return stale;
        };
        if let Ok(mut cache) = self.cache.lock() {
            cache.languages.clone_from(&languages);
            cache.expires_at = Some(Instant::now() + REMOTE_CACHE_TTL);
        }
        languages
    }

    fn fetch_remote_languages(&self) -> Result<Vec<String>, RemoteError> {
        let url = validated_http_url(&self.remote.index_url)?;
        let mut response = http_client()?.get(url).send()?;
        require_success(&response)?;
        let body = read_bounded(&mut response, MAX_INDEX_BYTES)?;
        let entries = serde_json::from_slice::<Vec<RemoteEntry>>(&body)?;
        let mut languages = entries
            .into_iter()
            .filter_map(|entry| entry.name)
            .filter_map(|name| name.strip_suffix(".traineddata").map(ToOwned::to_owned))
            .filter(|language| !language.eq_ignore_ascii_case("osd"))
            .filter(|language| is_safe_language(language))
            .collect::<Vec<_>>();
        languages.sort_unstable();
        languages.dedup();
        Ok(languages)
    }

    fn download_one(&self, language: &str) -> bool {
        self.try_download_one(language).is_ok()
    }

    fn try_download_one(&self, language: &str) -> Result<(), RemoteError> {
        if !is_safe_language(language) {
            return Err(RemoteError::TooLarge);
        }
        ensure_safe_directory(&self.directory)?;
        let encoded = format!("{language}.traineddata");
        let base = validated_http_url(&self.remote.download_base_url)?;
        let url = base.join(&encoded).map_err(|_| RemoteError::Url)?;
        if url.scheme() != base.scheme()
            || url.host_str() != base.host_str()
            || !url.path().starts_with(base.path())
        {
            return Err(RemoteError::TooLarge);
        }

        let response = http_client()?.get(url).send()?;
        require_success(&response)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_LANGUAGE_BYTES as u64)
        {
            return Err(RemoteError::TooLarge);
        }

        let target = self.directory.join(encoded);
        if fs::symlink_metadata(&target).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            return Err(RemoteError::TooLarge);
        }
        let mut temporary = NamedTempFile::new_in(&self.directory)?;
        let copied = std::io::copy(
            &mut response.take(MAX_LANGUAGE_BYTES as u64 + 1),
            temporary.as_file_mut(),
        )?;
        if copied > MAX_LANGUAGE_BYTES as u64 {
            return Err(RemoteError::TooLarge);
        }
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(target).map_err(|error| error.error)?;
        Ok(())
    }
}

pub(crate) fn routes(service: Arc<TessdataAdminService>) -> Router {
    Router::new()
        .route(
            "/api/v1/ui-data/tessdata-languages",
            get(tessdata_languages),
        )
        .route(
            "/api/v1/ui-data/tessdata/download",
            post(download_tessdata_languages),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(Extension(service))
}

async fn tessdata_languages(Extension(service): Extension<Arc<TessdataAdminService>>) -> Response {
    match task::spawn_blocking(move || service.status()).await {
        Ok(status) => Json(status).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn download_tessdata_languages(
    Extension(service): Extension<Arc<TessdataAdminService>>,
    Json(request): Json<TessdataDownloadRequest>,
) -> Response {
    let Some(languages) = request.languages else {
        return (
            StatusCode::BAD_REQUEST,
            Json(message("No languages provided for download")),
        )
            .into_response();
    };
    if languages.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(message("No languages provided for download")),
        )
            .into_response();
    }
    if languages.len() > MAX_LANGUAGES_PER_REQUEST {
        return (
            StatusCode::BAD_REQUEST,
            Json(message("Too many languages requested")),
        )
            .into_response();
    }
    if !writable_directory(&service.directory) {
        return (
            StatusCode::FORBIDDEN,
            Json(message(&service.directory.to_string_lossy())),
        )
            .into_response();
    }

    match task::spawn_blocking(move || service.download(languages)).await {
        Ok(result) => {
            let status = if !result.downloaded.is_empty() && result.failed.is_empty() {
                StatusCode::OK
            } else if !result.downloaded.is_empty() {
                StatusCode::MULTI_STATUS
            } else {
                StatusCode::BAD_GATEWAY
            };
            (status, Json(result)).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn installed_languages(directory: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut languages = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_file()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".traineddata").map(ToOwned::to_owned))
        .filter(|language| !language.eq_ignore_ascii_case("osd"))
        .filter(|language| is_safe_language(language))
        .collect::<Vec<_>>();
    languages.sort_unstable();
    languages.dedup();
    languages
}

fn writable_directory(directory: &Path) -> bool {
    if ensure_safe_directory(directory).is_err() {
        return false;
    }
    NamedTempFile::new_in(directory).is_ok()
}

fn ensure_safe_directory(directory: &Path) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tessdata path is not a direct directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(directory)?;
            let metadata = fs::symlink_metadata(directory)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "tessdata path is not a direct directory",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn is_safe_language(language: &str) -> bool {
    !language.is_empty()
        && language.len() <= MAX_LANGUAGE_NAME_BYTES
        && language
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-'))
}

fn http_client() -> Result<Client, reqwest::Error> {
    Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::limited(3))
        .user_agent("Stirling-PDF-App")
        .build()
}

fn validated_http_url(value: &str) -> Result<Url, RemoteError> {
    let url = Url::parse(value).map_err(|_| RemoteError::Url)?;
    if matches!(url.scheme(), "http" | "https") && url.host_str().is_some() {
        Ok(url)
    } else {
        Err(RemoteError::TooLarge)
    }
}

fn require_success(response: &HttpResponse) -> Result<(), RemoteError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(RemoteError::Status(response.status().as_u16()))
    }
}

fn read_bounded(response: &mut HttpResponse, maximum: usize) -> Result<Vec<u8>, RemoteError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(RemoteError::TooLarge);
    }
    let mut bytes = Vec::new();
    response.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        Err(RemoteError::TooLarge)
    } else {
        Ok(bytes)
    }
}

fn message(value: &str) -> serde_json::Value {
    serde_json::json!({ "message": value })
}

#[cfg(test)]
mod tests {
    use super::{TessdataAdminService, is_safe_language};
    use std::{
        fs,
        io::{Read as _, Write as _},
        net::TcpListener,
        thread,
    };

    #[test]
    fn validates_java_language_name_characters_with_explicit_bounds() {
        assert!(is_safe_language("eng"));
        assert!(is_safe_language("script_Latn+best-fast"));
        assert!(!is_safe_language(""));
        assert!(!is_safe_language("../eng"));
        assert!(!is_safe_language("eng.traineddata"));
        assert!(!is_safe_language(&"a".repeat(65)));
    }

    #[test]
    fn discovers_caches_and_atomically_downloads_remote_languages()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            for stream in listener.incoming().take(2) {
                let mut stream = stream?;
                let mut request = [0_u8; 2048];
                let read = stream.read(&mut request)?;
                let request = String::from_utf8_lossy(&request[..read]);
                let (content_type, body) = if request.starts_with("GET /index ") {
                    (
                        "application/json",
                        br#"[{"name":"deu.traineddata"},{"name":"eng.traineddata"},{"name":"osd.traineddata"},{"name":"README.md"}]"#.as_slice(),
                    )
                } else {
                    (
                        "application/octet-stream",
                        b"trained-language-data".as_slice(),
                    )
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )?;
                stream.write_all(body)?;
            }
            Ok(())
        });

        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("fra.traineddata"), b"installed")?;
        fs::write(directory.path().join("osd.traineddata"), b"orientation")?;
        let service = TessdataAdminService::with_remote(
            directory.path().to_path_buf(),
            format!("http://{address}/index"),
            format!("http://{address}/data/"),
        );

        let status = service.status();
        assert_eq!(status.installed, ["fra"]);
        assert_eq!(status.available, ["deu", "eng"]);
        assert!(status.writable);

        let result = service.download(vec![Some("eng".to_owned()), Some("unknown".to_owned())]);
        assert_eq!(result.downloaded, ["eng"]);
        assert_eq!(result.failed, [Some("unknown".to_owned())]);
        assert_eq!(
            fs::read(directory.path().join("eng.traineddata"))?,
            b"trained-language-data"
        );
        server.join().map_err(|_| "fixture server panicked")??;
        Ok(())
    }
}
