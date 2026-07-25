//! Server-held certificate lifecycle for secured PDF signing.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Multipart},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use chrono::{DateTime, SecondsFormat, Utc};
use p12_keystore::{
    Certificate as Pkcs12Certificate, KeyStore, KeyStoreEntry, Pkcs12ImportPolicy, PrivateKey,
    PrivateKeyChain,
};
use pkcs8::EncodePrivateKey as _;
use rand::RngExt as _;
use rsa::RsaPrivateKey;
use serde::Serialize;
use thiserror::Error;
use tokio::task;
use x509_certificate::{InMemorySigningKeyPair, X509CertificateBuilder, certificate::KeyUsage};
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

use crate::{
    security::SecurityAuditContext,
    signing_key::{Pkcs12SigningKey, SigningSecret},
};

const KEYSTORE_FILENAME: &str = "server-certificate.p12";
const PASSWORD_FILENAME: &str = "server-certificate.password";
const KEYSTORE_ALIAS: &str = "stirling-pdf-server";
const MAX_KEYSTORE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PASSWORD_BYTES: usize = 1_024;
const ROUTE_BODY_LIMIT: usize = MAX_KEYSTORE_BYTES + 64 * 1024;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Debug)]
pub(crate) struct ServerCertificateConfig {
    pub(crate) enabled: bool,
    pub(crate) organization_name: String,
    pub(crate) validity_days: u32,
    pub(crate) regenerate_on_startup: bool,
    pub(crate) config_directory: PathBuf,
}

pub(crate) struct ServerCertificateService {
    config: ServerCertificateConfig,
    password: Zeroizing<String>,
    operation_lock: Mutex<()>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServerCertificateInfo {
    exists: bool,
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

#[derive(Debug, Error)]
pub(crate) enum ServerCertificateError {
    #[error("the server certificate feature is disabled")]
    Disabled,
    #[error("no server certificate is configured")]
    Missing,
    #[error("invalid certificate or password")]
    Invalid,
    #[error("server certificate state is unavailable")]
    Poisoned,
    #[error("server certificate storage failed")]
    Io(#[from] std::io::Error),
    #[error("server certificate generation failed")]
    Generation,
}

impl ServerCertificateService {
    pub(crate) fn new(config: ServerCertificateConfig) -> Result<Self, ServerCertificateError> {
        validate_config(&config)?;
        fs::create_dir_all(&config.config_directory)?;
        let password = load_or_create_password(&config.config_directory)?;
        Ok(Self {
            config,
            password,
            operation_lock: Mutex::new(()),
        })
    }

    pub(crate) fn initialize(&self) -> Result<(), ServerCertificateError> {
        if !self.config.enabled {
            return Ok(());
        }
        let _guard = self.lock()?;
        let path = self.keystore_path();
        if self.config.regenerate_on_startup || !safe_regular_file_exists(&path)? {
            self.generate_locked()?;
        } else {
            self.load_signing_key_locked()?;
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    #[cfg(test)]
    fn has_certificate(&self) -> Result<bool, ServerCertificateError> {
        safe_regular_file_exists(&self.keystore_path())
    }

    pub(crate) fn info(&self) -> Result<ServerCertificateInfo, ServerCertificateError> {
        let _guard = self.lock()?;
        if !safe_regular_file_exists(&self.keystore_path())? {
            return Ok(ServerCertificateInfo {
                exists: false,
                subject: None,
                issuer: None,
                valid_from: None,
                valid_to: None,
            });
        }
        certificate_info(&self.certificate_der_locked()?)
    }

    pub(crate) fn certificate_der(&self) -> Result<Vec<u8>, ServerCertificateError> {
        let _guard = self.lock()?;
        self.certificate_der_locked()
    }

    pub(crate) fn signing_key(&self) -> Result<Pkcs12SigningKey, ServerCertificateError> {
        if !self.config.enabled {
            return Err(ServerCertificateError::Disabled);
        }
        let _guard = self.lock()?;
        self.load_signing_key_locked()
    }

    pub(crate) fn upload(
        &self,
        archive: &Zeroizing<Vec<u8>>,
        password: &Zeroizing<String>,
    ) -> Result<(), ServerCertificateError> {
        if archive.is_empty() || archive.len() > MAX_KEYSTORE_BYTES {
            return Err(ServerCertificateError::Invalid);
        }
        let _guard = self.lock()?;
        validate_uploaded_key(archive, password)?;
        let uploaded = KeyStore::from_pkcs12(archive, password, Pkcs12ImportPolicy::Strict)
            .map_err(|_| ServerCertificateError::Invalid)?;
        let (_, key_chain) = uploaded
            .private_key_chain()
            .ok_or(ServerCertificateError::Invalid)?;
        if key_chain.certs().is_empty() {
            return Err(ServerCertificateError::Invalid);
        }
        let mut managed = KeyStore::new();
        managed.add_entry(
            KEYSTORE_ALIAS,
            KeyStoreEntry::PrivateKeyChain(key_chain.clone()),
        );
        let bytes = Zeroizing::new(
            managed
                .writer(&self.password)
                .write()
                .map_err(|_| ServerCertificateError::Invalid)?,
        );
        write_private_file(&self.keystore_path(), &bytes)
    }

    pub(crate) fn delete(&self) -> Result<(), ServerCertificateError> {
        let _guard = self.lock()?;
        let path = self.keystore_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(ServerCertificateError::Invalid)
            }
            Ok(_) => {
                fs::remove_file(path)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ServerCertificateError::Io(error)),
        }
    }

    pub(crate) fn generate(&self) -> Result<(), ServerCertificateError> {
        if !self.config.enabled {
            return Err(ServerCertificateError::Disabled);
        }
        let _guard = self.lock()?;
        self.generate_locked()
    }

    fn generate_locked(&self) -> Result<(), ServerCertificateError> {
        let private_key = RsaPrivateKey::new(&mut rand::rng(), 2_048)
            .map_err(|_| ServerCertificateError::Generation)?;
        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|_| ServerCertificateError::Generation)?;
        let signing_key = InMemorySigningKeyPair::from_pkcs8_der(private_key_der.as_bytes())
            .map_err(|_| ServerCertificateError::Generation)?;
        let mut builder = X509CertificateBuilder::default();
        let common_name = format!("{} Server", self.config.organization_name);
        builder
            .subject()
            .append_common_name_utf8_string(&common_name)
            .map_err(|_| ServerCertificateError::Generation)?;
        builder
            .subject()
            .append_organization_utf8_string(&self.config.organization_name)
            .map_err(|_| ServerCertificateError::Generation)?;
        builder
            .subject()
            .append_country_utf8_string("US")
            .map_err(|_| ServerCertificateError::Generation)?;
        builder.serial_number(Utc::now().timestamp_millis().max(1));
        builder.validity_duration(chrono::Duration::days(i64::from(self.config.validity_days)));
        builder.constraint_not_ca();
        builder.key_usage(KeyUsage::DigitalSignature);
        let certificate = builder
            .create_with_key_pair(&signing_key)
            .map_err(|_| ServerCertificateError::Generation)?;
        let private_key = PrivateKey::from_der(private_key_der.as_bytes())
            .map_err(|_| ServerCertificateError::Generation)?;
        let certificate = Pkcs12Certificate::from_der(certificate.constructed_data())
            .map_err(|_| ServerCertificateError::Generation)?;
        let mut store = KeyStore::new();
        store.add_entry(
            KEYSTORE_ALIAS,
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                KEYSTORE_ALIAS,
                private_key,
                [certificate],
            )),
        );
        let bytes = Zeroizing::new(
            store
                .writer(&self.password)
                .write()
                .map_err(|_| ServerCertificateError::Generation)?,
        );
        write_private_file(&self.keystore_path(), &bytes)
    }

    fn certificate_der_locked(&self) -> Result<Vec<u8>, ServerCertificateError> {
        let store = self.load_store_locked()?;
        let (_, chain) = store
            .private_key_chain()
            .ok_or(ServerCertificateError::Invalid)?;
        chain
            .certs()
            .first()
            .map(|certificate| certificate.as_der().to_vec())
            .ok_or(ServerCertificateError::Invalid)
    }

    fn load_signing_key_locked(&self) -> Result<Pkcs12SigningKey, ServerCertificateError> {
        let bytes = read_keystore(&self.keystore_path())?;
        Pkcs12SigningKey::from_archive(
            SigningSecret::new(bytes.to_vec()),
            SigningSecret::new(self.password.as_bytes().to_vec()),
            Some(KEYSTORE_ALIAS),
        )
        .map_err(|_| ServerCertificateError::Invalid)
    }

    fn load_store_locked(&self) -> Result<KeyStore, ServerCertificateError> {
        let bytes = read_keystore(&self.keystore_path())?;
        KeyStore::from_pkcs12(&bytes, &self.password, Pkcs12ImportPolicy::Strict)
            .map_err(|_| ServerCertificateError::Invalid)
    }

    fn keystore_path(&self) -> PathBuf {
        self.config.config_directory.join(KEYSTORE_FILENAME)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ()>, ServerCertificateError> {
        self.operation_lock
            .lock()
            .map_err(|_| ServerCertificateError::Poisoned)
    }
}

pub(crate) fn routes() -> Router {
    Router::new()
        .route("/api/v1/admin/server-certificate/info", get(info))
        .route("/api/v1/admin/server-certificate/upload", post(upload))
        .route(
            "/api/v1/admin/server-certificate",
            delete(delete_certificate),
        )
        .route("/api/v1/admin/server-certificate/generate", post(generate))
        .route(
            "/api/v1/admin/server-certificate/certificate",
            get(download),
        )
        .route("/api/v1/admin/server-certificate/enabled", get(enabled))
        .layer(DefaultBodyLimit::max(ROUTE_BODY_LIMIT))
}

async fn info(Extension(service): Extension<std::sync::Arc<ServerCertificateService>>) -> Response {
    match task::spawn_blocking(move || service.info()).await {
        Ok(Ok(info)) => Json(info).into_response(),
        Ok(Err(error)) => certificate_error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn enabled(
    Extension(service): Extension<std::sync::Arc<ServerCertificateService>>,
) -> Response {
    Json(service.is_enabled()).into_response()
}

async fn upload(
    Extension(service): Extension<std::sync::Arc<ServerCertificateService>>,
    multipart: Multipart,
) -> Response {
    let (archive, password) = match read_upload(multipart).await {
        Ok(upload) => upload,
        Err(error) => return certificate_error_response(&error),
    };
    match task::spawn_blocking(move || service.upload(&archive, &password)).await {
        Ok(Ok(())) => "Server certificate uploaded successfully".into_response(),
        Ok(Err(error)) => certificate_error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn delete_certificate(
    Extension(service): Extension<std::sync::Arc<ServerCertificateService>>,
) -> Response {
    match task::spawn_blocking(move || service.delete()).await {
        Ok(Ok(())) => "Server certificate deleted successfully".into_response(),
        Ok(Err(error)) => certificate_error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn generate(
    Extension(service): Extension<std::sync::Arc<ServerCertificateService>>,
) -> Response {
    match task::spawn_blocking(move || service.generate()).await {
        Ok(Ok(())) => "New server certificate generated successfully".into_response(),
        Ok(Err(error)) => certificate_error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn download(
    Extension(service): Extension<std::sync::Arc<ServerCertificateService>>,
) -> Response {
    match task::spawn_blocking(move || service.certificate_der()).await {
        Ok(Ok(certificate)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/pkix-cert"),
            );
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"server-cert.cer\""),
            );
            (StatusCode::OK, headers, certificate).into_response()
        }
        Ok(Err(ServerCertificateError::Missing)) => StatusCode::NOT_FOUND.into_response(),
        Ok(Err(error)) => certificate_error_response(&error),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn read_upload(
    mut multipart: Multipart,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<String>), ServerCertificateError> {
    let mut archive = None;
    let mut password = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ServerCertificateError::Invalid)?
    {
        match field.name().unwrap_or_default() {
            "file" if archive.is_none() => {
                let filename = field.file_name().unwrap_or_default().to_owned();
                let content_type = field.content_type().map(ToOwned::to_owned);
                let supported_extension =
                    Path::new(&filename).extension().is_some_and(|extension| {
                        extension.eq_ignore_ascii_case("p12")
                            || extension.eq_ignore_ascii_case("pfx")
                    });
                if !supported_extension {
                    return Err(ServerCertificateError::Invalid);
                }
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| ServerCertificateError::Invalid)?;
                SecurityAuditContext::record_current_file_bytes(
                    &filename,
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    content_type.as_deref(),
                    &bytes,
                );
                if bytes.is_empty() || bytes.len() > MAX_KEYSTORE_BYTES {
                    return Err(ServerCertificateError::Invalid);
                }
                archive = Some(Zeroizing::new(bytes.to_vec()));
            }
            "password" if password.is_none() => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| ServerCertificateError::Invalid)?;
                if bytes.len() > MAX_PASSWORD_BYTES {
                    return Err(ServerCertificateError::Invalid);
                }
                password = Some(Zeroizing::new(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| ServerCertificateError::Invalid)?,
                ));
            }
            _ => {
                field
                    .bytes()
                    .await
                    .map_err(|_| ServerCertificateError::Invalid)?;
            }
        }
    }
    Ok((
        archive.ok_or(ServerCertificateError::Invalid)?,
        password.ok_or(ServerCertificateError::Invalid)?,
    ))
}

fn validate_uploaded_key(archive: &[u8], password: &str) -> Result<(), ServerCertificateError> {
    Pkcs12SigningKey::from_archive(
        SigningSecret::new(archive.to_vec()),
        SigningSecret::new(password.as_bytes().to_vec()),
        None,
    )
    .map(|_| ())
    .map_err(|_| ServerCertificateError::Invalid)
}

fn certificate_info(der: &[u8]) -> Result<ServerCertificateInfo, ServerCertificateError> {
    let (_, certificate) =
        parse_x509_certificate(der).map_err(|_| ServerCertificateError::Invalid)?;
    let valid_from = format_timestamp(
        certificate
            .validity()
            .not_before
            .to_datetime()
            .unix_timestamp(),
    )
    .ok_or(ServerCertificateError::Invalid)?;
    let valid_to = format_timestamp(
        certificate
            .validity()
            .not_after
            .to_datetime()
            .unix_timestamp(),
    )
    .ok_or(ServerCertificateError::Invalid)?;
    Ok(ServerCertificateInfo {
        exists: true,
        subject: Some(certificate.subject().to_string()),
        issuer: Some(certificate.issuer().to_string()),
        valid_from: Some(valid_from),
        valid_to: Some(valid_to),
    })
}

fn format_timestamp(timestamp: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn validate_config(config: &ServerCertificateConfig) -> Result<(), ServerCertificateError> {
    let organization = config.organization_name.trim();
    if organization.is_empty()
        || organization.len() > 128
        || organization.chars().any(char::is_control)
        || !(1..=3_650).contains(&config.validity_days)
    {
        return Err(ServerCertificateError::Invalid);
    }
    Ok(())
}

fn load_or_create_password(directory: &Path) -> Result<Zeroizing<String>, ServerCertificateError> {
    if let Some(password) = [
        "STIRLING_SERVER_CERTIFICATE_PASSWORD",
        "SYSTEM_SERVERCERTIFICATE_PASSWORD",
    ]
    .iter()
    .find_map(|name| std::env::var(name).ok())
    {
        return validate_password(Zeroizing::new(password));
    }
    let path = directory.join(PASSWORD_FILENAME);
    match read_password_file(&path) {
        Ok(password) => return Ok(password),
        Err(ServerCertificateError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let password = random_password();
    match create_private_file(&path, password.as_bytes()) {
        Ok(()) => Ok(password),
        Err(ServerCertificateError::Io(error))
            if error.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            read_password_file(&path)
        }
        Err(error) => Err(error),
    }
}

fn validate_password(
    password: Zeroizing<String>,
) -> Result<Zeroizing<String>, ServerCertificateError> {
    if password.len() < 16 || password.len() > 128 || password.chars().any(char::is_control) {
        Err(ServerCertificateError::Invalid)
    } else {
        Ok(password)
    }
}

fn read_password_file(path: &Path) -> Result<Zeroizing<String>, ServerCertificateError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 256 {
        return Err(ServerCertificateError::Invalid);
    }
    validate_password(Zeroizing::new(fs::read_to_string(path)?.trim().to_owned()))
}

fn random_password() -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    rand::rng().fill(bytes.as_mut());
    let mut password = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter().copied() {
        password.push(char::from(HEX[usize::from(byte >> 4)]));
        password.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    password
}

fn read_keystore(path: &Path) -> Result<Zeroizing<Vec<u8>>, ServerCertificateError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ServerCertificateError::Missing
        } else {
            ServerCertificateError::Io(error)
        }
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_KEYSTORE_BYTES as u64
    {
        return Err(ServerCertificateError::Invalid);
    }
    Ok(Zeroizing::new(fs::read(path)?))
}

fn safe_regular_file_exists(path: &Path) -> Result<bool, ServerCertificateError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(ServerCertificateError::Invalid)
        }
        Ok(metadata) if metadata.len() > MAX_KEYSTORE_BYTES as u64 => {
            Err(ServerCertificateError::Invalid)
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(ServerCertificateError::Io(error)),
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ServerCertificateError> {
    if bytes.is_empty() || bytes.len() > MAX_KEYSTORE_BYTES {
        return Err(ServerCertificateError::Invalid);
    }
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(ServerCertificateError::Invalid);
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    restrict_file_permissions(&file)?;
    Ok(())
}

fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), ServerCertificateError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    restrict_file_permissions(&file)?;
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(file: &fs::File) -> Result<(), ServerCertificateError> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn certificate_error_response(error: &ServerCertificateError) -> Response {
    match error {
        ServerCertificateError::Disabled | ServerCertificateError::Invalid => {
            (StatusCode::BAD_REQUEST, "Invalid certificate or password.").into_response()
        }
        ServerCertificateError::Missing => StatusCode::NOT_FOUND.into_response(),
        ServerCertificateError::Poisoned
        | ServerCertificateError::Io(_)
        | ServerCertificateError::Generation => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server certificate operation failed",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{ServerCertificateConfig, ServerCertificateService};
    use crate::signing_key::SigningKey as _;

    #[test]
    fn generates_reloads_and_deletes_a_managed_rsa_certificate()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let service = ServerCertificateService::new(ServerCertificateConfig {
            enabled: true,
            organization_name: "Stirling Test".to_owned(),
            validity_days: 30,
            regenerate_on_startup: false,
            config_directory: directory.path().to_path_buf(),
        })?;
        service.initialize()?;
        assert!(service.has_certificate()?);
        let info = service.info()?;
        assert!(info.exists);
        assert!(
            info.subject
                .as_deref()
                .is_some_and(|value| value.contains("Stirling Test"))
        );
        let mut signing_key = service.signing_key()?;
        assert!(
            !signing_key
                .sign(b"managed-signature-test")?
                .as_bytes()
                .is_empty()
        );
        let first_der = service.certificate_der()?;

        service.initialize()?;
        assert_eq!(service.certificate_der()?, first_der);
        service.delete()?;
        assert!(!service.has_certificate()?);
        Ok(())
    }
}
