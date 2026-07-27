//! Durable local identity and opaque-session primitives for secured mode.
//!
//! Passwords use Java-compatible `BCrypt`. Access, refresh, and API-key values are
//! random bearer secrets whose SHA-256 digests alone are persisted. Sessions are
//! server-side, revocable, rotated transactionally, and survive process restarts.
//! This module deliberately contains no HTTP fallback: callers must map every
//! error to a generic response and secured-mode startup remains fail-closed until
//! the surrounding middleware and route set pass security review.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    future::Future,
    path::Path,
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bcrypt::{DEFAULT_COST, hash, verify};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt as _;
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
    types::Value as SqlValue,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{io::AsyncReadExt as _, sync::Notify, task};
use zeroize::Zeroizing;

use crate::integration_config::{IntegrationConfig, IntegrationType, NewIntegrationConfig};
use crate::license::{LicenseState, LicenseVerification};
use crate::oidc_id_token::VerifiedOidcIdentity;
use crate::policy_config::{PolicyDefinition, PolicySource, SourceDocStats};
use crate::policy_ledger::{
    ClaimState, MAX_ATTEMPTS, ProcessedFileStatus, identity_hash as policy_identity_hash,
};
use crate::resource_access::{
    AccessPermission, DefaultAccessPolicy, OwnerScope, PrincipalType, ResourceGrant, ResourceType,
};
use crate::security_crypto::{
    ProtectedSecretCipher, SecurityCryptoError, generate_totp_secret, valid_totp_step,
};
use crate::security_jwt::VerifiedSupabaseIdentity;

const TOKEN_BYTES: usize = 32;
const MAX_BEARER_TOKEN_BYTES: usize = 128;
const MAX_USERNAME_BYTES: usize = 320;
// BCrypt ignores input after 72 bytes. Reject longer values so two distinct
// passwords can never authenticate as the same credential.
const MAX_PASSWORD_BYTES: usize = 72;
const MAX_ROLE_BYTES: usize = 64;
const MAX_AUDIT_VALUE_BYTES: usize = 512;
const MAX_FAILED_LOGINS: i64 = 5;
const LOCKOUT_SECONDS: i64 = 15 * 60;
// MFA backup codes: a fresh set replaces any prior one. Each code carries 80
// bits of CSPRNG entropy (10 octets -> 16 Base32 characters), grouped for
// human transcription and stored only as its SHA-256 digest.
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_BYTES: usize = 10;
const RECOVERY_CODE_GROUP: usize = 4;
const ACCESS_TOKEN_PREFIX: &str = "spdf_at_";
const REFRESH_TOKEN_PREFIX: &str = "spdf_rt_";
const API_KEY_PREFIX: &str = "spdf_ak_";
const SESSION_ID_PREFIX: &str = "spdf_sid_";
const INVITE_TOKEN_PREFIX: &str = "spdf_inv_";
const DEFAULT_TEAM_NAME: &str = "Default";
pub(crate) const INTERNAL_TEAM_NAME: &str = "Internal";
pub(crate) const INTERNAL_API_USERNAME: &str = "STIRLING-PDF-BACKEND-API-USER";
const MAX_TEAM_NAME_BYTES: usize = 100;
const MAX_EXTERNAL_ISSUER_BYTES: usize = 2_048;
const MAX_EXTERNAL_SUBJECT_BYTES: usize = 128;
const MAX_EXTERNAL_SESSION_ID_BYTES: usize = 256;
const MAX_PERMISSION_BYTES: usize = 128;
const MAX_EXTERNAL_PERMISSIONS: usize = 128;
const DEFAULT_USER_LIMIT: i64 = 5;
const UNLIMITED_USER_LIMIT: i64 = i32::MAX as i64;
const USER_LICENSE_SETTINGS_ID: i64 = 1;
const USER_SEAT_INTEGRITY_SECRET: &[u8] = b"stirling-pdf-user-license-guard";
const MAX_USER_SETTINGS: usize = 128;
const MAX_USER_SETTING_KEY_BYTES: usize = 256;
const MAX_USER_SETTING_VALUE_BYTES: usize = 4 * 1024;
const MAX_AUDIT_FILTER_VALUES: usize = 32;
const MAX_AUDIT_EXPORT_EVENTS: usize = 50_000;
const MAX_AUDIT_FILES: usize = 100;
const MAX_AUDIT_FILENAME_CHARS: usize = 255;
const MAX_AUDIT_CONTENT_TYPE_CHARS: usize = 128;
const MAX_AUDIT_PDF_AUTHOR_CHARS: usize = 512;
const MAX_AUDIT_FORM_VALUES: usize = 128;
const MAX_AUDIT_FORM_NAME_CHARS: usize = 128;
const MAX_AUDIT_FORM_VALUE_CHARS: usize = 2_048;
const REDACTED_AUDIT_FORM_VALUE: &str = "[REDACTED]";
const MAX_AUDIT_POLICY_LABEL_CHARS: usize = 200;
const MAX_AUDIT_POLICY_STEPS: usize = 50;
// Portal personal API-key bounds, mirroring Java `ApiKeyManagementService` /
// `ApiKeyHasher`.
/// Non-secret leading fragment kept for display (Java `DISPLAY_PREFIX_LENGTH`).
const API_KEY_DISPLAY_PREFIX_LEN: usize = 11;
/// Caps active keys per user so key creation can't multiply rate-limit budget
/// (Java `MAX_ACTIVE_KEYS_PER_USER`).
const MAX_ACTIVE_API_KEYS_PER_USER: i64 = 50;
/// Rolling window (days) for the portal "usage this month" figure
/// (Java `MONTH_WINDOW_DAYS`).
const API_KEY_MONTH_WINDOW_DAYS: i64 = 30;

pub const DEFAULT_ACCESS_TTL: Duration = Duration::from_secs(60 * 60);
pub const DEFAULT_REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Trusted request identity created by authentication middleware, never by a
/// request payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthContext {
    pub user_id: i64,
    pub username: String,
    pub authentication_source: AuthenticationSource,
    pub authentication_type: String,
    pub roles: BTreeSet<String>,
    pub team_id: Option<i64>,
    pub permissions: BTreeSet<String>,
    pub external_subject: Option<String>,
    pub force_password_change: bool,
    pub session_id: String,
    pub correlation_id: String,
}

impl AuthContext {
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthenticationSource {
    Password,
    AccessToken,
    ApiKey,
    SupabaseJwt,
    Oidc,
}

/// Newly issued secrets. These values are never persisted in plaintext and are
/// zeroized when the response owner drops them.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct SessionTokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
    pub expires_in: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityTeam {
    pub id: i64,
    pub name: String,
    pub member_count: i64,
}

/// One personal API key as the portal Infrastructure → API Keys tab lists it.
/// Never carries the secret; the plaintext is returned exactly once at creation.
/// Usage figures are aggregated from `security_api_key_daily_usage`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyRecord {
    pub key_id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub usage_today: i64,
    pub usage_month: i64,
    pub usage_total: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityUserSummary {
    pub id: i64,
    pub email: String,
    pub username: String,
    pub role: String,
    pub roles: Vec<String>,
    pub enabled: bool,
    pub authentication_type: String,
    pub team_id: Option<i64>,
    pub team_name: Option<String>,
    #[serde(flatten)]
    pub credential_state: SecurityUserCredentialState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityUserCredentialState {
    pub mfa_enabled: bool,
    pub locked: bool,
    pub force_password_change: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedInvite {
    pub token: Zeroizing<String>,
    pub email: Option<String>,
    pub role: String,
    pub team_id: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteDetails {
    pub email: Option<String>,
    pub role: String,
    pub team_id: i64,
    pub expires_at: i64,
    pub email_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteSummary {
    pub id: i64,
    pub email: Option<String>,
    pub role: String,
    pub team_id: i64,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Default)]
pub struct SecurityAuditFilter {
    pub event_types: Vec<String>,
    pub principals: Vec<String>,
    pub principal_contains: Option<String>,
    pub start_at: Option<i64>,
    pub end_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditEvent {
    pub id: i64,
    pub principal: String,
    pub event_type: String,
    pub source: String,
    pub data: String,
    pub timestamp: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecurityAuditFile {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) content_type: Option<String>,
    pub(crate) file_hash: Option<String>,
    pub(crate) pdf_author: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SecurityAuditFileCapture {
    pub(crate) hash: bool,
    pub(crate) pdf_author: bool,
}

impl SecurityAuditFile {
    fn metadata(name: &str, size: u64, content_type: Option<&str>) -> Option<Self> {
        Some(Self {
            name: bounded_audit_filename(name)?,
            size,
            content_type: content_type
                .and_then(|value| bounded_audit_value(value, MAX_AUDIT_CONTENT_TYPE_CHARS)),
            file_hash: None,
            pdf_author: None,
        })
    }

    pub(crate) async fn from_path(
        name: &str,
        size: u64,
        content_type: Option<&str>,
        path: &Path,
        capture: SecurityAuditFileCapture,
    ) -> Option<Self> {
        let mut file = Self::metadata(name, size, content_type)?;
        if capture.hash {
            file.file_hash = sha256_file(path).await;
        }
        if capture.pdf_author && is_pdf_content_type(content_type) {
            let path = path.to_owned();
            file.pdf_author = task::spawn_blocking(move || pdf_author_from_path(&path))
                .await
                .ok()
                .flatten();
        }
        Some(file)
    }

    fn from_bytes(
        name: &str,
        size: u64,
        content_type: Option<&str>,
        bytes: &[u8],
        capture: SecurityAuditFileCapture,
    ) -> Option<Self> {
        let mut file = Self::metadata(name, size, content_type)?;
        if capture.hash {
            file.file_hash = Some(lowercase_hex(&Sha256::digest(bytes)));
        }
        if capture.pdf_author && is_pdf_content_type(content_type) {
            file.pdf_author = pdf_author_from_bytes(bytes);
        }
        Some(file)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SecurityAuditEnrichment {
    pub(crate) files: Vec<SecurityAuditFile>,
    pub(crate) form_params: BTreeMap<String, Vec<String>>,
    pub(crate) automation: bool,
    pub(crate) policy_name: Option<String>,
    pub(crate) policy_steps: Vec<String>,
}

impl SecurityAuditEnrichment {
    pub(crate) fn policy_step(
        policy_name: &str,
        files: Vec<SecurityAuditFile>,
        include_files: bool,
    ) -> Self {
        Self {
            files: if include_files { files } else { Vec::new() },
            form_params: BTreeMap::new(),
            automation: true,
            policy_name: bounded_audit_label(policy_name),
            policy_steps: Vec::new(),
        }
    }

    fn merge_into(&self, data: &mut serde_json::Value) {
        if !self.files.is_empty() {
            data["files"] = serde_json::Value::Array(
                self.files
                    .iter()
                    .map(|file| {
                        let mut data = serde_json::json!({
                            "name": file.name,
                            "size": file.size,
                            "type": file.content_type,
                        });
                        if let Some(file_hash) = &file.file_hash {
                            data["fileHash"] = serde_json::Value::String(file_hash.clone());
                        }
                        if let Some(pdf_author) = &file.pdf_author {
                            data["pdfAuthor"] = serde_json::Value::String(pdf_author.clone());
                        }
                        data
                    })
                    .collect(),
            );
        }
        if !self.form_params.is_empty() {
            data["formParams"] = serde_json::json!(self.form_params);
        }
        if self.automation {
            data["automation"] = serde_json::Value::Bool(true);
        }
        if let Some(policy_name) = &self.policy_name {
            data["policyName"] = serde_json::Value::String(policy_name.clone());
        }
        if !self.policy_steps.is_empty() {
            data["policySteps"] = serde_json::Value::Array(
                self.policy_steps
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            );
        }
    }

    pub(crate) fn record_form_param(&mut self, name: &str, value: &str) {
        if name == "_csrf" {
            return;
        }
        let sensitive = is_sensitive_audit_form_name(name);
        let Some(name) = bounded_audit_form_name(name) else {
            return;
        };
        let value_count = self.form_params.values().map(Vec::len).sum::<usize>();
        if value_count >= MAX_AUDIT_FORM_VALUES {
            return;
        }
        let value = if sensitive {
            REDACTED_AUDIT_FORM_VALUE.to_owned()
        } else {
            bounded_audit_form_value(value)
        };
        self.form_params.entry(name).or_default().push(value);
    }
}

/// Request-scoped enrichment populated by handlers after multipart parsing.
///
/// The security middleware owns the outer request and snapshots this context
/// after the handler returns. Generic asynchronous jobs defer that snapshot
/// until their background handler has replayed the persisted body. This mirrors
/// Java's request attributes without buffering or replaying streamed request
/// bodies in middleware.
#[derive(Clone, Debug)]
pub(crate) struct SecurityAuditContext {
    enrichment: Arc<Mutex<SecurityAuditEnrichment>>,
    completion: Arc<SecurityAuditCompletion>,
    file_capture: SecurityAuditFileCapture,
    include_standard_data: bool,
}

#[derive(Debug, Default)]
struct SecurityAuditCompletion {
    deferred: AtomicBool,
    complete: AtomicBool,
    notify: Notify,
}

/// Marks a deferred request audit complete even when its worker exits early.
#[derive(Debug)]
pub(crate) struct SecurityAuditCompletionGuard {
    context: SecurityAuditContext,
}

impl Drop for SecurityAuditCompletionGuard {
    fn drop(&mut self) {
        self.context.complete_deferred();
    }
}

tokio::task_local! {
    static CURRENT_SECURITY_AUDIT_CONTEXT: SecurityAuditContext;
}

impl Default for SecurityAuditContext {
    fn default() -> Self {
        Self::new(false)
    }
}

impl SecurityAuditContext {
    pub(crate) fn new(include_files: bool) -> Self {
        Self::with_file_capture(include_files, SecurityAuditFileCapture::default())
    }

    pub(crate) fn with_file_capture(
        include_files: bool,
        file_capture: SecurityAuditFileCapture,
    ) -> Self {
        Self {
            enrichment: Arc::new(Mutex::new(SecurityAuditEnrichment::default())),
            completion: Arc::new(SecurityAuditCompletion::default()),
            file_capture,
            include_standard_data: include_files,
        }
    }

    pub(crate) async fn scope<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        CURRENT_SECURITY_AUDIT_CONTEXT
            .scope(self.clone(), future)
            .await
    }

    pub(crate) async fn record_current_file_path(
        name: &str,
        size: u64,
        content_type: Option<&str>,
        path: &Path,
    ) {
        let Ok(context) = CURRENT_SECURITY_AUDIT_CONTEXT.try_with(Clone::clone) else {
            return;
        };
        if !context.can_record_file() {
            return;
        }
        if let Some(file) =
            SecurityAuditFile::from_path(name, size, content_type, path, context.file_capture).await
        {
            context.push_file(file);
        }
    }

    pub(crate) fn record_current_file_bytes(
        name: &str,
        size: u64,
        content_type: Option<&str>,
        bytes: &[u8],
    ) {
        let _ = CURRENT_SECURITY_AUDIT_CONTEXT.try_with(|context| {
            if !context.can_record_file() {
                return;
            }
            if let Some(file) =
                SecurityAuditFile::from_bytes(name, size, content_type, bytes, context.file_capture)
            {
                context.push_file(file);
            }
        });
    }

    pub(crate) fn record_current_form_param(name: &str, value: &str) {
        let _ = CURRENT_SECURITY_AUDIT_CONTEXT
            .try_with(|context| context.record_form_param(name, value));
    }

    /// Defers the middleware snapshot until the returned worker guard drops.
    ///
    /// Generic asynchronous requests return a job identifier before their
    /// replayed multipart body reaches the handler. Sharing this context with
    /// that worker preserves streamed file enrichment without another body
    /// pass in the submission request.
    pub(crate) fn defer(&self) -> SecurityAuditCompletionGuard {
        self.completion.deferred.store(true, Ordering::Release);
        SecurityAuditCompletionGuard {
            context: self.clone(),
        }
    }

    pub(crate) fn is_deferred(&self) -> bool {
        self.completion.deferred.load(Ordering::Acquire)
    }

    pub(crate) async fn wait_for_deferred_completion(&self) {
        while !self.completion.complete.load(Ordering::Acquire) {
            let notified = self.completion.notify.notified();
            if self.completion.complete.load(Ordering::Acquire) {
                break;
            }
            notified.await;
        }
    }

    fn complete_deferred(&self) {
        self.completion.complete.store(true, Ordering::Release);
        self.completion.notify.notify_waiters();
    }

    #[cfg(test)]
    fn record_file(&self, name: &str, size: u64, content_type: Option<&str>) {
        let Some(file) = SecurityAuditFile::metadata(name, size, content_type) else {
            return;
        };
        self.push_file(file);
    }

    fn can_record_file(&self) -> bool {
        self.include_standard_data
            && self
                .enrichment
                .lock()
                .is_ok_and(|enrichment| enrichment.files.len() < MAX_AUDIT_FILES)
    }

    fn push_file(&self, file: SecurityAuditFile) {
        if !self.include_standard_data {
            return;
        }
        let Ok(mut enrichment) = self.enrichment.lock() else {
            return;
        };
        if enrichment.files.len() >= MAX_AUDIT_FILES {
            return;
        }
        enrichment.files.push(file);
    }

    fn record_form_param(&self, name: &str, value: &str) {
        if !self.include_standard_data {
            return;
        }
        let Ok(mut enrichment) = self.enrichment.lock() else {
            return;
        };
        enrichment.record_form_param(name, value);
    }

    pub(crate) fn set_policy(&self, name: &str, steps: impl IntoIterator<Item = String>) {
        let Ok(mut enrichment) = self.enrichment.lock() else {
            return;
        };
        enrichment.policy_name = bounded_audit_label(name);
        enrichment.policy_steps = steps
            .into_iter()
            .take(MAX_AUDIT_POLICY_STEPS)
            .filter_map(|step| bounded_audit_label(&step))
            .collect();
    }

    pub(crate) fn snapshot(&self) -> SecurityAuditEnrichment {
        self.enrichment
            .lock()
            .map(|enrichment| enrichment.clone())
            .unwrap_or_default()
    }
}

async fn sha256_file(path: &Path) -> Option<String> {
    let mut input = tokio::fs::File::open(path).await.ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = input.read(&mut buffer).await.ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(lowercase_hex(&digest.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn is_pdf_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/pdf"))
}

fn pdf_author_from_path(path: &Path) -> Option<String> {
    let document = lopdf::Document::load(path).ok()?;
    pdf_author(&document)
}

fn pdf_author_from_bytes(bytes: &[u8]) -> Option<String> {
    let document = lopdf::Document::load_mem(bytes).ok()?;
    pdf_author(&document)
}

fn pdf_author(document: &lopdf::Document) -> Option<String> {
    let info = document.trailer.get(b"Info").ok()?;
    let (_, info) = document.dereference(info).ok()?;
    let author = info.as_dict().ok()?.get(b"Author").ok()?;
    let (_, author) = document.dereference(author).ok()?;
    let author = lopdf::decode_text_string(author).ok()?;
    bounded_audit_value(&author, MAX_AUDIT_PDF_AUTHOR_CHARS)
}

fn bounded_audit_filename(value: &str) -> Option<String> {
    let filename = value.rsplit(['/', '\\']).next().unwrap_or(value);
    bounded_audit_value(filename, MAX_AUDIT_FILENAME_CHARS)
}

fn bounded_audit_form_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.chars().take(MAX_AUDIT_FORM_NAME_CHARS).collect())
}

fn bounded_audit_form_value(value: &str) -> String {
    value.chars().take(MAX_AUDIT_FORM_VALUE_CHARS).collect()
}

fn is_sensitive_audit_form_name(value: &str) -> bool {
    let normalized = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "privatekey",
        "credential",
        "authorization",
        "cookie",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
        || normalized == "pin"
        || normalized.ends_with("pincode")
        || normalized.ends_with("pin")
}

fn bounded_audit_value(value: &str, limit: usize) -> Option<String> {
    let value = value.replace(['\r', '\n'], " ");
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    Some(value.chars().take(limit).collect())
}

fn bounded_audit_label(value: &str) -> Option<String> {
    bounded_audit_value(value, MAX_AUDIT_POLICY_LABEL_CHARS)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAuditPage {
    pub events: Vec<SecurityAuditEvent>,
    pub total_events: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct SecurityHttpAuditRecord {
    pub context: Option<AuthContext>,
    pub client_ip: Option<String>,
    pub correlation_id: String,
    pub source: String,
    pub event_type: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub latency_ms: u64,
    pub include_standard_data: bool,
    pub annotated: bool,
    pub result: Option<String>,
    pub enrichment: SecurityAuditEnrichment,
    pub created_at: i64,
    pub timestamp: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetUsageStats {
    pub editors_deployed: i64,
    pub active_this_month: Option<i64>,
    pub pdfs_processed: Option<i64>,
}

/// Durable user-allocation values exposed to administrator surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSeatMetrics {
    pub max_allowed_users: i64,
    pub available_slots: i64,
    pub grandfathered_user_count: i64,
    pub license_max_users: i64,
    pub premium_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecurityAuditUsageScope {
    All,
    Ui,
    Api,
}

/// Durable security state for one standalone Rust process.
pub struct SecurityStore {
    connection: Mutex<Connection>,
    bcrypt_cost: u32,
    secret_cipher: Option<ProtectedSecretCipher>,
    license_state: RwLock<Option<Arc<LicenseState>>>,
}

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("authentication failed")]
    InvalidCredentials,
    #[error("authentication failed")]
    AccountLocked,
    #[error("authentication failed")]
    AccountDisabled,
    #[error("authentication token is invalid")]
    InvalidToken,
    #[error("authentication token is expired")]
    ExpiredToken,
    #[error("security input is invalid")]
    InvalidInput,
    #[error("security identity was not found")]
    UserNotFound,
    #[error("security team was not found")]
    TeamNotFound,
    #[error("security state conflicts with an existing record")]
    Conflict,
    #[error("active API key limit reached")]
    TooManyApiKeys,
    #[error("security user limit reached (allowed: {max_allowed}, available: {available_slots})")]
    UserLimitReached {
        max_allowed: i64,
        available_slots: i64,
    },
    #[error("system-owned security state cannot be changed")]
    ProtectedSystemState,
    #[error("security team must be empty")]
    TeamNotEmpty,
    #[error("invitation is invalid or expired")]
    InvalidInvite,
    #[error("multi-factor authentication is required")]
    MfaRequired,
    #[error("multi-factor authentication failed")]
    InvalidMfa,
    #[error("multi-factor authentication setup is required")]
    MfaSetupRequired,
    #[error("multi-factor authentication configuration is unavailable")]
    MfaConfiguration,
    #[error("integration credential encryption is unavailable")]
    IntegrationProtectionUnavailable,
    #[error("multi-factor authentication is already enabled")]
    MfaAlreadyEnabled,
    #[error("multi-factor authentication is unavailable for this account")]
    UnsupportedAuthenticationSource,
    #[error("security state is unavailable")]
    Poisoned,
    #[error("security store operation failed")]
    Storage(#[source] rusqlite::Error),
    #[error("audit query exceeds the bounded event limit")]
    AuditEventLimitExceeded,
    #[error("credential hashing failed")]
    PasswordHash(#[source] bcrypt::BcryptError),
    #[error("security store filesystem setup failed")]
    Filesystem(#[source] std::io::Error),
    #[error("protected security state is unavailable")]
    SecretProtection(#[source] SecurityCryptoError),
}

impl From<rusqlite::Error> for SecurityError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<bcrypt::BcryptError> for SecurityError {
    fn from(error: bcrypt::BcryptError) -> Self {
        Self::PasswordHash(error)
    }
}

impl From<SecurityCryptoError> for SecurityError {
    fn from(error: SecurityCryptoError) -> Self {
        Self::SecretProtection(error)
    }
}

#[derive(Clone)]
struct StoredUser {
    id: i64,
    username: String,
    password_hash: String,
    enabled: bool,
    authentication_type: String,
    team_id: Option<i64>,
    force_password_change: bool,
}

struct StoredSession {
    session_id: String,
    user_id: i64,
    expires_at: i64,
    revoked: bool,
}

impl SecurityStore {
    /// Opens or creates the standalone security database.
    ///
    /// # Errors
    ///
    /// Returns an error when its parent directory cannot be created, `SQLite`
    /// cannot be opened/configured, or the schema migration fails.
    pub fn open(path: &Path) -> Result<Self, SecurityError> {
        Self::open_internal(path, None)
    }

    /// Opens durable identity state with authenticated encryption enabled for
    /// MFA and future stored credentials.
    ///
    /// # Errors
    ///
    /// Returns an error for filesystem, `SQLite`, or schema initialization
    /// failures.
    pub fn open_protected(
        path: &Path,
        secret_cipher: ProtectedSecretCipher,
    ) -> Result<Self, SecurityError> {
        Self::open_internal(path, Some(secret_cipher))
    }

    fn open_internal(
        path: &Path,
        secret_cipher: Option<ProtectedSecretCipher>,
    ) -> Result<Self, SecurityError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(SecurityError::Filesystem)?;
        }
        let connection = Connection::open(path)?;
        initialize_connection(&connection)?;
        #[cfg(unix)]
        restrict_database_permissions(path)?;
        Ok(Self {
            connection: Mutex::new(connection),
            bcrypt_cost: DEFAULT_COST,
            secret_cipher,
            license_state: RwLock::new(None),
        })
    }

    /// Connects the verified live license result to durable seat accounting.
    /// Subsequent administrator mutations and periodic refreshes update the
    /// repository immediately through a weak callback.
    ///
    /// # Errors
    ///
    /// Returns an error when the durable seat settings cannot be synchronized.
    pub fn attach_license_state(
        self: &Arc<Self>,
        state: &Arc<LicenseState>,
    ) -> Result<(), SecurityError> {
        *self
            .license_state
            .write()
            .map_err(|_| SecurityError::Poisoned)? = Some(Arc::clone(state));
        let store = Arc::downgrade(self);
        state.subscribe(move |_| {
            let Some(store) = store.upgrade() else {
                return;
            };
            if let Err(error) = store.synchronize_license_max_users() {
                tracing::warn!(%error, "failed to synchronize verified user-seat entitlement");
            }
        });
        self.synchronize_license_max_users()
    }

    /// Returns the effective allocation and durable grandfathering values.
    ///
    /// # Errors
    ///
    /// Returns an error when the security repository is unavailable.
    pub fn user_seat_metrics(&self) -> Result<UserSeatMetrics, SecurityError> {
        let verification = self.current_license_verification()?;
        let connection = self.lock()?;
        seat_metrics(&connection, verification)
    }

    fn current_license_verification(&self) -> Result<LicenseVerification, SecurityError> {
        let state = self
            .license_state
            .read()
            .map_err(|_| SecurityError::Poisoned)?
            .clone();
        Ok(state.map_or_else(LicenseVerification::default, |state| state.current()))
    }

    fn synchronize_license_max_users(&self) -> Result<(), SecurityError> {
        // Take the database lock before reading the authoritative state so
        // concurrent refresh callbacks cannot persist an older result last.
        let connection = self.lock()?;
        let verification = self.current_license_verification()?;
        let license_max_users = if verification.running_pro_or_higher() {
            i64::from(verification.max_users)
        } else {
            0
        };
        connection.execute(
            "UPDATE user_license_settings SET license_max_users = ?1 WHERE id = ?2",
            params![license_max_users, USER_LICENSE_SETTINGS_ID],
        )?;
        Ok(())
    }

    /// Creates the first administrator only when the user table is empty.
    /// The caller must obtain credentials from trusted configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, password hashing failure, or
    /// unavailable persistent state.
    pub fn bootstrap_admin(&self, username: &str, password: &str) -> Result<bool, SecurityError> {
        self.create_first_user(username, password, ["ROLE_ADMIN"])
    }

    /// Reports whether durable identity state already contains any users.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn has_users(&self) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        let count: i64 =
            connection.query_row("SELECT COUNT(*) FROM security_users", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    /// Creates a local `BCrypt` user. This is the repository boundary used later
    /// by reviewed administrator and invitation handlers.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity data, duplicate users, password
    /// hashing failure, or unavailable persistent state.
    pub fn create_local_user<const N: usize>(
        &self,
        username: &str,
        password: &str,
        roles: [&str; N],
        team_id: Option<i64>,
    ) -> Result<i64, SecurityError> {
        let username = normalize_web_username(username)?;
        validate_password(password)?;
        let roles = normalize_roles(roles)?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let verification = self.current_license_verification()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if find_user(&transaction, &username.normalized)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        ensure_user_capacity(&transaction, verification, 1)?;
        let team_id = resolve_team_id(&transaction, team_id)?;
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 1, 'web', ?4)",
            params![
                username.original,
                username.normalized,
                password_hash,
                team_id
            ],
        )?;
        let user_id = transaction.last_insert_rowid();
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        transaction.commit()?;
        Ok(user_id)
    }

    /// Verifies that a bulk account invitation fits within the standalone
    /// community user allocation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty request, insufficient user slots, or
    /// unavailable persistent state.
    pub fn ensure_bulk_user_invite_capacity(
        &self,
        requested_users: usize,
    ) -> Result<(), SecurityError> {
        let requested_users =
            i64::try_from(requested_users).map_err(|_| SecurityError::InvalidInput)?;
        if requested_users == 0 {
            return Err(SecurityError::InvalidInput);
        }
        let verification = self.current_license_verification()?;
        let connection = self.lock()?;
        ensure_user_capacity(&connection, verification, requested_users)
    }

    /// Resolves the default invitation team and rejects the Internal team.
    /// An explicitly requested missing team is preserved so Java-compatible
    /// bulk handling can report it as an individual invitation failure.
    ///
    /// # Errors
    ///
    /// Returns an error for the Internal team or unavailable persistent state.
    pub fn resolve_bulk_user_invite_team(
        &self,
        team_id: Option<i64>,
    ) -> Result<i64, SecurityError> {
        let connection = self.lock()?;
        let team_id = match team_id {
            Some(team_id) => team_id,
            None => resolve_team_id(&connection, None)?,
        };
        if team_name_by_id(&connection, team_id)?
            .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        Ok(team_id)
    }

    /// Creates an enabled web user whose generated password must be replaced
    /// after the first login. The user allocation is checked in the same write
    /// transaction so concurrent invitation requests cannot exceed it.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity data or role, duplicate users, a
    /// full allocation, a missing/system team, password hashing failure, or
    /// unavailable persistent state.
    pub fn create_invited_local_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
        team_id: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_web_username(username)?;
        validate_password(password)?;
        let role = normalize_invitable_role(role)?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let verification = self.current_license_verification()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if find_user(&transaction, &username.normalized)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        ensure_user_capacity(&transaction, verification, 1)?;
        let team_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id,
              force_password_change)
             VALUES (?1, ?2, ?3, 1, 'web', ?4, 1)",
            params![
                username.original,
                username.normalized,
                password_hash,
                team_id
            ],
        )?;
        let user_id = transaction.last_insert_rowid();
        let roles = BTreeSet::from([role]);
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        transaction.commit()?;
        Ok(user_id)
    }

    /// Creates a disabled self-registration account in the Default team.
    /// The community user limit is checked in the same write transaction so
    /// concurrent registrations cannot overrun it.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid or duplicate credentials, a full account
    /// allocation, password hashing failure, or unavailable persistent state.
    pub fn register_local_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<i64, SecurityError> {
        let username = normalize_web_username(username)?;
        validate_password(password)?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let verification = self.current_license_verification()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if find_user(&transaction, &username.normalized)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        ensure_user_capacity(&transaction, verification, 1)?;
        let team_id = resolve_team_id(&transaction, None)?;
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 0, 'web', ?4)",
            params![
                username.original,
                username.normalized,
                password_hash,
                team_id
            ],
        )?;
        let user_id = transaction.last_insert_rowid();
        insert_roles(
            &transaction,
            user_id,
            &["ROLE_USER".to_owned()].into_iter().collect(),
        )?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        transaction.commit()?;
        Ok(user_id)
    }

    /// Atomically replaces every user-owned preference with the supplied map.
    ///
    /// # Errors
    ///
    /// Returns an error for missing users, oversized/invalid entries, or
    /// unavailable persistent state.
    pub fn replace_user_settings(
        &self,
        user_id: i64,
        settings: &BTreeMap<String, String>,
    ) -> Result<(), SecurityError> {
        validate_user_settings(settings)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if find_user_by_id(&transaction, user_id)?.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        transaction.execute(
            "DELETE FROM security_user_settings WHERE user_id = ?1",
            [user_id],
        )?;
        for (key, value) in settings {
            transaction.execute(
                "INSERT INTO security_user_settings (user_id, setting_key, setting_value)
                 VALUES (?1, ?2, ?3)",
                params![user_id, key, value],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Reads the complete durable preference map for one user.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing user or unavailable persistent state.
    pub fn user_settings(&self, user_id: i64) -> Result<BTreeMap<String, String>, SecurityError> {
        let connection = self.lock()?;
        if find_user_by_id(&connection, user_id)?.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        let mut statement = connection.prepare(
            "SELECT setting_key, setting_value FROM security_user_settings
             WHERE user_id = ?1 ORDER BY setting_key",
        )?;
        statement
            .query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(SecurityError::from)
    }

    /// Marks the authenticated user's first-run setup as complete.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing user or unavailable persistent state.
    pub fn complete_initial_setup(&self, user_id: i64) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        let updated = connection.execute(
            "UPDATE security_users SET initial_setup_completed = 1 WHERE user_id = ?1",
            [user_id],
        )?;
        if updated == 0 {
            return Err(SecurityError::UserNotFound);
        }
        Ok(())
    }

    /// Reports whether the durable first-run setup marker is complete.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing user or unavailable persistent state.
    pub fn initial_setup_is_complete(&self, user_id: i64) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT initial_setup_completed FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)
    }

    /// Resolves or provisions a fully verified Supabase subject without ever
    /// linking by email. Anonymous identities may upgrade to a full identity
    /// for the same `(issuer, subject)` but never downgrade or cross-link.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/conflicting identity state, disabled users,
    /// or unavailable persistence.
    pub fn authenticate_supabase_identity(
        &self,
        identity: &VerifiedSupabaseIdentity,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        validate_external_identity(identity, now)?;
        let username = normalize_username(&identity.username)?;
        let verification = self.current_license_verification()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user = resolve_external_user(&transaction, identity, &username, verification, now)?;
        let mut context = context_for_user(
            &transaction,
            &user,
            AuthenticationSource::SupabaseJwt,
            identity.session_id.clone(),
            correlation_id,
        )?;
        context.permissions.clone_from(&identity.permissions);
        context.external_subject = Some(identity.subject.clone());
        transaction.commit()?;
        Ok(context)
    }

    /// Resolves or provisions a verified generic-OIDC subject, reusing the exact
    /// same external-identity machinery as [`Self::authenticate_supabase_identity`].
    ///
    /// The verified OIDC identity is mapped onto the issuer-agnostic external
    /// identity shape ([`external_identity_from_oidc`]) and then run through the
    /// unchanged [`validate_external_identity`] / [`resolve_external_user`] /
    /// [`context_for_user`] path. Persistence is keyed by `(issuer, subject)` in
    /// the shared `security_external_identities` table, so an OIDC subject and a
    /// Supabase subject can never collide unless they share an issuer *and* a
    /// subject — i.e. are the same account at the same provider.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/conflicting identity state, disabled users,
    /// or unavailable persistence.
    pub fn authenticate_oidc_identity(
        &self,
        identity: &VerifiedOidcIdentity,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        let external = external_identity_from_oidc(identity);
        validate_external_identity(&external, now)?;
        let username = normalize_username(&external.username)?;
        let verification = self.current_license_verification()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user = resolve_external_user(&transaction, &external, &username, verification, now)?;
        let mut context = context_for_user(
            &transaction,
            &user,
            AuthenticationSource::Oidc,
            external.session_id.clone(),
            correlation_id,
        )?;
        context.permissions.clone_from(&external.permissions);
        context.external_subject = Some(external.subject.clone());
        transaction.commit()?;
        Ok(context)
    }

    /// Lists durable users and their live role, team, MFA, and lockout state.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn list_users(&self, now: i64) -> Result<Vec<SecurityUserSummary>, SecurityError> {
        let connection = self.lock()?;
        let rows = {
            let mut statement = connection.prepare(
                "SELECT u.user_id, u.username, u.username_norm, u.enabled,
                        u.authentication_type, u.team_id, t.name,
                        EXISTS(
                            SELECT 1 FROM security_mfa m
                            WHERE m.user_id = u.user_id AND m.enabled = 1
                        ), u.force_password_change
                 FROM security_users u
                 LEFT JOIN security_teams t ON t.team_id = u.team_id
                 ORDER BY u.username COLLATE NOCASE",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, bool>(7)?,
                        row.get::<_, bool>(8)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut users = Vec::with_capacity(rows.len());
        for (
            id,
            username,
            username_norm,
            enabled,
            authentication_type,
            team_id,
            team_name,
            mfa_enabled,
            force_password_change,
        ) in rows
        {
            let roles = roles_for_user(&connection, id)?
                .into_iter()
                .collect::<Vec<_>>();
            let role = roles.join(",");
            let locked = login_is_locked(&connection, &username_norm, now)?;
            users.push(SecurityUserSummary {
                id,
                email: username.clone(),
                username,
                role,
                roles,
                enabled,
                authentication_type,
                team_id,
                team_name,
                credential_state: SecurityUserCredentialState {
                    mfa_enabled,
                    locked,
                    force_password_change,
                },
            });
        }
        Ok(users)
    }

    /// Changes the authenticated local user's password and revokes all of
    /// their sessions atomically.
    ///
    /// # Errors
    ///
    /// Returns an authentication, input, conflict, or persistence error.
    pub fn change_own_password(
        &self,
        user_id: i64,
        current_password: &str,
        new_password: &str,
        now: i64,
    ) -> Result<(), SecurityError> {
        validate_password(current_password)?;
        validate_password(new_password)?;
        if current_password == new_password {
            return Err(SecurityError::Conflict);
        }
        let current_hash = self.web_password_hash(user_id)?;
        if !verify(current_password, &current_hash)? {
            return Err(SecurityError::InvalidCredentials);
        }
        let replacement_hash = hash(new_password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_users
             SET password_hash = ?1, force_password_change = 0
             WHERE user_id = ?2 AND password_hash = ?3 AND authentication_type = 'web'",
            params![replacement_hash, user_id, current_hash],
        )?;
        if updated != 1 {
            return Err(SecurityError::Conflict);
        }
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// Changes the authenticated local user's username after re-verifying the
    /// current password, then revokes all sessions.
    ///
    /// # Errors
    ///
    /// Returns an authentication, input, duplicate, or persistence error.
    pub fn change_own_username(
        &self,
        user_id: i64,
        current_password: &str,
        new_username: &str,
        now: i64,
    ) -> Result<(), SecurityError> {
        validate_password(current_password)?;
        let new_username = normalize_web_username(new_username)?;
        let current_hash = self.web_password_hash(user_id)?;
        if !verify(current_password, &current_hash)? {
            return Err(SecurityError::InvalidCredentials);
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = find_user_by_id(&transaction, user_id)?.ok_or(SecurityError::UserNotFound)?;
        if current
            .username
            .eq_ignore_ascii_case(&new_username.original)
        {
            return Err(SecurityError::Conflict);
        }
        if find_user(&transaction, &new_username.normalized)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        let old_normalized = current.username.to_lowercase();
        let updated = transaction.execute(
            "UPDATE security_users SET username = ?1, username_norm = ?2
             WHERE user_id = ?3 AND password_hash = ?4 AND authentication_type = 'web'",
            params![
                new_username.original,
                new_username.normalized,
                user_id,
                current_hash
            ],
        )?;
        if updated != 1 {
            return Err(SecurityError::Conflict);
        }
        transaction.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [old_normalized],
        )?;
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// Replaces another local user's password and revokes their sessions.
    /// Authorization and self-target restrictions belong to the HTTP policy.
    ///
    /// # Errors
    ///
    /// Returns an input, identity-source, missing-user, or persistence error.
    pub fn set_user_password(
        &self,
        username: &str,
        new_password: &str,
        now: i64,
    ) -> Result<i64, SecurityError> {
        self.set_user_password_with_force_change(username, new_password, false, now)
    }

    /// Replaces another local user's password, persists its forced-change
    /// policy, and revokes every active session in one transaction.
    ///
    /// # Errors
    ///
    /// Returns an input, identity-source, missing-user, protected-state, or
    /// persistence error.
    pub fn set_user_password_with_force_change(
        &self,
        username: &str,
        new_password: &str,
        force_password_change: bool,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        validate_password(new_password)?;
        let replacement_hash = hash(new_password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (user_id, authentication_type, team_id) = transaction
            .query_row(
                "SELECT user_id, authentication_type, team_id
                 FROM security_users WHERE username_norm = ?1",
                [&username.normalized],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        if authentication_type != "web" {
            return Err(SecurityError::UnsupportedAuthenticationSource);
        }
        if let Some(team_id) = team_id
            && team_name_by_id(&transaction, team_id)?
                .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "UPDATE security_users
             SET password_hash = ?1, force_password_change = ?2
             WHERE user_id = ?3",
            params![replacement_hash, force_password_change, user_id],
        )?;
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(user_id)
    }

    /// Replaces another user's assignable role and revokes their sessions.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/system state, missing users, or storage.
    pub fn set_user_role(
        &self,
        username: &str,
        role: &str,
        now: i64,
    ) -> Result<i64, SecurityError> {
        self.set_user_role_and_team(username, role, None, now)
    }

    /// Replaces another user's assignable role and optionally moves them to a
    /// non-system team in one transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/system state, missing users or teams, or
    /// unavailable persistence.
    pub fn set_user_role_and_team(
        &self,
        username: &str,
        role: &str,
        team_id: Option<i64>,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        let role = normalize_assignable_role(role)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user =
            find_user(&transaction, &username.normalized)?.ok_or(SecurityError::UserNotFound)?;
        reject_internal_user(&transaction, &user)?;
        if role != "ROLE_ADMIN"
            && user_has_role(&transaction, user.id, "ROLE_ADMIN")?
            && is_last_enabled_admin(&transaction, user.id)?
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "DELETE FROM security_user_roles WHERE user_id = ?1",
            [user.id],
        )?;
        transaction.execute(
            "INSERT INTO security_user_roles (user_id, role) VALUES (?1, ?2)",
            params![user.id, role],
        )?;
        if let Some(team_id) = team_id {
            let team_name =
                team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
            if team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
                return Err(SecurityError::ProtectedSystemState);
            }
            transaction.execute(
                "UPDATE security_users SET team_id = ?1 WHERE user_id = ?2",
                params![team_id, user.id],
            )?;
            insert_team_membership(&transaction, user.id, team_id, false)?;
        }
        revoke_sessions_in(&transaction, user.id, now)?;
        transaction.commit()?;
        Ok(user.id)
    }

    /// Enables or disables another user and revokes their sessions whenever
    /// account state changes.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/protected users or persistence failures.
    pub fn set_user_enabled(
        &self,
        username: &str,
        enabled: bool,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user =
            find_user(&transaction, &username.normalized)?.ok_or(SecurityError::UserNotFound)?;
        reject_internal_user(&transaction, &user)?;
        if !enabled
            && user.enabled
            && user_has_role(&transaction, user.id, "ROLE_ADMIN")?
            && is_last_enabled_admin(&transaction, user.id)?
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "UPDATE security_users SET enabled = ?1 WHERE user_id = ?2",
            params![enabled, user.id],
        )?;
        revoke_sessions_in(&transaction, user.id, now)?;
        transaction.commit()?;
        Ok(user.id)
    }

    /// Clears persistent login failures for an existing user.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/missing users or persistence failures.
    pub fn unlock_user(&self, username: &str) -> Result<(), SecurityError> {
        let username = normalize_username(username)?;
        let connection = self.lock()?;
        if find_user(&connection, &username.normalized)?.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        connection.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [&username.normalized],
        )?;
        Ok(())
    }

    /// Deletes another non-system user while preserving at least one enabled
    /// administrator.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/protected users or persistence failures.
    pub fn delete_user(&self, username: &str) -> Result<i64, SecurityError> {
        let username = normalize_username(username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user =
            find_user(&transaction, &username.normalized)?.ok_or(SecurityError::UserNotFound)?;
        reject_internal_user(&transaction, &user)?;
        if user.enabled
            && user_has_role(&transaction, user.id, "ROLE_ADMIN")?
            && is_last_enabled_admin(&transaction, user.id)?
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "INSERT OR IGNORE INTO security_external_identity_blocks
                 (issuer, subject, blocked_at)
             SELECT issuer, subject, unixepoch()
             FROM security_external_identities WHERE user_id = ?1",
            [user.id],
        )?;
        transaction.execute(
            "DELETE FROM resource_grants
             WHERE resource_type = 'INTEGRATION_CONFIG'
               AND resource_id IN (
                   SELECT CAST(integration_config_id AS TEXT)
                   FROM integration_configs WHERE owner_user_id = ?1
               )",
            [user.id],
        )?;
        transaction.execute(
            "DELETE FROM resource_grants
             WHERE principal_type = 'USER' AND principal_id = ?1",
            [user.id],
        )?;
        transaction.execute("DELETE FROM security_users WHERE user_id = ?1", [user.id])?;
        transaction.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [&username.normalized],
        )?;
        transaction.commit()?;
        Ok(user.id)
    }

    /// Verifies a local password, applies persistent lockout state, and returns
    /// trusted identity data without issuing a session yet.
    ///
    /// # Errors
    ///
    /// Returns a generic authentication error for rejected credentials/account
    /// state, or a storage/hash error when verification cannot complete safely.
    pub fn authenticate_password(
        &self,
        username: &str,
        password: &str,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        self.authenticate_password_stage(username, password, now, correlation_id, true)
    }

    /// Verifies password and, when enabled, a non-replayed TOTP step before
    /// returning a login context. When the submitted code is not a valid TOTP
    /// step it is tried as a single-use recovery (backup) code, which is only
    /// honored while MFA is enabled and only after the password stage succeeds.
    /// Failed TOTP and failed recovery attempts alike participate in the same
    /// persistent lockout counter as password failures.
    ///
    /// # Errors
    ///
    /// Returns a stable password/account/MFA rejection or a protected-state
    /// error. No session is issued by this method.
    pub fn authenticate_login(
        &self,
        username: &str,
        password: &str,
        mfa_code: Option<&str>,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        let context =
            self.authenticate_password_stage(username, password, now, correlation_id, false)?;
        let Some(mfa) = self.read_mfa(context.user_id)? else {
            self.clear_login_failures(&context.username)?;
            return Ok(context);
        };
        if !mfa.enabled {
            self.clear_login_failures(&context.username)?;
            return Ok(context);
        }
        let code = mfa_code
            .map(str::trim)
            .filter(|code| !code.is_empty())
            .ok_or(SecurityError::MfaRequired)?;
        let step = match self.validated_mfa_step(context.user_id, &mfa, code, now) {
            Ok(step) => step,
            Err(SecurityError::InvalidMfa) => {
                // The submitted value was not a valid TOTP step. Before failing,
                // try it as a single-use recovery code (reached only because
                // MFA is enabled and the password stage already succeeded). A
                // successful consume completes login exactly like a valid TOTP:
                // clear the lockout counter and return the same context, leaving
                // session issuance to the caller. A failed attempt falls through
                // to the shared MFA lockout, identical to a failed TOTP.
                if self.verify_and_consume_recovery_code(context.user_id, code, now)? {
                    self.clear_login_failures(&context.username)?;
                    return Ok(context);
                }
                self.record_mfa_failure(&context.username, now)?;
                return Err(SecurityError::InvalidMfa);
            }
            Err(error) => return Err(error),
        };
        let normalized = normalize_username(&context.username)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_mfa SET last_used_step = ?1, updated_at = ?2
             WHERE user_id = ?3 AND enabled = 1
               AND (last_used_step IS NULL OR last_used_step < ?1)",
            params![step, now, context.user_id],
        )?;
        if updated != 1 {
            transaction.rollback()?;
            drop(connection);
            self.record_mfa_failure(&context.username, now)?;
            return Err(SecurityError::InvalidMfa);
        }
        transaction.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [&normalized.normalized],
        )?;
        transaction.commit()?;
        Ok(context)
    }

    /// Starts a new MFA setup, replacing any previous pending setup with a
    /// freshly generated seed encrypted for this user.
    ///
    /// # Errors
    ///
    /// Returns an error for non-web accounts, already-enabled MFA, protected
    /// state failure, or unavailable persistence.
    pub fn begin_mfa_setup(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Zeroizing<String>, SecurityError> {
        let cipher = self.require_secret_cipher()?;
        let secret = generate_totp_secret();
        let associated_data = mfa_associated_data(user_id);
        let protected = cipher.encrypt(secret.as_bytes(), associated_data.as_bytes())?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let authentication_type = transaction
            .query_row(
                "SELECT authentication_type FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(SecurityError::InvalidToken)?;
        if authentication_type != "web" {
            return Err(SecurityError::UnsupportedAuthenticationSource);
        }
        if transaction
            .query_row(
                "SELECT enabled FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false)
        {
            return Err(SecurityError::MfaAlreadyEnabled);
        }
        transaction.execute(
            "INSERT INTO security_mfa
             (user_id, enabled, required, secret_ciphertext, last_used_step, updated_at)
             VALUES (?1, 0, 0, ?2, NULL, ?3)
             ON CONFLICT(user_id) DO UPDATE SET
                 enabled = 0,
                 secret_ciphertext = excluded.secret_ciphertext,
                 last_used_step = NULL,
                 updated_at = excluded.updated_at",
            params![user_id, protected, now],
        )?;
        transaction.commit()?;
        Ok(secret)
    }

    /// Enables pending MFA after validating and consuming the submitted TOTP
    /// time step, and issues the user's initial single-use recovery-code set in
    /// the same transaction so an enabled account always has backup codes. The
    /// plaintext codes are returned exactly once for the caller to display; only
    /// their digests are persisted (see [`Self::generate_recovery_codes`]).
    ///
    /// # Errors
    ///
    /// Returns an error for missing setup, invalid/replayed codes, or protected
    /// state failures.
    pub fn enable_mfa(
        &self,
        user_id: i64,
        code: &str,
        now: i64,
    ) -> Result<Vec<String>, SecurityError> {
        let mfa = self
            .read_mfa(user_id)?
            .ok_or(SecurityError::MfaSetupRequired)?;
        if mfa.enabled {
            return Err(SecurityError::MfaAlreadyEnabled);
        }
        let step = self.validated_mfa_step(user_id, &mfa, code, now)?;
        let entries = build_recovery_code_entries();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_mfa
             SET enabled = 1, required = 0, last_used_step = ?1, updated_at = ?2
             WHERE user_id = ?3 AND enabled = 0
               AND (last_used_step IS NULL OR last_used_step < ?1)",
            params![step, now, user_id],
        )?;
        if updated != 1 {
            transaction.rollback()?;
            return Err(SecurityError::InvalidMfa);
        }
        replace_recovery_codes(&transaction, user_id, &entries, now)?;
        transaction.commit()?;
        Ok(entries.into_iter().map(|(code, _)| code).collect())
    }

    /// Disables MFA after validating a fresh TOTP code. A user without enabled
    /// MFA is treated idempotently.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/replayed codes, corrupted protected state,
    /// or unavailable persistence.
    pub fn disable_mfa(&self, user_id: i64, code: &str, now: i64) -> Result<bool, SecurityError> {
        let Some(mfa) = self.read_mfa(user_id)? else {
            return Ok(false);
        };
        if !mfa.enabled {
            return Ok(false);
        }
        let step = self.validated_mfa_step(user_id, &mfa, code, now)?;
        let connection = self.lock()?;
        let deleted = connection.execute(
            "DELETE FROM security_mfa
             WHERE user_id = ?1 AND enabled = 1
               AND (last_used_step IS NULL OR last_used_step < ?2)",
            params![user_id, step],
        )?;
        if deleted == 1 {
            Ok(true)
        } else {
            Err(SecurityError::InvalidMfa)
        }
    }

    /// Clears an unfinished MFA setup without affecting enabled MFA.
    ///
    /// # Errors
    ///
    /// Returns an error when MFA is already enabled or persistence is
    /// unavailable.
    pub fn cancel_mfa_setup(&self, user_id: i64) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        if connection
            .query_row(
                "SELECT enabled FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false)
        {
            return Err(SecurityError::MfaAlreadyEnabled);
        }
        connection.execute(
            "DELETE FROM security_mfa WHERE user_id = ?1 AND enabled = 0",
            [user_id],
        )?;
        Ok(())
    }

    /// Removes another user's MFA state for an already-authorized
    /// administrator request.
    ///
    /// # Errors
    ///
    /// Returns an error when the target identity does not exist or persistence
    /// is unavailable.
    pub fn disable_mfa_by_username(&self, username: &str) -> Result<bool, SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        let user_id = connection
            .query_row(
                "SELECT user_id FROM security_users WHERE username_norm = ?1",
                [&normalized.normalized],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        Ok(connection.execute("DELETE FROM security_mfa WHERE user_id = ?1", [user_id])? > 0)
    }

    /// Reports enabled MFA without exposing its protected seed.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn mfa_is_enabled(&self, user_id: i64) -> Result<bool, SecurityError> {
        Ok(self.read_mfa(user_id)?.is_some_and(|mfa| mfa.enabled))
    }

    /// Issues a fresh set of single-use MFA recovery codes, invalidating any
    /// previously generated set for the user. The plaintext codes are returned
    /// exactly once for the caller to display; only their SHA-256 digests are
    /// persisted, so the set can never be recovered later — only regenerated.
    ///
    /// This is a standalone library function: it does not itself require MFA to
    /// be enabled, but the codes are only ever honored by the login path while
    /// MFA is enabled (see `authenticate_login`).
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn generate_recovery_codes(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Vec<String>, SecurityError> {
        let entries = build_recovery_code_entries();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        replace_recovery_codes(&transaction, user_id, &entries, now)?;
        transaction.commit()?;
        Ok(entries.into_iter().map(|(code, _)| code).collect())
    }

    /// Regenerates the caller's recovery-code set after re-authenticating with a
    /// fresh TOTP step, mirroring the re-auth requirement of
    /// [`Self::disable_mfa`]. MFA must already be enabled. The submitted TOTP
    /// step is consumed (its `last_used_step` is bumped) so it cannot be
    /// replayed, and the prior set is atomically replaced in the same
    /// transaction. The new plaintext codes are returned exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::MfaSetupRequired`] when MFA is not enabled,
    /// [`SecurityError::InvalidMfa`] for an invalid or replayed code, or a
    /// protected-state / persistence error.
    pub fn regenerate_recovery_codes(
        &self,
        user_id: i64,
        code: &str,
        now: i64,
    ) -> Result<Vec<String>, SecurityError> {
        let mfa = self
            .read_mfa(user_id)?
            .ok_or(SecurityError::MfaSetupRequired)?;
        if !mfa.enabled {
            return Err(SecurityError::MfaSetupRequired);
        }
        let step = self.validated_mfa_step(user_id, &mfa, code, now)?;
        let entries = build_recovery_code_entries();
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_mfa SET last_used_step = ?1, updated_at = ?2
             WHERE user_id = ?3 AND enabled = 1
               AND (last_used_step IS NULL OR last_used_step < ?1)",
            params![step, now, user_id],
        )?;
        if updated != 1 {
            transaction.rollback()?;
            return Err(SecurityError::InvalidMfa);
        }
        replace_recovery_codes(&transaction, user_id, &entries, now)?;
        transaction.commit()?;
        Ok(entries.into_iter().map(|(code, _)| code).collect())
    }

    /// Atomically consumes a single unused recovery code for the user. Returns
    /// `true` when exactly one matching unconsumed code was marked used, `false`
    /// when no live code matched (unknown, already consumed, or wrong user).
    ///
    /// The consume runs in an Immediate transaction with a rows-affected == 1
    /// guard, mirroring the TOTP `last_used_step` bump, so a code can never be
    /// spent twice even under concurrent login attempts.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn verify_and_consume_recovery_code(
        &self,
        user_id: i64,
        submitted: &str,
        now: i64,
    ) -> Result<bool, SecurityError> {
        let digest = token_digest(&normalize_recovery_code(submitted));
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE security_recovery_codes SET consumed_at = ?1
             WHERE user_id = ?2 AND code_hash = ?3 AND consumed_at IS NULL",
            params![now, user_id, digest],
        )?;
        if updated != 1 {
            transaction.rollback()?;
            return Ok(false);
        }
        transaction.commit()?;
        Ok(true)
    }

    /// Reports how many of the user's recovery codes remain unconsumed.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn remaining_recovery_codes(&self, user_id: i64) -> Result<i64, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT COUNT(*) FROM security_recovery_codes
                 WHERE user_id = ?1 AND consumed_at IS NULL",
                [user_id],
                |row| row.get(0),
            )
            .map_err(SecurityError::from)
    }

    /// Lists teams with live member counts for administrator views.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn list_teams(&self) -> Result<Vec<SecurityTeam>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT t.team_id, t.name, COUNT(u.user_id)
             FROM security_teams t
             LEFT JOIN security_users u ON u.team_id = t.team_id
             GROUP BY t.team_id, t.name
             ORDER BY t.name COLLATE NOCASE",
        )?;
        statement
            .query_map([], |row| {
                Ok(SecurityTeam {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    member_count: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Reports whether the login page should surface the default administrator
    /// credentials, mirroring Java
    /// `ProprietaryUIDataController.getLoginData`'s `showDefaultCredentials` /
    /// `firstTimeSetup` computation: `true` when there are no real users (the
    /// internal API user excluded), or exactly one real user which is the
    /// default `admin` account still on its first login (its initial setup not
    /// yet completed — the Rust equivalent of Java's `isFirstLogin`).
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn first_time_setup_required(&self) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        let count = real_user_count(&connection)?;
        if count == 0 {
            return Ok(true);
        }
        if count == 1 {
            // Java looks up the literal `admin` account (case-insensitively) and
            // checks its first-login flag; `username_norm` is the lowercased key.
            let admin_first_login: Option<bool> = connection
                .query_row(
                    "SELECT initial_setup_completed = 0
                     FROM security_users WHERE username_norm = 'admin'",
                    [],
                    |row| row.get(0),
                )
                .optional()?;
            return Ok(admin_first_login.unwrap_or(false));
        }
        Ok(false)
    }

    /// Reports whether MFA is *required* for the user, mirroring Java
    /// `MfaService.isMfaRequired` (default `false` when no MFA row exists).
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn mfa_is_required(&self, user_id: i64) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT required FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map(|value| value.unwrap_or(false))
            .map_err(SecurityError::from)
    }

    /// Returns the latest session activity per team (the internal team
    /// excluded), mirroring Java `SessionRepository.findLatestActivityByTeam`.
    /// Each entry is `(team_id, latest_activity)` where the activity is the most
    /// recent session `created_at` (unix seconds) across the team's members, or
    /// `None` when no member has ever had a session.
    ///
    /// Parity note: the Java query aggregates `MAX(lastRequest)` from Spring
    /// Session's per-request `lastRequest`; the Rust session store records only
    /// `created_at`, so this uses the latest session creation time as the
    /// closest available "last activity" signal.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn latest_session_activity_per_team(
        &self,
    ) -> Result<Vec<(i64, Option<i64>)>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT t.team_id, MAX(s.created_at)
             FROM security_teams t
             LEFT JOIN security_users u ON u.team_id = t.team_id
             LEFT JOIN security_sessions s ON s.user_id = u.user_id
             WHERE t.name <> ?1
             GROUP BY t.team_id
             ORDER BY t.team_id",
        )?;
        statement
            .query_map([INTERNAL_TEAM_NAME], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Returns `(team_id, user_id, username)` for every LEADER (team-owner)
    /// membership on a non-internal team, ordered by team then username. Mirrors
    /// Java `TeamMembershipRepository.findByRoleFetchingUserAndTeam(LEADER)`
    /// (the internal team filtered out). A LEADER is an `is_owner = 1` row of
    /// `security_team_memberships`.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn team_leaders(&self) -> Result<Vec<(i64, i64, String)>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT m.team_id, m.user_id, u.username
             FROM security_team_memberships m
             JOIN security_users u ON u.user_id = m.user_id
             JOIN security_teams t ON t.team_id = m.team_id
             WHERE m.is_owner = 1 AND t.name <> ?1
             ORDER BY m.team_id, u.username COLLATE NOCASE",
        )?;
        statement
            .query_map([INTERNAL_TEAM_NAME], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Resolves a team's display name, or `None` when the id is unknown. Used by
    /// the team-details projection to distinguish "not found" from the internal
    /// team (which is never exposed).
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn team_name(&self, team_id: i64) -> Result<Option<String>, SecurityError> {
        let connection = self.lock()?;
        team_name_by_id(&connection, team_id)
    }

    /// Returns `(username, latest_activity)` for every member of one team,
    /// mirroring Java `SessionRepository.findLatestSessionByTeamId`. The
    /// activity is the most recent session `created_at` (unix seconds) for that
    /// user, or `None` when they have never had a session. See
    /// [`Self::latest_session_activity_per_team`] for the `lastRequest` parity
    /// note.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn latest_session_by_team(
        &self,
        team_id: i64,
    ) -> Result<Vec<(String, Option<i64>)>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT u.username, MAX(s.created_at)
             FROM security_users u
             LEFT JOIN security_sessions s ON s.user_id = u.user_id
             WHERE u.team_id = ?1
             GROUP BY u.user_id, u.username
             ORDER BY u.username COLLATE NOCASE",
        )?;
        statement
            .query_map([team_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Returns the distinct usernames that currently hold a live session,
    /// mirroring Java `SessionRepository.findActivePrincipalsSince(cutoff)`
    /// (`expired = false AND lastRequest > cutoff`). The Rust session store
    /// records no per-request `lastRequest` and no `expired` flag, so a session
    /// is "live" when it is neither revoked nor past its refresh window at
    /// `now` (`revoked_at IS NULL AND refresh_expires_at > now`) — the refresh
    /// expiry is the Rust equivalent of Java's inactivity timeout. The `now`
    /// argument is the cutoff the expiry must still exceed. See
    /// [`Self::latest_session_activity_per_team`] for the shared `lastRequest`
    /// parity note.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn active_principals_since(&self, now: i64) -> Result<Vec<String>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT DISTINCT u.username
             FROM security_sessions s
             JOIN security_users u ON u.user_id = s.user_id
             WHERE s.revoked_at IS NULL AND s.refresh_expires_at > ?1
             ORDER BY u.username COLLATE NOCASE",
        )?;
        statement
            .query_map([now], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Returns `(username, latest_activity)` for every principal that has ever
    /// held a session — the most recent session `created_at` (unix seconds) per
    /// user. Mirrors Java `SessionRepository.findLatestRequestPerPrincipal`
    /// (`MAX(lastRequest) GROUP BY principalName`); the Rust store records no
    /// per-request `lastRequest`, so the latest session creation time stands in.
    /// Users who have never held a session are absent (the admin projection
    /// defaults them to epoch 0). No revoked/expired filter is applied, matching
    /// the Java query, which aggregates over every session row.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn latest_request_per_principal(&self) -> Result<Vec<(String, i64)>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT u.username, MAX(s.created_at)
             FROM security_sessions s
             JOIN security_users u ON u.user_id = s.user_id
             GROUP BY u.user_id, u.username
             ORDER BY u.username COLLATE NOCASE",
        )?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Returns `(user_id, created_at, initial_setup_completed)` for every user,
    /// supplying the two `security_users` columns the admin-settings roster
    /// needs on top of [`Self::list_users`]: the account creation time and the
    /// first-run marker. `created_at` is formatted as an ISO-8601 local
    /// date-time string (`YYYY-MM-DDTHH:MM:SS`, UTC) to match the Jackson
    /// serialization of Java `User.createdAt` (a `LocalDateTime`) the client
    /// consumes; the admin projection maps `initial_setup_completed = 0` onto
    /// Java's `isFirstLogin`. There is no `updated_at` column, so Java's
    /// `updatedAt` has no analogue here (a documented divergence).
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state cannot be read.
    pub fn admin_roster_lifecycle(&self) -> Result<Vec<(i64, String, bool)>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT user_id,
                    strftime('%Y-%m-%dT%H:%M:%S', created_at, 'unixepoch'),
                    initial_setup_completed
             FROM security_users
             ORDER BY user_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Creates a uniquely named team.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/duplicate names or unavailable state.
    pub fn create_team(&self, name: &str) -> Result<i64, SecurityError> {
        let name = validate_team_name(name)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if team_id_by_name(&transaction, name)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        transaction.execute("INSERT INTO security_teams (name) VALUES (?1)", [name])?;
        let team_id = transaction.last_insert_rowid();
        transaction.commit()?;
        Ok(team_id)
    }

    /// Renames a non-internal team.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system teams, invalid/duplicate names, or
    /// unavailable state.
    pub fn rename_team(&self, team_id: i64, new_name: &str) -> Result<(), SecurityError> {
        let new_name = validate_team_name(new_name)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if current_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        if team_id_by_name(&transaction, new_name)?.is_some() {
            return Err(SecurityError::Conflict);
        }
        transaction.execute(
            "UPDATE security_teams SET name = ?1 WHERE team_id = ?2",
            params![new_name, team_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Deletes an empty non-internal team.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system/non-empty teams or unavailable
    /// state.
    pub fn delete_team(&self, team_id: i64) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let name = team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        let member_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM security_users WHERE team_id = ?1",
            [team_id],
            |row| row.get(0),
        )?;
        if member_count != 0 {
            return Err(SecurityError::TeamNotEmpty);
        }
        let owned_resource_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM integration_configs WHERE owner_team_id = ?1",
            [team_id],
            |row| row.get(0),
        )?;
        if owned_resource_count != 0 {
            return Err(SecurityError::TeamNotEmpty);
        }
        transaction.execute(
            "DELETE FROM resource_grants
             WHERE principal_type = 'TEAM' AND principal_id = ?1",
            [team_id],
        )?;
        transaction.execute("DELETE FROM security_teams WHERE team_id = ?1", [team_id])?;
        transaction.commit()?;
        Ok(())
    }

    /// Moves a non-internal user into a non-internal team and synchronizes the
    /// single-team membership row.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system users or teams and unavailable
    /// state.
    pub fn assign_user_to_team(&self, user_id: i64, team_id: i64) -> Result<(), SecurityError> {
        self.assign_user_to_team_at(user_id, team_id, 0)
    }

    /// Moves a user and revokes all sessions at the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system users or teams and unavailable
    /// state.
    pub fn assign_user_to_team_at(
        &self,
        user_id: i64,
        team_id: i64,
        now: i64,
    ) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let target_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if target_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::ProtectedSystemState);
        }
        let current_team_id = transaction
            .query_row(
                "SELECT team_id FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        if let Some(current_team_id) = current_team_id
            && team_name_by_id(&transaction, current_team_id)?
                .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        transaction.execute(
            "UPDATE security_users SET team_id = ?1 WHERE user_id = ?2",
            params![team_id, user_id],
        )?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        revoke_sessions_in(&transaction, user_id, now)?;
        transaction.commit()?;
        Ok(())
    }

    /// Adds or removes the owner flag for a current member of a non-system
    /// team.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/system teams, non-members, or unavailable
    /// state.
    pub fn set_team_owner(
        &self,
        team_id: i64,
        user_id: i64,
        owner: bool,
    ) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let team_name =
            team_name_by_id(&transaction, team_id)?.ok_or(SecurityError::TeamNotFound)?;
        if team_name.eq_ignore_ascii_case(DEFAULT_TEAM_NAME)
            || team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME)
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        let member = transaction
            .query_row(
                "SELECT 1 FROM security_users WHERE user_id = ?1 AND team_id = ?2",
                params![user_id, team_id],
                |_| Ok(()),
            )
            .optional()?;
        if member.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        let updated = transaction.execute(
            "UPDATE security_team_memberships SET is_owner = ?1
             WHERE team_id = ?2 AND user_id = ?3",
            params![owner, team_id, user_id],
        )?;
        if updated != 1 {
            return Err(SecurityError::UserNotFound);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Issues a one-time invitation while persisting only its SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity/role/team/expiry, an existing user
    /// or active email invitation, or unavailable persistence.
    pub fn create_invite(
        &self,
        context: &AuthContext,
        email: Option<&str>,
        role: &str,
        team_id: Option<i64>,
        now: i64,
        expires_at: i64,
    ) -> Result<IssuedInvite, SecurityError> {
        if expires_at <= now {
            return Err(SecurityError::InvalidInput);
        }
        let email = email.map(normalize_invite_email).transpose()?;
        let role = normalize_assignable_role(role)?;
        let token = random_secret(INVITE_TOKEN_PREFIX);
        let digest = token_digest(&token);
        let verification = self.current_license_verification()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if verification.running_pro_or_higher() {
            let active_invites = transaction.query_row(
                "SELECT COUNT(*) FROM security_invites
                 WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?1",
                [now],
                |row| row.get::<_, i64>(0),
            )?;
            ensure_user_capacity(&transaction, verification, active_invites.saturating_add(1))?;
        }
        let team_id = resolve_team_id(&transaction, team_id)?;
        if team_name_by_id(&transaction, team_id)?
            .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            return Err(SecurityError::ProtectedSystemState);
        }
        if let Some(email) = email.as_deref() {
            if find_user(&transaction, email)?.is_some() {
                return Err(SecurityError::Conflict);
            }
            let active: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM security_invites
                 WHERE email = ?1 COLLATE NOCASE AND used_at IS NULL AND revoked_at IS NULL
                   AND expires_at > ?2",
                params![email, now],
                |row| row.get(0),
            )?;
            if active != 0 {
                return Err(SecurityError::Conflict);
            }
        }
        transaction.execute(
            "INSERT INTO security_invites
             (token_hash, email, role, team_id, expires_at, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                digest,
                email,
                role,
                team_id,
                expires_at,
                context.user_id,
                now
            ],
        )?;
        transaction.commit()?;
        Ok(IssuedInvite {
            token,
            email,
            role,
            team_id,
            expires_at,
        })
    }

    /// Validates a one-time invitation without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a single generic rejection for missing, revoked, used, expired,
    /// or already-provisioned email invitations.
    pub fn validate_invite(&self, token: &str, now: i64) -> Result<InviteDetails, SecurityError> {
        validate_token(token, INVITE_TOKEN_PREFIX).map_err(|_| SecurityError::InvalidInvite)?;
        let digest = token_digest(token);
        let connection = self.lock()?;
        let invite =
            find_active_invite(&connection, &digest, now)?.ok_or(SecurityError::InvalidInvite)?;
        if let Some(email) = invite.email.as_deref()
            && find_user(&connection, email)?.is_some()
        {
            return Err(SecurityError::InvalidInvite);
        }
        Ok(invite.into_details())
    }

    /// Atomically consumes an invitation and creates its local user, role, and
    /// team membership.
    ///
    /// # Errors
    ///
    /// Returns a generic invitation rejection for invalid/replayed/conflicting
    /// tokens, or a bounded input/storage error.
    pub fn accept_invite(
        &self,
        token: &str,
        provided_email: Option<&str>,
        password: &str,
        now: i64,
    ) -> Result<String, SecurityError> {
        validate_token(token, INVITE_TOKEN_PREFIX).map_err(|_| SecurityError::InvalidInvite)?;
        validate_password(password)?;
        let digest = token_digest(token);
        let normalized_provided = provided_email.map(normalize_invite_email).transpose()?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let invite =
            find_active_invite(&transaction, &digest, now)?.ok_or(SecurityError::InvalidInvite)?;
        let username = invite
            .email
            .clone()
            .or(normalized_provided)
            .ok_or(SecurityError::InvalidInput)?;
        if find_user(&transaction, &username)?.is_some() {
            return Err(SecurityError::InvalidInvite);
        }
        let team_name =
            team_name_by_id(&transaction, invite.team_id)?.ok_or(SecurityError::InvalidInvite)?;
        if team_name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Err(SecurityError::InvalidInvite);
        }
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 1, 'web', ?4)",
            params![username, username, password_hash, invite.team_id],
        )?;
        let user_id = transaction.last_insert_rowid();
        let roles = [invite.role.as_str()]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, invite.team_id, false)?;
        let consumed = transaction.execute(
            "UPDATE security_invites SET used_at = ?1
             WHERE invite_id = ?2 AND used_at IS NULL AND revoked_at IS NULL",
            params![now, invite.id],
        )?;
        if consumed != 1 {
            return Err(SecurityError::InvalidInvite);
        }
        transaction.commit()?;
        Ok(username)
    }

    /// Lists all currently active invitations for an administrator.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn list_active_invites(&self, now: i64) -> Result<Vec<InviteSummary>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT i.invite_id, i.email, i.role, i.team_id, u.username,
                    i.created_at, i.expires_at
             FROM security_invites i
             JOIN security_users u ON u.user_id = i.created_by
             WHERE i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?1
             ORDER BY i.created_at DESC, i.invite_id DESC",
        )?;
        statement
            .query_map([now], |row| {
                Ok(InviteSummary {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    role: row.get(2)?,
                    team_id: row.get(3)?,
                    created_by: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Revokes an invitation by identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when the invitation does not exist or state is
    /// unavailable.
    pub fn revoke_invite(&self, invite_id: i64, now: i64) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        let updated = connection.execute(
            "UPDATE security_invites SET revoked_at = ?1
             WHERE invite_id = ?2 AND revoked_at IS NULL",
            params![now, invite_id],
        )?;
        if updated == 0 {
            Err(SecurityError::InvalidInvite)
        } else {
            Ok(())
        }
    }

    /// Deletes expired, consumed, and revoked invitation rows.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn cleanup_invites(&self, now: i64) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM security_invites
                 WHERE expires_at <= ?1 OR used_at IS NOT NULL OR revoked_at IS NOT NULL",
                [now],
            )
            .map_err(SecurityError::from)
    }

    fn authenticate_password_stage(
        &self,
        username: &str,
        password: &str,
        now: i64,
        correlation_id: &str,
        clear_failures: bool,
    ) -> Result<AuthContext, SecurityError> {
        let normalized = normalize_username(username)?;
        validate_password(password)?;
        // Read the stored hash and lockout state under a brief lock, then
        // RELEASE it before any bcrypt work. A bcrypt verify/hash costs tens of
        // milliseconds; holding the single global connection mutex across it
        // serialises every authentication request, so a login flood collapses
        // the whole service to a few requests/second (DoS). Every bcrypt call
        // below therefore runs OFF-lock.
        let (user, locked) = {
            let connection = self.lock()?;
            let user = find_user(&connection, &normalized.normalized)?;
            let locked = if user.is_some() {
                login_is_locked(&connection, &normalized.normalized, now)?
            } else {
                false
            };
            (user, locked)
        };

        // Timing equalisation: unknown, locked, and non-web accounts still pay
        // exactly one bcrypt hash so response timing never reveals which case
        // occurred (enumeration resistance). This runs with no lock held.
        let Some(user) = user else {
            fake_password_work(password, self.bcrypt_cost)?;
            return Err(SecurityError::InvalidCredentials);
        };
        if locked {
            fake_password_work(password, self.bcrypt_cost)?;
            return Err(SecurityError::AccountLocked);
        }
        if user.authentication_type != "web" {
            fake_password_work(password, self.bcrypt_cost)?;
            return Err(SecurityError::InvalidCredentials);
        }
        let password_ok = verify(password, &user.password_hash)?;

        // Re-acquire the lock only to record the outcome. An Immediate
        // transaction serialises the failure-count update so concurrent
        // attempts cannot race the lockout threshold, matching the previous
        // single-lock atomicity without holding the mutex across bcrypt.
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !password_ok {
            let locked = record_login_failure(&transaction, &normalized.normalized, now)?;
            transaction.commit()?;
            return if locked {
                Err(SecurityError::AccountLocked)
            } else {
                Err(SecurityError::InvalidCredentials)
            };
        }
        if !user.enabled {
            // Correct password but disabled account: no state change, so the
            // Immediate transaction rolls back on drop (matches prior behavior).
            return Err(SecurityError::AccountDisabled);
        }
        if clear_failures {
            transaction.execute(
                "DELETE FROM security_login_attempts WHERE username_norm = ?1",
                [&normalized.normalized],
            )?;
        }
        let context = context_for_user(
            &transaction,
            &user,
            AuthenticationSource::Password,
            String::new(),
            correlation_id,
        )?;
        transaction.commit()?;
        Ok(context)
    }

    /// Persists a new opaque access/refresh pair for an authenticated user.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid lifetimes or unavailable persistent state.
    pub fn issue_session(
        &self,
        context: &AuthContext,
        now: i64,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<SessionTokens, SecurityError> {
        let generated = GeneratedSession::new(now, access_ttl, refresh_ttl)?;
        let connection = self.lock()?;
        insert_session(&connection, context.user_id, &generated)?;
        Ok(generated.tokens)
    }

    /// Authenticates a bearer access token against live user and revocation
    /// state. Expired tokens are never accepted during a refresh grace period.
    ///
    /// # Errors
    ///
    /// Returns a generic token/account error or a storage error when live state
    /// cannot be verified.
    pub fn authenticate_access_token(
        &self,
        token: &str,
        now: i64,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        validate_token(token, ACCESS_TOKEN_PREFIX)?;
        let digest = token_digest(token);
        let connection = self.lock()?;
        let session =
            find_session_by_access(&connection, &digest)?.ok_or(SecurityError::InvalidToken)?;
        validate_session(&session, now)?;
        let user =
            find_user_by_id(&connection, session.user_id)?.ok_or(SecurityError::InvalidToken)?;
        if !user.enabled {
            return Err(SecurityError::AccountDisabled);
        }
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::AccessToken,
            session.session_id,
            correlation_id,
        )
    }

    pub(crate) fn policy_automation_context(
        &self,
        username: &str,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        let user = find_user(&connection, &normalized.normalized)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::UserNotFound)?;
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::AccessToken,
            String::new(),
            correlation_id,
        )
    }

    /// Rotates a refresh token in one immediate `SQLite` transaction. The old
    /// access and refresh tokens are revoked before the replacement commits.
    ///
    /// # Errors
    ///
    /// Returns a generic token error, invalid-lifetime error, or storage error;
    /// no replacement is returned unless the transaction commits.
    pub fn rotate_refresh_token(
        &self,
        refresh_token: &str,
        now: i64,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<SessionTokens, SecurityError> {
        validate_token(refresh_token, REFRESH_TOKEN_PREFIX)?;
        let digest = token_digest(refresh_token);
        let generated = GeneratedSession::new(now, access_ttl, refresh_ttl)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session =
            find_session_by_refresh(&transaction, &digest)?.ok_or(SecurityError::InvalidToken)?;
        validate_session(&session, now)?;
        let user = find_user_by_id(&transaction, session.user_id)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        transaction.execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE session_id = ?2 AND revoked_at IS NULL",
            params![now, session.session_id],
        )?;
        insert_session(&transaction, user.id, &generated)?;
        transaction.commit()?;
        Ok(generated.tokens)
    }

    /// Rotates a Java-compatible web session using its current access token.
    /// The token may be expired only inside the caller's bounded refresh grace;
    /// successful rotation revokes it transactionally, preventing replay.
    ///
    /// # Errors
    ///
    /// Returns a generic token error, invalid-lifetime error, or storage error;
    /// no replacement is returned unless the transaction commits.
    pub fn rotate_access_token(
        &self,
        access_token: &str,
        now: i64,
        refresh_grace: Duration,
        access_ttl: Duration,
        refresh_ttl: Duration,
    ) -> Result<SessionTokens, SecurityError> {
        validate_token(access_token, ACCESS_TOKEN_PREFIX)?;
        let grace =
            i64::try_from(refresh_grace.as_secs()).map_err(|_| SecurityError::InvalidInput)?;
        let digest = token_digest(access_token);
        let generated = GeneratedSession::new(now, access_ttl, refresh_ttl)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session =
            find_session_by_access(&transaction, &digest)?.ok_or(SecurityError::InvalidToken)?;
        if session.revoked {
            return Err(SecurityError::InvalidToken);
        }
        if now > session.expires_at.saturating_add(grace) {
            return Err(SecurityError::ExpiredToken);
        }
        let user = find_user_by_id(&transaction, session.user_id)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        transaction.execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE session_id = ?2 AND revoked_at IS NULL",
            params![now, session.session_id],
        )?;
        insert_session(&transaction, user.id, &generated)?;
        transaction.commit()?;
        Ok(generated.tokens)
    }

    /// Revokes the session addressed by an access token. Invalid tokens are
    /// treated idempotently so logout does not become an account oracle.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed tokens or unavailable persistent state.
    pub fn revoke_access_token(&self, token: &str, now: i64) -> Result<(), SecurityError> {
        validate_token(token, ACCESS_TOKEN_PREFIX)?;
        let connection = self.lock()?;
        connection.execute(
            "UPDATE security_sessions SET revoked_at = COALESCE(revoked_at, ?1)
             WHERE access_hash = ?2",
            params![now, token_digest(token)],
        )?;
        Ok(())
    }

    /// Revokes every active session after password, role, team, or account
    /// changes.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn revoke_user_sessions(&self, user_id: i64, now: i64) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        Ok(connection.execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )?)
    }

    /// Creates a user-scoped API key and returns its plaintext exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when the user does not exist, randomness cannot be
    /// persisted, or security state is unavailable.
    pub fn create_api_key(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Zeroizing<String>, SecurityError> {
        let token = random_secret(API_KEY_PREFIX);
        let key_id = random_secret("akid_");
        let prefix = display_prefix(&token);
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO security_api_keys
                 (key_id, user_id, key_hash, created_at, name, prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key_id.as_str(),
                user_id,
                token_digest(&token),
                now,
                "Default key",
                prefix.as_str(),
            ],
        )?;
        Ok(token)
    }

    /// Reports whether the user has at least one live API key without exposing
    /// any bearer value.
    ///
    /// # Errors
    ///
    /// Returns an error for missing users or unavailable persistence.
    pub fn has_active_api_key(&self, user_id: i64) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        if find_user_by_id(&connection, user_id)?.is_none() {
            return Err(SecurityError::UserNotFound);
        }
        connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM security_api_keys
                    WHERE user_id = ?1 AND revoked_at IS NULL
                 )",
                [user_id],
                |row| row.get(0),
            )
            .map_err(SecurityError::from)
    }

    /// Revokes every prior key and returns one new plaintext API key exactly
    /// once. Only its digest is committed.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/disabled users or unavailable persistence.
    pub fn rotate_api_key(
        &self,
        user_id: i64,
        now: i64,
    ) -> Result<Zeroizing<String>, SecurityError> {
        let token = random_secret(API_KEY_PREFIX);
        let key_id = random_secret("akid_");
        let prefix = display_prefix(&token);
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user = find_user_by_id(&transaction, user_id)?.ok_or(SecurityError::UserNotFound)?;
        if !user.enabled {
            return Err(SecurityError::AccountDisabled);
        }
        transaction.execute(
            "UPDATE security_api_keys SET revoked_at = ?1
             WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )?;
        transaction.execute(
            "INSERT INTO security_api_keys
                 (key_id, user_id, key_hash, created_at, name, prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key_id.as_str(),
                user_id,
                token_digest(&token),
                now,
                "Default key",
                prefix.as_str(),
            ],
        )?;
        transaction.commit()?;
        Ok(token)
    }

    /// Binds an MCP OAuth-validated token subject to a provisioned Stirling
    /// account — the Rust port of Java's `McpUserBindingFilter` account check:
    /// the configured username-claim value must resolve, case-insensitively,
    /// to an existing **enabled** user, and the returned context carries that
    /// account's canonical username so audit/metering attribute correctly.
    ///
    /// The caller has already verified the JWT (signature, issuer, expiry,
    /// audience); this method only performs the account lookup, so it must
    /// never be reachable with an unverified claim value.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::InvalidToken`] when the subject has no
    /// enabled account (or the claim value cannot be a username), and a
    /// storage error when live state cannot be read.
    pub fn bind_mcp_oauth_user(
        &self,
        username_claim_value: &str,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        let username =
            normalize_username(username_claim_value).map_err(|_| SecurityError::InvalidToken)?;
        let connection = self.lock()?;
        let user = connection
            .query_row(
                "SELECT user_id, username, password_hash, enabled, authentication_type, team_id,
                        force_password_change
                 FROM security_users WHERE username_norm = ?1",
                [username.normalized.as_str()],
                stored_user_from_row,
            )
            .optional()?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::Oidc,
            correlation_id.to_owned(),
            correlation_id,
        )
    }

    /// Authenticates a hashed API key against its live user and role state.
    ///
    /// # Errors
    ///
    /// Returns a generic token/account error or a storage error when live state
    /// cannot be verified.
    pub fn authenticate_api_key(
        &self,
        api_key: &str,
        correlation_id: &str,
    ) -> Result<AuthContext, SecurityError> {
        validate_token(api_key, API_KEY_PREFIX)?;
        let digest = token_digest(api_key);
        let connection = self.lock()?;
        let key = connection
            .query_row(
                "SELECT key_id, user_id, revoked_at FROM security_api_keys WHERE key_hash = ?1",
                [digest],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()?
            .filter(|(_, _, revoked_at)| revoked_at.is_none())
            .ok_or(SecurityError::InvalidToken)?;
        let user = find_user_by_id(&connection, key.1)?
            .filter(|user| user.enabled)
            .ok_or(SecurityError::InvalidToken)?;
        // Best-effort per-key usage accounting; a write failure here must never
        // fail authentication (mirrors Java's async `ApiKeyUsageRecorder`).
        record_api_key_usage(&connection, &key.0);
        context_for_user(
            &connection,
            &user,
            AuthenticationSource::ApiKey,
            key.0,
            correlation_id,
        )
    }

    /// Lists the personal API keys the caller owns, newest first, with usage
    /// aggregated from `security_api_key_daily_usage` in a single grouped query
    /// (no per-key round trips). `today_epoch_day` is the UTC epoch day the
    /// "today" and rolling-30-day windows are measured against.
    ///
    /// # Errors
    ///
    /// Returns a storage error when persistent state is unavailable.
    pub fn list_api_keys(
        &self,
        user_id: i64,
        today_epoch_day: i64,
    ) -> Result<Vec<ApiKeyRecord>, SecurityError> {
        let month_start = today_epoch_day.saturating_sub(API_KEY_MONTH_WINDOW_DAYS - 1);
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT k.key_id, k.name, k.prefix, k.created_at, k.last_used_at, k.revoked_at,
                    COALESCE(SUM(CASE WHEN u.epoch_day = ?2 THEN u.count END), 0),
                    COALESCE(SUM(CASE WHEN u.epoch_day >= ?3 THEN u.count END), 0),
                    COALESCE(SUM(u.count), 0)
             FROM security_api_keys k
             LEFT JOIN security_api_key_daily_usage u ON u.key_id = k.key_id
             WHERE k.user_id = ?1
             GROUP BY k.key_id
             ORDER BY k.created_at DESC, k.key_id DESC",
        )?;
        let records = statement
            .query_map(params![user_id, today_epoch_day, month_start], |row| {
                Ok(ApiKeyRecord {
                    key_id: row.get(0)?,
                    name: row.get(1)?,
                    prefix: row.get(2)?,
                    created_at: row.get(3)?,
                    last_used_at: row.get(4)?,
                    revoked_at: row.get(5)?,
                    usage_today: row.get(6)?,
                    usage_month: row.get(7)?,
                    usage_total: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    /// Creates a named personal API key and returns its record plus the plaintext
    /// secret exactly once. Only the digest, name and non-secret prefix are
    /// persisted. Enforces the per-user active-key cap atomically so concurrent
    /// creates cannot exceed it.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError::TooManyApiKeys`] when the caller already owns the
    /// maximum number of active keys, or a storage error when persistence is
    /// unavailable.
    pub fn create_named_api_key(
        &self,
        user_id: i64,
        name: &str,
        now: i64,
    ) -> Result<(ApiKeyRecord, Zeroizing<String>), SecurityError> {
        let token = random_secret(API_KEY_PREFIX);
        let key_id = random_secret("akid_");
        let prefix = display_prefix(&token);
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active_owned: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM security_api_keys
             WHERE user_id = ?1 AND revoked_at IS NULL",
            [user_id],
            |row| row.get(0),
        )?;
        if active_owned >= MAX_ACTIVE_API_KEYS_PER_USER {
            return Err(SecurityError::TooManyApiKeys);
        }
        transaction.execute(
            "INSERT INTO security_api_keys
                 (key_id, user_id, key_hash, created_at, name, prefix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key_id.as_str(),
                user_id,
                token_digest(&token),
                now,
                name,
                prefix.as_str(),
            ],
        )?;
        transaction.commit()?;
        let record = ApiKeyRecord {
            key_id: key_id.as_str().to_owned(),
            name: name.to_owned(),
            prefix,
            created_at: now,
            last_used_at: None,
            revoked_at: None,
            usage_today: 0,
            usage_month: 0,
            usage_total: 0,
        };
        Ok((record, token))
    }

    /// Soft-revokes a personal key the caller owns, returning whether a key was
    /// found. An unknown key or a key owned by another user returns `Ok(false)`
    /// (never distinguished, so a caller cannot probe other users' key ids); a
    /// key the caller owns is stamped revoked idempotently and returns
    /// `Ok(true)`.
    ///
    /// # Errors
    ///
    /// Returns a storage error when persistence is unavailable.
    pub fn revoke_api_key(
        &self,
        user_id: i64,
        key_id: &str,
        now: i64,
    ) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        let owner: Option<i64> = connection
            .query_row(
                "SELECT user_id FROM security_api_keys WHERE key_id = ?1",
                [key_id],
                |row| row.get(0),
            )
            .optional()?;
        // Unknown or cross-user: report not-found without leaking existence.
        if owner != Some(user_id) {
            return Ok(false);
        }
        // Idempotent: re-revoking an already-revoked key keeps its first stamp.
        connection.execute(
            "UPDATE security_api_keys SET revoked_at = COALESCE(revoked_at, ?1)
             WHERE key_id = ?2",
            params![now, key_id],
        )?;
        Ok(true)
    }

    /// Persists a bounded event without any credential or token value.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid bounded fields or unavailable persistent
    /// state.
    pub fn record_audit(
        &self,
        context: &AuthContext,
        event_type: &str,
        path: &str,
        outcome: &str,
        now: i64,
    ) -> Result<(), SecurityError> {
        for value in [event_type, path, outcome, &context.correlation_id] {
            if value.is_empty() || value.len() > MAX_AUDIT_VALUE_BYTES {
                return Err(SecurityError::InvalidInput);
            }
        }
        let source = match context.authentication_source {
            AuthenticationSource::Password | AuthenticationSource::AccessToken => "WEB",
            AuthenticationSource::ApiKey => "API",
            AuthenticationSource::SupabaseJwt => "SUPABASE",
            AuthenticationSource::Oidc => "OIDC",
        };
        let status_code = outcome
            .strip_prefix("status:")
            .and_then(|value| value.parse::<u16>().ok());
        let normalized_outcome =
            status_code.map_or(
                outcome,
                |status| {
                    if status >= 400 { "failure" } else { "success" }
                },
            );
        let mut data = serde_json::json!({
            "path": path,
            "outcome": normalized_outcome,
        });
        if let Some(status_code) = status_code {
            data["status"] = serde_json::Value::String(normalized_outcome.to_owned());
            data["statusCode"] = serde_json::Value::from(status_code);
        }
        let data = serde_json::to_string(&data).map_err(|_| SecurityError::InvalidInput)?;
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO security_audit_events
             (user_id, principal, source, data, session_id, correlation_id,
              event_type, path, outcome, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                context.user_id,
                context.username,
                source,
                data,
                context.session_id,
                context.correlation_id,
                event_type,
                path,
                outcome,
                now
            ],
        )?;
        Ok(())
    }

    /// Inserts a fully specified audit event, returning its new id.
    ///
    /// The standard recorders synthesize request-shaped payloads and the policy
    /// boundary additionally supplies live `files`, `automation`, `policyName`,
    /// and `policySteps` enrichment. This seam remains useful for importing or
    /// testing other representative event shapes. The `path` and `outcome`
    /// columns are derived from the supplied `data` document when present, so a
    /// later read reconstructs the payload.
    ///
    /// # Errors
    ///
    /// Returns an error for bounded-field violations, an unparsable `data`
    /// document, or unavailable persistent state.
    pub fn insert_audit_event(
        &self,
        principal: &str,
        source: &str,
        event_type: &str,
        data: &str,
        created_at: i64,
    ) -> Result<i64, SecurityError> {
        for value in [principal, source, event_type] {
            if value.is_empty() || value.len() > MAX_AUDIT_VALUE_BYTES {
                return Err(SecurityError::InvalidInput);
            }
        }
        let parsed = serde_json::from_str::<serde_json::Value>(data)
            .map_err(|_| SecurityError::InvalidInput)?;
        let (path, outcome) = parsed.as_object().map_or_else(
            || (String::new(), String::new()),
            |object| {
                let path = object
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let outcome = object
                    .get("outcome")
                    .or_else(|| object.get("status"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                (path, outcome)
            },
        );
        if path.len() > MAX_AUDIT_VALUE_BYTES {
            return Err(SecurityError::InvalidInput);
        }
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO security_audit_events
             (user_id, principal, source, data, session_id, correlation_id,
              event_type, path, outcome, created_at)
             VALUES (NULL, ?1, ?2, ?3, '', '', ?4, ?5, ?6, ?7)",
            params![
                principal, source, data, event_type, path, outcome, created_at
            ],
        )?;
        Ok(connection.last_insert_rowid())
    }

    /// Persists one post-handler controller event for the reviewed HTTP audit
    /// boundary. Unlike the legacy mutation helper, a returned HTTP error is
    /// still a successful method outcome; Java records failure only when the
    /// controller throws.
    pub(crate) fn record_http_audit(
        &self,
        record: &SecurityHttpAuditRecord,
    ) -> Result<(), SecurityError> {
        let (user_id, principal, session_id) =
            record
                .context
                .as_ref()
                .map_or((None, "system", ""), |context| {
                    (
                        Some(context.user_id),
                        context.username.as_str(),
                        context.session_id.as_str(),
                    )
                });
        for value in [
            principal,
            record.source.as_str(),
            record.event_type.as_str(),
            record.method.as_str(),
            record.path.as_str(),
            record.correlation_id.as_str(),
            session_id,
        ] {
            if value.len() > MAX_AUDIT_VALUE_BYTES {
                return Err(SecurityError::InvalidInput);
            }
        }
        if record.event_type.is_empty()
            || record.method.is_empty()
            || record.path.is_empty()
            || record.correlation_id.is_empty()
        {
            return Err(SecurityError::InvalidInput);
        }
        let outcome_key = if record.annotated {
            "status"
        } else {
            "outcome"
        };
        let mut data = serde_json::json!({
            "timestamp": record.timestamp.as_str(),
            "principal": principal,
            "httpMethod": record.method.as_str(),
            "path": record.path.as_str(),
        });
        data[outcome_key] = serde_json::Value::String("success".to_owned());
        if let Some(client_ip) = &record.client_ip {
            if client_ip.len() > MAX_AUDIT_VALUE_BYTES {
                return Err(SecurityError::InvalidInput);
            }
            data["__ipAddress"] = serde_json::Value::String(client_ip.clone());
        }
        if record.include_standard_data {
            data["sessionId"] = if session_id.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(session_id.to_owned())
            };
            data["requestId"] = serde_json::Value::String(record.correlation_id.clone());
            data["latencyMs"] = serde_json::Value::from(record.latency_ms);
            data["statusCode"] = serde_json::Value::from(record.status_code);
            if let Some(client_ip) = &record.client_ip {
                data["clientIp"] = serde_json::Value::String(client_ip.clone());
            }
        }
        if let Some(result) = &record.result {
            data["result"] = serde_json::Value::String(result.clone());
        }
        record.enrichment.merge_into(&mut data);
        let data = serde_json::to_string(&data).map_err(|_| SecurityError::InvalidInput)?;
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO security_audit_events
             (user_id, principal, source, data, session_id, correlation_id,
              event_type, path, outcome, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'success', ?9)",
            params![
                user_id,
                principal,
                record.source.as_str(),
                data,
                session_id,
                record.correlation_id.as_str(),
                record.event_type.as_str(),
                record.path.as_str(),
                record.created_at,
            ],
        )?;
        Ok(())
    }

    /// Returns a newest-first page of durable audit events matching bounded filters.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid filters/pagination or unavailable persistent state.
    pub fn query_audit_events(
        &self,
        filter: &SecurityAuditFilter,
        offset: usize,
        limit: usize,
    ) -> Result<SecurityAuditPage, SecurityError> {
        if limit == 0 || limit > 200 {
            return Err(SecurityError::InvalidInput);
        }
        let limit = i64::try_from(limit).map_err(|_| SecurityError::InvalidInput)?;
        let offset = i64::try_from(offset).map_err(|_| SecurityError::InvalidInput)?;
        let (where_clause, values) = audit_filter_sql(filter)?;
        let connection = self.lock()?;
        let count_sql = format!("SELECT COUNT(*) FROM security_audit_events{where_clause}");
        let total_events: i64 =
            connection.query_row(&count_sql, params_from_iter(values.iter()), |row| {
                row.get(0)
            })?;
        let query_sql = format!(
            "SELECT event_id, principal, event_type, source, data, path, outcome, created_at
             FROM security_audit_events{where_clause}
             ORDER BY created_at DESC, event_id DESC LIMIT ? OFFSET ?"
        );
        let mut query_values = values;
        query_values.push(SqlValue::Integer(limit));
        query_values.push(SqlValue::Integer(offset));
        let mut statement = connection.prepare(&query_sql)?;
        let events = statement
            .query_map(params_from_iter(query_values.iter()), audit_event_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SecurityAuditPage {
            events,
            total_events: usize::try_from(total_events).map_err(|_| SecurityError::InvalidInput)?,
        })
    }

    /// Returns a bounded newest-first export set matching the same filters.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid filters, an oversized export, or unavailable state.
    pub fn export_audit_events(
        &self,
        filter: &SecurityAuditFilter,
    ) -> Result<Vec<SecurityAuditEvent>, SecurityError> {
        let page = self.query_audit_events(filter, 0, 200)?;
        if page.total_events > MAX_AUDIT_EXPORT_EVENTS {
            return Err(SecurityError::InvalidInput);
        }
        if page.total_events <= page.events.len() {
            return Ok(page.events);
        }
        let (where_clause, mut values) = audit_filter_sql(filter)?;
        values.push(SqlValue::Integer(
            i64::try_from(MAX_AUDIT_EXPORT_EVENTS).map_err(|_| SecurityError::InvalidInput)?,
        ));
        let query_sql = format!(
            "SELECT event_id, principal, event_type, source, data, path, outcome, created_at
             FROM security_audit_events{where_clause}
             ORDER BY created_at DESC, event_id DESC LIMIT ?"
        );
        let connection = self.lock()?;
        let mut statement = connection.prepare(&query_sql)?;
        statement
            .query_map(params_from_iter(values.iter()), audit_event_from_row)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Lists all distinct stored event types in lexical order.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn audit_event_types(&self) -> Result<Vec<String>, SecurityError> {
        self.audit_distinct_values("event_type")
    }

    /// Computes the self-hosted editor-fleet usage card from durable identities
    /// and STANDARD-level WEB audit events.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent security or audit state is unavailable.
    pub fn fleet_usage_stats(
        &self,
        standard_audit_enabled: bool,
        now: i64,
    ) -> Result<FleetUsageStats, SecurityError> {
        let connection = self.lock()?;
        let editors_deployed = connection.query_row(
            "SELECT COUNT(*) FROM security_users WHERE username_norm <> LOWER(?1)",
            [INTERNAL_API_USERNAME],
            |row| row.get::<_, i64>(0),
        )?;
        if !standard_audit_enabled {
            return Ok(FleetUsageStats {
                editors_deployed,
                active_this_month: None,
                pdfs_processed: None,
            });
        }
        let since = now.saturating_sub(30 * 24 * 60 * 60);
        let active_this_month = connection.query_row(
            "SELECT COUNT(DISTINCT principal)
             FROM security_audit_events
             WHERE source = 'WEB' AND event_type <> 'UI_DATA' AND created_at > ?1",
            [since],
            |row| row.get::<_, i64>(0),
        )?;
        let pdfs_processed = connection.query_row(
            "SELECT COUNT(*)
             FROM security_audit_events
             WHERE source = 'WEB'
               AND event_type IN ('PDF_PROCESS', 'FILE_OPERATION')
               AND created_at > 0",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(FleetUsageStats {
            editors_deployed,
            active_this_month: Some(active_this_month.min(editors_deployed)),
            pdfs_processed: Some(pdfs_processed),
        })
    }

    /// Loads only the retained JSON payloads needed by endpoint-usage
    /// aggregation, after applying Java's strict cutoff and exact UI/non-UI
    /// type split. The explicit row bound replaces Java's unbounded materialization.
    pub(crate) fn endpoint_usage_audit_data(
        &self,
        cutoff: i64,
        scope: SecurityAuditUsageScope,
    ) -> Result<Vec<String>, SecurityError> {
        let type_predicate = match scope {
            SecurityAuditUsageScope::All => "",
            SecurityAuditUsageScope::Ui => " AND event_type = 'UI_DATA'",
            SecurityAuditUsageScope::Api => " AND event_type <> 'UI_DATA'",
        };
        let connection = self.lock()?;
        let count_sql = format!(
            "SELECT COUNT(*) FROM security_audit_events
             WHERE created_at > ?1{type_predicate}"
        );
        let count = connection.query_row(&count_sql, [cutoff], |row| row.get::<_, i64>(0))?;
        if count > 50_000 {
            return Err(SecurityError::AuditEventLimitExceeded);
        }
        let query_sql = format!(
            "SELECT data FROM security_audit_events
             WHERE created_at > ?1{type_predicate}"
        );
        let mut statement = connection.prepare(&query_sql)?;
        statement
            .query_map([cutoff], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    /// Lists all distinct retained principals in lexical order.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn audit_principals(&self) -> Result<Vec<String>, SecurityError> {
        self.audit_distinct_values("principal")
    }

    /// Deletes audit events strictly older than the supplied timestamp.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn delete_audit_events_before(&self, cutoff: i64) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM security_audit_events WHERE created_at < ?1",
                [cutoff],
            )
            .map_err(SecurityError::from)
    }

    /// Deletes every retained audit event.
    ///
    /// # Errors
    ///
    /// Returns an error when persistent state is unavailable.
    pub fn clear_audit_events(&self) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        connection
            .execute("DELETE FROM security_audit_events", [])
            .map_err(SecurityError::from)
    }

    fn audit_distinct_values(&self, column: &str) -> Result<Vec<String>, SecurityError> {
        let sql = match column {
            "event_type" => {
                "SELECT DISTINCT event_type FROM security_audit_events ORDER BY event_type"
            }
            "principal" => {
                "SELECT DISTINCT principal FROM security_audit_events
                 WHERE principal != '' ORDER BY principal COLLATE NOCASE"
            }
            _ => return Err(SecurityError::InvalidInput),
        };
        let connection = self.lock()?;
        let mut statement = connection.prepare(sql)?;
        statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(SecurityError::from)
    }

    fn read_mfa(&self, user_id: i64) -> Result<Option<StoredMfa>, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT enabled, secret_ciphertext, last_used_step
                 FROM security_mfa WHERE user_id = ?1",
                [user_id],
                |row| {
                    Ok(StoredMfa {
                        enabled: row.get(0)?,
                        secret_ciphertext: row.get(1)?,
                        last_used_step: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(SecurityError::from)
    }

    fn validated_mfa_step(
        &self,
        user_id: i64,
        mfa: &StoredMfa,
        code: &str,
        now: i64,
    ) -> Result<i64, SecurityError> {
        let cipher = self.require_secret_cipher()?;
        let associated_data = mfa_associated_data(user_id);
        let plaintext = cipher.decrypt(&mfa.secret_ciphertext, associated_data.as_bytes())?;
        let secret =
            std::str::from_utf8(&plaintext).map_err(|_| SecurityError::MfaConfiguration)?;
        let step = valid_totp_step(secret, code, now).ok_or(SecurityError::InvalidMfa)?;
        if mfa
            .last_used_step
            .is_some_and(|last_used| step <= last_used)
        {
            return Err(SecurityError::InvalidMfa);
        }
        Ok(step)
    }

    fn require_secret_cipher(&self) -> Result<&ProtectedSecretCipher, SecurityError> {
        self.secret_cipher
            .as_ref()
            .ok_or(SecurityError::MfaConfiguration)
    }

    pub(crate) fn is_team_owner(&self, user_id: i64, team_id: i64) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM security_team_memberships
                     WHERE user_id = ?1 AND team_id = ?2 AND is_owner = 1
                 )",
                params![user_id, team_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(crate) fn is_any_team_owner(&self, user_id: i64) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM security_team_memberships
                     WHERE user_id = ?1 AND is_owner = 1
                 )",
                [user_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(crate) fn resource_principal_exists(
        &self,
        principal_type: PrincipalType,
        principal_id: i64,
    ) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        let table = match principal_type {
            PrincipalType::User => "security_users",
            PrincipalType::Team => "security_teams",
        };
        let column = match principal_type {
            PrincipalType::User => "user_id",
            PrincipalType::Team => "team_id",
        };
        connection
            .query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {column} = ?1)"),
                [principal_id],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn upsert_resource_grant(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
        principal_type: PrincipalType,
        principal_id: i64,
        permission: AccessPermission,
        granted_by_user_id: i64,
    ) -> Result<ResourceGrant, SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing_id = transaction
            .query_row(
                "SELECT resource_grant_id FROM resource_grants
                 WHERE resource_type = ?1 AND resource_id = ?2
                   AND principal_type = ?3 AND principal_id = ?4
                 ORDER BY resource_grant_id LIMIT 1",
                params![
                    resource_type.as_str(),
                    resource_id,
                    principal_type.as_str(),
                    principal_id,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(existing_id) = existing_id {
            transaction.execute(
                "UPDATE resource_grants
                 SET permission = ?1, granted_by_user_id = ?2
                 WHERE resource_grant_id = ?3",
                params![permission.as_str(), granted_by_user_id, existing_id],
            )?;
            transaction.execute(
                "DELETE FROM resource_grants
                 WHERE resource_type = ?1 AND resource_id = ?2
                   AND principal_type = ?3 AND principal_id = ?4
                   AND resource_grant_id != ?5",
                params![
                    resource_type.as_str(),
                    resource_id,
                    principal_type.as_str(),
                    principal_id,
                    existing_id,
                ],
            )?;
        } else {
            transaction.execute(
                "INSERT INTO resource_grants
                     (resource_type, resource_id, principal_type, principal_id, permission,
                      granted_by_user_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    resource_type.as_str(),
                    resource_id,
                    principal_type.as_str(),
                    principal_id,
                    permission.as_str(),
                    granted_by_user_id,
                ],
            )?;
        }
        let grant = transaction.query_row(
            "SELECT resource_grant_id, resource_type, resource_id, principal_type, principal_id,
                    permission,
                    strftime('%Y-%m-%dT%H:%M:%S', created_at, 'unixepoch')
             FROM resource_grants
             WHERE resource_type = ?1 AND resource_id = ?2
               AND principal_type = ?3 AND principal_id = ?4",
            params![
                resource_type.as_str(),
                resource_id,
                principal_type.as_str(),
                principal_id,
            ],
            resource_grant_from_row,
        )?;
        transaction.commit()?;
        Ok(grant)
    }

    pub(crate) fn revoke_resource_grant(&self, id: i64) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM resource_grants WHERE resource_grant_id = ?1",
            [id],
        )?;
        Ok(())
    }

    pub(crate) fn list_resource_grants(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
    ) -> Result<Vec<ResourceGrant>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT resource_grant_id, resource_type, resource_id, principal_type, principal_id,
                    permission,
                    strftime('%Y-%m-%dT%H:%M:%S', created_at, 'unixepoch')
             FROM resource_grants
             WHERE resource_type = ?1 AND resource_id = ?2 ORDER BY resource_grant_id",
        )?;
        statement
            .query_map(
                params![resource_type.as_str(), resource_id],
                resource_grant_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn list_resource_grants_for_principal(
        &self,
        principal_type: PrincipalType,
        principal_id: i64,
    ) -> Result<Vec<ResourceGrant>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT resource_grant_id, resource_type, resource_id, principal_type, principal_id,
                    permission,
                    strftime('%Y-%m-%dT%H:%M:%S', created_at, 'unixepoch')
             FROM resource_grants
             WHERE principal_type = ?1 AND principal_id = ?2 ORDER BY resource_grant_id",
        )?;
        statement
            .query_map(
                params![principal_type.as_str(), principal_id],
                resource_grant_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn granted_resource_ids(
        &self,
        resource_type: ResourceType,
        user_id: i64,
        team_id: Option<i64>,
    ) -> Result<BTreeSet<String>, SecurityError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT DISTINCT resource_id FROM resource_grants
             WHERE resource_type = ?1
               AND ((principal_type = 'USER' AND principal_id = ?2)
                 OR (principal_type = 'TEAM' AND principal_id = ?3))
             ORDER BY resource_id",
        )?;
        statement
            .query_map(params![resource_type.as_str(), user_id, team_id], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn create_integration_config(
        &self,
        config: &NewIntegrationConfig,
    ) -> Result<IntegrationConfig, SecurityError> {
        let encrypted = self.encrypt_integration_config(&config.config)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO integration_configs
                 (integration_type, name, scope, owner_user_id, owner_team_id,
                  enabled, locked, default_access, config_encrypted)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                config.integration_type.as_str(),
                config.name,
                config.scope.as_str(),
                config.owner_user_id,
                config.owner_team_id,
                config.enabled,
                config.locked,
                config.default_access.as_str(),
                encrypted,
            ],
        )?;
        let id = transaction.last_insert_rowid();
        let stored = select_integration_config(&transaction, id, self.integration_cipher()?)?
            .ok_or(SecurityError::Conflict)?;
        transaction.commit()?;
        Ok(stored)
    }

    pub(crate) fn update_integration_config(
        &self,
        config: &IntegrationConfig,
    ) -> Result<IntegrationConfig, SecurityError> {
        let encrypted = self.encrypt_integration_config(&config.config)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = transaction.execute(
            "UPDATE integration_configs
             SET name = ?1, enabled = ?2, locked = ?3, default_access = ?4,
                 config_encrypted = ?5, updated_at = unixepoch()
             WHERE integration_config_id = ?6",
            params![
                config.name,
                config.enabled,
                config.locked,
                config.default_access.as_str(),
                encrypted,
                config.id,
            ],
        )?;
        if updated != 1 {
            return Err(SecurityError::Conflict);
        }
        let stored =
            select_integration_config(&transaction, config.id, self.integration_cipher()?)?
                .ok_or(SecurityError::Conflict)?;
        transaction.commit()?;
        Ok(stored)
    }

    pub(crate) fn get_integration_config(
        &self,
        id: i64,
    ) -> Result<Option<IntegrationConfig>, SecurityError> {
        let connection = self.lock()?;
        select_integration_config(&connection, id, self.integration_cipher()?)
    }

    pub(crate) fn list_integration_configs(&self) -> Result<Vec<IntegrationConfig>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT integration_config_id, integration_type, name, scope,
                    owner_user_id, owner_team_id, enabled, locked, default_access,
                    config_encrypted,
                    strftime('%Y-%m-%dT%H:%M:%S', created_at, 'unixepoch'),
                    strftime('%Y-%m-%dT%H:%M:%S', updated_at, 'unixepoch')
             FROM integration_configs ORDER BY integration_config_id",
        )?;
        statement
            .query_map([], |row| integration_config_from_row(row, cipher))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn locked_server_integration_exists(
        &self,
        integration_type: IntegrationType,
    ) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM integration_configs
                     WHERE scope = 'SERVER' AND integration_type = ?1 AND locked = 1
                 )",
                [integration_type.as_str()],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(crate) fn delete_integration_config(&self, id: i64) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM resource_grants
             WHERE resource_type = 'INTEGRATION_CONFIG' AND resource_id = ?1",
            [id.to_string()],
        )?;
        transaction.execute(
            "DELETE FROM integration_configs WHERE integration_config_id = ?1",
            [id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn integration_config_usages(&self, id: i64) -> Result<Vec<String>, SecurityError> {
        let mut usages = self
            .list_all_policy_sources()?
            .into_iter()
            .filter(|source| options_reference_integration(&source.options, id))
            .map(|source| format!("source '{}'", source.name))
            .collect::<Vec<_>>();
        usages.extend(
            self.list_all_policy_definitions()?
                .into_iter()
                .filter(|policy| options_reference_integration(&policy.output.options, id))
                .map(|policy| format!("pipeline '{}'", policy.name)),
        );
        Ok(usages)
    }

    pub(crate) fn save_policy_source(&self, source: &PolicySource) -> Result<(), SecurityError> {
        let plaintext = serde_json::to_vec(source).map_err(|_| SecurityError::InvalidInput)?;
        let encrypted = self
            .integration_cipher()?
            .encrypt_java_compatible(&plaintext)?;
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO policy_sources
                 (id, name, type, owner, team_id, enabled, source_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 type = excluded.type,
                 owner = excluded.owner,
                 team_id = excluded.team_id,
                 enabled = excluded.enabled,
                 source_json = excluded.source_json",
            params![
                source.id,
                source.name,
                source.source_type,
                source.owner,
                source.team_id,
                source.enabled,
                encrypted,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn get_policy_source(
        &self,
        id: &str,
    ) -> Result<Option<PolicySource>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT source_json FROM policy_sources WHERE id = ?1",
                [id],
                |row| protected_json_from_row(row, 0, cipher),
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn list_policy_sources(
        &self,
        team_id: Option<i64>,
    ) -> Result<Vec<PolicySource>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT source_json FROM policy_sources
             WHERE team_id IS ?1 ORDER BY name, id",
        )?;
        statement
            .query_map([team_id], |row| protected_json_from_row(row, 0, cipher))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn list_all_policy_sources(&self) -> Result<Vec<PolicySource>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare("SELECT source_json FROM policy_sources")?;
        statement
            .query_map([], |row| protected_json_from_row(row, 0, cipher))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn delete_policy_source(&self, id: &str) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        connection.execute("DELETE FROM policy_sources WHERE id = ?1", [id])?;
        Ok(())
    }

    pub(crate) fn policy_source_doc_stats(
        &self,
        source_ids: &[String],
    ) -> Result<BTreeMap<String, SourceDocStats>, SecurityError> {
        let connection = self.lock()?;
        let now_hour: i64 =
            connection.query_row("SELECT CAST(unixepoch() / 3600 AS INTEGER)", [], |row| {
                row.get(0)
            })?;
        let first_day_hour = ((now_hour / 24) - 29) * 24;
        let mut result = BTreeMap::new();
        let mut statement = connection.prepare(
            "SELECT
                 COALESCE((SELECT doc_total FROM policy_source_doc_totals WHERE source_id = ?1), 0),
                 COALESCE(SUM(CASE WHEN bucket_hour >= ?2 THEN doc_count ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN bucket_hour >= ?3 THEN doc_count ELSE 0 END), 0)
             FROM policy_source_doc_counts WHERE source_id = ?1",
        )?;
        for source_id in source_ids {
            let (total, recent_docs, monthly_docs) =
                statement.query_row(params![source_id, now_hour - 23, first_day_hour], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?;
            result.insert(
                source_id.clone(),
                SourceDocStats {
                    total: u64::try_from(total).unwrap_or_default(),
                    last_24h: u64::try_from(recent_docs).unwrap_or_default(),
                    last_30d: u64::try_from(monthly_docs).unwrap_or_default(),
                },
            );
        }
        Ok(result)
    }

    pub(crate) fn policy_source_daily_series(
        &self,
        source_id: &str,
    ) -> Result<Vec<u64>, SecurityError> {
        const DAYS: usize = 30;
        const DAYS_I64: i64 = 30;
        let connection = self.lock()?;
        let current_day: i64 =
            connection.query_row("SELECT CAST(unixepoch() / 86400 AS INTEGER)", [], |row| {
                row.get(0)
            })?;
        let first_day = current_day - (DAYS_I64 - 1);
        let mut series = vec![0_u64; DAYS];
        let mut statement = connection.prepare(
            "SELECT CAST(bucket_hour / 24 AS INTEGER), SUM(doc_count)
             FROM policy_source_doc_counts
             WHERE source_id = ?1 AND bucket_hour >= ?2
             GROUP BY CAST(bucket_hour / 24 AS INTEGER)",
        )?;
        let rows = statement.query_map(params![source_id, first_day * 24], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (day, count) = row?;
            let index = day - first_day;
            if let Ok(index) = usize::try_from(index)
                && index < DAYS
            {
                series[index] = u64::try_from(count).unwrap_or_default();
            }
        }
        Ok(series)
    }

    pub(crate) fn record_policy_source_docs(
        &self,
        source_id: &str,
        documents: u64,
    ) -> Result<(), SecurityError> {
        if documents == 0 {
            return Ok(());
        }
        let documents = i64::try_from(documents).map_err(|_| SecurityError::InvalidInput)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let bucket_hour: i64 =
            transaction.query_row("SELECT CAST(unixepoch() / 3600 AS INTEGER)", [], |row| {
                row.get(0)
            })?;
        transaction.execute(
            "INSERT INTO policy_source_doc_totals(source_id, doc_total) VALUES (?1, ?2)
             ON CONFLICT(source_id) DO UPDATE SET doc_total = doc_total + excluded.doc_total",
            params![source_id, documents],
        )?;
        transaction.execute(
            "INSERT INTO policy_source_doc_counts(source_id, bucket_hour, doc_count)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(source_id, bucket_hour)
             DO UPDATE SET doc_count = doc_count + excluded.doc_count",
            params![source_id, bucket_hour, documents],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(dead_code, reason = "used by the staged policy source-sweep port")]
    pub(crate) fn policy_processed_states(
        &self,
        policy_id: &str,
        identities: &[String],
    ) -> Result<HashMap<String, ClaimState>, SecurityError> {
        if identities.is_empty() {
            return Ok(HashMap::new());
        }
        let identity_by_hash = identities
            .iter()
            .map(|identity| (policy_identity_hash(identity), identity.clone()))
            .collect::<HashMap<_, _>>();
        let hashes = identity_by_hash.keys().cloned().collect::<Vec<_>>();
        let connection = self.lock()?;
        let mut states = HashMap::new();
        for chunk in hashes.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT identity_hash, status, signature, content_hash
                 FROM policy_processed_files
                 WHERE policy_id = ? AND identity_hash IN ({placeholders})"
            );
            let mut values = Vec::with_capacity(chunk.len() + 1);
            values.push(SqlValue::Text(policy_id.to_owned()));
            values.extend(chunk.iter().cloned().map(SqlValue::Text));
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(params_from_iter(values.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?;
            for row in rows {
                let (hash, status_value, gate, content_hash) = row?;
                let identity = identity_by_hash
                    .get(&hash)
                    .cloned()
                    .ok_or(SecurityError::Conflict)?;
                states.insert(
                    identity,
                    ClaimState {
                        status: ProcessedFileStatus::parse(&status_value)?,
                        gate,
                        content_hash,
                    },
                );
            }
        }
        Ok(states)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code, reason = "used by the staged policy source-sweep port")]
    pub(crate) fn claim_policy_processed_file(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
        content_hash: Option<&str>,
        observed: Option<&ClaimState>,
        now_millis: i64,
    ) -> Result<bool, SecurityError> {
        validate_policy_claim(policy_id, identity, gate, content_hash)?;
        let hash = policy_identity_hash(identity);
        let connection = self.lock()?;
        let Some(observed) = observed else {
            return connection
                .execute(
                    "INSERT INTO policy_processed_files
                         (policy_id, identity_hash, identity, signature, content_hash, status,
                          attempts, last_seen, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'PROCESSING', 1, ?6, ?6)
                     ON CONFLICT(policy_id, identity_hash) DO NOTHING",
                    params![policy_id, hash, identity, gate, content_hash, now_millis],
                )
                .map(|updated| updated == 1)
                .map_err(Into::into);
        };
        if observed.status == ProcessedFileStatus::Processing {
            return Ok(false);
        }
        if observed.gate == gate {
            if observed.status != ProcessedFileStatus::Interrupted {
                return Ok(false);
            }
            return connection
                .execute(
                    "UPDATE policy_processed_files
                     SET status = 'PROCESSING', attempts = attempts + 1,
                         last_seen = ?1, updated_at = ?1
                     WHERE policy_id = ?2 AND identity_hash = ?3
                       AND status = 'INTERRUPTED' AND signature = ?4 AND attempts < ?5",
                    params![now_millis, policy_id, hash, gate, MAX_ATTEMPTS],
                )
                .map(|updated| updated == 1)
                .map_err(Into::into);
        }
        let Some(content_hash) = content_hash else {
            return connection
                .execute(
                    "UPDATE policy_processed_files
                     SET status = 'PROCESSING', signature = ?1, content_hash = NULL, attempts = 1,
                         last_seen = ?2, updated_at = ?2
                     WHERE policy_id = ?3 AND identity_hash = ?4
                       AND status <> 'PROCESSING' AND signature <> ?1",
                    params![gate, now_millis, policy_id, hash],
                )
                .map(|updated| updated == 1)
                .map_err(Into::into);
        };
        if observed.content_hash.as_deref() == Some(content_hash) {
            if observed.status == ProcessedFileStatus::Interrupted {
                return connection
                    .execute(
                        "UPDATE policy_processed_files
                         SET status = 'PROCESSING', signature = ?1, attempts = attempts + 1,
                             last_seen = ?2, updated_at = ?2
                         WHERE policy_id = ?3 AND identity_hash = ?4
                           AND status = 'INTERRUPTED' AND content_hash = ?5 AND attempts < ?6",
                        params![
                            gate,
                            now_millis,
                            policy_id,
                            hash,
                            content_hash,
                            MAX_ATTEMPTS
                        ],
                    )
                    .map(|updated| updated == 1)
                    .map_err(Into::into);
            }
            connection.execute(
                "UPDATE policy_processed_files
                 SET signature = ?1, last_seen = ?2, updated_at = ?2
                 WHERE policy_id = ?3 AND identity_hash = ?4
                   AND status <> 'PROCESSING' AND content_hash = ?5 AND signature <> ?1",
                params![gate, now_millis, policy_id, hash, content_hash],
            )?;
            return Ok(false);
        }
        connection
            .execute(
                "UPDATE policy_processed_files
                 SET status = 'PROCESSING', signature = ?1, content_hash = ?2, attempts = 1,
                     last_seen = ?3, updated_at = ?3
                 WHERE policy_id = ?4 AND identity_hash = ?5
                   AND status <> 'PROCESSING'
                   AND (content_hash IS NULL OR content_hash <> ?2)",
                params![gate, content_hash, now_millis, policy_id, hash],
            )
            .map(|updated| updated == 1)
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code, reason = "used by the staged policy source-sweep port")]
    pub(crate) fn settle_policy_processed_file(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
        content_hash: Option<&str>,
        status: ProcessedFileStatus,
        now_millis: i64,
    ) -> Result<(), SecurityError> {
        validate_policy_claim(policy_id, identity, gate, content_hash)?;
        if status == ProcessedFileStatus::Processing {
            return Err(SecurityError::InvalidInput);
        }
        let connection = self.lock()?;
        connection.execute(
            "INSERT INTO policy_processed_files
                 (policy_id, identity_hash, identity, signature, content_hash, status,
                  attempts, last_seen, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7)
             ON CONFLICT(policy_id, identity_hash) DO UPDATE SET
                 signature = excluded.signature,
                 content_hash = excluded.content_hash,
                 status = excluded.status,
                 last_seen = excluded.last_seen,
                 updated_at = excluded.updated_at",
            params![
                policy_id,
                policy_identity_hash(identity),
                identity,
                gate,
                content_hash,
                status.as_str(),
                now_millis
            ],
        )?;
        Ok(())
    }

    #[allow(dead_code, reason = "used by the staged policy output-sink port")]
    pub(crate) fn forget_policy_processed_output(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
    ) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM policy_processed_files
             WHERE policy_id = ?1 AND identity_hash = ?2
               AND signature = ?3 AND status = 'DONE'",
            params![policy_id, policy_identity_hash(identity), gate],
        )?;
        Ok(())
    }

    #[allow(dead_code, reason = "used by the staged policy source-sweep port")]
    pub(crate) fn all_policy_processed_done(&self, identity: &str) -> Result<bool, SecurityError> {
        let connection = self.lock()?;
        let unsettled: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM policy_processed_files
                 WHERE identity_hash = ?1 AND status <> 'DONE'
             )",
            [policy_identity_hash(identity)],
            |row| row.get(0),
        )?;
        Ok(!unsettled)
    }

    #[allow(dead_code, reason = "used by the staged policy source-sweep port")]
    pub(crate) fn mark_policy_processed_seen(
        &self,
        policy_id: &str,
        identities: &[String],
        now_millis: i64,
    ) -> Result<(), SecurityError> {
        if identities.is_empty() {
            return Ok(());
        }
        let hashes = identities
            .iter()
            .map(|identity| policy_identity_hash(identity))
            .collect::<Vec<_>>();
        let connection = self.lock()?;
        for chunk in hashes.chunks(500) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "UPDATE policy_processed_files SET last_seen = ?
                 WHERE policy_id = ? AND identity_hash IN ({placeholders})"
            );
            let mut values = Vec::with_capacity(chunk.len() + 2);
            values.push(SqlValue::Integer(now_millis));
            values.push(SqlValue::Text(policy_id.to_owned()));
            values.extend(chunk.iter().cloned().map(SqlValue::Text));
            connection.execute(&sql, params_from_iter(values.iter()))?;
        }
        Ok(())
    }

    #[allow(dead_code, reason = "used by the staged policy source-sweep port")]
    pub(crate) fn delete_unseen_policy_processed(
        &self,
        policy_id: &str,
        seen_since_millis: i64,
    ) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        connection
            .execute(
                "DELETE FROM policy_processed_files
                 WHERE policy_id = ?1 AND last_seen < ?2 AND status <> 'PROCESSING'",
                params![policy_id, seen_since_millis],
            )
            .map_err(Into::into)
    }

    #[allow(dead_code, reason = "mounted with the staged processed-history route")]
    pub(crate) fn clear_policy_processed_history(
        &self,
        policy_id: &str,
    ) -> Result<(), SecurityError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM policy_processed_files WHERE policy_id = ?1",
            [policy_id],
        )?;
        Ok(())
    }

    pub(crate) fn recover_interrupted_policy_files(
        &self,
        now_millis: i64,
    ) -> Result<usize, SecurityError> {
        let connection = self.lock()?;
        connection
            .execute(
                "UPDATE policy_processed_files
                 SET status = 'INTERRUPTED', updated_at = ?1
                 WHERE status = 'PROCESSING'",
                [now_millis],
            )
            .map_err(Into::into)
    }

    pub(crate) fn save_policy_definition(
        &self,
        policy: &PolicyDefinition,
    ) -> Result<(), SecurityError> {
        let plaintext = serde_json::to_vec(policy).map_err(|_| SecurityError::InvalidInput)?;
        let encrypted = self
            .integration_cipher()?
            .encrypt_java_compatible(&plaintext)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing_sort_order = transaction
            .query_row(
                "SELECT sort_order FROM policies WHERE id = ?1",
                [&policy.id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        let sort_order = existing_sort_order.unwrap_or_else(|| {
            transaction
                .query_row(
                    "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM policies
                     WHERE team_id IS ?1",
                    [policy.team_id],
                    |row| row.get(0),
                )
                .unwrap_or(0)
        });
        transaction.execute(
            "INSERT INTO policies
                 (id, name, owner, enabled, trigger_type, team_id, sort_order, policy_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 owner = excluded.owner,
                 enabled = excluded.enabled,
                 trigger_type = excluded.trigger_type,
                 team_id = excluded.team_id,
                 sort_order = excluded.sort_order,
                 policy_json = excluded.policy_json",
            params![
                policy.id,
                policy.name,
                policy.owner,
                policy.enabled,
                policy.trigger.as_ref().map(|trigger| &trigger.trigger_type),
                policy.team_id,
                sort_order,
                encrypted,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn get_policy_definition(
        &self,
        id: &str,
    ) -> Result<Option<PolicyDefinition>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT policy_json FROM policies WHERE id = ?1",
                [id],
                |row| protected_json_from_row(row, 0, cipher),
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn list_policy_definitions(
        &self,
        team_id: Option<i64>,
    ) -> Result<Vec<PolicyDefinition>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT policy_json FROM policies WHERE team_id IS ?1
             ORDER BY COALESCE(sort_order, 0), id",
        )?;
        statement
            .query_map([team_id], |row| protected_json_from_row(row, 0, cipher))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn list_all_policy_definitions(
        &self,
    ) -> Result<Vec<PolicyDefinition>, SecurityError> {
        let cipher = self.integration_cipher()?;
        let connection = self.lock()?;
        let mut statement = connection.prepare("SELECT policy_json FROM policies")?;
        statement
            .query_map([], |row| protected_json_from_row(row, 0, cipher))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn reorder_policy_definitions(
        &self,
        team_id: Option<i64>,
        ids: &[String],
    ) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut position = 0_i64;
        for id in ids {
            let updated = transaction.execute(
                "UPDATE policies SET sort_order = ?1 WHERE id = ?2 AND team_id IS ?3",
                params![position, id, team_id],
            )?;
            if updated == 1 {
                position += 1;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn delete_policy_definition(&self, id: &str) -> Result<(), SecurityError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "DELETE FROM policy_processed_files WHERE policy_id = ?1",
            [id],
        )?;
        transaction.execute("DELETE FROM policies WHERE id = ?1", [id])?;
        transaction.commit()?;
        Ok(())
    }

    fn integration_cipher(&self) -> Result<&ProtectedSecretCipher, SecurityError> {
        self.secret_cipher
            .as_ref()
            .ok_or(SecurityError::IntegrationProtectionUnavailable)
    }

    fn encrypt_integration_config(
        &self,
        config: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<String, SecurityError> {
        let plaintext = serde_json::to_vec(config).map_err(|_| SecurityError::InvalidInput)?;
        self.integration_cipher()?
            .encrypt_java_compatible(&plaintext)
            .map_err(Into::into)
    }

    fn clear_login_failures(&self, username: &str) -> Result<(), SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM security_login_attempts WHERE username_norm = ?1",
            [normalized.normalized],
        )?;
        Ok(())
    }

    fn record_mfa_failure(&self, username: &str, now: i64) -> Result<(), SecurityError> {
        let normalized = normalize_username(username)?;
        let connection = self.lock()?;
        let _locked = record_login_failure(&connection, &normalized.normalized, now)?;
        Ok(())
    }

    fn create_first_user<const N: usize>(
        &self,
        username: &str,
        password: &str,
        roles: [&str; N],
    ) -> Result<bool, SecurityError> {
        let username = normalize_web_username(username)?;
        validate_password(password)?;
        let roles = normalize_roles(roles)?;
        let password_hash = hash(password, self.bcrypt_cost)?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let user_count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM security_users", [], |row| row.get(0))?;
        if user_count != 0 {
            transaction.rollback()?;
            return Ok(false);
        }
        let team_id = resolve_team_id(&transaction, None)?;
        transaction.execute(
            "INSERT INTO security_users
             (username, username_norm, password_hash, enabled, authentication_type, team_id)
             VALUES (?1, ?2, ?3, 1, 'web', ?4)",
            params![
                username.original,
                username.normalized,
                password_hash,
                team_id
            ],
        )?;
        let user_id = transaction.last_insert_rowid();
        insert_roles(&transaction, user_id, &roles)?;
        insert_team_membership(&transaction, user_id, team_id, false)?;
        transaction.commit()?;
        Ok(true)
    }

    fn web_password_hash(&self, user_id: i64) -> Result<String, SecurityError> {
        let connection = self.lock()?;
        let (password_hash, authentication_type) = connection
            .query_row(
                "SELECT password_hash, authentication_type
                 FROM security_users WHERE user_id = ?1",
                [user_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .ok_or(SecurityError::UserNotFound)?;
        if authentication_type != "web" {
            return Err(SecurityError::UnsupportedAuthenticationSource);
        }
        Ok(password_hash)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, SecurityError> {
        self.connection.lock().map_err(|_| SecurityError::Poisoned)
    }

    #[cfg(test)]
    pub(crate) fn audit_event_count(&self) -> Result<i64, SecurityError> {
        let connection = self.lock()?;
        connection
            .query_row("SELECT COUNT(*) FROM security_audit_events", [], |row| {
                row.get(0)
            })
            .map_err(SecurityError::from)
    }

    #[cfg(test)]
    pub(crate) fn in_memory() -> Result<Self, SecurityError> {
        Self::in_memory_with_cost(4)
    }

    #[cfg(test)]
    pub(crate) fn in_memory_with_cost(bcrypt_cost: u32) -> Result<Self, SecurityError> {
        let connection = Connection::open_in_memory()?;
        initialize_connection(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            bcrypt_cost,
            secret_cipher: Some(ProtectedSecretCipher::random()),
            license_state: RwLock::new(None),
        })
    }
}

fn audit_filter_sql(
    filter: &SecurityAuditFilter,
) -> Result<(String, Vec<SqlValue>), SecurityError> {
    if filter.event_types.len() > MAX_AUDIT_FILTER_VALUES
        || filter.principals.len() > MAX_AUDIT_FILTER_VALUES
        || (filter.principal_contains.is_some() && !filter.principals.is_empty())
        || filter.start_at.is_some() != filter.end_at.is_some()
        || filter
            .start_at
            .zip(filter.end_at)
            .is_some_and(|(start, end)| start >= end)
    {
        return Err(SecurityError::InvalidInput);
    }
    for value in filter
        .event_types
        .iter()
        .chain(&filter.principals)
        .chain(filter.principal_contains.iter())
    {
        if value.is_empty()
            || value.len() > MAX_AUDIT_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(SecurityError::InvalidInput);
        }
    }
    let mut clauses = Vec::new();
    let mut values = Vec::new();
    if !filter.event_types.is_empty() {
        clauses.push(format!(
            "event_type IN ({})",
            vec!["?"; filter.event_types.len()].join(",")
        ));
        values.extend(filter.event_types.iter().cloned().map(SqlValue::Text));
    }
    if !filter.principals.is_empty() {
        clauses.push(format!(
            "principal IN ({})",
            vec!["?"; filter.principals.len()].join(",")
        ));
        values.extend(filter.principals.iter().cloned().map(SqlValue::Text));
    }
    if let Some(principal) = &filter.principal_contains {
        clauses.push("LOWER(principal) LIKE LOWER(?)".to_owned());
        values.push(SqlValue::Text(format!("%{principal}%")));
    }
    if let Some((start, end)) = filter.start_at.zip(filter.end_at) {
        clauses.push("created_at >= ? AND created_at < ?".to_owned());
        values.push(SqlValue::Integer(start));
        values.push(SqlValue::Integer(end));
    }
    let where_clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    Ok((where_clause, values))
}

fn resource_grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResourceGrant> {
    let resource_type = row.get::<_, String>(1)?;
    let principal_type = row.get::<_, String>(3)?;
    let permission = row.get::<_, String>(5)?;
    Ok(ResourceGrant {
        id: row.get(0)?,
        resource_type: ResourceType::from_database(&resource_type)
            .ok_or_else(|| invalid_persisted_enum(1, &resource_type))?,
        resource_id: row.get(2)?,
        principal_type: PrincipalType::from_database(&principal_type)
            .ok_or_else(|| invalid_persisted_enum(3, &principal_type))?,
        principal_id: row.get(4)?,
        permission: AccessPermission::from_database(&permission)
            .ok_or_else(|| invalid_persisted_enum(5, &permission))?,
        created_at: row.get(6)?,
    })
}

fn select_integration_config(
    connection: &Connection,
    id: i64,
    cipher: &ProtectedSecretCipher,
) -> Result<Option<IntegrationConfig>, SecurityError> {
    connection
        .query_row(
            "SELECT integration_config_id, integration_type, name, scope,
                    owner_user_id, owner_team_id, enabled, locked, default_access,
                    config_encrypted,
                    strftime('%Y-%m-%dT%H:%M:%S', created_at, 'unixepoch'),
                    strftime('%Y-%m-%dT%H:%M:%S', updated_at, 'unixepoch')
             FROM integration_configs WHERE integration_config_id = ?1",
            [id],
            |row| integration_config_from_row(row, cipher),
        )
        .optional()
        .map_err(Into::into)
}

fn integration_config_from_row(
    row: &rusqlite::Row<'_>,
    cipher: &ProtectedSecretCipher,
) -> rusqlite::Result<IntegrationConfig> {
    let integration_type = row.get::<_, String>(1)?;
    let scope = row.get::<_, String>(3)?;
    let default_access = row.get::<_, String>(8)?;
    let encrypted = row.get::<_, Option<String>>(9)?;
    let config = match encrypted.filter(|value| !value.trim().is_empty()) {
        Some(encrypted) => {
            let plaintext = cipher
                .decrypt_java_compatible(&encrypted)
                .map_err(|error| invalid_persisted_value(9, error))?;
            serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&plaintext)
                .unwrap_or_default()
        }
        None => serde_json::Map::new(),
    };
    Ok(IntegrationConfig {
        id: row.get(0)?,
        integration_type: IntegrationType::from_database(&integration_type)
            .ok_or_else(|| invalid_persisted_enum(1, &integration_type))?,
        name: row.get(2)?,
        scope: OwnerScope::from_database(&scope)
            .ok_or_else(|| invalid_persisted_enum(3, &scope))?,
        owner_user_id: row.get(4)?,
        owner_team_id: row.get(5)?,
        enabled: row.get(6)?,
        locked: row.get(7)?,
        default_access: DefaultAccessPolicy::from_database(&default_access)
            .ok_or_else(|| invalid_persisted_enum(8, &default_access))?,
        config,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn invalid_persisted_enum(index: usize, value: &str) -> rusqlite::Error {
    invalid_persisted_value(
        index,
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid persisted enum value {value:?}"),
        ),
    )
}

fn invalid_persisted_value(
    index: usize,
    error: impl std::error::Error + Send + Sync + 'static,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(error))
}

fn protected_json_from_row<T: DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
    cipher: &ProtectedSecretCipher,
) -> rusqlite::Result<T> {
    let stored = row.get::<_, String>(index)?;
    let plaintext = cipher.decrypt_java_compatible(&stored).map_or_else(
        |_| stored.as_bytes().to_vec(),
        |plaintext| plaintext.to_vec(),
    );
    serde_json::from_slice(&plaintext).map_err(|error| invalid_persisted_value(index, error))
}

fn options_reference_integration(
    options: &serde_json::Map<String, serde_json::Value>,
    integration_id: i64,
) -> bool {
    options.get("connectionId").is_some_and(|reference| {
        reference.as_i64() == Some(integration_id)
            || reference
                .as_str()
                .and_then(|reference| reference.trim().parse::<i64>().ok())
                == Some(integration_id)
    })
}

fn audit_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecurityAuditEvent> {
    let stored_data = row.get::<_, String>(4)?;
    let path = row.get::<_, String>(5)?;
    let outcome = row.get::<_, String>(6)?;
    let mut data = serde_json::from_str::<serde_json::Value>(&stored_data).unwrap_or_else(|_| {
        serde_json::json!({
            "rawData": stored_data,
        })
    });
    if let Some(object) = data.as_object_mut() {
        object
            .entry("path")
            .or_insert_with(|| serde_json::Value::String(path));
        object
            .entry("outcome")
            .or_insert_with(|| serde_json::Value::String(outcome));
    }
    Ok(SecurityAuditEvent {
        id: row.get(0)?,
        principal: row.get(1)?,
        event_type: row.get(2)?,
        source: row.get(3)?,
        data: serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_owned()),
        timestamp: row.get(7)?,
    })
}

struct NormalizedUsername {
    original: String,
    normalized: String,
}

struct StoredMfa {
    enabled: bool,
    secret_ciphertext: String,
    last_used_step: Option<i64>,
}

struct StoredInvite {
    id: i64,
    email: Option<String>,
    role: String,
    team_id: i64,
    expires_at: i64,
}

impl StoredInvite {
    fn into_details(self) -> InviteDetails {
        let email_required = self.email.is_none();
        InviteDetails {
            email: self.email,
            role: self.role,
            team_id: self.team_id,
            expires_at: self.expires_at,
            email_required,
        }
    }
}

fn mfa_associated_data(user_id: i64) -> String {
    format!("stirling-security-mfa-v1:user:{user_id}")
}

fn validate_team_name(name: &str) -> Result<&str, SecurityError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_TEAM_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(SecurityError::InvalidInput);
    }
    Ok(name)
}

fn normalize_invite_email(email: &str) -> Result<String, SecurityError> {
    let normalized = normalize_username(email)?;
    if !normalized.normalized.contains('@') {
        return Err(SecurityError::InvalidInput);
    }
    Ok(normalized.normalized)
}

fn resolve_external_user(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    verification: LicenseVerification,
    now: i64,
) -> Result<StoredUser, SecurityError> {
    let blocked: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM security_external_identity_blocks
             WHERE issuer = ?1 AND subject = ?2
         )",
        params![identity.issuer, identity.subject],
        |row| row.get(0),
    )?;
    if blocked {
        return Err(SecurityError::AccountDisabled);
    }
    let existing_user_id = transaction
        .query_row(
            "SELECT user_id FROM security_external_identities
             WHERE issuer = ?1 AND subject = ?2",
            params![identity.issuer, identity.subject],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    if let Some(user_id) = existing_user_id {
        update_external_user(transaction, identity, username, user_id, now)
    } else {
        ensure_user_capacity(transaction, verification, 1)?;
        insert_external_user(transaction, identity, username, now)
    }
}

fn update_external_user(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    user_id: i64,
    now: i64,
) -> Result<StoredUser, SecurityError> {
    let mut user = find_user_by_id(transaction, user_id)?.ok_or(SecurityError::InvalidToken)?;
    if !user.enabled {
        return Err(SecurityError::AccountDisabled);
    }
    if user.authentication_type == "anonymous" && !identity.anonymous {
        reject_external_username_collision(transaction, username, user.id)?;
        transaction.execute(
            "UPDATE security_users
             SET username = ?1, username_norm = ?2, authentication_type = ?3
             WHERE user_id = ?4 AND authentication_type = 'anonymous'",
            params![
                username.original,
                username.normalized,
                identity.authentication_type,
                user.id
            ],
        )?;
        transaction.execute(
            "DELETE FROM security_user_roles WHERE user_id = ?1",
            [user.id],
        )?;
        transaction.execute(
            "INSERT INTO security_user_roles (user_id, role) VALUES (?1, 'ROLE_USER')",
            [user.id],
        )?;
        user.username.clone_from(&username.original);
        user.authentication_type
            .clone_from(&identity.authentication_type);
    } else if identity.anonymous != (user.authentication_type == "anonymous") {
        return Err(SecurityError::InvalidToken);
    } else if !identity.anonymous {
        update_external_profile(transaction, identity, username, &mut user)?;
    }
    transaction.execute(
        "UPDATE security_external_identities SET last_seen_at = ?1
         WHERE issuer = ?2 AND subject = ?3",
        params![now, identity.issuer, identity.subject],
    )?;
    Ok(user)
}

fn update_external_profile(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    user: &mut StoredUser,
) -> Result<(), SecurityError> {
    if !user.username.eq_ignore_ascii_case(&username.original) {
        reject_external_username_collision(transaction, username, user.id)?;
        transaction.execute(
            "UPDATE security_users SET username = ?1, username_norm = ?2 WHERE user_id = ?3",
            params![username.original, username.normalized, user.id],
        )?;
        user.username.clone_from(&identity.username);
    }
    transaction.execute(
        "UPDATE security_users SET authentication_type = ?1 WHERE user_id = ?2",
        params![identity.authentication_type, user.id],
    )?;
    user.authentication_type
        .clone_from(&identity.authentication_type);
    Ok(())
}

fn reject_external_username_collision(
    transaction: &Transaction<'_>,
    username: &NormalizedUsername,
    user_id: i64,
) -> Result<(), SecurityError> {
    if find_user(transaction, &username.normalized)?
        .is_some_and(|candidate| candidate.id != user_id)
    {
        return Err(SecurityError::Conflict);
    }
    Ok(())
}

fn insert_external_user(
    transaction: &Transaction<'_>,
    identity: &VerifiedSupabaseIdentity,
    username: &NormalizedUsername,
    now: i64,
) -> Result<StoredUser, SecurityError> {
    if find_user(transaction, &username.normalized)?.is_some() {
        return Err(SecurityError::Conflict);
    }
    transaction.execute(
        "INSERT INTO security_users
         (username, username_norm, password_hash, enabled, authentication_type, team_id)
         VALUES (?1, ?2, '', 1, ?3, NULL)",
        params![
            username.original,
            username.normalized,
            identity.authentication_type
        ],
    )?;
    let user_id = transaction.last_insert_rowid();
    transaction.execute(
        "INSERT INTO security_teams (name) VALUES (?1)",
        [format!("Personal-{user_id}")],
    )?;
    let team_id = transaction.last_insert_rowid();
    transaction.execute(
        "UPDATE security_users SET team_id = ?1 WHERE user_id = ?2",
        params![team_id, user_id],
    )?;
    transaction.execute(
        "INSERT INTO security_user_roles (user_id, role) VALUES (?1, ?2)",
        params![user_id, identity.role],
    )?;
    insert_team_membership(transaction, user_id, team_id, true)?;
    transaction.execute(
        "INSERT INTO security_external_identities
         (issuer, subject, user_id, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![identity.issuer, identity.subject, user_id, now],
    )?;
    find_user_by_id(transaction, user_id)?.ok_or(SecurityError::InvalidToken)
}

fn validate_external_identity(
    identity: &VerifiedSupabaseIdentity,
    now: i64,
) -> Result<(), SecurityError> {
    let expected_role = if identity.anonymous {
        "ROLE_LIMITED_API_USER"
    } else {
        "ROLE_USER"
    };
    let valid_authentication_type = if identity.anonymous {
        identity.authentication_type == "anonymous"
    } else {
        matches!(identity.authentication_type.as_str(), "supabase" | "oauth2")
    };
    if now <= 0
        || identity.issuer.is_empty()
        || identity.issuer.len() > MAX_EXTERNAL_ISSUER_BYTES
        || identity.subject.is_empty()
        || identity.subject.len() > MAX_EXTERNAL_SUBJECT_BYTES
        || identity.session_id.is_empty()
        || identity.session_id.len() > MAX_EXTERNAL_SESSION_ID_BYTES
        || identity.role != expected_role
        || !valid_authentication_type
        || identity.permissions.len() > MAX_EXTERNAL_PERMISSIONS
        || identity.permissions.iter().any(|permission| {
            permission.is_empty()
                || permission.len() > MAX_PERMISSION_BYTES
                || permission.chars().any(char::is_control)
        })
        || [&identity.issuer, &identity.subject, &identity.session_id]
            .into_iter()
            .any(|value| value.chars().any(char::is_control))
    {
        return Err(SecurityError::InvalidInput);
    }
    Ok(())
}

/// Maps a verified generic-OIDC identity onto the issuer-agnostic external
/// identity shape the external-user resolution path already consumes, so OIDC
/// login reuses that path verbatim instead of forking a parallel one.
///
/// Field mapping (per ticket 37a):
/// - `username`: `preferred_username`, else `email`, else `subject` — the first
///   non-empty of those, so provisioning never fails for lack of a username.
/// - `authentication_type`: fixed `"oauth2"`, one of the two non-anonymous
///   values [`validate_external_identity`] accepts (the same value the Supabase
///   path uses for a full `OAuth2` upgrade).
/// - `role`: the default `"ROLE_USER"` [`validate_external_identity`] requires
///   for a non-anonymous identity.
/// - `session_id`: the id token's `sid` when present and non-empty, else a
///   freshly generated random identifier (never empty — the validator rejects
///   an empty session id).
/// - `permissions`: empty. `anonymous`: false (OIDC login is always a full
///   identity here).
fn external_identity_from_oidc(identity: &VerifiedOidcIdentity) -> VerifiedSupabaseIdentity {
    let username = [
        identity.preferred_username.as_deref(),
        identity.email.as_deref(),
        Some(identity.subject.as_str()),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .find(|candidate| !candidate.is_empty())
    .unwrap_or(identity.subject.as_str())
    .to_owned();
    let session_id = identity
        .sid
        .as_deref()
        .map(str::trim)
        .filter(|sid| !sid.is_empty())
        .map_or_else(generate_external_session_id, ToOwned::to_owned);
    VerifiedSupabaseIdentity {
        issuer: identity.issuer.clone(),
        subject: identity.subject.clone(),
        username,
        email: identity.email.clone(),
        authentication_type: "oauth2".to_owned(),
        role: "ROLE_USER".to_owned(),
        session_id,
        permissions: BTreeSet::new(),
        anonymous: false,
    }
}

/// A random URL-safe session identifier for an OIDC identity whose id token
/// carried no `sid`. Reuses the codebase's token-generation convention (32
/// random octets, base64url-no-pad — 43 characters, well under the external
/// session-id length bound) without a bearer-token prefix, since this is an
/// identifier the auth context records, not a secret presented back.
fn generate_external_session_id() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn normalize_assignable_role(role: &str) -> Result<String, SecurityError> {
    let role = role.trim().to_ascii_uppercase();
    if !matches!(role.as_str(), "ROLE_USER" | "ROLE_ADMIN" | "ROLE_DEMO_USER") {
        return Err(SecurityError::InvalidInput);
    }
    Ok(role)
}

fn normalize_invitable_role(role: &str) -> Result<String, SecurityError> {
    let role = role.trim().to_ascii_uppercase();
    if !matches!(
        role.as_str(),
        "ROLE_ADMIN"
            | "ROLE_USER"
            | "ROLE_PRO_USER"
            | "ROLE_LIMITED_API_USER"
            | "ROLE_EXTRA_LIMITED_API_USER"
            | "ROLE_WEB_ONLY_USER"
            | "ROLE_DEMO_USER"
    ) {
        return Err(SecurityError::InvalidInput);
    }
    Ok(role)
}

fn find_active_invite(
    connection: &Connection,
    digest: &[u8],
    now: i64,
) -> Result<Option<StoredInvite>, SecurityError> {
    connection
        .query_row(
            "SELECT invite_id, email, role, team_id, expires_at
             FROM security_invites
             WHERE token_hash = ?1 AND used_at IS NULL AND revoked_at IS NULL
               AND expires_at > ?2",
            params![digest, now],
            |row| {
                Ok(StoredInvite {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    role: row.get(2)?,
                    team_id: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(SecurityError::from)
}

fn team_id_by_name(connection: &Connection, name: &str) -> Result<Option<i64>, SecurityError> {
    connection
        .query_row(
            "SELECT team_id FROM security_teams WHERE name = ?1 COLLATE NOCASE",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(SecurityError::from)
}

fn team_name_by_id(connection: &Connection, team_id: i64) -> Result<Option<String>, SecurityError> {
    connection
        .query_row(
            "SELECT name FROM security_teams WHERE team_id = ?1",
            [team_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(SecurityError::from)
}

fn normalize_username(username: &str) -> Result<NormalizedUsername, SecurityError> {
    let original = username.trim();
    if original.is_empty()
        || original.len() > MAX_USERNAME_BYTES
        || original.chars().any(char::is_control)
    {
        return Err(SecurityError::InvalidInput);
    }
    Ok(NormalizedUsername {
        original: original.to_owned(),
        normalized: original.to_lowercase(),
    })
}

fn normalize_web_username(username: &str) -> Result<NormalizedUsername, SecurityError> {
    let username = normalize_username(username)?;
    if matches!(username.normalized.as_str(), "all_users" | "anonymoususer")
        || (!is_simple_web_username(&username.original)
            && !is_web_email_address(&username.original))
    {
        return Err(SecurityError::InvalidInput);
    }
    Ok(username)
}

fn is_simple_web_username(username: &str) -> bool {
    let bytes = username.as_bytes();
    if !(3..=50).contains(&bytes.len())
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
    {
        return false;
    }
    !bytes.windows(2).any(|pair| {
        pair.iter()
            .all(|byte| matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-'))
    })
}

fn is_web_email_address(email: &str) -> bool {
    if email.is_empty() || email.len() > MAX_USERNAME_BYTES {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if domain.contains('@')
        || local.is_empty()
        || local.len() > 64
        || !local
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !local
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !local
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return false;
    }
    let labels = domain.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || labels
            .first()
            .is_none_or(|label| label.len() < 2 || label.starts_with('-'))
    {
        return false;
    }
    labels.last().is_some_and(|label| {
        label.len() >= 2 && label.bytes().all(|byte| byte.is_ascii_alphabetic())
    })
}

fn validate_user_settings(settings: &BTreeMap<String, String>) -> Result<(), SecurityError> {
    if settings.len() > MAX_USER_SETTINGS
        || settings.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > MAX_USER_SETTING_KEY_BYTES
                || key.chars().any(char::is_control)
                || value.len() > MAX_USER_SETTING_VALUE_BYTES
                || value.contains('\0')
        })
    {
        return Err(SecurityError::InvalidInput);
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), SecurityError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || password.contains('\0') {
        return Err(SecurityError::InvalidInput);
    }
    Ok(())
}

fn normalize_roles<const N: usize>(roles: [&str; N]) -> Result<BTreeSet<String>, SecurityError> {
    let mut normalized = BTreeSet::new();
    for role in roles {
        if !role.starts_with("ROLE_")
            || role.len() > MAX_ROLE_BYTES
            || !role
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        {
            return Err(SecurityError::InvalidInput);
        }
        normalized.insert(role.to_owned());
    }
    if normalized.is_empty() {
        return Err(SecurityError::InvalidInput);
    }
    Ok(normalized)
}

#[allow(clippy::too_many_lines)]
fn initialize_connection(connection: &Connection) -> Result<(), SecurityError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA synchronous = FULL;
         CREATE TABLE IF NOT EXISTS security_teams (
             team_id INTEGER PRIMARY KEY AUTOINCREMENT,
             name TEXT NOT NULL COLLATE NOCASE UNIQUE,
             created_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         INSERT OR IGNORE INTO security_teams (name) VALUES ('Default');
         INSERT OR IGNORE INTO security_teams (name) VALUES ('Internal');
         CREATE TABLE IF NOT EXISTS security_users (
             user_id INTEGER PRIMARY KEY AUTOINCREMENT,
             username TEXT NOT NULL,
             username_norm TEXT NOT NULL UNIQUE,
             password_hash TEXT NOT NULL,
             enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
             authentication_type TEXT NOT NULL,
             team_id INTEGER,
             force_password_change INTEGER NOT NULL DEFAULT 0
                 CHECK(force_password_change IN (0, 1)),
             initial_setup_completed INTEGER NOT NULL DEFAULT 0
                 CHECK(initial_setup_completed IN (0, 1)),
             created_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS security_user_roles (
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             role TEXT NOT NULL,
             PRIMARY KEY(user_id, role)
         );
         CREATE TABLE IF NOT EXISTS security_team_memberships (
             team_id INTEGER NOT NULL REFERENCES security_teams(team_id) ON DELETE CASCADE,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             is_owner INTEGER NOT NULL DEFAULT 0 CHECK(is_owner IN (0, 1)),
             created_at INTEGER NOT NULL DEFAULT (unixepoch()),
             PRIMARY KEY(team_id, user_id),
             UNIQUE(user_id)
         );
         CREATE TABLE IF NOT EXISTS security_login_attempts (
             username_norm TEXT PRIMARY KEY,
             failure_count INTEGER NOT NULL,
             last_failed_at INTEGER NOT NULL,
             locked_until INTEGER
         );
         CREATE TABLE IF NOT EXISTS security_sessions (
             session_id TEXT PRIMARY KEY,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             access_hash BLOB NOT NULL UNIQUE,
             refresh_hash BLOB NOT NULL UNIQUE,
             access_expires_at INTEGER NOT NULL,
             refresh_expires_at INTEGER NOT NULL,
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS security_sessions_user_idx
             ON security_sessions(user_id, revoked_at);
         CREATE TABLE IF NOT EXISTS security_api_keys (
             key_id TEXT PRIMARY KEY,
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             key_hash BLOB NOT NULL UNIQUE,
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS security_invites (
             invite_id INTEGER PRIMARY KEY AUTOINCREMENT,
             token_hash BLOB NOT NULL UNIQUE,
             email TEXT COLLATE NOCASE,
             role TEXT NOT NULL,
             team_id INTEGER NOT NULL REFERENCES security_teams(team_id),
             expires_at INTEGER NOT NULL,
             used_at INTEGER,
             created_by INTEGER NOT NULL REFERENCES security_users(user_id),
             created_at INTEGER NOT NULL,
             revoked_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS security_invites_active_email_idx
             ON security_invites(email, expires_at, used_at, revoked_at);
         CREATE TABLE IF NOT EXISTS security_audit_events (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             user_id INTEGER REFERENCES security_users(user_id) ON DELETE SET NULL,
             principal TEXT NOT NULL,
             source TEXT NOT NULL,
             data TEXT NOT NULL,
             session_id TEXT NOT NULL,
             correlation_id TEXT NOT NULL,
             event_type TEXT NOT NULL,
             path TEXT NOT NULL,
             outcome TEXT NOT NULL,
             created_at INTEGER NOT NULL
         );",
    )?;
    initialize_user_license_settings_schema(connection)?;
    initialize_resource_access_schema(connection)?;
    initialize_user_security_schema(connection)?;
    migrate_audit_event_details(connection)?;
    migrate_api_key_details(connection)?;
    migrate_force_password_change(connection)?;
    migrate_initial_setup_completed(connection)?;
    initialize_external_identity_schema(connection)?;
    migrate_team_memberships(connection)?;
    Ok(())
}

#[derive(Clone)]
struct StoredUserLicenseSettings {
    grandfathered_user_count: i64,
    grandfathering_locked: bool,
    license_max_users: i64,
    integrity_salt: String,
    signature: String,
}

fn initialize_user_license_settings_schema(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_license_settings (
             id INTEGER PRIMARY KEY CHECK(id = 1),
             grandfathered_user_count INTEGER NOT NULL,
             grandfathering_locked INTEGER NOT NULL
                 CHECK(grandfathering_locked IN (0, 1)),
             license_max_users INTEGER NOT NULL,
             integrity_salt TEXT NOT NULL,
             grandfathered_user_signature TEXT NOT NULL
         );",
    )?;
    let existing = load_user_license_settings(connection)?;
    match existing {
        None => {
            let count = real_user_count(connection)?.max(DEFAULT_USER_LIMIT);
            let salt = random_integrity_salt();
            let signature = user_seat_signature(count, &salt)?;
            connection.execute(
                "INSERT INTO user_license_settings
                 (id, grandfathered_user_count, grandfathering_locked,
                  license_max_users, integrity_salt, grandfathered_user_signature)
                 VALUES (?1, ?2, 1, 0, ?3, ?4)",
                params![USER_LICENSE_SETTINGS_ID, count, salt, signature],
            )?;
        }
        Some(settings) if !settings.grandfathering_locked => {
            let count = real_user_count(connection)?.max(DEFAULT_USER_LIMIT);
            let salt = if settings.integrity_salt.trim().is_empty() {
                random_integrity_salt()
            } else {
                settings.integrity_salt
            };
            let signature = user_seat_signature(count, &salt)?;
            connection.execute(
                "UPDATE user_license_settings
                 SET grandfathered_user_count = ?1, grandfathering_locked = 1,
                     integrity_salt = ?2, grandfathered_user_signature = ?3
                 WHERE id = ?4",
                params![count, salt, signature, USER_LICENSE_SETTINGS_ID],
            )?;
        }
        Some(settings) if settings.signature.trim().is_empty() => {
            let salt = if settings.integrity_salt.trim().is_empty() {
                random_integrity_salt()
            } else {
                settings.integrity_salt
            };
            let signature = user_seat_signature(settings.grandfathered_user_count, &salt)?;
            connection.execute(
                "UPDATE user_license_settings
                 SET integrity_salt = ?1, grandfathered_user_signature = ?2
                 WHERE id = ?3",
                params![salt, signature, USER_LICENSE_SETTINGS_ID],
            )?;
        }
        Some(_) => {}
    }
    Ok(())
}

fn load_user_license_settings(
    connection: &Connection,
) -> Result<Option<StoredUserLicenseSettings>, SecurityError> {
    connection
        .query_row(
            "SELECT grandfathered_user_count, grandfathering_locked, license_max_users,
                    integrity_salt, grandfathered_user_signature
             FROM user_license_settings WHERE id = ?1",
            [USER_LICENSE_SETTINGS_ID],
            |row| {
                Ok(StoredUserLicenseSettings {
                    grandfathered_user_count: row.get(0)?,
                    grandfathering_locked: row.get(1)?,
                    license_max_users: row.get(2)?,
                    integrity_salt: row.get(3)?,
                    signature: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(SecurityError::from)
}

fn validated_user_license_settings(
    connection: &Connection,
) -> Result<StoredUserLicenseSettings, SecurityError> {
    let mut settings = load_user_license_settings(connection)?
        .ok_or(SecurityError::Storage(rusqlite::Error::QueryReturnedNoRows))?;
    let mut changed = false;
    if settings.integrity_salt.trim().is_empty() {
        settings.integrity_salt = random_integrity_salt();
        changed = true;
    }
    let signed_count = settings
        .signature
        .split_once(':')
        .and_then(|(count, _)| count.parse::<i64>().ok());
    let signature_valid = signed_count.is_some_and(|count| {
        user_seat_signature(count, &settings.integrity_salt)
            .is_ok_and(|expected| expected == settings.signature)
    });
    let mut target_count = settings.grandfathered_user_count;
    if signature_valid {
        if let Some(count) = signed_count
            && count != target_count
        {
            target_count = count;
            changed = true;
        }
    } else {
        // Preserve the Java migration contract: a parseable embedded count is
        // retained when an old secret or salt invalidates the digest.
        target_count = signed_count.unwrap_or(real_user_count(connection)?.max(DEFAULT_USER_LIMIT));
        changed = true;
    }
    target_count = target_count.max(DEFAULT_USER_LIMIT);
    if target_count != settings.grandfathered_user_count {
        settings.grandfathered_user_count = target_count;
        changed = true;
    }
    if changed || settings.signature.trim().is_empty() {
        settings.signature = user_seat_signature(target_count, &settings.integrity_salt)?;
        connection.execute(
            "UPDATE user_license_settings
             SET grandfathered_user_count = ?1, integrity_salt = ?2,
                 grandfathered_user_signature = ?3 WHERE id = ?4",
            params![
                target_count,
                settings.integrity_salt,
                settings.signature,
                USER_LICENSE_SETTINGS_ID
            ],
        )?;
    }
    Ok(settings)
}

fn user_seat_signature(count: i64, salt: &str) -> Result<String, SecurityError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(USER_SEAT_INTEGRITY_SECRET)
        .map_err(|_| SecurityError::InvalidInput)?;
    mac.update(format!("{count}:{salt}").as_bytes());
    Ok(format!(
        "{count}:{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn random_integrity_salt() -> String {
    let mut bytes = [0_u8; 24];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn real_user_count(connection: &Connection) -> Result<i64, SecurityError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM security_users
             WHERE username_norm <> LOWER(?1)",
            [INTERNAL_API_USERNAME],
            |row| row.get(0),
        )
        .map_err(SecurityError::from)
}

fn seat_metrics(
    connection: &Connection,
    verification: LicenseVerification,
) -> Result<UserSeatMetrics, SecurityError> {
    let settings = validated_user_license_settings(connection)?;
    let current_users = real_user_count(connection)?;
    let max_allowed_users = if verification.running_pro_or_higher() {
        if settings.license_max_users == 0 {
            UNLIMITED_USER_LIMIT
        } else {
            settings.license_max_users
        }
    } else {
        settings.grandfathered_user_count
    };
    Ok(UserSeatMetrics {
        max_allowed_users,
        available_slots: max_allowed_users.saturating_sub(current_users).max(0),
        grandfathered_user_count: settings
            .grandfathered_user_count
            .saturating_sub(DEFAULT_USER_LIMIT)
            .max(0),
        license_max_users: settings.license_max_users,
        premium_enabled: verification.running_pro_or_higher(),
    })
}

fn ensure_user_capacity(
    connection: &Connection,
    verification: LicenseVerification,
    requested_users: i64,
) -> Result<(), SecurityError> {
    if requested_users <= 0 {
        return Err(SecurityError::InvalidInput);
    }
    let metrics = seat_metrics(connection, verification)?;
    if requested_users > metrics.available_slots {
        return Err(SecurityError::UserLimitReached {
            max_allowed: metrics.max_allowed_users,
            available_slots: metrics.available_slots,
        });
    }
    Ok(())
}

fn initialize_resource_access_schema(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS resource_grants (
             resource_grant_id INTEGER PRIMARY KEY AUTOINCREMENT,
             resource_type TEXT NOT NULL
                 CHECK(resource_type IN ('PORTAL', 'INTEGRATION_CONFIG')),
             resource_id TEXT NOT NULL DEFAULT '',
             principal_type TEXT NOT NULL CHECK(principal_type IN ('USER', 'TEAM')),
             principal_id INTEGER NOT NULL,
             permission TEXT NOT NULL DEFAULT 'USE' CHECK(permission IN ('USE', 'MANAGE')),
             granted_by_user_id INTEGER
                 REFERENCES security_users(user_id) ON DELETE SET NULL,
             created_at INTEGER NOT NULL DEFAULT (unixepoch()),
             UNIQUE(resource_type, resource_id, principal_type, principal_id)
         );
         CREATE INDEX IF NOT EXISTS resource_grants_resource_idx
             ON resource_grants(resource_type, resource_id);
         CREATE INDEX IF NOT EXISTS resource_grants_principal_idx
             ON resource_grants(principal_type, principal_id);
         CREATE TABLE IF NOT EXISTS integration_configs (
             integration_config_id INTEGER PRIMARY KEY AUTOINCREMENT,
             integration_type TEXT NOT NULL CHECK(integration_type IN ('S3', 'MCP', 'API', 'PURVIEW')),
             name TEXT NOT NULL,
             scope TEXT NOT NULL CHECK(scope IN ('USER', 'TEAM', 'SERVER')),
             owner_user_id INTEGER
                 REFERENCES security_users(user_id) ON DELETE CASCADE,
             owner_team_id INTEGER
                 REFERENCES security_teams(team_id) ON DELETE RESTRICT,
             enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
             locked INTEGER NOT NULL DEFAULT 0 CHECK(locked IN (0, 1)),
             default_access TEXT NOT NULL DEFAULT 'EXPLICIT_ONLY'
                 CHECK(default_access IN ('ORG_ALL', 'ADMINS_AND_TEAM_LEADS', 'EXPLICIT_ONLY')),
             config_encrypted TEXT,
             created_at INTEGER NOT NULL DEFAULT (unixepoch()),
             updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
             CHECK(
                 (scope = 'USER' AND owner_user_id IS NOT NULL AND owner_team_id IS NULL)
                 OR (scope = 'TEAM' AND owner_user_id IS NULL AND owner_team_id IS NOT NULL)
                 OR (scope = 'SERVER' AND owner_user_id IS NULL AND owner_team_id IS NULL)
             )
         );",
    )?;
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS integration_configs_owner_user_idx
             ON integration_configs(owner_user_id);
         CREATE INDEX IF NOT EXISTS integration_configs_owner_team_idx
             ON integration_configs(owner_team_id);
         CREATE INDEX IF NOT EXISTS integration_configs_type_idx
             ON integration_configs(integration_type);
         CREATE INDEX IF NOT EXISTS integration_configs_scope_idx
             ON integration_configs(scope);",
    )?;
    initialize_policy_config_schema(connection)?;
    Ok(())
}

fn initialize_policy_config_schema(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS policies (
             id TEXT PRIMARY KEY,
             name TEXT,
             owner TEXT,
             enabled INTEGER NOT NULL DEFAULT 0,
             trigger_type TEXT,
             team_id INTEGER,
             sort_order INTEGER,
             policy_json TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_policies_team ON policies(team_id);
         CREATE INDEX IF NOT EXISTS idx_policies_trigger ON policies(trigger_type, enabled);
         CREATE TABLE IF NOT EXISTS policy_sources (
             id TEXT PRIMARY KEY,
             name TEXT,
             type TEXT,
             owner TEXT,
             team_id INTEGER,
             enabled INTEGER NOT NULL DEFAULT 0,
             source_json TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_policy_sources_team ON policy_sources(team_id);
         CREATE TABLE IF NOT EXISTS policy_source_doc_counts (
             source_id TEXT NOT NULL,
             bucket_hour INTEGER NOT NULL,
             doc_count INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY(source_id, bucket_hour)
         );
         CREATE TABLE IF NOT EXISTS policy_source_doc_totals (
             source_id TEXT PRIMARY KEY,
             doc_total INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS policy_processed_files (
             policy_id TEXT NOT NULL,
             identity_hash TEXT NOT NULL,
             identity TEXT,
             signature TEXT NOT NULL,
             content_hash TEXT,
             status TEXT NOT NULL
                 CHECK(status IN ('PROCESSING', 'DONE', 'ERROR', 'INTERRUPTED')),
             attempts INTEGER NOT NULL DEFAULT 1,
             last_seen INTEGER NOT NULL DEFAULT 0,
             updated_at INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY(policy_id, identity_hash)
         );
         CREATE INDEX IF NOT EXISTS idx_processed_files_policy_seen
             ON policy_processed_files(policy_id, last_seen);
         CREATE INDEX IF NOT EXISTS idx_processed_files_identity
             ON policy_processed_files(identity_hash);",
    )?;
    let policy_columns = connection
        .prepare("SELECT name FROM pragma_table_info('policies')")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !policy_columns.contains("sort_order") {
        connection.execute_batch("ALTER TABLE policies ADD COLUMN sort_order INTEGER;")?;
    }
    Ok(())
}

#[allow(dead_code, reason = "used by the staged policy source-sweep port")]
fn validate_policy_claim(
    policy_id: &str,
    identity: &str,
    gate: &str,
    content_hash: Option<&str>,
) -> Result<(), SecurityError> {
    if policy_id.is_empty()
        || policy_id.len() > 255
        || identity.is_empty()
        || identity.len() > 4_096
        || gate.is_empty()
        || gate.len() > 255
        || content_hash.is_some_and(|hash| hash.is_empty() || hash.len() > 64)
    {
        Err(SecurityError::InvalidInput)
    } else {
        Ok(())
    }
}

fn migrate_audit_event_details(connection: &Connection) -> Result<(), SecurityError> {
    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('security_audit_events')")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !columns.contains("principal") {
        connection.execute_batch(
            "ALTER TABLE security_audit_events
                 ADD COLUMN principal TEXT NOT NULL DEFAULT '';",
        )?;
    }
    if !columns.contains("source") {
        connection.execute_batch(
            "ALTER TABLE security_audit_events
                 ADD COLUMN source TEXT NOT NULL DEFAULT 'WEB';",
        )?;
    }
    if !columns.contains("data") {
        connection.execute_batch(
            "ALTER TABLE security_audit_events
                 ADD COLUMN data TEXT NOT NULL DEFAULT '{}';",
        )?;
    }
    connection.execute_batch(
        "UPDATE security_audit_events
         SET principal = COALESCE(
             (SELECT username FROM security_users
              WHERE security_users.user_id = security_audit_events.user_id),
             principal
         )
         WHERE principal = '';
         CREATE INDEX IF NOT EXISTS security_audit_timestamp_idx
             ON security_audit_events(created_at);
         CREATE INDEX IF NOT EXISTS security_audit_principal_idx
             ON security_audit_events(principal);
         CREATE INDEX IF NOT EXISTS security_audit_type_idx
             ON security_audit_events(event_type);
         CREATE INDEX IF NOT EXISTS security_audit_type_source_timestamp_idx
             ON security_audit_events(event_type, source, created_at);
         CREATE INDEX IF NOT EXISTS security_audit_source_timestamp_principal_idx
             ON security_audit_events(source, created_at, principal);",
    )?;
    Ok(())
}

/// Adds the portal personal-API-key columns and the daily-usage table to an
/// existing `security_api_keys` schema. Idempotent and column-guarded so it is
/// safe on both fresh and previously-migrated databases: named keys carry a
/// display `name`, a non-secret `prefix`, and a nullable `last_used_at`, and
/// per-key request counts accumulate in `security_api_key_daily_usage`.
fn migrate_api_key_details(connection: &Connection) -> Result<(), SecurityError> {
    let columns = connection
        .prepare("SELECT name FROM pragma_table_info('security_api_keys')")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !columns.contains("name") {
        connection.execute_batch(
            "ALTER TABLE security_api_keys
                 ADD COLUMN name TEXT NOT NULL DEFAULT 'Default key';",
        )?;
    }
    if !columns.contains("prefix") {
        connection.execute_batch(
            "ALTER TABLE security_api_keys
                 ADD COLUMN prefix TEXT NOT NULL DEFAULT '';",
        )?;
    }
    if !columns.contains("last_used_at") {
        connection.execute_batch(
            "ALTER TABLE security_api_keys
                 ADD COLUMN last_used_at INTEGER;",
        )?;
    }
    connection.execute_batch(
        "CREATE INDEX IF NOT EXISTS security_api_keys_owner_idx
             ON security_api_keys(user_id, revoked_at);
         CREATE TABLE IF NOT EXISTS security_api_key_daily_usage (
             key_id TEXT NOT NULL
                 REFERENCES security_api_keys(key_id) ON DELETE CASCADE,
             epoch_day INTEGER NOT NULL,
             count INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (key_id, epoch_day)
         );",
    )?;
    Ok(())
}

fn initialize_user_security_schema(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_mfa (
             user_id INTEGER PRIMARY KEY REFERENCES security_users(user_id) ON DELETE CASCADE,
             enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0, 1)),
             required INTEGER NOT NULL DEFAULT 0 CHECK(required IN (0, 1)),
             secret_ciphertext TEXT NOT NULL,
             last_used_step INTEGER,
             updated_at INTEGER NOT NULL DEFAULT (unixepoch())
         );
         CREATE TABLE IF NOT EXISTS security_user_settings (
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             setting_key TEXT NOT NULL,
             setting_value TEXT NOT NULL,
             PRIMARY KEY(user_id, setting_key)
         );
         CREATE TABLE IF NOT EXISTS security_recovery_codes (
             user_id INTEGER NOT NULL REFERENCES security_users(user_id) ON DELETE CASCADE,
             code_hash BLOB NOT NULL UNIQUE,
             created_at INTEGER NOT NULL,
             consumed_at INTEGER
         );
         CREATE INDEX IF NOT EXISTS security_recovery_codes_user_idx
             ON security_recovery_codes(user_id);",
    )?;
    Ok(())
}

fn migrate_force_password_change(connection: &Connection) -> Result<(), SecurityError> {
    let column_exists: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM pragma_table_info('security_users')
             WHERE name = 'force_password_change'
         )",
        [],
        |row| row.get(0),
    )?;
    if !column_exists {
        connection.execute_batch(
            "ALTER TABLE security_users
             ADD COLUMN force_password_change INTEGER NOT NULL DEFAULT 0
                 CHECK(force_password_change IN (0, 1));",
        )?;
    }
    Ok(())
}

fn migrate_initial_setup_completed(connection: &Connection) -> Result<(), SecurityError> {
    let column_exists: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM pragma_table_info('security_users')
             WHERE name = 'initial_setup_completed'
         )",
        [],
        |row| row.get(0),
    )?;
    if !column_exists {
        connection.execute_batch(
            "ALTER TABLE security_users
             ADD COLUMN initial_setup_completed INTEGER NOT NULL DEFAULT 0
                 CHECK(initial_setup_completed IN (0, 1));",
        )?;
    }
    Ok(())
}

fn initialize_external_identity_schema(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS security_external_identities (
             issuer TEXT NOT NULL,
             subject TEXT NOT NULL,
             user_id INTEGER NOT NULL UNIQUE
                 REFERENCES security_users(user_id) ON DELETE CASCADE,
             created_at INTEGER NOT NULL,
             last_seen_at INTEGER NOT NULL,
             PRIMARY KEY(issuer, subject)
         );
         CREATE TABLE IF NOT EXISTS security_external_identity_blocks (
             issuer TEXT NOT NULL,
             subject TEXT NOT NULL,
             blocked_at INTEGER NOT NULL,
             PRIMARY KEY(issuer, subject)
         );",
    )?;
    Ok(())
}

fn migrate_team_memberships(connection: &Connection) -> Result<(), SecurityError> {
    connection.execute_batch(
        "UPDATE security_users
         SET team_id = (SELECT team_id FROM security_teams WHERE name = 'Default')
         WHERE team_id IS NULL
            OR team_id NOT IN (SELECT team_id FROM security_teams);
         INSERT OR IGNORE INTO security_team_memberships (team_id, user_id, is_owner)
         SELECT team_id, user_id, 0 FROM security_users;
         UPDATE security_team_memberships
         SET team_id = (
             SELECT security_users.team_id
             FROM security_users
             WHERE security_users.user_id = security_team_memberships.user_id
         )
         WHERE team_id != (
             SELECT security_users.team_id
             FROM security_users
             WHERE security_users.user_id = security_team_memberships.user_id
         );",
    )?;
    Ok(())
}

#[cfg(unix)]
fn restrict_database_permissions(path: &Path) -> Result<(), SecurityError> {
    use std::os::unix::fs::PermissionsExt as _;

    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(SecurityError::Filesystem)
}

fn insert_roles(
    transaction: &Transaction<'_>,
    user_id: i64,
    roles: &BTreeSet<String>,
) -> Result<(), SecurityError> {
    for role in roles {
        transaction.execute(
            "INSERT INTO security_user_roles (user_id, role) VALUES (?1, ?2)",
            params![user_id, role],
        )?;
    }
    Ok(())
}

fn resolve_team_id(
    connection: &Connection,
    requested_team_id: Option<i64>,
) -> Result<i64, SecurityError> {
    if let Some(team_id) = requested_team_id {
        return connection
            .query_row(
                "SELECT team_id FROM security_teams WHERE team_id = ?1",
                [team_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(SecurityError::TeamNotFound);
    }
    connection
        .query_row(
            "SELECT team_id FROM security_teams WHERE name = ?1 COLLATE NOCASE",
            [DEFAULT_TEAM_NAME],
            |row| row.get(0),
        )
        .map_err(SecurityError::from)
}

fn insert_team_membership(
    connection: &Connection,
    user_id: i64,
    team_id: i64,
    owner: bool,
) -> Result<(), SecurityError> {
    connection.execute(
        "INSERT INTO security_team_memberships (team_id, user_id, is_owner)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(user_id) DO UPDATE SET
             team_id = excluded.team_id,
             is_owner = excluded.is_owner",
        params![team_id, user_id, owner],
    )?;
    Ok(())
}

fn find_user(
    connection: &Connection,
    username_norm: &str,
) -> Result<Option<StoredUser>, SecurityError> {
    connection
        .query_row(
            "SELECT user_id, username, password_hash, enabled, authentication_type, team_id,
                    force_password_change
             FROM security_users WHERE username_norm = ?1",
            [username_norm],
            stored_user_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn find_user_by_id(
    connection: &Connection,
    user_id: i64,
) -> Result<Option<StoredUser>, SecurityError> {
    connection
        .query_row(
            "SELECT user_id, username, password_hash, enabled, authentication_type, team_id,
                    force_password_change
             FROM security_users WHERE user_id = ?1",
            [user_id],
            stored_user_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn stored_user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredUser> {
    Ok(StoredUser {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        enabled: row.get(3)?,
        authentication_type: row.get(4)?,
        team_id: row.get(5)?,
        force_password_change: row.get(6)?,
    })
}

fn roles_for_user(
    connection: &Connection,
    user_id: i64,
) -> Result<BTreeSet<String>, SecurityError> {
    let mut statement = connection
        .prepare("SELECT role FROM security_user_roles WHERE user_id = ?1 ORDER BY role")?;
    statement
        .query_map([user_id], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(SecurityError::from)
}

fn user_has_role(connection: &Connection, user_id: i64, role: &str) -> Result<bool, SecurityError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM security_user_roles WHERE user_id = ?1 AND role = ?2
             )",
            params![user_id, role],
            |row| row.get(0),
        )
        .map_err(SecurityError::from)
}

fn is_last_enabled_admin(
    connection: &Connection,
    excluded_user_id: i64,
) -> Result<bool, SecurityError> {
    let remaining: i64 = connection.query_row(
        "SELECT COUNT(DISTINCT u.user_id)
         FROM security_users u
         JOIN security_user_roles r ON r.user_id = u.user_id
         WHERE u.enabled = 1 AND r.role = 'ROLE_ADMIN' AND u.user_id != ?1",
        [excluded_user_id],
        |row| row.get(0),
    )?;
    Ok(remaining == 0)
}

fn reject_internal_user(connection: &Connection, user: &StoredUser) -> Result<(), SecurityError> {
    if let Some(team_id) = user.team_id
        && team_name_by_id(connection, team_id)?
            .is_some_and(|name| name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
    {
        return Err(SecurityError::ProtectedSystemState);
    }
    Ok(())
}

fn revoke_sessions_in(
    connection: &Connection,
    user_id: i64,
    now: i64,
) -> Result<usize, SecurityError> {
    connection
        .execute(
            "UPDATE security_sessions SET revoked_at = ?1
             WHERE user_id = ?2 AND revoked_at IS NULL",
            params![now, user_id],
        )
        .map_err(SecurityError::from)
}

fn context_for_user(
    connection: &Connection,
    user: &StoredUser,
    source: AuthenticationSource,
    session_id: String,
    correlation_id: &str,
) -> Result<AuthContext, SecurityError> {
    let roles = roles_for_user(connection, user.id)?;
    if roles.is_empty() {
        return Err(SecurityError::InvalidToken);
    }
    Ok(AuthContext {
        user_id: user.id,
        username: user.username.clone(),
        authentication_source: source,
        authentication_type: user.authentication_type.clone(),
        roles,
        team_id: user.team_id,
        permissions: BTreeSet::new(),
        external_subject: None,
        force_password_change: user.force_password_change,
        session_id,
        correlation_id: correlation_id.to_owned(),
    })
}

fn login_is_locked(
    connection: &Connection,
    username_norm: &str,
    now: i64,
) -> Result<bool, SecurityError> {
    let locked_until = connection
        .query_row(
            "SELECT locked_until FROM security_login_attempts WHERE username_norm = ?1",
            [username_norm],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten();
    Ok(locked_until.is_some_and(|locked_until| locked_until > now))
}

fn record_login_failure(
    connection: &Connection,
    username_norm: &str,
    now: i64,
) -> Result<bool, SecurityError> {
    let previous = connection
        .query_row(
            "SELECT failure_count, locked_until FROM security_login_attempts
             WHERE username_norm = ?1",
            [username_norm],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()?;
    let failure_count = previous.map_or(1, |(count, locked_until)| {
        if locked_until.is_some_and(|until| until <= now) {
            1
        } else {
            count.saturating_add(1)
        }
    });
    let locked_until =
        (failure_count >= MAX_FAILED_LOGINS).then_some(now.saturating_add(LOCKOUT_SECONDS));
    connection.execute(
        "INSERT INTO security_login_attempts
         (username_norm, failure_count, last_failed_at, locked_until)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(username_norm) DO UPDATE SET
             failure_count = excluded.failure_count,
             last_failed_at = excluded.last_failed_at,
             locked_until = excluded.locked_until",
        params![username_norm, failure_count, now, locked_until],
    )?;
    Ok(locked_until.is_some())
}

fn fake_password_work(password: &str, bcrypt_cost: u32) -> Result<(), SecurityError> {
    let _ = hash(password, bcrypt_cost)?;
    Ok(())
}

struct GeneratedSession {
    session_id: Zeroizing<String>,
    access_hash: Vec<u8>,
    refresh_hash: Vec<u8>,
    access_expires_at: i64,
    refresh_expires_at: i64,
    created_at: i64,
    tokens: SessionTokens,
}

impl GeneratedSession {
    fn new(now: i64, access_ttl: Duration, refresh_ttl: Duration) -> Result<Self, SecurityError> {
        let access_seconds =
            i64::try_from(access_ttl.as_secs()).map_err(|_| SecurityError::InvalidInput)?;
        let refresh_seconds =
            i64::try_from(refresh_ttl.as_secs()).map_err(|_| SecurityError::InvalidInput)?;
        if access_seconds <= 0 || refresh_seconds <= access_seconds {
            return Err(SecurityError::InvalidInput);
        }
        let access_token = random_secret(ACCESS_TOKEN_PREFIX);
        let refresh_token = random_secret(REFRESH_TOKEN_PREFIX);
        let access_hash = token_digest(&access_token);
        let refresh_hash = token_digest(&refresh_token);
        Ok(Self {
            session_id: random_secret(SESSION_ID_PREFIX),
            access_hash,
            refresh_hash,
            access_expires_at: now.saturating_add(access_seconds),
            refresh_expires_at: now.saturating_add(refresh_seconds),
            created_at: now,
            tokens: SessionTokens {
                access_token,
                refresh_token,
                expires_in: access_ttl.as_secs(),
            },
        })
    }
}

fn insert_session(
    connection: &Connection,
    user_id: i64,
    session: &GeneratedSession,
) -> Result<(), SecurityError> {
    connection.execute(
        "INSERT INTO security_sessions
         (session_id, user_id, access_hash, refresh_hash, access_expires_at,
          refresh_expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            session.session_id.as_str(),
            user_id,
            session.access_hash,
            session.refresh_hash,
            session.access_expires_at,
            session.refresh_expires_at,
            session.created_at
        ],
    )?;
    Ok(())
}

fn find_session_by_access(
    connection: &Connection,
    digest: &[u8],
) -> Result<Option<StoredSession>, SecurityError> {
    connection
        .query_row(
            "SELECT session_id, user_id, access_expires_at, revoked_at IS NOT NULL
             FROM security_sessions WHERE access_hash = ?1",
            [digest],
            stored_session_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn find_session_by_refresh(
    connection: &Connection,
    digest: &[u8],
) -> Result<Option<StoredSession>, SecurityError> {
    connection
        .query_row(
            "SELECT session_id, user_id, refresh_expires_at, revoked_at IS NOT NULL
             FROM security_sessions WHERE refresh_hash = ?1",
            [digest],
            stored_session_from_row,
        )
        .optional()
        .map_err(SecurityError::from)
}

fn stored_session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSession> {
    Ok(StoredSession {
        session_id: row.get(0)?,
        user_id: row.get(1)?,
        expires_at: row.get(2)?,
        revoked: row.get(3)?,
    })
}

fn validate_session(session: &StoredSession, now: i64) -> Result<(), SecurityError> {
    if session.revoked {
        return Err(SecurityError::InvalidToken);
    }
    if session.expires_at <= now {
        return Err(SecurityError::ExpiredToken);
    }
    Ok(())
}

fn random_secret(prefix: &str) -> Zeroizing<String> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rng().fill(&mut bytes);
    Zeroizing::new(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn validate_token(token: &str, prefix: &str) -> Result<(), SecurityError> {
    if !token.starts_with(prefix)
        || token.len() > MAX_BEARER_TOKEN_BYTES
        || token.len() != prefix.len().saturating_add(43)
        || !token[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SecurityError::InvalidToken);
    }
    Ok(())
}

fn token_digest(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Non-secret leading fragment of a raw key shown in listings (mirrors Java
/// `ApiKeyHasher.displayPrefix`): the first [`API_KEY_DISPLAY_PREFIX_LEN`]
/// characters, or the whole value when shorter. Character-based so it never
/// splits a UTF-8 boundary.
fn display_prefix(token: &str) -> String {
    token.chars().take(API_KEY_DISPLAY_PREFIX_LEN).collect()
}

/// Best-effort per-key usage accounting for a successful API-key authentication:
/// bumps today's tally (UTC epoch day, matching `list_api_keys`) and stamps
/// last-used. Every error is swallowed so a usage-write failure can never fail
/// or roll back authentication, mirroring Java's async `ApiKeyUsageRecorder`.
fn record_api_key_usage(connection: &Connection, key_id: &str) {
    if let Err(error) = connection.execute(
        "INSERT INTO security_api_key_daily_usage (key_id, epoch_day, count)
         VALUES (?1, CAST(unixepoch() / 86400 AS INTEGER), 1)
         ON CONFLICT(key_id, epoch_day) DO UPDATE SET count = count + 1",
        params![key_id],
    ) {
        tracing::debug!(%error, "failed to record API key usage");
    }
    if let Err(error) = connection.execute(
        "UPDATE security_api_keys SET last_used_at = unixepoch() WHERE key_id = ?1",
        params![key_id],
    ) {
        tracing::debug!(%error, "failed to stamp API key last-used");
    }
}

/// Builds a fresh batch of [`RECOVERY_CODE_COUNT`] recovery codes paired with
/// their persisted digests, de-duplicating digests within the batch so every
/// INSERT can rely on the UNIQUE constraint. The plaintext codes never leave
/// this batch except through the caller's single return value.
fn build_recovery_code_entries() -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut seen: HashSet<Vec<u8>> = HashSet::with_capacity(RECOVERY_CODE_COUNT);
    while entries.len() < RECOVERY_CODE_COUNT {
        let code = generate_recovery_code();
        let digest = token_digest(&normalize_recovery_code(&code));
        // Guard against the (astronomically unlikely) intra-batch digest
        // collision so every INSERT can rely on the UNIQUE constraint.
        if seen.insert(digest.clone()) {
            entries.push((code, digest));
        }
    }
    entries
}

/// Replaces the user's stored recovery-code digests within an open transaction:
/// the prior set is deleted and the supplied digests are inserted unconsumed.
/// Regeneration therefore invalidates every previously issued code.
fn replace_recovery_codes(
    transaction: &Transaction,
    user_id: i64,
    entries: &[(String, Vec<u8>)],
    now: i64,
) -> Result<(), SecurityError> {
    transaction.execute(
        "DELETE FROM security_recovery_codes WHERE user_id = ?1",
        [user_id],
    )?;
    for (_, digest) in entries {
        transaction.execute(
            "INSERT INTO security_recovery_codes (user_id, code_hash, created_at, consumed_at)
             VALUES (?1, ?2, ?3, NULL)",
            params![user_id, digest, now],
        )?;
    }
    Ok(())
}

/// Produces one human-typeable recovery code: CSPRNG octets Base32-encoded
/// (RFC 4648 alphabet, matching the TOTP-seed convention) and dash-grouped for
/// transcription, e.g. `AB2C-D3EF-GH4J-K5MN`.
fn generate_recovery_code() -> String {
    let mut bytes = [0_u8; RECOVERY_CODE_BYTES];
    rand::rng().fill(&mut bytes);
    let encoded = BASE32_NOPAD.encode(&bytes);
    encoded
        .as_bytes()
        .chunks(RECOVERY_CODE_GROUP)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Canonicalizes a recovery code for hashing so display grouping and casing do
/// not affect matching: dashes, spaces, and any other non-alphanumeric input
/// are dropped and letters are upper-cased before the SHA-256 digest is taken.
fn normalize_recovery_code(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL, MAX_AUDIT_FILES, MAX_AUDIT_FORM_VALUE_CHARS,
        REDACTED_AUDIT_FORM_VALUE, SecurityAuditContext, SecurityAuditFilter, SecurityError,
        SecurityStore, initialize_connection,
    };
    use crate::integration_config::{IntegrationType, NewIntegrationConfig};
    use crate::resource_access::{
        AccessPermission, DefaultAccessPolicy, OwnerScope, PrincipalType, ResourceType,
    };
    use crate::security_crypto::totp_code_at;
    use crate::security_jwt::VerifiedSupabaseIdentity;
    use rusqlite::Connection;

    #[test]
    fn audit_file_enrichment_is_opt_in_sanitized_and_bounded() {
        let basic = SecurityAuditContext::new(false);
        basic.record_file("ignored.pdf", 1, Some("application/pdf"));
        basic.record_form_param("angle", "90");
        assert!(basic.snapshot().files.is_empty());
        assert!(basic.snapshot().form_params.is_empty());

        let standard = SecurityAuditContext::new(true);
        standard.record_file(
            "../folder\\invoice\r\n.pdf",
            42,
            Some(" application/pdf\r\nignored "),
        );
        for index in 0..MAX_AUDIT_FILES {
            standard.record_file(&format!("document-{index}.pdf"), 1, None);
        }
        standard.record_form_param("angle", "90");
        standard.record_form_param("angle", "180");
        standard.record_form_param("_csrf", "must-not-appear");
        standard.record_form_param("private-key-password", "must-not-appear");
        standard.record_form_param("spineLocation", "RIGHT");
        standard.record_form_param("empty", "");
        standard.record_form_param("bounded", &"x".repeat(MAX_AUDIT_FORM_VALUE_CHARS + 1));

        let enrichment = standard.snapshot();
        assert_eq!(enrichment.files.len(), MAX_AUDIT_FILES);
        assert_eq!(enrichment.files[0].name, "invoice  .pdf");
        assert_eq!(enrichment.files[0].size, 42);
        assert_eq!(
            enrichment.files[0].content_type.as_deref(),
            Some("application/pdf  ignored")
        );
        assert_eq!(enrichment.form_params["angle"], ["90", "180"]);
        assert!(!enrichment.form_params.contains_key("_csrf"));
        assert_eq!(
            enrichment.form_params["private-key-password"],
            [REDACTED_AUDIT_FORM_VALUE]
        );
        assert_eq!(enrichment.form_params["spineLocation"], ["RIGHT"]);
        assert_eq!(enrichment.form_params["empty"], [""]);
        assert_eq!(
            enrichment.form_params["bounded"][0].len(),
            MAX_AUDIT_FORM_VALUE_CHARS
        );
    }

    #[test]
    fn bootstraps_bcrypt_admin_and_persists_lockout() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("Admin", "correct horse battery staple")?);
        assert!(!store.bootstrap_admin("other", "other password")?);

        let context = store.authenticate_password(
            " admin ",
            "correct horse battery staple",
            1_000,
            "request-1",
        )?;
        assert_eq!(context.username, "Admin");
        assert!(context.has_role("ROLE_ADMIN"));

        for attempt in 0..4 {
            assert!(matches!(
                store.authenticate_password("ADMIN", "wrong", 2_000 + attempt, "request"),
                Err(SecurityError::InvalidCredentials)
            ));
        }
        assert!(matches!(
            store.authenticate_password("ADMIN", "wrong", 2_004, "request"),
            Err(SecurityError::AccountLocked)
        ));
        assert!(matches!(
            store.authenticate_password("ADMIN", "correct horse battery staple", 2_005, "request"),
            Err(SecurityError::AccountLocked)
        ));
        Ok(())
    }

    #[test]
    fn rejects_passwords_bcrypt_would_silently_truncate() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = SecurityStore::in_memory()?;
        let overlong_password = "x".repeat(73);
        assert!(matches!(
            store.create_local_user(
                "long-password@example.test",
                &overlong_password,
                ["ROLE_USER"],
                None,
            ),
            Err(SecurityError::InvalidInput)
        ));
        Ok(())
    }

    #[test]
    fn migrates_legacy_users_into_default_team_membership() -> Result<(), Box<dyn std::error::Error>>
    {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE security_users (
                 user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 username_norm TEXT NOT NULL UNIQUE,
                 password_hash TEXT NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
                 authentication_type TEXT NOT NULL,
                 team_id INTEGER,
                 created_at INTEGER NOT NULL DEFAULT (unixepoch())
             );
             INSERT INTO security_users
                 (username, username_norm, password_hash, authentication_type, team_id)
             VALUES ('legacy', 'legacy', 'unused', 'web', NULL);
             CREATE TABLE security_audit_events (
                 event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 session_id TEXT NOT NULL,
                 correlation_id TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 path TEXT NOT NULL,
                 outcome TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             INSERT INTO security_audit_events
                 (user_id, session_id, correlation_id, event_type, path, outcome, created_at)
             VALUES (1, 'legacy-session', 'legacy-request', 'HTTP_MUTATION',
                     '/api/v1/legacy', 'status:200', 1000);",
        )?;

        initialize_connection(&connection)?;

        let migrated: (String, String, i64) = connection.query_row(
            "SELECT t.name, mt.name, m.is_owner
             FROM security_users u
             JOIN security_teams t ON t.team_id = u.team_id
             JOIN security_team_memberships m ON m.user_id = u.user_id
             JOIN security_teams mt ON mt.team_id = m.team_id
             WHERE u.username_norm = 'legacy'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(migrated, ("Default".to_owned(), "Default".to_owned(), 0));
        let migrated_flags: (bool, bool) = connection.query_row(
            "SELECT force_password_change, initial_setup_completed
             FROM security_users WHERE username_norm = 'legacy'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(migrated_flags, (false, false));
        let settings_table_exists: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'security_user_settings'
             )",
            [],
            |row| row.get(0),
        )?;
        assert!(settings_table_exists);
        let migrated_audit: (String, String, String) = connection.query_row(
            "SELECT principal, source, data FROM security_audit_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(
            migrated_audit,
            ("legacy".to_owned(), "WEB".to_owned(), "{}".to_owned())
        );
        Ok(())
    }

    #[test]
    fn filters_exports_and_cleans_durable_audit_events() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("audit-admin", "audit-admin-password")?);
        let context = store.authenticate_password(
            "audit-admin",
            "audit-admin-password",
            100,
            "audit-request",
        )?;
        store.record_audit(
            &context,
            "HTTP_MUTATION",
            "/api/v1/admin/settings",
            "status:200",
            1_000,
        )?;
        store.record_audit(
            &context,
            "PDF_PROCESS",
            "/api/v1/misc/compress-pdf",
            "status:500",
            2_000,
        )?;
        store.record_audit(
            &context,
            "USER_LOGIN",
            "/api/v1/auth/login",
            "success",
            3_000,
        )?;

        let page = store.query_audit_events(&SecurityAuditFilter::default(), 1, 1)?;
        assert_eq!(page.total_events, 3);
        assert_eq!(page.events[0].event_type, "PDF_PROCESS");
        let filtered = store.export_audit_events(&SecurityAuditFilter {
            event_types: vec!["PDF_PROCESS".to_owned()],
            principal_contains: Some("ADMIN".to_owned()),
            start_at: Some(1_500),
            end_at: Some(2_500),
            ..SecurityAuditFilter::default()
        })?;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].principal, "audit-admin");
        let data: serde_json::Value = serde_json::from_str(&filtered[0].data)?;
        assert_eq!(data["outcome"], "failure");
        assert_eq!(data["statusCode"], 500);
        assert_eq!(store.audit_principals()?, ["audit-admin"]);
        assert!(
            store
                .audit_event_types()?
                .contains(&"USER_LOGIN".to_owned())
        );
        assert_eq!(store.delete_audit_events_before(2_500)?, 2);
        assert_eq!(store.clear_audit_events()?, 1);
        assert_eq!(store.audit_event_count()?, 0);
        Ok(())
    }

    #[test]
    fn persists_bounded_registration_settings_and_initial_setup()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("security.db");
        let store = SecurityStore::open(&database)?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let user_id = store.register_local_user("pending@example.test", "pending-test-password")?;
        assert!(matches!(
            store.authenticate_password(
                "pending@example.test",
                "pending-test-password",
                100,
                "disabled"
            ),
            Err(SecurityError::AccountDisabled)
        ));
        assert!(matches!(
            store.register_local_user("pending@example.test", "another-test-password"),
            Err(SecurityError::Conflict)
        ));
        assert!(matches!(
            store.register_local_user("a--b", "invalid-username-password"),
            Err(SecurityError::InvalidInput)
        ));

        let first_settings = BTreeMap::from([
            ("language".to_owned(), "en-US".to_owned()),
            ("theme".to_owned(), "dark".to_owned()),
        ]);
        store.replace_user_settings(user_id, &first_settings)?;
        assert!(!store.initial_setup_is_complete(user_id)?);
        store.complete_initial_setup(user_id)?;

        let second_settings = BTreeMap::from([("language".to_owned(), "fr-FR".to_owned())]);
        store.replace_user_settings(user_id, &second_settings)?;
        let oversized = BTreeMap::from([("key".to_owned(), "x".repeat(4 * 1024 + 1))]);
        assert!(matches!(
            store.replace_user_settings(user_id, &oversized),
            Err(SecurityError::InvalidInput)
        ));
        drop(store);

        let reopened = SecurityStore::open(&database)?;
        assert_eq!(reopened.user_settings(user_id)?, second_settings);
        assert!(reopened.initial_setup_is_complete(user_id)?);
        for username in ["third-user", "fourth-user", "fifth-user"] {
            reopened.register_local_user(username, "registration-test-password")?;
        }
        assert!(matches!(
            reopened.register_local_user("sixth-user", "registration-test-password"),
            Err(SecurityError::UserLimitReached {
                max_allowed: 5,
                available_slots: 0,
            })
        ));
        Ok(())
    }

    #[test]
    fn rotates_and_revokes_durable_opaque_sessions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("security.db");
        let store = SecurityStore::open(&database)?;
        assert!(store.bootstrap_admin("admin", "stirling-test-password")?);
        let login =
            store.authenticate_password("admin", "stirling-test-password", 10_000, "login")?;
        let first = store.issue_session(&login, 10_000, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL)?;
        let old_access = first.access_token.to_string();
        let old_refresh = first.refresh_token.to_string();
        drop(store);

        let reopened = SecurityStore::open(&database)?;
        let authenticated = reopened.authenticate_access_token(&old_access, 10_001, "request")?;
        assert_eq!(authenticated.user_id, login.user_id);
        let second = reopened.rotate_refresh_token(
            &old_refresh,
            10_002,
            DEFAULT_ACCESS_TTL,
            DEFAULT_REFRESH_TTL,
        )?;
        assert!(matches!(
            reopened.authenticate_access_token(&old_access, 10_003, "request"),
            Err(SecurityError::InvalidToken)
        ));
        assert!(matches!(
            reopened.rotate_refresh_token(
                &old_refresh,
                10_003,
                DEFAULT_ACCESS_TTL,
                DEFAULT_REFRESH_TTL
            ),
            Err(SecurityError::InvalidToken)
        ));
        let new_access = second.access_token.to_string();
        reopened.authenticate_access_token(&new_access, 10_003, "request")?;
        reopened.revoke_access_token(&new_access, 10_004)?;
        assert!(matches!(
            reopened.authenticate_access_token(&new_access, 10_005, "request"),
            Err(SecurityError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn stores_only_api_key_digests() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("security.db");
        let store = SecurityStore::open(&database)?;
        let team_id = store.create_team("API Team")?;
        let user_id = store.create_local_user(
            "user@example.test",
            "safe password",
            ["ROLE_USER"],
            Some(team_id),
        )?;
        let api_key = store.create_api_key(user_id, 100)?;
        let context = store.authenticate_api_key(&api_key, "api-request")?;
        assert_eq!(context.user_id, user_id);
        assert_eq!(context.team_id, Some(team_id));
        drop(store);

        let connection = Connection::open(database)?;
        let digest: Vec<u8> =
            connection.query_row("SELECT key_hash FROM security_api_keys", [], |row| {
                row.get(0)
            })?;
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, api_key.as_bytes());
        Ok(())
    }

    #[test]
    fn rotates_api_keys_without_retaining_recoverable_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let user_id = store.create_local_user(
            "key-owner@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        assert!(!store.has_active_api_key(user_id)?);
        let first = store.rotate_api_key(user_id, 100)?;
        assert!(store.has_active_api_key(user_id)?);
        store.authenticate_api_key(&first, "first")?;
        let second = store.rotate_api_key(user_id, 200)?;
        assert!(matches!(
            store.authenticate_api_key(&first, "revoked"),
            Err(SecurityError::InvalidToken)
        ));
        store.authenticate_api_key(&second, "second")?;
        let persisted: Vec<Vec<u8>> = store
            .lock()?
            .prepare("SELECT key_hash FROM security_api_keys ORDER BY created_at")?
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        assert_eq!(persisted.len(), 2);
        assert!(persisted.iter().all(|digest| digest.len() == 32));
        assert!(persisted.iter().all(|digest| digest != first.as_bytes()));
        assert!(persisted.iter().all(|digest| digest != second.as_bytes()));
        Ok(())
    }

    #[test]
    fn lists_named_api_keys_with_usage_windows() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let user_id = store.create_local_user(
            "api-usage@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        // The store persists the name verbatim (the HTTP layer owns trimming);
        // the prefix is the non-secret leading fragment of the raw key.
        let (record, secret) = store.create_named_api_key(user_id, "Prod", 1_000)?;
        assert_eq!(record.name, "Prod");
        assert_eq!(record.prefix.chars().count(), 11);
        assert!(secret.starts_with(record.prefix.as_str()));
        assert_eq!(
            (record.usage_today, record.usage_month, record.usage_total),
            (0, 0, 0)
        );

        // Seed usage across three epoch days: today, 15 days ago (inside the
        // rolling 30-day window), and 40 days ago (outside the month, in total).
        let today = 20_000_i64;
        {
            let connection = store.lock()?;
            connection.execute(
                "INSERT INTO security_api_key_daily_usage (key_id, epoch_day, count)
                 VALUES (?1, ?2, 5), (?1, ?3, 3), (?1, ?4, 7)",
                rusqlite::params![record.key_id, today, today - 15, today - 40],
            )?;
        }

        let keys = store.list_api_keys(user_id, today)?;
        assert_eq!(keys.len(), 1);
        let key = &keys[0];
        assert_eq!(key.usage_today, 5);
        // Rolling 30-day window (epoch_day >= today - 29): 5 (today) + 3 = 8.
        assert_eq!(key.usage_month, 8);
        // Lifetime: 5 + 3 + 7 = 15.
        assert_eq!(key.usage_total, 15);
        assert!(key.last_used_at.is_none());
        assert!(key.revoked_at.is_none());
        Ok(())
    }

    #[test]
    fn month_window_boundary_is_inclusive_of_29_days_ago() -> Result<(), Box<dyn std::error::Error>>
    {
        // Guards the off-by-one in the rolling 30-day window: the oldest day
        // still counted for "usage this month" is `today - 29`; `today - 30`
        // falls just outside it but still counts toward the lifetime total
        // (parity with Java `sumSinceByIds(ids, today - (MONTH_WINDOW_DAYS - 1))`).
        let store = SecurityStore::in_memory()?;
        let user_id = store.create_local_user(
            "api-boundary@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        let (record, _secret) = store.create_named_api_key(user_id, "boundary", 1_000)?;
        let today = 50_000_i64;
        {
            let connection = store.lock()?;
            connection.execute(
                "INSERT INTO security_api_key_daily_usage (key_id, epoch_day, count)
                 VALUES (?1, ?2, 2), (?1, ?3, 4)",
                rusqlite::params![record.key_id, today - 29, today - 30],
            )?;
        }
        let keys = store.list_api_keys(user_id, today)?;
        let key = &keys[0];
        // Only the `today - 29` row (2) is inside the month window.
        assert_eq!(key.usage_month, 2);
        // Both rows count toward the lifetime total.
        assert_eq!(key.usage_total, 6);
        assert_eq!(key.usage_today, 0);
        Ok(())
    }

    #[test]
    fn create_named_api_key_enforces_active_cap() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let user_id = store.create_local_user(
            "api-cap@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        for index in 0..50 {
            store.create_named_api_key(user_id, &format!("k{index}"), 1_000)?;
        }
        assert!(matches!(
            store.create_named_api_key(user_id, "one too many", 1_000),
            Err(SecurityError::TooManyApiKeys)
        ));
        // Revoking one frees a slot; the freed key lists as revoked, not gone.
        let victim = store.list_api_keys(user_id, 100)?[0].key_id.clone();
        assert!(store.revoke_api_key(user_id, &victim, 2_000)?);
        assert!(
            store
                .create_named_api_key(user_id, "now fits", 1_000)
                .is_ok()
        );
        let revoked = store
            .list_api_keys(user_id, 100)?
            .into_iter()
            .find(|key| key.key_id == victim)
            .ok_or("revoked key still listed")?;
        assert!(revoked.revoked_at.is_some());
        Ok(())
    }

    #[test]
    fn revoke_api_key_is_owner_scoped_and_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let owner = store.create_local_user(
            "api-owner@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        let attacker = store.create_local_user(
            "api-attacker@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        let (record, _secret) = store.create_named_api_key(owner, "owned", 1_000)?;
        // Unknown id and cross-user id both report not-found (never revoke).
        assert!(!store.revoke_api_key(owner, "akid_missing", 2_000)?);
        assert!(!store.revoke_api_key(attacker, &record.key_id, 2_000)?);
        assert!(store.list_api_keys(owner, 100)?[0].revoked_at.is_none());
        // First revoke succeeds and stamps the time; a second is idempotent and
        // keeps the first stamp.
        assert!(store.revoke_api_key(owner, &record.key_id, 2_000)?);
        assert!(store.revoke_api_key(owner, &record.key_id, 9_000)?);
        assert_eq!(store.list_api_keys(owner, 100)?[0].revoked_at, Some(2_000));
        Ok(())
    }

    #[test]
    fn manages_local_users_and_preserves_one_enabled_administrator()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 100, "admin")?;
        assert!(matches!(
            store.set_user_role("admin", "ROLE_USER", 101),
            Err(SecurityError::ProtectedSystemState)
        ));
        assert!(matches!(
            store.set_user_enabled("admin", false, 101),
            Err(SecurityError::ProtectedSystemState)
        ));
        assert!(matches!(
            store.delete_user("admin"),
            Err(SecurityError::ProtectedSystemState)
        ));

        let user_id = store.create_local_user(
            "person@example.test",
            "first-test-password",
            ["ROLE_USER"],
            None,
        )?;
        let user = store.authenticate_password(
            "person@example.test",
            "first-test-password",
            200,
            "user",
        )?;
        let session = store.issue_session(&user, 200, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL)?;
        assert!(matches!(
            store.change_own_password(user_id, "wrong-test-password", "second-test-password", 201),
            Err(SecurityError::InvalidCredentials)
        ));
        store.change_own_password(user_id, "first-test-password", "second-test-password", 202)?;
        assert!(matches!(
            store.authenticate_access_token(&session.access_token, 203, "revoked"),
            Err(SecurityError::InvalidToken)
        ));
        let changed = store.authenticate_password(
            "person@example.test",
            "second-test-password",
            204,
            "changed",
        )?;
        store.change_own_username(
            changed.user_id,
            "second-test-password",
            "renamed@example.test",
            205,
        )?;
        store.authenticate_password(
            "renamed@example.test",
            "second-test-password",
            206,
            "renamed",
        )?;

        let second_admin_id = store.create_local_user(
            "second-admin@example.test",
            "admin-two-password",
            ["ROLE_ADMIN"],
            None,
        )?;
        store.set_user_role("admin", "ROLE_USER", 207)?;
        store.set_user_enabled("renamed@example.test", false, 208)?;
        assert!(matches!(
            store.authenticate_password(
                "renamed@example.test",
                "second-test-password",
                209,
                "disabled"
            ),
            Err(SecurityError::AccountDisabled)
        ));
        store.set_user_enabled("renamed@example.test", true, 210)?;
        store.set_user_password("renamed@example.test", "admin-reset-password", 211)?;
        store.authenticate_password(
            "renamed@example.test",
            "admin-reset-password",
            212,
            "reset",
        )?;
        let users = store.list_users(212)?;
        assert_eq!(users.len(), 3);
        assert!(
            users.iter().any(|user| {
                user.id == second_admin_id && user.roles == ["ROLE_ADMIN".to_owned()]
            })
        );
        assert_eq!(store.delete_user("renamed@example.test")?, user_id);
        assert_eq!(store.list_users(213)?.len(), 2);
        assert_eq!(admin.user_id, 1);
        Ok(())
    }

    #[test]
    fn forced_password_change_is_durable_and_self_service_clears_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let user_id = store.create_local_user(
            "person@example.test",
            "first-test-password",
            ["ROLE_USER"],
            None,
        )?;
        store.set_user_password_with_force_change(
            "person@example.test",
            "forced-test-password",
            true,
            100,
        )?;
        let forced = store.authenticate_password(
            "person@example.test",
            "forced-test-password",
            101,
            "forced",
        )?;
        assert_eq!(forced.user_id, user_id);
        assert!(forced.force_password_change);

        store.change_own_password(user_id, "forced-test-password", "final-test-password", 102)?;
        let changed = store.authenticate_password(
            "person@example.test",
            "final-test-password",
            103,
            "cleared",
        )?;
        assert!(!changed.force_password_change);
        Ok(())
    }

    #[test]
    fn unlocks_persistent_login_failures_for_existing_users()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        for attempt in 0..5 {
            let _ = store.authenticate_password("admin", "wrong", 100 + attempt, "attempt");
        }
        assert!(matches!(
            store.authenticate_password("admin", "admin-test-password", 110, "locked"),
            Err(SecurityError::AccountLocked)
        ));
        store.unlock_user("ADMIN")?;
        store.authenticate_password("admin", "admin-test-password", 111, "unlocked")?;
        assert!(matches!(
            store.unlock_user("missing"),
            Err(SecurityError::UserNotFound)
        ));
        Ok(())
    }

    #[test]
    fn provisions_external_subjects_without_email_linking_and_upgrades_anonymous_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        let anonymous = external_identity(
            "123e4567-e89b-12d3-a456-426614174000",
            "anon_123e4567-e89b-12d3-a456-426614174000",
            true,
        );
        let first = store.authenticate_supabase_identity(&anonymous, 100, "anonymous")?;
        assert!(first.has_role("ROLE_LIMITED_API_USER"));
        assert_eq!(
            first.authentication_source,
            super::AuthenticationSource::SupabaseJwt
        );
        assert_eq!(
            first.external_subject.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert!(matches!(
            store.authenticate_password(&anonymous.username, "any-password", 101, "password"),
            Err(SecurityError::InvalidCredentials)
        ));

        let mut upgraded = external_identity(
            "123e4567-e89b-12d3-a456-426614174000",
            "person@example.test",
            false,
        );
        upgraded.authentication_type = "oauth2".to_owned();
        let upgraded_context = store.authenticate_supabase_identity(&upgraded, 102, "upgraded")?;
        assert_eq!(upgraded_context.user_id, first.user_id);
        assert!(upgraded_context.has_role("ROLE_USER"));
        assert!(!upgraded_context.has_role("ROLE_LIMITED_API_USER"));
        assert!(matches!(
            store.authenticate_supabase_identity(&anonymous, 103, "downgrade"),
            Err(SecurityError::InvalidToken)
        ));

        let collision = external_identity(
            "123e4567-e89b-12d3-a456-426614174999",
            "person@example.test",
            false,
        );
        assert!(matches!(
            store.authenticate_supabase_identity(&collision, 104, "collision"),
            Err(SecurityError::Conflict)
        ));
        let users = store.list_users(105)?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].team_name.as_deref(), Some("Personal-1"));
        Ok(())
    }

    #[test]
    fn external_auth_uses_live_local_roles_and_enabled_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("local-admin", "local-admin-password")?);
        let identity = external_identity(
            "123e4567-e89b-12d3-a456-426614174111",
            "external@example.test",
            false,
        );
        let first = store.authenticate_supabase_identity(&identity, 100, "first")?;
        assert!(first.has_role("ROLE_USER"));
        store.set_user_role("external@example.test", "ROLE_ADMIN", 101)?;
        let promoted = store.authenticate_supabase_identity(&identity, 102, "promoted")?;
        assert!(promoted.has_role("ROLE_ADMIN"));
        store.set_user_enabled("external@example.test", false, 103)?;
        assert!(matches!(
            store.authenticate_supabase_identity(&identity, 104, "disabled"),
            Err(SecurityError::AccountDisabled)
        ));
        store.delete_user("external@example.test")?;
        assert!(matches!(
            store.authenticate_supabase_identity(&identity, 105, "deleted"),
            Err(SecurityError::AccountDisabled)
        ));
        Ok(())
    }

    fn external_identity(
        subject: &str,
        username: &str,
        anonymous: bool,
    ) -> VerifiedSupabaseIdentity {
        VerifiedSupabaseIdentity {
            issuer: "https://project.supabase.co/auth/v1".to_owned(),
            subject: subject.to_owned(),
            username: username.to_owned(),
            email: (!anonymous).then(|| username.to_owned()),
            authentication_type: if anonymous { "anonymous" } else { "supabase" }.to_owned(),
            role: if anonymous {
                "ROLE_LIMITED_API_USER"
            } else {
                "ROLE_USER"
            }
            .to_owned(),
            session_id: "external-session".to_owned(),
            permissions: ["pdf.read".to_owned()].into_iter().collect(),
            anonymous,
        }
    }

    #[test]
    fn encrypts_mfa_seed_and_rejects_missing_invalid_and_replayed_codes()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context =
            store.authenticate_password("admin", "test-only-password", 1_000, "mfa-setup")?;
        let secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        let persisted: String = store.lock()?.query_row(
            "SELECT secret_ciphertext FROM security_mfa WHERE user_id = ?1",
            [context.user_id],
            |row| row.get(0),
        )?;
        assert!(persisted.starts_with("enc:v1:"));
        assert!(!persisted.contains(secret.as_str()));

        let enable_time = 30_000;
        let enable_code = totp_code_at(&secret, enable_time).ok_or("missing TOTP")?;
        store.enable_mfa(context.user_id, &enable_code, enable_time)?;
        assert!(store.mfa_is_enabled(context.user_id)?);
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                None,
                enable_time + 30,
                "login",
            ),
            Err(SecurityError::MfaRequired)
        ));
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some("000000"),
                enable_time + 30,
                "login",
            ),
            Err(SecurityError::InvalidMfa)
        ));

        let login_time = enable_time + 30;
        let login_code = totp_code_at(&secret, login_time).ok_or("missing TOTP")?;
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(&login_code),
            login_time,
            "login",
        )?;
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some(&login_code),
                login_time,
                "replay",
            ),
            Err(SecurityError::InvalidMfa)
        ));

        let disable_time = login_time + 30;
        let disable_code = totp_code_at(&secret, disable_time).ok_or("missing TOTP")?;
        assert!(store.disable_mfa(context.user_id, &disable_code, disable_time)?);
        assert!(!store.mfa_is_enabled(context.user_id)?);
        assert!(
            store
                .authenticate_login(
                    "admin",
                    "test-only-password",
                    None,
                    disable_time + 30,
                    "login-without-mfa",
                )
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn cancels_only_pending_mfa_setup() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context =
            store.authenticate_password("admin", "test-only-password", 1_000, "mfa-setup")?;
        let _secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        store.cancel_mfa_setup(context.user_id)?;
        assert!(!store.mfa_is_enabled(context.user_id)?);

        let secret = store.begin_mfa_setup(context.user_id, 1_002)?;
        let now = 60_000;
        let code = totp_code_at(&secret, now).ok_or("missing TOTP")?;
        store.enable_mfa(context.user_id, &code, now)?;
        assert!(matches!(
            store.cancel_mfa_setup(context.user_id),
            Err(SecurityError::MfaAlreadyEnabled)
        ));
        drop(secret);
        Ok(())
    }

    fn store_with_mfa_admin() -> Result<(SecurityStore, i64), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context =
            store.authenticate_password("admin", "test-only-password", 1_000, "mfa-setup")?;
        let secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        let enable_time = 30_000;
        let enable_code = totp_code_at(&secret, enable_time).ok_or("missing TOTP")?;
        store.enable_mfa(context.user_id, &enable_code, enable_time)?;
        drop(secret);
        Ok((store, context.user_id))
    }

    fn admin_failure_count(store: &SecurityStore) -> Result<i64, Box<dyn std::error::Error>> {
        let count = store.lock()?.query_row(
            "SELECT COALESCE(
                 (SELECT failure_count FROM security_login_attempts
                  WHERE username_norm = 'admin'),
                 0
             )",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    #[test]
    fn recovery_code_substitutes_for_totp_and_issues_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let (store, user_id) = store_with_mfa_admin()?;
        let codes = store.generate_recovery_codes(user_id, 40_000)?;
        assert_eq!(codes.len(), 10);
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);

        // No TOTP is supplied; the recovery code is submitted in its place and
        // must complete login exactly as a valid TOTP would, yielding a context
        // from which a real session can be issued.
        let context = store.authenticate_login(
            "admin",
            "test-only-password",
            Some(codes[0].as_str()),
            60_000,
            "recovery-login",
        )?;
        let tokens =
            store.issue_session(&context, 60_000, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL)?;
        assert!(tokens.access_token.starts_with("spdf_at_"));
        assert_eq!(store.remaining_recovery_codes(user_id)?, 9);
        Ok(())
    }

    #[test]
    fn recovery_code_is_single_use() -> Result<(), Box<dyn std::error::Error>> {
        let (store, user_id) = store_with_mfa_admin()?;
        let codes = store.generate_recovery_codes(user_id, 40_000)?;

        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(codes[0].as_str()),
            60_000,
            "first",
        )?;
        assert_eq!(store.remaining_recovery_codes(user_id)?, 9);

        // The same code must never authenticate a second time.
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some(codes[0].as_str()),
                60_030,
                "replay",
            ),
            Err(SecurityError::InvalidMfa)
        ));
        assert_eq!(store.remaining_recovery_codes(user_id)?, 9);
        Ok(())
    }

    #[test]
    fn failed_recovery_code_feeds_the_shared_mfa_lockout() -> Result<(), Box<dyn std::error::Error>>
    {
        let (store, user_id) = store_with_mfa_admin()?;
        let codes = store.generate_recovery_codes(user_id, 40_000)?;
        assert_eq!(admin_failure_count(&store)?, 0);

        // A single wrong recovery code is rejected, counted against the shared
        // lockout, and consumes nothing.
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some("AAAA-AAAA-AAAA-AAAA"),
                60_000,
                "wrong-recovery",
            ),
            Err(SecurityError::InvalidMfa)
        ));
        assert_eq!(admin_failure_count(&store)?, 1);
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);

        // Drive the same counter to the lockout threshold (constant `now`, so
        // the failures accumulate rather than resetting).
        for _ in 1..5 {
            assert!(matches!(
                store.authenticate_login(
                    "admin",
                    "test-only-password",
                    Some("AAAA-AAAA-AAAA-AAAA"),
                    60_000,
                    "wrong-recovery",
                ),
                Err(SecurityError::InvalidMfa)
            ));
        }
        assert_eq!(admin_failure_count(&store)?, 5);

        // Locked: even a genuine recovery code is refused at the password
        // stage's lock gate, so it is never consumed.
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some(codes[0].as_str()),
                60_000,
                "locked",
            ),
            Err(SecurityError::AccountLocked)
        ));
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);
        Ok(())
    }

    #[test]
    fn regenerating_recovery_codes_invalidates_the_prior_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let (store, user_id) = store_with_mfa_admin()?;
        let first = store.generate_recovery_codes(user_id, 40_000)?;
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);

        let second = store.generate_recovery_codes(user_id, 41_000)?;
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);

        // A code from the superseded set no longer authenticates.
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some(first[0].as_str()),
                60_000,
                "stale",
            ),
            Err(SecurityError::InvalidMfa)
        ));
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);

        // A code from the current set does, and decrements the remaining count.
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(second[0].as_str()),
            60_030,
            "fresh",
        )?;
        assert_eq!(store.remaining_recovery_codes(user_id)?, 9);
        Ok(())
    }

    #[test]
    fn recovery_code_is_inert_when_mfa_disabled() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context = store.authenticate_password("admin", "test-only-password", 1_000, "setup")?;
        // Codes exist, but MFA is never enabled for this user.
        let codes = store.generate_recovery_codes(context.user_id, 40_000)?;
        assert_eq!(store.remaining_recovery_codes(context.user_id)?, 10);

        // Password alone authenticates (no second factor is required), and the
        // recovery code passed in the mfa_code slot is never consulted, so it
        // stays unconsumed.
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(codes[0].as_str()),
            60_000,
            "no-mfa",
        )?;
        assert_eq!(store.remaining_recovery_codes(context.user_id)?, 10);
        Ok(())
    }

    #[test]
    fn recovery_code_does_not_bypass_a_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
        let (store, user_id) = store_with_mfa_admin()?;
        let codes = store.generate_recovery_codes(user_id, 40_000)?;

        // Wrong password + a valid recovery code is rejected at the password
        // stage, before any second-factor logic runs, so the code is untouched.
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "wrong-password",
                Some(codes[0].as_str()),
                60_000,
                "wrong-password",
            ),
            Err(SecurityError::InvalidCredentials)
        ));
        assert_eq!(store.remaining_recovery_codes(user_id)?, 10);

        // The very same code still authenticates once the correct password is
        // supplied, proving the rejected attempt neither consumed nor spent it.
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(codes[0].as_str()),
            60_030,
            "correct-password",
        )?;
        assert_eq!(store.remaining_recovery_codes(user_id)?, 9);
        Ok(())
    }

    #[test]
    fn enabling_mfa_auto_issues_a_live_recovery_code_set() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context = store.authenticate_password("admin", "test-only-password", 1_000, "setup")?;
        let secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        let enable_time = 30_000;
        let enable_code = totp_code_at(&secret, enable_time).ok_or("missing TOTP")?;

        // Enabling returns an initial set of ten codes in the same operation.
        let codes = store.enable_mfa(context.user_id, &enable_code, enable_time)?;
        assert_eq!(codes.len(), 10);
        assert_eq!(store.remaining_recovery_codes(context.user_id)?, 10);

        // The auto-issued codes are immediately usable at the login MFA step.
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(codes[0].as_str()),
            enable_time + 60,
            "auto-issued",
        )?;
        assert_eq!(store.remaining_recovery_codes(context.user_id)?, 9);
        drop(secret);
        Ok(())
    }

    #[test]
    fn regenerate_requires_a_fresh_totp_and_invalidates_the_prior_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context = store.authenticate_password("admin", "test-only-password", 1_000, "setup")?;
        let secret = store.begin_mfa_setup(context.user_id, 1_001)?;
        let enable_time = 30_000;
        let enable_code = totp_code_at(&secret, enable_time).ok_or("missing TOTP")?;
        let first = store.enable_mfa(context.user_id, &enable_code, enable_time)?;

        // The enable step is already consumed, so replaying it cannot regenerate.
        assert!(matches!(
            store.regenerate_recovery_codes(context.user_id, &enable_code, enable_time),
            Err(SecurityError::InvalidMfa)
        ));
        // A malformed code is refused as well.
        assert!(matches!(
            store.regenerate_recovery_codes(context.user_id, "not-a-totp", enable_time + 60),
            Err(SecurityError::InvalidMfa)
        ));
        // Neither refusal touched the live set.
        assert_eq!(store.remaining_recovery_codes(context.user_id)?, 10);

        // A fresh step regenerates: ten new codes, disjoint from the old set.
        let regen_time = enable_time + 60;
        let regen_code = totp_code_at(&secret, regen_time).ok_or("missing regen TOTP")?;
        let second = store.regenerate_recovery_codes(context.user_id, &regen_code, regen_time)?;
        assert_eq!(second.len(), 10);
        assert!(first.iter().all(|code| !second.contains(code)));
        assert_eq!(store.remaining_recovery_codes(context.user_id)?, 10);

        // A code from the superseded set is dead; a new code authenticates.
        assert!(matches!(
            store.authenticate_login(
                "admin",
                "test-only-password",
                Some(first[0].as_str()),
                regen_time + 60,
                "stale",
            ),
            Err(SecurityError::InvalidMfa)
        ));
        store.authenticate_login(
            "admin",
            "test-only-password",
            Some(second[0].as_str()),
            regen_time + 90,
            "fresh",
        )?;
        drop(secret);
        Ok(())
    }

    #[test]
    fn regenerate_is_refused_until_mfa_is_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let context = store.authenticate_password("admin", "test-only-password", 1_000, "setup")?;
        // No MFA at all.
        assert!(matches!(
            store.regenerate_recovery_codes(context.user_id, "123456", 2_000),
            Err(SecurityError::MfaSetupRequired)
        ));
        // A pending (not-yet-enabled) setup is still insufficient.
        let secret = store.begin_mfa_setup(context.user_id, 2_001)?;
        assert!(matches!(
            store.regenerate_recovery_codes(context.user_id, "123456", 2_100),
            Err(SecurityError::MfaSetupRequired)
        ));
        drop(secret);
        Ok(())
    }

    #[test]
    fn enforces_team_membership_and_system_team_invariants()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let teams = store.list_teams()?;
        let default_team = teams
            .iter()
            .find(|team| team.name == "Default")
            .ok_or("missing default team")?;
        let internal_team = teams
            .iter()
            .find(|team| team.name == "Internal")
            .ok_or("missing internal team")?;
        assert_eq!(default_team.member_count, 1);

        let project_team = store.create_team("Project Alpha")?;
        assert!(matches!(
            store.create_team("project alpha"),
            Err(SecurityError::Conflict)
        ));
        let user_id = store.create_local_user(
            "user@example.test",
            "test-only-password",
            ["ROLE_USER"],
            None,
        )?;
        store.assign_user_to_team(user_id, project_team)?;
        store.set_team_owner(project_team, user_id, true)?;
        assert!(matches!(
            store.delete_team(project_team),
            Err(SecurityError::TeamNotEmpty)
        ));
        assert!(matches!(
            store.assign_user_to_team(user_id, internal_team.id),
            Err(SecurityError::ProtectedSystemState)
        ));
        assert!(matches!(
            store.set_team_owner(default_team.id, user_id, true),
            Err(SecurityError::ProtectedSystemState)
        ));
        store.assign_user_to_team(user_id, default_team.id)?;
        store.delete_team(project_team)?;
        assert!(matches!(
            store.rename_team(internal_team.id, "Renamed"),
            Err(SecurityError::ProtectedSystemState)
        ));
        Ok(())
    }

    #[test]
    fn invitations_store_only_digests_and_are_consumed_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let admin = store.authenticate_password("admin", "test-only-password", 1_000, "invite")?;
        let team_id = store.create_team("Invite Team")?;
        let issued = store.create_invite(
            &admin,
            Some("New.User@Example.Test"),
            "ROLE_USER",
            Some(team_id),
            2_000,
            5_600,
        )?;
        let digest: Vec<u8> =
            store
                .lock()?
                .query_row("SELECT token_hash FROM security_invites", [], |row| {
                    row.get(0)
                })?;
        assert_eq!(digest.len(), 32);
        assert_ne!(digest, issued.token.as_bytes());
        let details = store.validate_invite(&issued.token, 2_001)?;
        assert_eq!(details.email.as_deref(), Some("new.user@example.test"));
        assert_eq!(details.team_id, team_id);
        assert!(!details.email_required);

        let username = store.accept_invite(
            &issued.token,
            Some("ignored@example.test"),
            "invite-password",
            2_002,
        )?;
        assert_eq!(username, "new.user@example.test");
        assert!(matches!(
            store.validate_invite(&issued.token, 2_003),
            Err(SecurityError::InvalidInvite)
        ));
        let user = store.authenticate_password(
            "NEW.USER@example.test",
            "invite-password",
            2_004,
            "accepted",
        )?;
        assert_eq!(user.team_id, Some(team_id));
        assert!(user.has_role("ROLE_USER"));
        Ok(())
    }

    #[test]
    fn general_invitations_require_email_and_support_revoke_cleanup()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let admin = store.authenticate_password("admin", "test-only-password", 1_000, "invite")?;
        let issued = store.create_invite(&admin, None, "ROLE_USER", None, 2_000, 2_100)?;
        assert!(store.validate_invite(&issued.token, 2_001)?.email_required);
        assert!(matches!(
            store.accept_invite(&issued.token, None, "invite-password", 2_002),
            Err(SecurityError::InvalidInput)
        ));
        assert_eq!(store.list_active_invites(2_003)?.len(), 1);
        let invite_id = store.list_active_invites(2_003)?[0].id;
        store.revoke_invite(invite_id, 2_004)?;
        assert!(matches!(
            store.validate_invite(&issued.token, 2_005),
            Err(SecurityError::InvalidInvite)
        ));
        assert_eq!(store.cleanup_invites(2_005)?, 1);
        Ok(())
    }

    #[test]
    fn resource_schema_cleans_user_state_and_rejects_team_deletion_with_owned_configs()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "test-only-password")?);
        let admin = store.authenticate_password("admin", "test-only-password", 100, "admin")?;
        let user_id = store.create_local_user(
            "resource-user@example.test",
            "resource-user-password",
            ["ROLE_USER"],
            None,
        )?;
        store.upsert_resource_grant(
            ResourceType::Portal,
            "",
            PrincipalType::User,
            user_id,
            AccessPermission::Use,
            admin.user_id,
        )?;
        let config = store.create_integration_config(&NewIntegrationConfig {
            integration_type: IntegrationType::Api,
            name: "Owned API".to_owned(),
            scope: OwnerScope::User,
            owner_user_id: Some(user_id),
            owner_team_id: None,
            enabled: true,
            locked: false,
            default_access: DefaultAccessPolicy::ExplicitOnly,
            config: serde_json::Map::new(),
        })?;
        store.upsert_resource_grant(
            ResourceType::IntegrationConfig,
            &config.id.to_string(),
            PrincipalType::User,
            admin.user_id,
            AccessPermission::Manage,
            admin.user_id,
        )?;

        assert_eq!(store.delete_user("resource-user@example.test")?, user_id);
        let connection = store.lock()?;
        let integration_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM integration_configs", [], |row| {
                row.get(0)
            })?;
        let grant_count: i64 =
            connection.query_row("SELECT COUNT(*) FROM resource_grants", [], |row| row.get(0))?;
        drop(connection);
        assert_eq!(integration_count, 0);
        assert_eq!(grant_count, 0);

        let team_id = store.create_team("Owned Resource Team")?;
        store.create_integration_config(&NewIntegrationConfig {
            integration_type: IntegrationType::Mcp,
            name: "Team MCP".to_owned(),
            scope: OwnerScope::Team,
            owner_user_id: None,
            owner_team_id: Some(team_id),
            enabled: true,
            locked: false,
            default_access: DefaultAccessPolicy::ExplicitOnly,
            config: serde_json::Map::new(),
        })?;
        assert!(matches!(
            store.delete_team(team_id),
            Err(SecurityError::TeamNotEmpty)
        ));
        Ok(())
    }

    // FINDING #1 (DoS): bcrypt must run OUTSIDE the global connection mutex.
    // The stored hash + lockout state are read under a brief lock, the lock is
    // released, verify()/fake_password_work() run off-lock, then an Immediate
    // transaction re-acquires only to record the outcome atomically.
    #[test]
    fn off_lock_refactor_preserves_failure_recording_and_reset()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "correct horse battery staple")?);

        // Four wrong attempts accrue but stay below the lockout threshold (5).
        for attempt in 0..4 {
            assert!(matches!(
                store.authenticate_password("admin", "nope", 1_000 + attempt, "fail"),
                Err(SecurityError::InvalidCredentials)
            ));
        }
        // A correct password still authenticates and clears the counter, proving
        // the re-acquired transaction commits the success-path reset.
        store.authenticate_password("admin", "correct horse battery staple", 1_010, "ok")?;
        // So four further failures again fall one short of locking...
        for attempt in 0..4 {
            assert!(matches!(
                store.authenticate_password("admin", "nope", 1_020 + attempt, "fail"),
                Err(SecurityError::InvalidCredentials)
            ));
        }
        // ...and the fifth consecutive failure trips the lockout, showing the
        // off-lock failure recording is still atomic and correctly counted.
        assert!(matches!(
            store.authenticate_password("admin", "nope", 1_030, "fail"),
            Err(SecurityError::AccountLocked)
        ));
        // A correct password is refused while locked (fake work, no bypass).
        assert!(matches!(
            store.authenticate_password("admin", "correct horse battery staple", 1_031, "locked"),
            Err(SecurityError::AccountLocked)
        ));
        // Unknown users get the identical generic rejection (no enumeration).
        assert!(matches!(
            store.authenticate_password("ghost", "whatever", 1_040, "unknown"),
            Err(SecurityError::InvalidCredentials)
        ));
        Ok(())
    }

    // FINDING #1 (DoS): structural proof that bcrypt is not serialised by the
    // connection mutex. N authentications launched concurrently must finish
    // meaningfully faster than the same N run back-to-back; that is only
    // possible if the (expensive) bcrypt verify runs while the lock is free.
    #[test]
    fn password_authentication_runs_bcrypt_off_the_connection_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Instant;

        // Number of authentications timed serially and then concurrently.
        const N: usize = 6;

        // Parallelism is only observable with more than one core: CPU-bound
        // bcrypt cannot overlap on a single core regardless of locking, so the
        // timing assertion would be meaningless there.
        let cores = thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        if cores < 2 {
            return Ok(());
        }

        // Cost tuned so one verify is comfortably measurable (tens of ms) while
        // the whole test stays well under a second.
        let store = Arc::new(SecurityStore::in_memory_with_cost(9)?);
        assert!(store.bootstrap_admin("admin", "correct horse battery staple")?);

        let password = "correct horse battery staple";

        // Warm caches/JIT of the hashing path so neither measurement below eats
        // a one-off cold-start cost.
        store.authenticate_password("admin", password, 500, "warm")?;

        // Serial baseline: N authentications back-to-back = N bcrypts in series.
        // The timestamp is constant: every attempt uses the correct password, so
        // it only ever clears an (empty) failure counter.
        let serial_start = Instant::now();
        for _ in 0..N {
            store.authenticate_password("admin", password, 1_000, "serial")?;
        }
        let serial = serial_start.elapsed();

        // Same N authentications launched simultaneously. Under the old
        // under-lock behavior every verify would serialise on the mutex and the
        // wall time would match `serial`; off-lock they overlap across cores.
        let barrier = Arc::new(Barrier::new(N));
        let concurrent_start = Instant::now();
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store
                        .authenticate_password("admin", password, 2_000, "flood")
                        .map(|_| ())
                })
            })
            .collect();
        for handle in handles {
            handle.join().map_err(|_| "auth thread panicked")??;
        }
        let concurrent = concurrent_start.elapsed();

        // Overlap must pull concurrent wall time well below the serial baseline.
        // 0.7 leaves generous headroom for scheduler noise while still failing
        // the old behavior, where concurrent ~= serial.
        let budget = serial.mul_f64(0.7);
        assert!(
            concurrent < budget,
            "concurrent auth {concurrent:?} not sub-linear vs serial {serial:?} \
             (budget {budget:?}); bcrypt appears to run under the connection lock",
        );
        Ok(())
    }
}

#[cfg(test)]
mod proprietary_ui_data_store_tests {
    use super::{INTERNAL_TEAM_NAME, SecurityStore};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn first_time_setup_true_when_no_real_users() -> TestResult {
        let store = SecurityStore::in_memory()?;
        // No users at all → defaults must be surfaced.
        assert!(store.first_time_setup_required()?);
        Ok(())
    }

    #[test]
    fn first_time_setup_true_for_lone_admin_on_first_login() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        // A single admin that has not completed initial setup keeps defaults on.
        assert!(store.first_time_setup_required()?);
        Ok(())
    }

    #[test]
    fn first_time_setup_false_after_admin_completes_setup() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 1_000, "setup")?;
        store.complete_initial_setup(admin.user_id)?;
        assert!(!store.first_time_setup_required()?);
        Ok(())
    }

    #[test]
    fn first_time_setup_false_with_multiple_real_users() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        store.create_local_user("second", "second-test-password", ["ROLE_USER"], None)?;
        assert!(!store.first_time_setup_required()?);
        Ok(())
    }

    #[test]
    fn first_time_setup_ignores_internal_api_user() -> TestResult {
        // A lone internal API user is not a real user, so setup is still needed.
        let store = SecurityStore::in_memory()?;
        store.create_local_user(
            "STIRLING-PDF-BACKEND-API-USER",
            "internal-api-password",
            ["ROLE_USER"],
            None,
        )?;
        assert!(store.first_time_setup_required()?);
        Ok(())
    }

    #[test]
    fn mfa_is_required_defaults_false_without_row() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 1_000, "mfa")?;
        assert!(!store.mfa_is_required(admin.user_id)?);
        Ok(())
    }

    #[test]
    fn team_queries_exclude_internal_team_and_expose_leaders() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let team_id = store.create_team("Engineering")?;
        let owner_id =
            store.create_local_user("lead", "lead-test-password", ["ROLE_USER"], Some(team_id))?;
        store.set_team_owner(team_id, owner_id, true)?;

        // The internal team never appears in any team projection.
        let activity = store.latest_session_activity_per_team()?;
        let teams = store.list_teams()?;
        let internal_id = teams
            .iter()
            .find(|team| team.name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
            .map(|team| team.id)
            .ok_or("internal team should be seeded")?;
        assert!(
            !activity.iter().any(|(id, _)| *id == internal_id),
            "internal team must be filtered from activity"
        );

        // The created team has no sessions yet → activity is None.
        let engineering = activity
            .iter()
            .find(|(id, _)| *id == team_id)
            .ok_or("engineering team should be present")?;
        assert!(engineering.1.is_none());

        // The owner is reported as a leader of the team.
        let leaders = store.team_leaders()?;
        assert!(
            leaders
                .iter()
                .any(|(tid, uid, name)| *tid == team_id && *uid == owner_id && name == "lead")
        );
        assert!(
            !leaders.iter().any(|(tid, _, _)| *tid == internal_id),
            "internal team leaders must be filtered"
        );
        Ok(())
    }

    #[test]
    fn team_name_and_latest_session_reflect_activity() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let team_id = store.create_team("Design")?;
        let member = store.create_local_user(
            "artist",
            "artist-test-password",
            ["ROLE_USER"],
            Some(team_id),
        )?;
        assert_eq!(store.team_name(team_id)?.as_deref(), Some("Design"));
        assert!(store.team_name(999_999)?.is_none());

        // Before any session the member's latest activity is None.
        let before = store.latest_session_by_team(team_id)?;
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].0, "artist");
        assert!(before[0].1.is_none());

        // After a session is issued its creation time is the latest activity.
        let context =
            store.authenticate_password("artist", "artist-test-password", 5_000, "login")?;
        assert_eq!(context.user_id, member);
        store.issue_session(
            &context,
            5_000,
            super::DEFAULT_ACCESS_TTL,
            super::DEFAULT_REFRESH_TTL,
        )?;
        let after = store.latest_session_by_team(team_id)?;
        assert_eq!(after[0].1, Some(5_000));
        Ok(())
    }

    #[test]
    fn active_principals_reflect_live_non_revoked_sessions() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 1_000, "login")?;

        // No sessions yet: nobody is active.
        assert!(store.active_principals_since(1_000)?.is_empty());

        // Issue a session at t=1_000 with the default (30-day refresh) window.
        store.issue_session(
            &admin,
            1_000,
            super::DEFAULT_ACCESS_TTL,
            super::DEFAULT_REFRESH_TTL,
        )?;

        // Within the refresh window the principal is live even long after the
        // 1-hour access token would have lapsed.
        let one_day_later = 1_000 + 24 * 60 * 60;
        assert_eq!(
            store.active_principals_since(one_day_later)?,
            vec!["admin".to_owned()]
        );

        // Past the refresh expiry the session is no longer live.
        let refresh_expiry = 1_000 + i64::try_from(super::DEFAULT_REFRESH_TTL.as_secs())?;
        assert!(
            store
                .active_principals_since(refresh_expiry + 1)?
                .is_empty()
        );

        // A revoked session never counts as active, even inside its window.
        store.revoke_user_sessions(admin.user_id, one_day_later)?;
        assert!(store.active_principals_since(one_day_later)?.is_empty());
        Ok(())
    }

    #[test]
    fn latest_request_per_principal_reports_max_session_creation() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 1_000, "login")?;

        // No sessions → no principals reported (caller defaults them to 0).
        assert!(store.latest_request_per_principal()?.is_empty());

        // Two sessions: the newer creation time wins, even once it is revoked
        // (the aggregate ignores revocation, matching the Java query).
        store.issue_session(
            &admin,
            2_000,
            super::DEFAULT_ACCESS_TTL,
            super::DEFAULT_REFRESH_TTL,
        )?;
        store.issue_session(
            &admin,
            9_000,
            super::DEFAULT_ACCESS_TTL,
            super::DEFAULT_REFRESH_TTL,
        )?;
        store.revoke_user_sessions(admin.user_id, 10_000)?;
        assert_eq!(
            store.latest_request_per_principal()?,
            vec![("admin".to_owned(), 9_000)]
        );
        Ok(())
    }

    #[test]
    fn admin_roster_lifecycle_exposes_creation_and_setup_marker() -> TestResult {
        let store = SecurityStore::in_memory()?;
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin_id = store
            .list_users(0)?
            .into_iter()
            .find(|user| user.username == "admin")
            .map(|user| user.id)
            .ok_or("admin present")?;

        let lifecycle = store.admin_roster_lifecycle()?;
        let (_, created_at, initial_setup) = lifecycle
            .into_iter()
            .find(|(id, _, _)| *id == admin_id)
            .ok_or("admin lifecycle row")?;
        // A fresh admin has not completed initial setup (Java `isFirstLogin`).
        assert!(!initial_setup);
        // created_at is an ISO-8601 local date-time (no timezone/offset suffix).
        assert_eq!(created_at.len(), "2026-07-25T12:34:56".len());
        assert_eq!(created_at.as_bytes()[10], b'T');

        // Completing setup flips the marker the projection reads.
        store.complete_initial_setup(admin_id)?;
        let updated = store.admin_roster_lifecycle()?;
        let (_, _, setup_after) = updated
            .into_iter()
            .find(|(id, _, _)| *id == admin_id)
            .ok_or("admin lifecycle row after setup")?;
        assert!(setup_after);
        Ok(())
    }
}
