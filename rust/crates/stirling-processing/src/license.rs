//! Commercial license verification compatible with the Java Keygen boundary.
//!
//! Offline certificate and `key/` licenses are authenticated with the pinned
//! Ed25519 public key. Opaque standard keys are validated against Keygen and
//! may activate the current machine. Configuration intent alone never grants
//! a paid tier.

use std::{
    fs,
    net::ToSocketAddrs as _,
    sync::{Arc, Mutex, RwLock, mpsc},
    thread,
    time::Duration,
};

use base64::{
    Engine as _, alphabet,
    engine::{
        DecodePaddingMode,
        general_purpose::{GeneralPurpose, GeneralPurposeConfig},
    },
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use signature_v2::Verifier as _;
use sysinfo::{Networks, System};
use thiserror::Error;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::security_policy::LicenseTier;

const ACCOUNT_ID: &str = "e5430f69-e834-4ae4-befd-b602aae5f372";
const BASE_URL: &str = "https://api.keygen.sh/v1/accounts";
const PUBLIC_KEY: [u8; 32] = [
    0x9f, 0xbc, 0x0d, 0x78, 0x59, 0x3d, 0xcf, 0xcf, 0x03, 0xc9, 0x45, 0x14, 0x6e, 0xdd, 0x60, 0x08,
    0x3b, 0xf5, 0xfa, 0xe7, 0x7d, 0xbc, 0x08, 0xaa, 0xa3, 0x93, 0x5f, 0x03, 0xce, 0x94, 0xa5, 0x8d,
];
const CERT_PREFIX: &str = "-----BEGIN LICENSE FILE-----";
const CERT_SUFFIX: &str = "-----END LICENSE FILE-----";
const JWT_PREFIX: &str = "key/";
const JSON_API_MEDIA_TYPE: &str = "application/vnd.api+json";
const STANDARD_ATTEMPTS: usize = 5;
const LICENSE_REFRESH_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const JAVA_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// Resolved trusted configuration used by the license checker.
#[derive(Clone)]
pub struct LicenseConfig {
    pub enabled: bool,
    pub key: Zeroizing<String>,
    pub initial_max_users: i32,
}

/// Thread-safe live license configuration shared by administrator mutations
/// and the periodic verifier. Keeping this separate from [`LicenseState`]
/// preserves the distinction between untrusted configuration intent and a
/// verified entitlement result.
pub struct LicenseConfigState {
    config: RwLock<LicenseConfig>,
}

impl LicenseConfigState {
    #[must_use]
    pub fn new(config: LicenseConfig) -> Self {
        Self {
            config: RwLock::new(config),
        }
    }

    #[must_use]
    pub fn current(&self) -> LicenseConfig {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn replace(&self, config: LicenseConfig) {
        *self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = config;
    }
}

/// One verified license result. `max_users == 0` means unlimited for Server.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LicenseVerification {
    pub tier: LicenseTier,
    pub max_users: i32,
}

impl LicenseVerification {
    #[must_use]
    pub const fn running_pro_or_higher(self) -> bool {
        matches!(self.tier, LicenseTier::Server | LicenseTier::Enterprise)
    }

    #[must_use]
    pub const fn running_enterprise(self) -> bool {
        matches!(self.tier, LicenseTier::Enterprise)
    }

    #[must_use]
    pub const fn tier_name(self) -> &'static str {
        match self.tier {
            LicenseTier::Normal => "NORMAL",
            LicenseTier::Server => "SERVER",
            LicenseTier::Enterprise => "ENTERPRISE",
        }
    }
}

/// Thread-safe dynamic result used by status responses and periodic refresh.
/// Route entitlements deliberately retain their startup snapshot, matching the
/// Java endpoint aspects.
pub struct LicenseState {
    verification: RwLock<LicenseVerification>,
    listeners: Mutex<Vec<LicenseStateListener>>,
}

type LicenseStateListener = Arc<dyn Fn(LicenseVerification) + Send + Sync>;

impl LicenseState {
    #[must_use]
    pub fn new(verification: LicenseVerification) -> Self {
        Self {
            verification: RwLock::new(verification),
            listeners: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn current(&self) -> LicenseVerification {
        *self
            .verification
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn replace(&self, verification: LicenseVerification) {
        *self
            .verification
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = verification;
        let listeners = self
            .listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for listener in listeners {
            listener(verification);
        }
    }

    pub(crate) fn subscribe(&self, listener: impl Fn(LicenseVerification) + Send + Sync + 'static) {
        self.listeners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::new(listener));
    }

    /// Adds the Java dynamic license fields to `/api/v1/config/app-config`.
    pub fn apply_to_app_config(&self, config: &mut Value) {
        let current = self.current();
        let Some(config) = config.as_object_mut() else {
            return;
        };
        config.insert(
            "runningProOrHigher".to_owned(),
            Value::Bool(current.running_pro_or_higher()),
        );
        config.insert(
            "runningEE".to_owned(),
            Value::Bool(current.running_enterprise()),
        );
        config.insert(
            "license".to_owned(),
            Value::String(current.tier_name().to_owned()),
        );
    }
}

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("failed to construct the Keygen HTTP client: {0}")]
    HttpClient(String),
    #[error("license verification failed after {attempts} attempts: {last_error}")]
    OnlineVerification { attempts: usize, last_error: String },
}

#[derive(Clone)]
struct RetryPolicy {
    attempts: usize,
    delay_unit: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts: STANDARD_ATTEMPTS,
            delay_unit: Duration::from_secs(3),
        }
    }
}

#[derive(Clone)]
struct HttpRequest {
    method: Method,
    url: String,
    authorization: Option<Zeroizing<String>>,
    body: Option<Zeroizing<String>>,
}

struct HttpResponse {
    status: u16,
    body: String,
}

trait LicenseTransport: Send + Sync {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String>;
}

struct ReqwestLicenseTransport {
    commands: mpsc::Sender<TransportCommand>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

enum TransportCommand {
    Execute(HttpRequest, mpsc::SyncSender<Result<HttpResponse, String>>),
    Shutdown,
}

impl ReqwestLicenseTransport {
    fn new() -> Result<Self, LicenseError> {
        let (commands, command_receiver) = mpsc::channel();
        let (initialized, initialization_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("stirling-keygen-http".to_owned())
            .spawn(move || run_transport_worker(&command_receiver, &initialized))
            .map_err(|error| LicenseError::HttpClient(error.to_string()))?;
        match initialization_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                worker: Mutex::new(Some(worker)),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(LicenseError::HttpClient(error))
            }
            Err(error) => {
                let _ = worker.join();
                Err(LicenseError::HttpClient(error.to_string()))
            }
        }
    }
}

impl LicenseTransport for ReqwestLicenseTransport {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let (response, receiver) = mpsc::sync_channel(1);
        self.commands
            .send(TransportCommand::Execute(request, response))
            .map_err(|_| "Keygen HTTP worker is unavailable".to_owned())?;
        receiver
            .recv()
            .map_err(|_| "Keygen HTTP worker stopped before responding".to_owned())?
    }
}

impl Drop for ReqwestLicenseTransport {
    fn drop(&mut self) {
        let _ = self.commands.send(TransportCommand::Shutdown);
        if let Some(worker) = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = worker.join();
        }
    }
}

fn run_transport_worker(
    commands: &mpsc::Receiver<TransportCommand>,
    initialized: &mpsc::SyncSender<Result<(), String>>,
) {
    let client = match Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            let _ = initialized.send(Err(error.to_string()));
            return;
        }
    };
    if initialized.send(Ok(())).is_err() {
        return;
    }
    while let Ok(command) = commands.recv() {
        match command {
            TransportCommand::Execute(request, response) => {
                let _ = response.send(execute_reqwest_request(&client, request));
            }
            TransportCommand::Shutdown => return,
        }
    }
}

fn execute_reqwest_request(client: &Client, request: HttpRequest) -> Result<HttpResponse, String> {
    let mut builder = client
        .request(request.method, request.url)
        .header("Accept", JSON_API_MEDIA_TYPE)
        .header("Content-Type", JSON_API_MEDIA_TYPE);
    if let Some(authorization) = request.authorization.as_ref() {
        builder = builder.header("Authorization", authorization.as_str());
    }
    if let Some(body) = request.body.as_ref() {
        builder = builder.body(body.as_str().to_owned());
    }
    let response = builder.send().map_err(|error| error.to_string())?;
    let status = response.status().as_u16();
    let body = response.text().map_err(|error| error.to_string())?;
    Ok(HttpResponse { status, body })
}

/// Verifies offline and online commercial licenses without exposing the key to
/// request handlers.
#[derive(Clone)]
pub struct LicenseVerifier {
    verifying_key: VerifyingKey,
    transport: Arc<dyn LicenseTransport>,
    base_url: String,
    account_id: String,
    retry: RetryPolicy,
    fingerprint: Arc<dyn Fn() -> String + Send + Sync>,
}

impl LicenseVerifier {
    /// Constructs the production verifier with the pinned Stirling Keygen key.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared HTTP client cannot be built.
    pub fn production() -> Result<Self, LicenseError> {
        Ok(Self {
            verifying_key: VerifyingKey::from_bytes(&PUBLIC_KEY).map_err(|error| {
                LicenseError::OnlineVerification {
                    attempts: 0,
                    last_error: format!("invalid pinned Ed25519 key: {error}"),
                }
            })?,
            transport: Arc::new(ReqwestLicenseTransport::new()?),
            base_url: BASE_URL.to_owned(),
            account_id: ACCOUNT_ID.to_owned(),
            retry: RetryPolicy::default(),
            fingerprint: Arc::new(generate_machine_fingerprint),
        })
    }

    /// Resolves `file:` references and verifies the configured license.
    /// Offline errors and invalid online responses fail closed to Normal. Only
    /// exhausted online transport/parsing retries return an error.
    ///
    /// # Errors
    ///
    /// Returns [`LicenseError::OnlineVerification`] after all online attempts
    /// fail due to transport or response parsing errors.
    pub fn verify_config(
        &self,
        config: &LicenseConfig,
        prior_max_users: i32,
    ) -> Result<LicenseVerification, LicenseError> {
        if !config.enabled {
            return Ok(LicenseVerification {
                tier: LicenseTier::Normal,
                max_users: prior_max_users,
            });
        }
        let Some(key) = resolve_license_key(config.key.as_str()) else {
            return Ok(LicenseVerification {
                tier: LicenseTier::Normal,
                max_users: prior_max_users,
            });
        };
        self.verify_key(key.as_str(), prior_max_users)
    }

    fn verify_key(
        &self,
        key: &str,
        prior_max_users: i32,
    ) -> Result<LicenseVerification, LicenseError> {
        let mut context = LicenseContext::new(prior_max_users);
        let valid = if java_trim(key).starts_with(CERT_PREFIX) {
            info!("detected certificate-based commercial license");
            self.verify_certificate(key, &mut context)
        } else if java_trim(key).starts_with(JWT_PREFIX) {
            info!("detected signed key-style commercial license");
            self.verify_jwt(key, &mut context)
        } else {
            info!("detected standard online commercial license");
            return self.verify_standard(key, context);
        };
        Ok(context.verification(valid))
    }

    fn verify_certificate(&self, license: &str, context: &mut LicenseContext) -> bool {
        let encoded_outer = license
            .replace(CERT_PREFIX, "")
            .replace(CERT_SUFFIX, "")
            .replace("\r\n", "")
            .replace('\n', "");
        let Ok(outer_bytes) = decode_standard_base64(&encoded_outer) else {
            return false;
        };
        let outer_text = String::from_utf8_lossy(&outer_bytes);
        let Ok(outer) = serde_json::from_str::<Value>(&outer_text) else {
            return false;
        };
        let encrypted_data = text_at(&outer, &["enc"]).unwrap_or_default();
        let signature = text_at(&outer, &["sig"]).unwrap_or_default();
        if text_at(&outer, &["alg"]).as_deref() != Some("base64+ed25519") {
            return false;
        }
        if !self.verify_basic_signature(format!("license/{encrypted_data}").as_bytes(), &signature)
        {
            return false;
        }
        let Ok(payload) = decode_standard_base64(&encrypted_data) else {
            return false;
        };
        let payload_text = String::from_utf8_lossy(&payload);
        let Ok(payload) = serde_json::from_str::<Value>(&payload_text) else {
            return false;
        };
        process_certificate_payload(&payload, context, Utc::now())
    }

    fn verify_jwt(&self, license: &str, context: &mut LicenseContext) -> bool {
        let Some(license_data) = license.get(JWT_PREFIX.len()..) else {
            return false;
        };
        let Some((payload, signature)) = license_data.split_once('.') else {
            return false;
        };
        if !self.verify_url_signature(format!("key/{payload}").as_bytes(), signature) {
            return false;
        }
        let Ok(payload) = decode_url_compatible_base64(payload) else {
            return false;
        };
        let payload_text = String::from_utf8_lossy(&payload);
        let Ok(payload) = serde_json::from_str::<Value>(&payload_text) else {
            return false;
        };
        process_jwt_payload(&payload, context, Utc::now())
    }

    fn verify_basic_signature(&self, message: &[u8], encoded_signature: &str) -> bool {
        let Ok(signature) = decode_standard_base64(encoded_signature) else {
            return false;
        };
        self.verify_signature_bytes(message, &signature)
    }

    fn verify_url_signature(&self, message: &[u8], encoded_signature: &str) -> bool {
        let Ok(signature) = decode_url_compatible_base64(encoded_signature) else {
            return false;
        };
        self.verify_signature_bytes(message, &signature)
    }

    fn verify_signature_bytes(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = Signature::from_slice(signature) else {
            return false;
        };
        self.verifying_key.verify(message, &signature).is_ok()
    }

    fn verify_standard(
        &self,
        key: &str,
        mut context: LicenseContext,
    ) -> Result<LicenseVerification, LicenseError> {
        let fingerprint = (self.fingerprint)();
        let mut last_error = "unknown error".to_owned();
        for attempt in 1..=self.retry.attempts {
            match self.verify_standard_once(key, &fingerprint, &mut context) {
                Ok(valid) => return Ok(context.verification(valid)),
                Err(error) => {
                    last_error = error;
                    warn!(
                        attempt,
                        attempts = self.retry.attempts,
                        "online license check failed"
                    );
                    if attempt < self.retry.attempts {
                        let multiplier = u32::try_from(attempt).unwrap_or(u32::MAX);
                        thread::sleep(self.retry.delay_unit.saturating_mul(multiplier));
                    }
                }
            }
        }
        Err(LicenseError::OnlineVerification {
            attempts: self.retry.attempts,
            last_error,
        })
    }

    fn verify_standard_once(
        &self,
        key: &str,
        fingerprint: &str,
        context: &mut LicenseContext,
    ) -> Result<bool, String> {
        let mut response = self.validate_license(key, fingerprint, context)?;
        let mut valid = bool_at(&response, &["meta", "valid"], false);
        if !valid {
            let code = text_at(&response, &["meta", "code"]).unwrap_or_default();
            if matches!(
                code.as_str(),
                "NO_MACHINE" | "NO_MACHINES" | "FINGERPRINT_SCOPE_MISMATCH"
            ) {
                let license_id = text_at(&response, &["data", "id"]).unwrap_or_default();
                if self.activate_machine(key, &license_id, fingerprint, context)? {
                    response = self.validate_license(key, fingerprint, context)?;
                    valid = bool_at(&response, &["meta", "valid"], false);
                }
            }
        }
        Ok(valid)
    }

    fn validate_license(
        &self,
        key: &str,
        fingerprint: &str,
        context: &mut LicenseContext,
    ) -> Result<Value, String> {
        let body = Zeroizing::new(
            serde_json::to_string(&json!({
                "meta": {
                    "key": key,
                    "scope": { "fingerprint": fingerprint }
                }
            }))
            .map_err(|error| error.to_string())?,
        );
        let response = self.transport.execute(HttpRequest {
            method: Method::POST,
            url: format!(
                "{}/{}/licenses/actions/validate-key",
                self.base_url, self.account_id
            ),
            authorization: None,
            body: Some(body),
        })?;
        let value = serde_json::from_str::<Value>(&response.body)
            .map_err(|error| format!("invalid Keygen validation response: {error}"))?;
        if response.status == 200 {
            update_online_context(&value, context);
        }
        Ok(value)
    }

    fn activate_machine(
        &self,
        key: &str,
        license_id: &str,
        fingerprint: &str,
        context: &LicenseContext,
    ) -> Result<bool, String> {
        if context.floating
            && let Some(machines) = self.fetch_machines(key, license_id)?
        {
            let data = machines
                .get("data")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if data.iter().any(|machine| {
                text_at(machine, &["attributes", "fingerprint"]).as_deref() == Some(fingerprint)
            }) {
                return Ok(true);
            }
            let current_machines = i32::try_from(data.len()).unwrap_or(i32::MAX);
            if current_machines >= context.max_machines
                && let Some(machine_id) = oldest_machine_id(data)
                && !self.deregister_machine(key, &machine_id)
            {
                return Ok(false);
            }
        }

        let hostname = System::host_name().unwrap_or_else(|| "Unknown".to_owned());
        let platform = java_style_platform_name();
        let body = Zeroizing::new(
            serde_json::to_string(&json!({
                "data": {
                    "type": "machines",
                    "attributes": {
                        "fingerprint": fingerprint,
                        "platform": platform,
                        "name": hostname
                    },
                    "relationships": {
                        "license": { "data": { "type": "licenses", "id": license_id } }
                    }
                }
            }))
            .map_err(|error| error.to_string())?,
        );
        let response = self.transport.execute(HttpRequest {
            method: Method::POST,
            url: format!("{}/{}/machines", self.base_url, self.account_id),
            authorization: Some(Zeroizing::new(format!("License {key}"))),
            body: Some(body),
        })?;
        Ok(response.status == 201)
    }

    fn fetch_machines(&self, key: &str, license_id: &str) -> Result<Option<Value>, String> {
        let response = self.transport.execute(HttpRequest {
            method: Method::GET,
            url: format!(
                "{}/{}/licenses/{license_id}/machines",
                self.base_url, self.account_id
            ),
            authorization: Some(Zeroizing::new(format!("License {key}"))),
            body: None,
        })?;
        if response.status != 200 {
            return Ok(None);
        }
        serde_json::from_str(&response.body)
            .map(Some)
            .map_err(|error| format!("invalid Keygen machines response: {error}"))
    }

    fn deregister_machine(&self, key: &str, machine_id: &str) -> bool {
        self.transport
            .execute(HttpRequest {
                method: Method::DELETE,
                url: format!(
                    "{}/{}/machines/{machine_id}",
                    self.base_url, self.account_id
                ),
                authorization: Some(Zeroizing::new(format!("License {key}"))),
                body: None,
            })
            .is_ok_and(|response| response.status == 204)
    }
}

/// Periodic checker that updates dynamic status but preserves the last result
/// when an online refresh exhausts all retries.
#[derive(Clone)]
pub struct LicenseRefreshRuntime {
    verifier: LicenseVerifier,
    config: Arc<LicenseConfigState>,
    state: Arc<LicenseState>,
}

impl LicenseRefreshRuntime {
    #[must_use]
    pub fn new(
        verifier: LicenseVerifier,
        config: Arc<LicenseConfigState>,
        state: Arc<LicenseState>,
    ) -> Self {
        Self {
            verifier,
            config,
            state,
        }
    }

    pub async fn run_forever(self) {
        loop {
            tokio::time::sleep(LICENSE_REFRESH_INTERVAL).await;
            self.refresh_once().await;
        }
    }

    async fn refresh_once(&self) {
        let verifier = self.verifier.clone();
        let config = self.config.current();
        let prior = self.state.current().max_users;
        match tokio::task::spawn_blocking(move || verifier.verify_config(&config, prior)).await {
            Ok(Ok(verification)) => self.state.replace(verification),
            Ok(Err(error)) => {
                warn!(%error, "periodic license check failed; retaining prior status");
            }
            Err(error) => warn!(%error, "periodic license task failed; retaining prior status"),
        }
    }
}

#[derive(Clone, Copy)]
struct LicenseContext {
    floating: bool,
    max_machines: i32,
    enterprise: bool,
    max_users: i32,
}

impl LicenseContext {
    const fn new(max_users: i32) -> Self {
        Self {
            floating: false,
            max_machines: 1,
            enterprise: false,
            max_users,
        }
    }

    const fn verification(self, valid: bool) -> LicenseVerification {
        let tier = if !valid {
            LicenseTier::Normal
        } else if self.enterprise {
            LicenseTier::Enterprise
        } else {
            LicenseTier::Server
        };
        LicenseVerification {
            tier,
            max_users: self.max_users,
        }
    }
}

fn resolve_license_key(configured: &str) -> Option<Zeroizing<String>> {
    if java_trim(configured).is_empty() {
        warn!("commercial license key is not specified");
        return None;
    }
    let Some(path) = configured.strip_prefix("file:") else {
        return Some(Zeroizing::new(configured.to_owned()));
    };
    match fs::read_to_string(path) {
        Ok(key) => Some(Zeroizing::new(key)),
        Err(error) => {
            warn!(%error, "failed to read commercial license file");
            None
        }
    }
}

fn process_certificate_payload(
    payload: &Value,
    context: &mut LicenseContext,
    now: DateTime<Utc>,
) -> bool {
    if let Some(meta) = payload.get("meta").and_then(Value::as_object) {
        let issued = meta.get("issued").and_then(non_null_text);
        let expiry = meta.get("expiry").and_then(non_null_text);
        if let (Some(issued), Some(expiry)) = (issued, expiry) {
            let (Some(issued), Some(expiry)) =
                (parse_java_instant(&issued), parse_java_instant(&expiry))
            else {
                return false;
            };
            if issued > now || expiry < now {
                return false;
            }
        }
    }
    let Some(data) = payload.get("data").and_then(Value::as_object) else {
        return false;
    };
    if let Some(attributes) = data.get("attributes").and_then(Value::as_object) {
        context.floating = attributes
            .get("floating")
            .is_some_and(|value| node_bool(value, false));
        context.max_machines = attributes
            .get("maxMachines")
            .map_or(1, |value| node_i32(value, 1));
        if let Some(metadata) = attributes.get("metadata").and_then(Value::as_object) {
            context.enterprise = metadata
                .get("isEnterprise")
                .is_some_and(|value| node_bool(value, false));
            context.max_users = metadata.get("users").map_or_else(
                || i32::from(context.enterprise),
                |value| node_i32(value, i32::from(context.enterprise)),
            );
        }
        if let Some(status) = attributes.get("status").and_then(non_null_text)
            && !matches!(status.as_str(), "ACTIVE" | "EXPIRING")
        {
            return false;
        }
    }
    true
}

fn process_jwt_payload(payload: &Value, context: &mut LicenseContext, now: DateTime<Utc>) -> bool {
    let license = payload
        .get("license")
        .filter(|value| value.is_object())
        .or_else(|| payload.get("id").and_then(non_null_text).map(|_| payload));
    let Some(license) = license else {
        return false;
    };
    context.floating = bool_at(license, &["floating"], false);
    context.max_machines = i32_at(license, &["maxMachines"], 1);
    if let Some(expiry) = license.get("expiry").and_then(non_null_text)
        && expiry != "null"
    {
        let Some(expiry) = parse_java_instant(&expiry) else {
            return false;
        };
        if now > expiry {
            return false;
        }
    }
    if let Some(policy) = payload.get("policy").and_then(Value::as_object) {
        if policy
            .get("floating")
            .is_some_and(|value| node_bool(value, false))
        {
            context.floating = true;
            context.max_machines = policy
                .get("maxMachines")
                .map_or(1, |value| node_i32(value, 1));
        }
        context.enterprise = policy
            .get("isEnterprise")
            .is_some_and(|value| node_bool(value, false));
        let mut users = policy.get("users").map_or(-1, |value| node_i32(value, -1));
        if users == -1 {
            if let Some(metadata) = policy.get("metadata").and_then(Value::as_object) {
                context.enterprise = metadata
                    .get("isEnterprise")
                    .map_or(context.enterprise, |value| {
                        node_bool(value, context.enterprise)
                    });
                users = metadata.get("users").map_or_else(
                    || i32::from(context.enterprise),
                    |value| node_i32(value, i32::from(context.enterprise)),
                );
            } else {
                users = i32::from(context.enterprise);
            }
        }
        context.max_users = users;
    }
    true
}

fn update_online_context(response: &Value, context: &mut LicenseContext) {
    if let Some(attributes) = value_at(response, &["data", "attributes"]) {
        context.floating = bool_at(attributes, &["floating"], false);
        context.max_machines = i32_at(attributes, &["maxMachines"], 1);
    }
    if let Some(policy) = response
        .get("included")
        .and_then(Value::as_array)
        .and_then(|included| {
            included
                .iter()
                .find(|entry| text_at(entry, &["type"]).as_deref() == Some("policies"))
        })
        && bool_at(policy, &["attributes", "floating"], false)
    {
        context.floating = true;
        context.max_machines = i32_at(policy, &["attributes", "maxMachines"], 1);
    }
    context.enterprise = bool_at(
        response,
        &["data", "attributes", "metadata", "isEnterprise"],
        false,
    );
    context.max_users = i32_at(
        response,
        &["data", "attributes", "metadata", "users"],
        i32::from(context.enterprise),
    );
}

fn oldest_machine_id(machines: &[Value]) -> Option<String> {
    let oldest = machines
        .iter()
        .filter_map(|machine| {
            let id = text_at(machine, &["id"])?;
            let created = text_at(machine, &["attributes", "created"])?;
            let created = parse_java_instant(&created)?;
            Some((created, id))
        })
        .min_by_key(|(created, _)| *created)
        .map(|(_, id)| id);
    oldest.or_else(|| {
        machines
            .first()
            .and_then(|machine| text_at(machine, &["id"]))
    })
}

fn decode_standard_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    JAVA_BASE64.decode(value)
}

fn decode_url_compatible_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    decode_standard_base64(&value.replace('-', "+").replace('_', "/"))
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |current, key| current.get(key))
}

fn text_at(value: &Value, path: &[&str]) -> Option<String> {
    value_at(value, path).and_then(non_null_text)
}

fn non_null_text(value: &Value) -> Option<String> {
    match value {
        Value::Null | Value::Array(_) | Value::Object(_) => None,
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
    }
}

fn bool_at(value: &Value, path: &[&str], default: bool) -> bool {
    value_at(value, path).map_or(default, |value| node_bool(value, default))
}

fn node_bool(value: &Value, default: bool) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Number(value) if value.as_i64().is_some_and(|value| value != 0) => true,
        Value::Number(value) if value.as_u64().is_some_and(|value| value != 0) => true,
        Value::Number(value) if value.as_i64() == Some(0) || value.as_u64() == Some(0) => false,
        Value::String(value) if value == "true" => true,
        Value::String(value) if value == "false" => false,
        _ => default,
    }
}

fn i32_at(value: &Value, path: &[&str], default: i32) -> i32 {
    value_at(value, path).map_or(default, |value| node_i32(value, default))
}

fn node_i32(value: &Value, default: i32) -> i32 {
    match value {
        Value::Number(value) => value.as_i64().map_or_else(
            || {
                value.as_f64().map_or(default, |value| {
                    let value = value.trunc();
                    if value >= f64::from(i32::MIN) && value <= f64::from(i32::MAX) {
                        value.to_string().parse().unwrap_or(default)
                    } else {
                        default
                    }
                })
            },
            |value| i32::try_from(value).unwrap_or(default),
        ),
        Value::String(value) => value.trim().parse().unwrap_or(default),
        _ => default,
    }
}

fn java_style_platform_name() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Mac OS X",
        "windows" => "Windows",
        other => other,
    }
}

pub(crate) fn generate_machine_fingerprint() -> String {
    let Some(hostname) = System::host_name() else {
        return "GenericID".to_owned();
    };
    let Ok(primary_addresses) = (hostname.as_str(), 0).to_socket_addrs() else {
        return "GenericID".to_owned();
    };
    let primary_addresses = primary_addresses
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    let networks = Networks::new_with_refreshed_list();
    let primary_mac = networks
        .iter()
        .find(|(_, network)| {
            network
                .ip_networks()
                .iter()
                .any(|network| primary_addresses.contains(&network.addr))
        })
        .map(|(_, network)| network.mac_address())
        .filter(|mac| !mac.is_unspecified());
    let fallback_mac = networks
        .iter()
        .filter(|(_, network)| !network.mac_address().is_unspecified())
        .filter(|(_, network)| {
            network
                .ip_networks()
                .iter()
                .any(|network| !network.addr.is_loopback())
        })
        .min_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, network)| network.mac_address());
    let source = primary_mac
        .or(fallback_mac)
        .map_or_else(|| hostname, |mac| data_encoding::HEXUPPER.encode(&mac.0));
    let digest = Sha256::digest(source.as_bytes());
    data_encoding::HEXLOWER.encode(&digest)
}

fn java_trim(value: &str) -> &str {
    value.trim_matches(|character| u32::from(character) <= 0x20)
}

fn parse_java_instant(value: &str) -> Option<DateTime<Utc>> {
    let time_separator = value.find(['T', 't'])?;
    let time = value.get(time_separator + 1..)?;
    let bytes = time.as_bytes();
    if bytes.len() < 9
        || bytes.get(2) != Some(&b':')
        || bytes.get(5) != Some(&b':')
        || !bytes.get(..2)?.iter().all(u8::is_ascii_digit)
        || !bytes.get(3..5)?.iter().all(u8::is_ascii_digit)
        || !bytes.get(6..8)?.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let suffix = time.get(8..)?;
    let zone = if let Some(fraction) = suffix.strip_prefix('.') {
        let digit_count = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if !(1..=9).contains(&digit_count) {
            return None;
        }
        fraction.get(digit_count..)?
    } else {
        suffix
    };
    let valid_zone = matches!(zone, "Z" | "z")
        || (zone.len() == 6
            && matches!(zone.as_bytes().first(), Some(b'+' | b'-'))
            && zone.as_bytes().get(3) == Some(&b':')
            && zone.as_bytes().get(1..3)?.iter().all(u8::is_ascii_digit)
            && zone.as_bytes().get(4..6)?.iter().all(u8::is_ascii_digit));
    if !valid_zone {
        return None;
    }
    let normalized = value.replace('t', "T").replace('z', "Z");
    DateTime::parse_from_rfc3339(&normalized)
        .ok()
        .map(|instant| instant.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use signature_v2::Signer as _;
    use tempfile::tempdir;

    use super::*;

    const TEST_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedRequest {
        method: Method,
        url: String,
        authorization: Option<String>,
        body: Option<String>,
    }

    struct ScriptedTransport {
        responses: Mutex<VecDeque<Result<HttpResponse, String>>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<Result<HttpResponse, String>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl LicenseTransport for ScriptedTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(RecordedRequest {
                    method: request.method,
                    url: request.url,
                    authorization: request
                        .authorization
                        .as_ref()
                        .map(|value| value.as_str().to_owned()),
                    body: request.body.as_ref().map(|value| value.as_str().to_owned()),
                });
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or_else(|| Err("scripted response queue exhausted".to_owned()))
        }
    }

    fn response(status: u16, body: &Value) -> HttpResponse {
        HttpResponse {
            status,
            body: body.to_string(),
        }
    }

    fn verifier_with_transport(
        signing_key: &SigningKey,
        transport: Arc<dyn LicenseTransport>,
    ) -> LicenseVerifier {
        LicenseVerifier {
            verifying_key: signing_key.verifying_key(),
            transport,
            base_url: "https://keygen.example.test/v1/accounts".to_owned(),
            account_id: "account-test".to_owned(),
            retry: RetryPolicy {
                attempts: STANDARD_ATTEMPTS,
                delay_unit: Duration::ZERO,
            },
            fingerprint: Arc::new(|| "fingerprint-test".to_owned()),
        }
    }

    fn offline_verifier(signing_key: &SigningKey) -> LicenseVerifier {
        verifier_with_transport(signing_key, ScriptedTransport::new(Vec::new()))
    }

    fn signed_certificate(signing_key: &SigningKey, payload: &Value) -> String {
        let encrypted_data = JAVA_BASE64.encode(payload.to_string());
        let signature = signing_key.sign(format!("license/{encrypted_data}").as_bytes());
        let envelope = json!({
            "enc": encrypted_data,
            "sig": JAVA_BASE64.encode(signature.to_bytes()),
            "alg": "base64+ed25519"
        });
        format!(
            "{CERT_PREFIX}\n{}\n{CERT_SUFFIX}",
            JAVA_BASE64.encode(envelope.to_string())
        )
    }

    fn signed_jwt(signing_key: &SigningKey, payload: &Value) -> String {
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload.to_string());
        let signature = signing_key.sign(format!("key/{encoded_payload}").as_bytes());
        format!(
            "key/{encoded_payload}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn validation(valid: bool, enterprise: bool, users: i32) -> Value {
        json!({
            "meta": { "valid": valid },
            "data": {
                "id": "license-1",
                "attributes": {
                    "floating": false,
                    "maxMachines": 1,
                    "metadata": { "isEnterprise": enterprise, "users": users }
                }
            }
        })
    }

    #[test]
    fn premium_disabled_short_circuits_without_transport() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let transport = ScriptedTransport::new(Vec::new());
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        let result = verifier.verify_config(
            &LicenseConfig {
                enabled: false,
                key: Zeroizing::new("standard-key".to_owned()),
                initial_max_users: 7,
            },
            7,
        )?;
        assert_eq!(
            result,
            LicenseVerification {
                tier: LicenseTier::Normal,
                max_users: 7
            }
        );
        assert!(transport.requests().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn production_transport_can_be_dropped_inside_an_async_runtime()
    -> Result<(), LicenseError> {
        let verifier = LicenseVerifier::production()?;
        drop(verifier);
        tokio::task::yield_now().await;
        Ok(())
    }

    #[tokio::test]
    async fn periodic_refresh_reads_the_latest_administrator_configuration()
    -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let transport =
            ScriptedTransport::new(vec![Ok(response(200, &validation(true, false, 0)))]);
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        let config = Arc::new(LicenseConfigState::new(LicenseConfig {
            enabled: false,
            key: Zeroizing::new("startup-key".to_owned()),
            initial_max_users: 4,
        }));
        let state = Arc::new(LicenseState::new(LicenseVerification {
            tier: LicenseTier::Normal,
            max_users: 4,
        }));
        let refresh = LicenseRefreshRuntime::new(verifier, Arc::clone(&config), Arc::clone(&state));

        config.replace(LicenseConfig {
            enabled: true,
            key: Zeroizing::new("administrator-key".to_owned()),
            initial_max_users: 4,
        });
        refresh.refresh_once().await;

        assert_eq!(
            state.current(),
            LicenseVerification {
                tier: LicenseTier::Server,
                max_users: 0,
            }
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        let body: Value = serde_json::from_str(requests[0].body.as_deref().unwrap_or_default())
            .unwrap_or(Value::Null);
        assert_eq!(body["meta"]["key"], "administrator-key");
        Ok(())
    }

    #[test]
    fn signed_certificate_resolves_server_and_enterprise_tiers() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifier = offline_verifier(&signing_key);
        let server = signed_certificate(
            &signing_key,
            &json!({"data":{"attributes":{"status":"ACTIVE","metadata":{"isEnterprise":false,"users":0}}}}),
        );
        let enterprise = signed_certificate(
            &signing_key,
            &json!({"data":{"attributes":{"status":"EXPIRING","metadata":{"isEnterprise":true,"users":25}}}}),
        );
        assert_eq!(
            verifier.verify_key(&server, 9)?,
            LicenseVerification {
                tier: LicenseTier::Server,
                max_users: 0
            }
        );
        assert_eq!(
            verifier.verify_key(&enterprise, 9)?,
            LicenseVerification {
                tier: LicenseTier::Enterprise,
                max_users: 25
            }
        );
        Ok(())
    }

    #[test]
    fn certificate_preserves_java_date_status_and_stale_user_semantics() -> Result<(), LicenseError>
    {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifier = offline_verifier(&signing_key);
        let inactive = signed_certificate(
            &signing_key,
            &json!({
                "meta":{"issued":"2020-01-01T00:00:00Z","expiry":"2099-01-01T00:00:00Z"},
                "data":{"attributes":{"status":"SUSPENDED","metadata":{"isEnterprise":true,"users":18}}}
            }),
        );
        assert_eq!(
            verifier.verify_key(&inactive, 4)?,
            LicenseVerification {
                tier: LicenseTier::Normal,
                max_users: 18
            }
        );
        let no_attributes = signed_certificate(&signing_key, &json!({"data":{}}));
        assert_eq!(
            verifier.verify_key(&no_attributes, 4)?,
            LicenseVerification {
                tier: LicenseTier::Server,
                max_users: 4
            }
        );
        Ok(())
    }

    #[test]
    fn certificate_detection_uses_java_trim_but_parser_uses_original_input()
    -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifier = offline_verifier(&signing_key);
        let certificate = signed_certificate(&signing_key, &json!({"data":{}}));
        assert_eq!(
            verifier.verify_key(&format!("\n{certificate}\n"), 0)?.tier,
            LicenseTier::Server
        );
        assert_eq!(
            verifier.verify_key(&format!(" {certificate}"), 0)?.tier,
            LicenseTier::Normal
        );
        Ok(())
    }

    #[test]
    fn signed_key_payload_supports_policy_fallback_and_stale_users() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifier = offline_verifier(&signing_key);
        let enterprise = signed_jwt(
            &signing_key,
            &json!({
                "license":{"id":"license-1","expiry":"2099-01-01T00:00:00Z"},
                "account":{"id":"different-account"},
                "policy":{"floating":true,"maxMachines":3,"metadata":{"isEnterprise":true,"users":12}}
            }),
        );
        assert_eq!(
            verifier.verify_key(&enterprise, 5)?,
            LicenseVerification {
                tier: LicenseTier::Enterprise,
                max_users: 12
            }
        );
        let no_policy = signed_jwt(&signing_key, &json!({"id":"license-2"}));
        assert_eq!(
            verifier.verify_key(&no_policy, 5)?,
            LicenseVerification {
                tier: LicenseTier::Server,
                max_users: 5
            }
        );
        Ok(())
    }

    #[test]
    fn forged_offline_signature_fails_closed() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifier = LicenseVerifier::production()?;
        let certificate = signed_certificate(&signing_key, &json!({"data":{}}));
        assert_eq!(
            verifier.verify_key(&certificate, 3)?,
            LicenseVerification {
                tier: LicenseTier::Normal,
                max_users: 3
            }
        );
        Ok(())
    }

    #[test]
    fn file_reference_is_loaded_without_trimming() -> Result<(), Box<dyn std::error::Error>> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let verifier = offline_verifier(&signing_key);
        let directory = tempdir()?;
        let path = directory.path().join("license.lic");
        fs::write(&path, signed_certificate(&signing_key, &json!({"data":{}})))?;
        let result = verifier.verify_config(
            &LicenseConfig {
                enabled: true,
                key: Zeroizing::new(format!("file:{}", path.display())),
                initial_max_users: 0,
            },
            0,
        )?;
        assert_eq!(result.tier, LicenseTier::Server);
        Ok(())
    }

    #[test]
    fn java_base64_and_scalar_coercions_are_preserved() {
        assert_eq!(decode_standard_base64("YQ").ok(), Some(b"a".to_vec()));
        assert!(decode_standard_base64("Y Q==").is_err());
        assert!(node_bool(&json!(2), false));
        assert!(!node_bool(&json!(0), true));
        assert!(!node_bool(&json!("TRUE"), false));
        assert_eq!(node_i32(&json!(2.9), -1), 2);
        assert_eq!(node_i32(&json!("+01"), -1), 1);
        assert_eq!(node_i32(&json!(2_147_483_648_i64), -1), -1);
    }

    #[test]
    fn java_instant_requires_seconds_and_at_most_nine_fraction_digits() {
        assert!(parse_java_instant("2026-01-01T01:02:03Z").is_some());
        assert!(parse_java_instant("2026-01-01t01:02:03.123456789z").is_some());
        assert!(parse_java_instant("2026-01-01T01:02:03+02:30").is_some());
        assert!(parse_java_instant("2026-01-01 01:02:03Z").is_none());
        assert!(parse_java_instant("2026-01-01T01:02Z").is_none());
        assert!(parse_java_instant("2026-01-01T01:02:03.1234567890Z").is_none());
    }

    #[test]
    fn valid_standard_key_posts_exact_validation_contract() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let transport =
            ScriptedTransport::new(vec![Ok(response(200, &validation(true, true, 20)))]);
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        assert_eq!(
            verifier.verify_key("standard-secret", 0)?,
            LicenseVerification {
                tier: LicenseTier::Enterprise,
                max_users: 20
            }
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::POST);
        assert_eq!(
            requests[0].url,
            "https://keygen.example.test/v1/accounts/account-test/licenses/actions/validate-key"
        );
        assert_eq!(requests[0].authorization, None);
        let body: Value = serde_json::from_str(requests[0].body.as_deref().unwrap_or_default())
            .unwrap_or(Value::Null);
        assert_eq!(body["meta"]["key"], "standard-secret");
        assert_eq!(body["meta"]["scope"]["fingerprint"], "fingerprint-test");
        Ok(())
    }

    #[test]
    fn machine_scope_failure_activates_and_revalidates() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let invalid = json!({
            "meta":{"valid":false,"code":"NO_MACHINE"},
            "data":{"id":"license-1","attributes":{"metadata":{"isEnterprise":false,"users":0}}}
        });
        let transport = ScriptedTransport::new(vec![
            Ok(response(200, &invalid)),
            Ok(response(201, &json!({}))),
            Ok(response(200, &validation(true, false, 0))),
        ]);
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        assert_eq!(
            verifier.verify_key("standard-secret", 0)?.tier,
            LicenseTier::Server
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[1].url.ends_with("/account-test/machines"));
        assert_eq!(
            requests[1].authorization.as_deref(),
            Some("License standard-secret")
        );
        Ok(())
    }

    #[test]
    fn floating_activation_removes_oldest_machine_first() -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let invalid = json!({
            "meta":{"valid":false,"code":"NO_MACHINES"},
            "data":{"id":"license-1","attributes":{"floating":true,"maxMachines":1,"metadata":{}}}
        });
        let machines = json!({"data":[
            {"id":"newer","attributes":{"fingerprint":"other-1","created":"2025-01-01T00:00:00Z"}},
            {"id":"oldest","attributes":{"fingerprint":"other-2","created":"2024-01-01T00:00:00Z"}}
        ]});
        let transport = ScriptedTransport::new(vec![
            Ok(response(200, &invalid)),
            Ok(response(200, &machines)),
            Ok(response(204, &Value::Null)),
            Ok(response(201, &json!({}))),
            Ok(response(200, &validation(true, false, 0))),
        ]);
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        assert_eq!(
            verifier.verify_key("standard-secret", 0)?.tier,
            LicenseTier::Server
        );
        let requests = transport.requests();
        assert_eq!(requests.len(), 5);
        assert!(requests[2].url.ends_with("/machines/oldest"));
        assert_eq!(requests[2].method, Method::DELETE);
        Ok(())
    }

    #[test]
    fn online_transport_errors_retry_five_times_without_exposing_key() {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let transport = ScriptedTransport::new(
            (0..STANDARD_ATTEMPTS)
                .map(|_| Err("network unavailable".to_owned()))
                .collect(),
        );
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        let result = verifier.verify_key("standard-secret", 0);
        assert!(matches!(
            result,
            Err(LicenseError::OnlineVerification {
                attempts: STANDARD_ATTEMPTS,
                ..
            })
        ));
        assert_eq!(transport.requests().len(), STANDARD_ATTEMPTS);
        let error = result
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(!error.contains("standard-secret"));
    }

    #[test]
    fn non_success_validation_json_is_not_retried_and_can_still_be_valid()
    -> Result<(), LicenseError> {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let transport = ScriptedTransport::new(vec![Ok(response(
            422,
            &json!({"meta":{"valid":true},"data":{"id":"license-1"}}),
        ))]);
        let verifier = verifier_with_transport(&signing_key, transport.clone());
        assert_eq!(
            verifier.verify_key("standard-secret", 8)?.tier,
            LicenseTier::Server
        );
        assert_eq!(transport.requests().len(), 1);
        Ok(())
    }

    #[test]
    fn live_state_overrides_default_app_config_license_fields() {
        let state = LicenseState::new(LicenseVerification {
            tier: LicenseTier::Enterprise,
            max_users: 30,
        });
        let mut config = json!({
            "runningProOrHigher": false,
            "runningEE": false,
            "license": "NORMAL"
        });
        state.apply_to_app_config(&mut config);
        assert_eq!(config["runningProOrHigher"], true);
        assert_eq!(config["runningEE"], true);
        assert_eq!(config["license"], "ENTERPRISE");
    }
}
