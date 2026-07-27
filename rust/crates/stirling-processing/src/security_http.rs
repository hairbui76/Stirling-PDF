//! Reviewed HTTP boundary for the local secured-mode foundation.
//!
//! This router is intentionally opt-in: the production binary continues to
//! refuse secured-mode startup until MFA, external identity, invitations,
//! tenant resources, and the remaining review gates are complete.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::{Body, HttpBody as _, to_bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Multipart, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use futures_util::StreamExt as _;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::task;
use zeroize::Zeroizing;

use crate::{
    license::LicenseError,
    oidc_discovery::OidcDiscoveryCache,
    oidc_id_token::OidcJwksCache,
    oidc_login::{
        OidcLoginError, OidcLoginProviderConfig, OidcLoginStateStore, complete_oidc_login,
        initiate_oidc_login,
    },
    runtime_config::RuntimeConfig,
    security::{
        AuthContext, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL, SecurityAuditContext,
        SecurityAuditFileCapture, SecurityError, SecurityHttpAuditRecord, SecurityStore,
        SessionTokens,
    },
    security_crypto::{ProtectedSecretCipher, totp_auth_uri},
    security_jwt::{SupabaseJwtError, SupabaseJwtVerifier},
    security_policy::{
        AuthorizationDenial, EndpointEntitlement, EndpointPolicy, LicenseTier, authorize,
        authorize_entitlement, endpoint_entitlement, endpoint_policy,
    },
    smtp_mail::{SmtpMailService, is_valid_recipient},
};

const MAX_AUTH_BODY_BYTES: usize = 8 * 1024;
const REFRESH_GRACE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
const AUTOMATION_HEADER: HeaderName = HeaderName::from_static("x-stirling-automation");
/// Name of the cookie carrying the OIDC login-CSRF browser binding. Set at
/// `/authorize`, required back at `/callback` (see [`oidc_authorize`]).
const OIDC_CSRF_COOKIE: &str = "spdf_oidc_csrf";
/// Path the OIDC browser-binding cookie is scoped to: the OIDC login routes
/// only, so it is never attached to unrelated requests.
const OIDC_COOKIE_PATH: &str = "/api/v1/auth/oidc";
/// Name of the SPA's post-login redirect-path cookie (Java parity:
/// `TauriOAuthUtils.SPA_REDIRECT_COOKIE`). The SPA writes the path it wants to
/// land on after SSO; the OIDC callback honors it once and clears it.
const SPA_REDIRECT_COOKIE: &str = "stirling_redirect_path";
/// Default SPA landing path for the OIDC browser callback (Java parity:
/// `TauriOAuthUtils.DEFAULT_CALLBACK_PATH`) — the route `AuthCallback.tsx`
/// serves, which reads `#access_token=…` on success / `?errorOAuth=…` on
/// failure.
const SPA_CALLBACK_PATH: &str = "/auth/callback";
/// The one `errorOAuth` value every browser-facing OIDC callback failure
/// carries (Java's generic fallback in
/// `CustomOAuth2AuthenticationFailureHandler`). Deliberately a single constant:
/// the redirect must not reveal which check tripped, the redirect-shaped
/// counterpart of the API's single generic 401 principle.
const OIDC_BROWSER_ERROR_VALUE: &str = "oauth2AuthenticationError";
const AUDIT_LEVEL_OFF: u8 = 0;
const AUDIT_LEVEL_BASIC: u8 = 1;
const AUDIT_LEVEL_STANDARD: u8 = 2;
const AUDIT_LEVEL_VERBOSE: u8 = 3;
const MAX_AUDIT_CLIENT_IP_CHARS: usize = 512;
const MAX_AUDIT_RESULT_CHARS: usize = 1_000;
const MAX_AUDIT_RESULT_BODY_BYTES: u64 = 64 * 1_024;

#[derive(Clone)]
struct RequestCorrelation(String);

#[derive(Clone)]
pub struct SecurityHttpConfig {
    pub totp_issuer: String,
    pub invites_enabled: bool,
    pub invite_expiry_hours: u64,
    pub frontend_url: String,
    pub backend_url: String,
    pub audit_enabled: bool,
    pub audit_level: u8,
    pub audit_file_capture: SecurityAuditFileCaptureConfig,
    pub audit_capture_operation_results: bool,
    pub license_tier: LicenseTier,
    pub external_jwt: Option<Arc<SupabaseJwtVerifier>>,
    /// Generic-OIDC login provider (public-client PKCE). `None` disables the
    /// `/api/v1/auth/oidc/*` login routes entirely (they are not mounted),
    /// mirroring the "absent issuer ⇒ off" convention of [`Self::external_jwt`].
    pub oidc_login_provider: Option<OidcLoginProviderConfig>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SecurityAuditFileCaptureConfig {
    pub file_hash: bool,
    pub pdf_author: bool,
}

#[derive(Clone, Default)]
struct SecurityMailState {
    smtp: Option<Arc<SmtpMailService>>,
}

#[derive(Clone)]
struct SecurityMiddlewareState {
    store: Arc<SecurityStore>,
    external_jwt: Option<Arc<SupabaseJwtVerifier>>,
    audit_enabled: bool,
    audit_level: u8,
    audit_file_capture: SecurityAuditFileCapture,
    audit_capture_operation_results: bool,
    license_tier: LicenseTier,
}

#[derive(Debug, Error)]
pub enum SecurityStartupError {
    #[error("security repository initialization failed")]
    Repository(#[source] SecurityError),
    #[error("an empty security database requires configured initial administrator credentials")]
    MissingInitialAdministrator,
    #[error("external JWT verifier initialization failed")]
    ExternalJwt(#[source] SupabaseJwtError),
    #[error("commercial license verification failed")]
    LicenseVerification(#[source] LicenseError),
    #[error("server certificate initialization failed")]
    ServerCertificate(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("durable storage initialization failed")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("collaborative signing initialization failed")]
    WorkflowSigning(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Opens durable secured-mode state and bootstraps its first administrator from
/// trusted settings only when the database is empty.
///
/// # Errors
///
/// Returns an error when the repository cannot be opened, the configured
/// credentials are invalid, or an empty database has no initial administrator.
pub fn initialize_security_store(
    runtime_config: &RuntimeConfig,
) -> Result<Arc<SecurityStore>, SecurityStartupError> {
    let bootstrap = runtime_config.security_bootstrap_config();
    let secret_cipher = ProtectedSecretCipher::from_config_or_file(
        bootstrap
            .credential_encryption_key
            .as_ref()
            .map(|key| key.as_str()),
        &bootstrap.credential_encryption_key_path,
    )
    .map_err(SecurityError::from)
    .map_err(SecurityStartupError::Repository)?;
    let store = SecurityStore::open_protected(&bootstrap.database_path, secret_cipher)
        .map_err(SecurityStartupError::Repository)?;
    if store
        .has_users()
        .map_err(SecurityStartupError::Repository)?
    {
        return Ok(Arc::new(store));
    }
    let credentials = bootstrap
        .initial_login
        .ok_or(SecurityStartupError::MissingInitialAdministrator)?;
    store
        .bootstrap_admin(&credentials.username, &credentials.password)
        .map_err(SecurityStartupError::Repository)?;
    Ok(Arc::new(store))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: Zeroizing<String>,
    mfa_code: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    username: String,
    password: Zeroizing<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshRequest {
    refresh_token: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MfaCodeRequest {
    code: Zeroizing<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MfaSetupResponse {
    secret: Zeroizing<String>,
    otpauth_uri: Zeroizing<String>,
}

#[derive(Serialize)]
struct AuthenticationResponse {
    user: AuthenticationUser,
    session: SessionTokens,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationUser {
    id: i64,
    email: String,
    username: String,
    role: String,
    enabled: bool,
    portal_access: bool,
    team_lead: bool,
    authentication_type: &'static str,
    #[serde(rename = "app_metadata")]
    app_metadata: AppMetadata,
    #[serde(rename = "user_metadata")]
    user_metadata: UserMetadata,
}

#[derive(Serialize)]
struct AppMetadata {
    provider: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserMetadata {
    first_login: bool,
    force_password_change: bool,
}

struct AdminPasswordChangeInput {
    username: String,
    new_password: Zeroizing<String>,
    force_password_change: bool,
    delivery: Option<PasswordChangeDelivery>,
}

struct PasswordChangeDelivery {
    include_password: bool,
}

enum AdminPasswordChangeError {
    InvalidForm,
    SelfTarget,
    MissingPassword,
    UserNotFound,
    ProtectedState,
    ServiceUnavailable,
    EmailNotConfigured,
    InvalidRecipient,
    DeliveryFailed,
}

impl IntoResponse for AdminPasswordChangeError {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidForm => invalid_form_response(),
            Self::SelfTarget => named_json_error(
                StatusCode::BAD_REQUEST,
                "Cannot change your own password.",
                "Cannot change your own password.",
            ),
            Self::MissingPassword => named_json_error(
                StatusCode::BAD_REQUEST,
                "New password is required.",
                "New password is required.",
            ),
            Self::UserNotFound => {
                named_json_error(StatusCode::NOT_FOUND, "User not found.", "User not found.")
            }
            Self::ProtectedState => named_json_error(
                StatusCode::BAD_REQUEST,
                "Protected account state cannot be changed.",
                "Protected account state cannot be changed.",
            ),
            Self::ServiceUnavailable => service_unavailable_response(),
            Self::EmailNotConfigured => named_json_error(
                StatusCode::BAD_REQUEST,
                "Email is not configured.",
                "Email is not configured.",
            ),
            Self::InvalidRecipient => named_json_error(
                StatusCode::BAD_REQUEST,
                "User's email is not a valid email address. Notifications are disabled.",
                "User's email is not a valid email address. Notifications are disabled.",
            ),
            Self::DeliveryFailed => named_json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password updated but notification delivery failed",
                "Password updated but notification delivery failed",
            ),
        }
    }
}

/// Adds the secure auth routes and fail-closed middleware to an existing router.
///
/// The executable does not call this yet; integration tests use it to prove the
/// boundary before secured-mode startup can be enabled.
pub fn secure_router(router: Router, store: Arc<SecurityStore>) -> Router {
    secure_router_with_config(
        router,
        store,
        SecurityHttpConfig {
            totp_issuer: "Stirling PDF".to_owned(),
            invites_enabled: true,
            invite_expiry_hours: 168,
            frontend_url: String::new(),
            backend_url: String::new(),
            audit_enabled: true,
            audit_level: AUDIT_LEVEL_STANDARD,
            audit_file_capture: SecurityAuditFileCaptureConfig::default(),
            audit_capture_operation_results: false,
            license_tier: LicenseTier::Normal,
            external_jwt: None,
            oidc_login_provider: None,
        },
    )
}

/// Adds the secure boundary with a deployment-specific authenticator issuer.
pub fn secure_router_with_config(
    router: Router,
    store: Arc<SecurityStore>,
    config: SecurityHttpConfig,
) -> Router {
    secure_router_with_mail(router, store, config, None)
}

/// Everything the OIDC login routes share, built once per secured router: the
/// provider config plus the three `Arc`'d singletons (pending-login state
/// store, discovery-metadata cache, and JWKS cache) the authorize/callback
/// handlers receive via request extensions.
type OidcLoginRuntime = (
    OidcLoginProviderConfig,
    Arc<OidcLoginStateStore>,
    Arc<OidcDiscoveryCache>,
    Arc<OidcJwksCache>,
);

pub(crate) fn secure_router_with_mail(
    router: Router,
    store: Arc<SecurityStore>,
    config: SecurityHttpConfig,
    smtp: Option<Arc<SmtpMailService>>,
) -> Router {
    let middleware_state = SecurityMiddlewareState {
        store: Arc::clone(&store),
        external_jwt: config.external_jwt.clone(),
        // Java's AuditService is an Enterprise-only service even when the
        // nested audit setting itself is enabled.
        audit_enabled: config.audit_enabled && config.license_tier == LicenseTier::Enterprise,
        audit_level: config
            .audit_level
            .clamp(AUDIT_LEVEL_OFF, AUDIT_LEVEL_VERBOSE),
        audit_file_capture: SecurityAuditFileCapture {
            hash: config.audit_file_capture.file_hash,
            pdf_author: config.audit_file_capture.pdf_author,
        },
        audit_capture_operation_results: config.audit_capture_operation_results,
        license_tier: config.license_tier,
    };
    // A single shared state store, created once here so the authorize and
    // callback routes correlate against the same pending-login table, plus a
    // single shared discovery cache so repeated `/authorize` calls reuse one
    // provider-metadata fetch instead of re-hitting the IdP each time, plus a
    // single shared JWKS cache so repeated callbacks reuse one signing-key
    // fetch (bounded TTL + kid-miss refresh cooldown). `None` provider config
    // leaves the OIDC login routes unmounted (fail-closed off).
    let oidc_login = config.oidc_login_provider.clone().map(|provider| {
        (
            provider,
            Arc::new(OidcLoginStateStore::new()),
            Arc::new(OidcDiscoveryCache::new()),
            Arc::new(OidcJwksCache::new()),
        )
    });
    router
        .merge(auth_routes(oidc_login))
        .layer(middleware::from_fn_with_state(
            middleware_state,
            enforce_security,
        ))
        .layer(Extension(store))
        .layer(Extension(config))
        .layer(Extension(SecurityMailState { smtp }))
}

fn auth_routes(oidc_login: Option<OidcLoginRuntime>) -> Router {
    let mut router = Router::new()
        .merge(crate::security_audit_http::routes())
        .merge(crate::portal_audit::routes())
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(current_user))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/mfa/setup", get(setup_mfa))
        .route("/api/v1/auth/mfa/enable", post(enable_mfa))
        .route("/api/v1/auth/mfa/disable", post(disable_mfa))
        .route(
            "/api/v1/auth/mfa/disable/admin/{username}",
            post(disable_mfa_by_admin),
        )
        .route("/api/v1/auth/mfa/setup/cancel", post(cancel_mfa_setup))
        .route(
            "/api/v1/auth/mfa/recovery-codes/regenerate",
            post(regenerate_recovery_codes),
        )
        .route("/api/v1/user/register", post(register_user))
        .route("/api/v1/user/change-username", post(change_username))
        .route("/api/v1/user/change-password", post(change_password))
        .route(
            "/api/v1/user/change-password-on-login",
            post(change_password_on_login),
        )
        .route("/api/v1/user/get-api-key", post(get_api_key))
        .route("/api/v1/user/update-api-key", post(update_api_key))
        .route(
            "/api/v1/user/updateUserSettings",
            post(update_user_settings),
        )
        .route(
            "/api/v1/user/complete-initial-setup",
            post(complete_initial_setup),
        )
        .route("/api/v1/user/users", get(list_signing_users))
        .route("/api/v1/usage/fleet-stats", get(fleet_usage_stats))
        .route("/api/v1/user/admin/list", get(list_users_by_admin))
        .route("/api/v1/user/admin/saveUser", post(save_user_by_admin))
        .route(
            "/api/v1/user/admin/inviteUsers",
            post(invite_users_by_admin),
        )
        .route(
            "/api/v1/user/admin/changeRole",
            post(change_user_role_by_admin),
        )
        .route(
            "/api/v1/user/admin/changePasswordForUser",
            post(change_user_password_by_admin),
        )
        .route(
            "/api/v1/user/admin/changeUserEnabled/{username}",
            post(change_user_enabled_by_admin),
        )
        .route(
            "/api/v1/user/admin/unlockUser/{username}",
            post(unlock_user_by_admin),
        )
        .route(
            "/api/v1/user/admin/deleteUser/{username}",
            post(delete_user_by_admin),
        )
        .route("/api/v1/team/list", get(list_teams))
        .route("/api/v1/team/create", post(create_team))
        .route("/api/v1/team/rename", post(rename_team))
        .route("/api/v1/team/delete", post(delete_team))
        .route("/api/v1/team/setOwner", post(set_team_owner))
        .route("/api/v1/team/removeOwner", post(remove_team_owner))
        .route("/api/v1/team/addUser", post(add_user_to_team))
        .route("/api/v1/invite/generate", post(generate_invite))
        .route("/api/v1/invite/list", get(list_invites))
        .route("/api/v1/invite/revoke/{invite_id}", delete(revoke_invite))
        .route("/api/v1/invite/cleanup", post(cleanup_invites))
        .route("/api/v1/invite/validate/{token}", get(validate_invite))
        .route("/api/v1/invite/accept/{token}", post(accept_invite));
    // The generic-OIDC login routes only exist when a provider is configured.
    // They share the single state store built above and read the provider config
    // from a request extension, mirroring how every other handler reaches the
    // `SecurityStore`. Both routes are public (the browser has no session yet);
    // `is_public_auth` in `security_policy` classifies them accordingly.
    if let Some((provider, store, discovery, jwks_cache)) = oidc_login {
        router = router
            .route("/api/v1/auth/oidc/authorize", post(oidc_authorize))
            .route("/api/v1/auth/oidc/callback", get(oidc_callback))
            .layer(Extension(provider))
            .layer(Extension(store))
            .layer(Extension(discovery))
            .layer(Extension(jwks_cache));
    }
    router.layer(DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
}

async fn enforce_security(
    State(state): State<SecurityMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    let correlation = RequestCorrelation(random_request_id());
    request.extensions_mut().insert(correlation.clone());
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let policy = endpoint_policy(&method, &path);
    let context = if policy == EndpointPolicy::Public {
        None
    } else if policy == EndpointPolicy::ParticipantToken {
        return denial_response(
            AuthorizationDenial::ParticipantTokenRequired,
            &correlation.0,
        );
    } else {
        match authenticate_request(
            &state.store,
            state.external_jwt.as_ref(),
            request.headers(),
            &correlation.0,
        )
        .await
        {
            Ok(context) => Some(context),
            Err(response) => return with_request_id(response, &correlation.0),
        }
    };
    if let Err(denial) = authorize(policy, context.as_ref()) {
        return denial_response(denial, &correlation.0);
    }
    let entitlement = endpoint_entitlement(&method, &path);
    if let Err(required) = authorize_entitlement(state.license_tier, entitlement) {
        return entitlement_denial_response(required, &path, &correlation.0);
    }
    let audit_plan =
        audit_capture_plan(&state, &method, &path, request.headers(), context.as_ref());
    let audit_client_ip = audit_plan.and_then(|_| audit_client_ip(&request));
    let audit_principal_context = context.clone();
    let audit_enrichment_context = audit_plan.map(|plan| {
        SecurityAuditContext::with_file_capture(
            plan.include_standard_data,
            state.audit_file_capture,
        )
    });
    if let Some(context) = &audit_enrichment_context {
        request.extensions_mut().insert(context.clone());
    }
    if let Some(context) = context {
        request.extensions_mut().insert(context);
    }
    let started_at = Instant::now();
    let response = if let Some(audit_context) = &audit_enrichment_context {
        audit_context.scope(next.run(request)).await
    } else {
        next.run(request).await
    };
    if let Some(plan) = audit_plan {
        return finish_http_audit(
            PendingHttpAudit {
                store: Arc::clone(&state.store),
                capture_operation_results: state.audit_capture_operation_results,
                plan,
                context: audit_principal_context,
                client_ip: audit_client_ip,
                correlation_id: correlation.0,
                method: method.as_str().to_owned(),
                path,
                started_at,
                enrichment_context: audit_enrichment_context,
            },
            response,
        )
        .await;
    }
    with_request_id(response, &correlation.0)
}

struct PendingHttpAudit {
    store: Arc<SecurityStore>,
    capture_operation_results: bool,
    plan: AuditCapturePlan,
    context: Option<AuthContext>,
    client_ip: Option<String>,
    correlation_id: String,
    method: String,
    path: String,
    started_at: Instant,
    enrichment_context: Option<SecurityAuditContext>,
}

async fn finish_http_audit(pending: PendingHttpAudit, response: Response) -> Response {
    let now = Utc::now();
    let latency_ms = u64::try_from(pending.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
    let status_code = response.status().as_u16();
    let capture_result = pending.capture_operation_results
        && !pending.plan.annotated
        && pending.plan.event_type != "UI_DATA";
    let (response, result) = if capture_result {
        capture_text_operation_result(response).await
    } else {
        (response, None)
    };
    let mut record = SecurityHttpAuditRecord {
        context: pending.context,
        client_ip: pending.client_ip,
        correlation_id: pending.correlation_id.clone(),
        source: pending.plan.source.to_owned(),
        event_type: pending.plan.event_type.to_owned(),
        method: pending.method,
        path: redacted_audit_path(&pending.path),
        status_code,
        latency_ms,
        include_standard_data: pending.plan.include_standard_data,
        annotated: pending.plan.annotated,
        result,
        enrichment: pending
            .enrichment_context
            .as_ref()
            .map(SecurityAuditContext::snapshot)
            .unwrap_or_default(),
        created_at: now.timestamp(),
        timestamp: now.to_rfc3339(),
    };
    let store_for_audit = pending.store;
    // Java persists controller audit events asynchronously and fail-open.
    // Generic asynchronous jobs keep enriching the request context after
    // this submission response. Defer only that write until the worker
    // signals completion; normal handlers retain deterministic persistence.
    if let Some(audit_context) = pending
        .enrichment_context
        .filter(SecurityAuditContext::is_deferred)
    {
        task::spawn(async move {
            audit_context.wait_for_deferred_completion().await;
            record.enrichment = audit_context.snapshot();
            let _ = task::spawn_blocking(move || store_for_audit.record_http_audit(&record)).await;
        });
    } else {
        // Await the bounded SQLite write for deterministic request tests,
        // but never replace the handler response when persistence fails.
        let _ = task::spawn_blocking(move || store_for_audit.record_http_audit(&record)).await;
    }
    with_request_id(response, &pending.correlation_id)
}

async fn capture_text_operation_result(response: Response) -> (Response, Option<String>) {
    if !is_text_operation_result(&response)
        || response
            .body()
            .size_hint()
            .exact()
            .is_none_or(|size| size == 0 || size > MAX_AUDIT_RESULT_BODY_BYTES)
    {
        return (response, None);
    }

    let (parts, body) = response.into_parts();
    let mut stream = body.into_data_stream();
    let mut chunks = Vec::new();
    let mut captured = Vec::new();
    let mut complete = true;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                captured.extend_from_slice(&bytes);
                chunks.push(Ok(bytes));
            }
            Err(error) => {
                chunks.push(Err(error));
                complete = false;
                break;
            }
        }
    }
    let response =
        Response::from_parts(parts, Body::from_stream(futures_util::stream::iter(chunks)));
    let result = complete
        .then(|| String::from_utf8(captured).ok())
        .flatten()
        .map(|value| bounded_operation_result(&value));
    (response, result)
}

fn is_text_operation_result(response: &Response) -> bool {
    let Some(content_type) = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    else {
        return false;
    };
    let content_type = content_type.to_ascii_lowercase();
    content_type.starts_with("text/")
        || content_type == "application/json"
        || content_type.ends_with("+json")
        || content_type == "application/xml"
        || content_type.ends_with("+xml")
        || content_type == "application/x-www-form-urlencoded"
}

fn bounded_operation_result(value: &str) -> String {
    let mut chars = value.chars();
    let prefix = chars
        .by_ref()
        .take(MAX_AUDIT_RESULT_CHARS)
        .collect::<String>();
    if chars.next().is_none() {
        return prefix;
    }
    let mut bounded = prefix
        .chars()
        .take(MAX_AUDIT_RESULT_CHARS.saturating_sub(3))
        .collect::<String>();
    bounded.push_str("...");
    bounded
}

fn audit_client_ip(request: &Request) -> Option<String> {
    let forwarded_for = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(forwarded_for) = forwarded_for {
        return Some(
            forwarded_for
                .chars()
                .take(MAX_AUDIT_CLIENT_IP_CHARS)
                .collect(),
        );
    }
    let real_ip = request
        .headers()
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(real_ip) = real_ip {
        return Some(real_ip.chars().take(MAX_AUDIT_CLIENT_IP_CHARS).collect());
    }
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|address| address.0.ip().to_string())
}

#[derive(Clone, Copy)]
struct AuditCapturePlan {
    event_type: &'static str,
    source: &'static str,
    include_standard_data: bool,
    annotated: bool,
}

fn audit_capture_plan(
    state: &SecurityMiddlewareState,
    method: &axum::http::Method,
    path: &str,
    headers: &HeaderMap,
    context: Option<&AuthContext>,
) -> Option<AuditCapturePlan> {
    if !state.audit_enabled
        || state.audit_level < AUDIT_LEVEL_BASIC
        || is_static_resource_path(path)
        || (state.audit_level == AUDIT_LEVEL_STANDARD && is_standard_polling_get(method, path))
    {
        return None;
    }
    let annotated_event = explicit_audit_event(method, path);
    let annotated = annotated_event.is_some();
    let event_type = annotated_event.unwrap_or_else(|| inferred_audit_event(method, path));
    let source = if annotated {
        // Java leaves source null for explicit @Audited events. The reviewed
        // Rust schema predates that contract and is NOT NULL; an empty value
        // preserves exclusion from every named source aggregate.
        ""
    } else {
        audit_source(context, headers, path)
    };
    Some(AuditCapturePlan {
        event_type,
        source,
        include_standard_data: !annotated && state.audit_level >= AUDIT_LEVEL_STANDARD,
        annotated,
    })
}

fn explicit_audit_event(method: &axum::http::Method, path: &str) -> Option<&'static str> {
    if method != axum::http::Method::POST {
        return None;
    }
    match path {
        "/api/v1/auth/login" | "/api/v1/auth/refresh" => Some("USER_LOGIN"),
        "/api/v1/user/change-username"
        | "/api/v1/user/change-password"
        | "/api/v1/user/change-password-on-login"
        | "/api/v1/user/update-api-key" => Some("USER_PROFILE_UPDATE"),
        "/api/v1/invite/generate" => Some("SETTINGS_CHANGED"),
        _ if path.starts_with("/api/v1/user/admin/unlockUser/") => Some("SETTINGS_CHANGED"),
        _ if path.starts_with("/api/v1/user/admin/deleteUser/") => Some("USER_PROFILE_UPDATE"),
        _ => None,
    }
}

pub(crate) fn inferred_audit_event(method: &axum::http::Method, path: &str) -> &'static str {
    if method == axum::http::Method::GET {
        return if is_ui_data_get(path) {
            "UI_DATA"
        } else {
            "HTTP_REQUEST"
        };
    }
    if path.starts_with("/api/v1/user/")
        || path.starts_with("/api/v1/users/")
        || path.starts_with("/api/v1/auth/")
    {
        "USER_PROFILE_UPDATE"
    } else if path == "/api/v1/admin" || path.starts_with("/api/v1/admin/") {
        "SETTINGS_CHANGED"
    } else {
        let lowercase = path.to_ascii_lowercase();
        if lowercase.starts_with("/api/v1/files/")
            || lowercase.starts_with("/api/v1/storage/files")
            || lowercase.contains("/upload/")
            || lowercase.contains("/download/")
        {
            "FILE_OPERATION"
        } else {
            "PDF_PROCESS"
        }
    }
}

fn is_ui_data_get(path: &str) -> bool {
    path.starts_with("/api/v1/auth/")
        || path.starts_with("/api/v1/ui-data/")
        || path.starts_with("/api/v1/proprietary/ui-data/")
        || path.starts_with("/api/v1/config/")
        || path.starts_with("/api/v1/admin/settings/")
        || path.starts_with("/api/v1/user/")
        || path.starts_with("/api/v1/users/")
        || matches!(path, "/api/v1/admin/license-info" | "/login")
}

fn audit_source(context: Option<&AuthContext>, headers: &HeaderMap, path: &str) -> &'static str {
    let Some(context) = context else {
        return "SYSTEM";
    };
    if context.authentication_source == crate::security::AuthenticationSource::ApiKey {
        return "API";
    }
    if headers.contains_key(&AUTOMATION_HEADER) {
        "AUTOMATION"
    } else if path.starts_with("/api/v1/ai/") {
        "AI"
    } else {
        "WEB"
    }
}

fn is_standard_polling_get(method: &axum::http::Method, path: &str) -> bool {
    method == axum::http::Method::GET
        && (matches!(
            path,
            "/api/v1/auth/me"
                | "/api/v1/app-config"
                | "/api/v1/footer-info"
                | "/api/v1/admin/license-info"
                | "/api/v1/endpoints-availability"
                | "/health"
                | "/metrics"
                | "/actuator/health"
                | "/actuator/metrics"
        ) || path.starts_with("/health/")
            || path.starts_with("/metrics/")
            || path.starts_with("/actuator/health/")
            || path.starts_with("/actuator/metrics/"))
}

fn is_static_resource_path(path: &str) -> bool {
    matches!(path, "/favicon.ico" | "/manifest.json")
        || path.starts_with("/assets/")
        || path.starts_with("/locales/")
}

/// Path prefixes whose trailing segment is a bearer-equivalent secret (an
/// invite token used as the sole credential for an unauthenticated route),
/// not a resource id. The audit trail must never persist these tokens
/// verbatim, so [`redacted_audit_path`] replaces that segment before the
/// path reaches [`SecurityHttpAuditRecord`].
const AUDIT_TOKEN_PATH_PREFIXES: &[&str] = &["/api/v1/invite/validate/", "/api/v1/invite/accept/"];

fn redacted_audit_path(path: &str) -> String {
    for prefix in AUDIT_TOKEN_PATH_PREFIXES {
        if let Some(token) = path.strip_prefix(prefix)
            && !token.is_empty()
        {
            return format!("{prefix}[REDACTED]");
        }
    }
    path.to_owned()
}

async fn authenticate_request(
    store: &Arc<SecurityStore>,
    external_jwt: Option<&Arc<SupabaseJwtVerifier>>,
    headers: &HeaderMap,
    correlation_id: &str,
) -> Result<AuthContext, Response> {
    let bearer = bearer_token(headers).map_err(|()| unauthorized_response())?;
    let api_key = single_header(headers, &API_KEY_HEADER).map_err(|()| unauthorized_response())?;
    if bearer.is_some() == api_key.is_some() {
        return Err(unauthorized_response());
    }
    let store = Arc::clone(store);
    let correlation_id = correlation_id.to_owned();
    let result = if let Some(token) = bearer {
        let token = Zeroizing::new(token.to_owned());
        if token.starts_with("spdf_at_") {
            task::spawn_blocking(move || {
                store.authenticate_access_token(&token, Utc::now().timestamp(), &correlation_id)
            })
            .await
        } else {
            let Some(verifier) = external_jwt.cloned() else {
                return Err(unauthorized_response());
            };
            task::spawn_blocking(move || {
                let identity = verifier
                    .verify(&token)
                    .map_err(|_| SecurityError::InvalidToken)?;
                store.authenticate_supabase_identity(
                    &identity,
                    Utc::now().timestamp(),
                    &correlation_id,
                )
            })
            .await
        }
    } else {
        let api_key = Zeroizing::new(api_key.unwrap_or_default().to_owned());
        task::spawn_blocking(move || store.authenticate_api_key(&api_key, &correlation_id)).await
    };
    match result {
        Ok(Ok(context)) => Ok(context),
        Ok(Err(_)) => Err(unauthorized_response()),
        Err(_) => Err(service_unavailable_response()),
    }
}

async fn login(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(correlation): Extension<RequestCorrelation>,
    Json(request): Json<LoginRequest>,
) -> Response {
    if request.username.trim().is_empty() || request.password.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "Invalid request");
    }
    let store_for_login = Arc::clone(&store);
    let correlation_id = correlation.0;
    let result = task::spawn_blocking(move || {
        let now = Utc::now().timestamp();
        let context = store_for_login.authenticate_login(
            &request.username,
            &request.password,
            request.mfa_code.as_ref().map(|code| code.as_str()),
            now,
            &correlation_id,
        )?;
        let tokens = store_for_login.issue_session(
            &context,
            now,
            DEFAULT_ACCESS_TTL,
            DEFAULT_REFRESH_TTL,
        )?;
        Ok::<_, SecurityError>((context, tokens))
    })
    .await;
    match result {
        Ok(Ok((context, tokens))) => Json(AuthenticationResponse {
            user: authentication_user(&context),
            session: tokens,
        })
        .into_response(),
        Ok(Err(SecurityError::InvalidInput)) => {
            json_error(StatusCode::BAD_REQUEST, "Invalid request")
        }
        Ok(Err(
            SecurityError::InvalidCredentials
            | SecurityError::AccountLocked
            | SecurityError::AccountDisabled,
        )) => json_error(StatusCode::UNAUTHORIZED, "Invalid username or password"),
        Ok(Err(SecurityError::MfaRequired)) => named_json_error(
            StatusCode::UNAUTHORIZED,
            "mfa_required",
            "Two-factor code required",
        ),
        Ok(Err(SecurityError::InvalidMfa)) => named_json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_mfa_code",
            "Invalid two-factor code",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OidcAuthorizeResponse {
    authorization_url: String,
    state: String,
}

/// The provider's redirect back to us carries the authorization `code` and the
/// `state` we issued. Both are required; a provider may append extra params
/// (e.g. `iss`, `session_state`), so unknown fields are ignored, not rejected.
#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// Begins a generic-OIDC login: discovers the provider, builds the authorization
/// request, persists the single-use `state`, and returns the redirect URL plus
/// that `state` as JSON — consistent with the JSON bodies every other auth route
/// returns. It ALSO sets the login-CSRF browser-binding cookie
/// ([`OIDC_CSRF_COOKIE`], `HttpOnly; Secure; SameSite=Lax`) that
/// [`oidc_callback`] requires the browser to present back before completing the
/// login — a server-enforced defense (RFC 9700), not an optional frontend step.
/// Turning the returned URL into an actual browser redirect remains the
/// frontend's job.
async fn oidc_authorize(
    Extension(provider): Extension<OidcLoginProviderConfig>,
    Extension(store): Extension<Arc<OidcLoginStateStore>>,
    Extension(discovery): Extension<Arc<OidcDiscoveryCache>>,
) -> Response {
    // The cookie's Max-Age tracks the store's state TTL, so it expires with the
    // pending login. Read before the store is moved into the blocking closure.
    let cookie_max_age = store.state_ttl();
    // Discovery and state persistence are blocking (SSRF-safe `reqwest::blocking`
    // plus a `std::sync::Mutex`), so run them off the async executor like `login`.
    let result =
        task::spawn_blocking(move || initiate_oidc_login(&provider, &store, &discovery)).await;
    match result {
        Ok(Ok(initiated)) => {
            let cookie = oidc_binding_cookie(&initiated.browser_binding, cookie_max_age);
            let mut response = Json(OidcAuthorizeResponse {
                authorization_url: initiated.authorization_url,
                state: initiated.state,
            })
            .into_response();
            if let Some(cookie) = cookie {
                response.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            response
        }
        // Every initiate failure is a server-side / transient condition, not the
        // caller's fault: a bad provider config, an unreachable/invalid IdP, or
        // the state store being momentarily at capacity (`AtCapacity`). All
        // collapse to the same retryable service-unavailable, leaking neither
        // which stage failed nor which limit was hit.
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

/// Builds the `Set-Cookie` value binding a pending OIDC login to the browser
/// that started it. `value` is the login's [`InitiatedOidcLogin::browser_binding`];
/// [`oidc_callback`] requires the browser to present it back, which is the
/// server-enforced login-CSRF defense (RFC 9700).
///
/// Attributes: `HttpOnly` (script can't read it), `Secure` (never sent over
/// plaintext HTTP), `SameSite=Lax` (rides the top-level GET redirect back from
/// the `IdP`, but not cross-site subrequests), `Path` scopes it to the OIDC login
/// routes, and `Max-Age` matches the server-side state TTL.
///
/// [`InitiatedOidcLogin::browser_binding`]: crate::oidc_login::InitiatedOidcLogin::browser_binding
fn oidc_binding_cookie(value: &str, max_age: Duration) -> Option<HeaderValue> {
    // `value` is CSPRNG base64url (cookie-token safe), so this never fails in
    // practice; on the impossible failure we omit the cookie, which fails closed
    // (the callback then rejects for want of a binding).
    HeaderValue::from_str(&format!(
        "{OIDC_CSRF_COOKIE}={value}; HttpOnly; Secure; SameSite=Lax; Path={OIDC_COOKIE_PATH}; Max-Age={}",
        max_age.as_secs()
    ))
    .ok()
}

/// Reads one named cookie from a request's `Cookie` header, if present. The
/// header may pack several cookies separated by `;`; only the named one is
/// returned.
fn request_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .find(|(candidate, _)| candidate.trim() == name)
        .map(|(_, value)| value.trim().to_owned())
}

/// Reads the OIDC login browser-binding cookie ([`OIDC_CSRF_COOKIE`]) from a
/// request's `Cookie` header, if present.
fn oidc_binding_cookie_value(headers: &HeaderMap) -> Option<String> {
    request_cookie_value(headers, OIDC_CSRF_COOKIE)
}

/// Completes a generic-OIDC login from the provider's callback and answers the
/// BROWSER that landed here, mirroring Java's
/// `CustomOAuth2AuthenticationSuccessHandler` /
/// `CustomOAuth2AuthenticationFailureHandler` pair: extracts `code` and
/// `state`, reads the login-CSRF browser-binding cookie ([`OIDC_CSRF_COOKIE`])
/// set at [`oidc_authorize`], exchanges and verifies through
/// [`complete_oidc_login`] (which requires that cookie to equal the binding
/// stored for this login before it does anything else), and:
///
/// - on success, 302-redirects to the SPA —
///   `{origin}{redirect-path}#access_token={token}` — exactly the fragment
///   `AuthCallback.tsx` consumes, with the origin resolved context-aware (see
///   [`oidc_redirect_origin`]) and the path taken from the
///   [`SPA_REDIRECT_COOKIE`] the SPA set before starting SSO (see
///   [`spa_redirect_path`]); the cookie is cleared on the way out
///   ([`oidc_browser_redirect`]).
/// - on every genuine login rejection — a missing/empty `code` or `state`
///   (Java's `OAuth2LoginAuthenticationFilter` treats that as an
///   authentication failure too), an absent or wrong browser-binding cookie
///   (the login-CSRF rejection), an unknown/expired/replayed `state`, a failed
///   token exchange or id-token/nonce verification, or an account-level denial
///   — 302-redirects to `{redirect-path}?errorOAuth=oauth2AuthenticationError`
///   ([`oidc_failure_redirect`]), one fixed error value so the redirect never
///   reveals which check tripped (the browser-flow counterpart of the API's
///   single generic 401 principle; Java redirects here as well, it never
///   answers this browser flow with raw JSON).
/// - infrastructure faults (a poisoned lock, repository/crypto failures) stay
///   retryable 503 JSON — in Java those surface as 5xx error responses, not
///   redirects (see [`oidc_callback_error_response`]).
async fn oidc_callback(
    Extension(store): Extension<Arc<OidcLoginStateStore>>,
    Extension(jwks_cache): Extension<Arc<OidcJwksCache>>,
    Extension(security): Extension<Arc<SecurityStore>>,
    Extension(correlation): Extension<RequestCorrelation>,
    headers: HeaderMap,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    let (Some(code), Some(state)) = (query.code, query.state) else {
        return oidc_failure_redirect(&headers);
    };
    if code.is_empty() || state.is_empty() {
        return oidc_failure_redirect(&headers);
    }
    // Login-CSRF binding (RFC 9700): hand the browser's binding cookie to
    // `complete_oidc_login`, which rejects the login unless it equals the binding
    // stored for this `state`. A cross-site forged callback carries `state`+`code`
    // but not the victim browser's cookie, so it can't satisfy this.
    let browser_binding = oidc_binding_cookie_value(&headers);
    let correlation_id = correlation.0;
    let result = task::spawn_blocking(move || {
        complete_oidc_login(
            &state,
            &code,
            browser_binding.as_deref(),
            &store,
            &jwks_cache,
            &security,
            Utc::now().timestamp(),
            &correlation_id,
        )
    })
    .await;
    match result {
        Ok(Ok(completed)) => {
            oidc_success_redirect(&headers, completed.tokens.access_token.as_str())
        }
        Ok(Err(error)) => oidc_callback_error_response(&error, &headers),
        Err(_) => service_unavailable_response(),
    }
}

/// Maps a completion failure to an HTTP response. Infrastructure faults (a
/// poisoned store lock, or a repository/crypto failure while provisioning the
/// verified identity) are retryable 503s; every genuine login rejection —
/// an absent/wrong browser-binding cookie (login-CSRF), an unknown/expired/replayed
/// `state`, a failed token exchange, a failed id-token (or nonce) verification,
/// or an account-level denial — collapses to the single browser error redirect
/// ([`oidc_failure_redirect`]) so the response never reveals which check
/// tripped.
fn oidc_callback_error_response(error: &OidcLoginError, headers: &HeaderMap) -> Response {
    match error {
        OidcLoginError::StateUnavailable
        | OidcLoginError::Identity(
            SecurityError::Poisoned
            | SecurityError::Storage(_)
            | SecurityError::PasswordHash(_)
            | SecurityError::Filesystem(_)
            | SecurityError::SecretProtection(_)
            | SecurityError::MfaConfiguration
            | SecurityError::IntegrationProtectionUnavailable
            | SecurityError::AuditEventLimitExceeded,
        ) => service_unavailable_response(),
        _ => oidc_failure_redirect(headers),
    }
}

/// The success redirect the browser lands on after a completed OIDC login:
/// `302 Found` to `{origin}{redirect-path}#access_token={token}` — byte-level
/// the format Java's `buildContextAwareRedirectUrl` produces for the web flow
/// and the fragment `AuthCallback.tsx` parses (`URLSearchParams` over the
/// hash). The token rides the URL FRAGMENT, never the query, so it is not sent
/// to any server the origin resolution may pick.
///
/// Java appends `&nonce=…` only for `tauri:`-prefixed desktop states; this
/// port never issues such states (the state is CSPRNG base64url, which cannot
/// contain `:`), so a success here can never be a Tauri flow and no nonce is
/// appended.
fn oidc_success_redirect(headers: &HeaderMap, access_token: &str) -> Response {
    let origin = oidc_redirect_origin(headers);
    let path = spa_redirect_path(headers);
    oidc_browser_redirect(&format!("{origin}{path}#access_token={access_token}"))
}

/// The failure redirect the browser lands on when the OIDC login is rejected:
/// `302 Found` to `{redirect-path}?errorOAuth=oauth2AuthenticationError`,
/// mirroring Java's `CustomOAuth2AuthenticationFailureHandler`
/// (`buildFailureRedirectUrl` + `errorOAuth` query param). Deliberate
/// differences from Java, both documented in the contract:
///
/// - the `Location` is context-relative (a bare path), exactly like Java's
///   `DefaultRedirectStrategy` — the browser resolves it against the origin it
///   is already on, so no forwarded-header trust is needed on the failure path;
/// - the error value is ALWAYS the one fixed [`OIDC_BROWSER_ERROR_VALUE`]
///   rather than Java's per-cause `OAuth2` error code, preserving this port's
///   "reveal nothing about which check tripped" principle in redirect form;
/// - the `tauri:` desktop-state branch is not ported (no such states are ever
///   issued here), so no request parameters are ever reflected into the
///   redirect.
fn oidc_failure_redirect(headers: &HeaderMap) -> Response {
    let path = spa_redirect_path(headers);
    let separator = if path.contains('?') { '&' } else { '?' };
    oidc_browser_redirect(&format!(
        "{path}{separator}errorOAuth={OIDC_BROWSER_ERROR_VALUE}"
    ))
}

/// Builds the `302 Found` browser redirect both OIDC callback outcomes share,
/// clearing the SPA redirect-path cookie on the way out with Java's exact
/// clearing attributes (`clearRedirectCookie`: `Path=/; Max-Age=0;
/// SameSite=Lax`, no `HttpOnly`/`Secure` — the SPA itself writes this cookie
/// from script). If `location` cannot be a header value (a non-ASCII or
/// control byte smuggled through a forwarded header), the redirect falls back
/// to the default SPA callback path instead of failing open.
fn oidc_browser_redirect(location: &str) -> Response {
    let location = HeaderValue::from_str(location)
        .unwrap_or_else(|_| HeaderValue::from_static(SPA_CALLBACK_PATH));
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(header::LOCATION, location);
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("stirling_redirect_path=; Path=/; Max-Age=0; SameSite=Lax"),
    );
    response
}

/// Resolves the SPA path the OIDC callback should send the browser to, from
/// the [`SPA_REDIRECT_COOKIE`] the SPA sets right before starting SSO
/// (`springAuthClient.signInWithOAuth` persists the user's intended
/// destination there, URL-encoded). Mirrors Java's `resolveRedirectPath` +
/// `TauriOAuthUtils.extractRedirectPathFromCookie`: the value is
/// form-urlencoded-decoded (`URLDecoder` semantics), trimmed, and must start
/// with `/` — otherwise the default [`SPA_CALLBACK_PATH`] is used. One
/// hardening on top of Java: values starting `//` or `/\` are rejected too,
/// because on the (context-relative) failure redirect a protocol-relative
/// `Location` would be an attacker-settable open redirect.
fn spa_redirect_path(headers: &HeaderMap) -> String {
    let cookie_path = request_cookie_value(headers, SPA_REDIRECT_COOKIE)
        .and_then(|raw| form_urlencoded_decode(&raw))
        .map(|decoded| decoded.trim().to_owned())
        .filter(|path| {
            path.starts_with('/') && !path.starts_with("//") && !path.starts_with("/\\")
        });
    cookie_path.unwrap_or_else(|| SPA_CALLBACK_PATH.to_owned())
}

/// Decodes an `application/x-www-form-urlencoded` value with Java
/// `URLDecoder.decode` semantics: `+` becomes a space and `%XX` becomes the
/// byte `XX`. Returns [`None`] where Java would throw (a truncated or
/// non-hex `%` escape) or where the decoded bytes are not UTF-8 — the caller
/// then falls back to the default path.
fn form_urlencoded_decode(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let escape = [bytes.next()?, bytes.next()?];
                let escape = std::str::from_utf8(&escape).ok()?;
                decoded.push(u8::from_str_radix(escape, 16).ok()?);
            }
            other => decoded.push(other),
        }
    }
    String::from_utf8(decoded).ok()
}

/// Resolves the browser-facing origin for the OIDC success redirect,
/// mirroring Java's `buildContextAwareRedirectUrl` precedence exactly:
/// `X-Forwarded-Host`(+`-Proto`/`-Port`) first, then the `Referer` (unless it
/// is a known OAuth provider domain — the `IdP` just redirected here), then the
/// request's own `Host`. Trusting `X-Forwarded-*` unconditionally is Java's
/// choice, deliberately mirrored no further: these headers only steer where
/// THIS browser is sent, and the token travels in the fragment, which
/// browsers never transmit to the target server.
///
/// Java can always name a server (`serverName`); a raw socket has no such
/// guarantee, so with no resolvable origin this returns the empty string and
/// the `Location` degrades to a context-relative path — the browser then
/// resolves it against the origin it is already on, which is strictly safer.
fn oidc_redirect_origin(headers: &HeaderMap) -> String {
    forwarded_origin(headers)
        .or_else(|| referer_origin(headers))
        .or_else(|| host_origin(headers))
        .unwrap_or_default()
}

/// `X-Forwarded-Host` branch of [`oidc_redirect_origin`] (Java's
/// `resolveForwardedOrigin`): first comma-separated host, scheme from the
/// first `X-Forwarded-Proto` entry (falling back to the engine's own scheme,
/// plain `http`), and — only when the host carries no port of its own —
/// `X-Forwarded-Port` unless it is the scheme's default.
fn forwarded_origin(headers: &HeaderMap) -> Option<String> {
    let forwarded_host = headers.get("x-forwarded-host")?.to_str().ok()?;
    let host = forwarded_host.split(',').next()?.trim();
    if host.is_empty() {
        return None;
    }
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .and_then(|value| value.split(',').next())
        .map_or("http", str::trim);
    let mut host = host.to_owned();
    if !host.contains(':')
        && let Some(port) = headers
            .get("x-forwarded-port")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|port| !port.is_empty())
        && !is_default_port(proto, port)
    {
        host = format!("{host}:{port}");
    }
    Some(format!("{proto}://{host}"))
}

/// `Referer` branch of [`oidc_redirect_origin`] (Java's
/// `resolveOriginFromReferer`): the referer's `scheme://host[:port]` — port
/// only when explicit and neither 80 nor 443 — unless the referer is a known
/// OAuth provider domain (the `IdP` that just redirected the browser here, not
/// where the SPA lives).
fn referer_origin(headers: &HeaderMap) -> Option<String> {
    let referer = headers.get(header::REFERER)?.to_str().ok()?;
    if referer.is_empty() {
        return None;
    }
    let referer = url::Url::parse(referer).ok()?;
    let host = referer.host_str()?;
    if is_oauth_provider_domain(&host.to_lowercase()) {
        return None;
    }
    let origin = match referer.port() {
        Some(port) if port != 80 && port != 443 => {
            format!("{}://{host}:{port}", referer.scheme())
        }
        _ => format!("{}://{host}", referer.scheme()),
    };
    Some(origin)
}

/// Last-resort branch of [`oidc_redirect_origin`] (Java's
/// `buildOriginFromRequest`): the request's own `Host` header on the engine's
/// own scheme (plain `http` — TLS terminates in front of this service, and
/// that case is covered by the forwarded branch), dropping the scheme-default
/// port the way Java skips `serverPort` 80.
fn host_origin(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?.trim();
    if host.is_empty() {
        return None;
    }
    let host = host.strip_suffix(":80").unwrap_or(host);
    Some(format!("http://{host}"))
}

/// Java's `isDefaultPort`: 80 for `http`, 443 for `https` (schemes compared
/// case-insensitively); an unparseable port is NOT default, so it gets
/// appended verbatim exactly as Java appends it.
fn is_default_port(proto: &str, port: &str) -> bool {
    match port.parse::<u32>() {
        Ok(80) => proto.eq_ignore_ascii_case("http"),
        Ok(443) => proto.eq_ignore_ascii_case("https"),
        _ => false,
    }
}

/// Java's `isOAuthProviderDomain`: substring match over the lowercased
/// referer host, so a redirect never targets the `IdP` the browser just came
/// from.
fn is_oauth_provider_domain(hostname: &str) -> bool {
    [
        "google.com",
        "googleapis.com",
        "github.com",
        "microsoft.com",
        "microsoftonline.com",
        "linkedin.com",
        "apple.com",
    ]
    .iter()
    .any(|provider| hostname.contains(provider))
}

async fn setup_mfa(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Extension(config): Extension<SecurityHttpConfig>,
) -> Response {
    let store_for_setup = Arc::clone(&store);
    let user_id = context.user_id;
    let result = task::spawn_blocking(move || {
        store_for_setup.begin_mfa_setup(user_id, Utc::now().timestamp())
    })
    .await;
    match result {
        Ok(Ok(secret)) => {
            let uri = Zeroizing::new(totp_auth_uri(
                &config.totp_issuer,
                &context.username,
                &secret,
            ));
            Json(MfaSetupResponse {
                secret,
                otpauth_uri: uri,
            })
            .into_response()
        }
        Ok(Err(SecurityError::MfaAlreadyEnabled)) => named_json_error(
            StatusCode::CONFLICT,
            "MFA already enabled",
            "MFA already enabled",
        ),
        Ok(Err(SecurityError::UnsupportedAuthenticationSource)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "MFA settings are only available for web accounts",
            "MFA settings are only available for web accounts",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn enable_mfa(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<MfaCodeRequest>,
) -> Response {
    if request.code.trim().is_empty() {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "MFA code is required",
            "MFA code is required",
        );
    }
    let result = task::spawn_blocking(move || {
        store.enable_mfa(context.user_id, &request.code, Utc::now().timestamp())
    })
    .await;
    match result {
        // The freshly issued recovery codes are returned exactly once here; only
        // their digests are persisted, so they can never be surfaced again.
        Ok(Ok(recovery_codes)) => Json(serde_json::json!({
            "enabled": true,
            "recoveryCodes": recovery_codes,
        }))
        .into_response(),
        Ok(Err(SecurityError::MfaSetupRequired)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "MFA setup required",
            "MFA setup required",
        ),
        Ok(Err(SecurityError::InvalidMfa)) => named_json_error(
            StatusCode::UNAUTHORIZED,
            "Invalid two-factor code",
            "Invalid two-factor code",
        ),
        Ok(Err(SecurityError::MfaAlreadyEnabled)) => named_json_error(
            StatusCode::CONFLICT,
            "MFA already enabled",
            "MFA already enabled",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn disable_mfa(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<MfaCodeRequest>,
) -> Response {
    if request.code.trim().is_empty() {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "MFA code is required",
            "MFA code is required",
        );
    }
    let result = task::spawn_blocking(move || {
        store.disable_mfa(context.user_id, &request.code, Utc::now().timestamp())
    })
    .await;
    match result {
        Ok(Ok(_)) => Json(serde_json::json!({ "enabled": false })).into_response(),
        Ok(Err(SecurityError::InvalidMfa)) => named_json_error(
            StatusCode::UNAUTHORIZED,
            "Invalid two-factor code",
            "Invalid two-factor code",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn cancel_mfa_setup(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    let result = task::spawn_blocking(move || store.cancel_mfa_setup(context.user_id)).await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "cleared": true })).into_response(),
        Ok(Err(SecurityError::MfaAlreadyEnabled)) => named_json_error(
            StatusCode::CONFLICT,
            "MFA already enabled",
            "MFA already enabled",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

/// Regenerates the authenticated caller's MFA recovery codes. The operation is
/// scoped strictly to `context.user_id` (never a request-supplied identifier)
/// and, mirroring [`disable_mfa`], requires a fresh TOTP code as re-auth for
/// this sensitive action. The new plaintext codes are returned exactly once;
/// the prior set is invalidated.
async fn regenerate_recovery_codes(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Json(request): Json<MfaCodeRequest>,
) -> Response {
    if request.code.trim().is_empty() {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "MFA code is required",
            "MFA code is required",
        );
    }
    let result = task::spawn_blocking(move || {
        store.regenerate_recovery_codes(context.user_id, &request.code, Utc::now().timestamp())
    })
    .await;
    match result {
        Ok(Ok(recovery_codes)) => {
            Json(serde_json::json!({ "recoveryCodes": recovery_codes })).into_response()
        }
        Ok(Err(SecurityError::MfaSetupRequired)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "MFA is not enabled",
            "MFA is not enabled",
        ),
        Ok(Err(SecurityError::InvalidMfa)) => named_json_error(
            StatusCode::UNAUTHORIZED,
            "Invalid two-factor code",
            "Invalid two-factor code",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn disable_mfa_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Path(username): Path<String>,
) -> Response {
    let result = task::spawn_blocking(move || store.disable_mfa_by_username(&username)).await;
    match result {
        Ok(Ok(_)) => Json(serde_json::json!({ "enabled": false })).into_response(),
        Ok(Err(SecurityError::UserNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "User not found", "User not found")
        }
        Ok(Err(SecurityError::InvalidInput)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "Invalid username",
            "Invalid username",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn change_username(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let (Some(current_password), Some(new_username)) = (
        required_form_field(&fields, "currentPasswordChangeUsername"),
        required_form_field(&fields, "newUsername"),
    ) else {
        return invalid_form_response();
    };
    let current_password = Zeroizing::new(current_password.to_owned());
    let new_username = new_username.to_owned();
    let result = task::spawn_blocking(move || {
        store.change_own_username(
            context.user_id,
            &current_password,
            &new_username,
            Utc::now().timestamp(),
        )
    })
    .await;
    credential_mutation_response(
        &result,
        "Username changed successfully. Please log in again.",
    )
}

async fn register_user(
    Extension(store): Extension<Arc<SecurityStore>>,
    Json(request): Json<RegisterRequest>,
) -> Response {
    if request.username.trim().is_empty() {
        return registration_error("Invalid username format");
    }
    if request.password.is_empty() {
        return registration_error("Password is required");
    }
    let username = request.username.trim().to_owned();
    let response_username = username.clone();
    let password = request.password;
    let result =
        task::spawn_blocking(move || store.register_local_user(&username, &password)).await;
    match result {
        Ok(Ok(user_id)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "user": {
                    "id": user_id,
                    "email": response_username.clone(),
                    "username": response_username,
                    "role": "ROLE_USER",
                    "enabled": false,
                    "app_metadata": { "provider": "web" },
                },
                "message": "Account created successfully. Please log in.",
            })),
        )
            .into_response(),
        Ok(Err(SecurityError::Conflict)) => registration_error("User already exists"),
        Ok(Err(SecurityError::InvalidInput)) => registration_error("Invalid username format"),
        Ok(Err(SecurityError::UserLimitReached {
            max_allowed,
            available_slots,
        })) => registration_error(format!(
            "Maximum number of users reached. Allowed: {max_allowed}, Available slots: {available_slots}"
        )),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

fn registration_error(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message.into() })),
    )
        .into_response()
}

async fn change_password(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Response {
    change_password_fields(store, context, multipart, false).await
}

async fn change_password_on_login(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Response {
    change_password_fields(store, context, multipart, true).await
}

async fn change_password_fields(
    store: Arc<SecurityStore>,
    context: AuthContext,
    multipart: Multipart,
    require_confirmation: bool,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let (Some(current_password), Some(new_password)) = (
        required_form_field(&fields, "currentPassword"),
        required_form_field(&fields, "newPassword"),
    ) else {
        return invalid_form_response();
    };
    if require_confirmation && required_form_field(&fields, "confirmPassword") != Some(new_password)
    {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "passwordMismatch",
            "New password and confirmation do not match",
        );
    }
    let current_password = Zeroizing::new(current_password.to_owned());
    let new_password = Zeroizing::new(new_password.to_owned());
    let result = task::spawn_blocking(move || {
        store.change_own_password(
            context.user_id,
            &current_password,
            &new_password,
            Utc::now().timestamp(),
        )
    })
    .await;
    credential_mutation_response(
        &result,
        "Password changed successfully. Please log in again.",
    )
}

async fn update_user_settings(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Json(settings): Json<BTreeMap<String, String>>,
) -> Response {
    let result =
        task::spawn_blocking(move || store.replace_user_settings(context.user_id, &settings)).await;
    match result {
        Ok(Ok(())) => {
            Json(serde_json::json!({ "message": "Settings updated successfully" })).into_response()
        }
        Ok(Err(SecurityError::InvalidInput)) => invalid_form_response(),
        Ok(Err(SecurityError::UserNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "User not found", "User not found")
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn complete_initial_setup(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match task::spawn_blocking(move || store.complete_initial_setup(context.user_id)).await {
        Ok(Ok(())) => Json(serde_json::json!({ "success": true })).into_response(),
        Ok(Err(SecurityError::UserNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "User not found", "User not found")
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

fn credential_mutation_response(
    result: &Result<Result<(), SecurityError>, task::JoinError>,
    description: &'static str,
) -> Response {
    match result {
        Ok(Ok(())) => Json(serde_json::json!({
            "message": "credsUpdated",
            "description": description,
        }))
        .into_response(),
        Ok(Err(SecurityError::InvalidCredentials)) => named_json_error(
            StatusCode::UNAUTHORIZED,
            "incorrectPassword",
            "Incorrect password",
        ),
        Ok(Err(SecurityError::Conflict)) => named_json_error(
            StatusCode::CONFLICT,
            "credentialConflict",
            "The requested credential is unchanged or already in use",
        ),
        Ok(Err(SecurityError::UnsupportedAuthenticationSource)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "unsupportedAuthenticationType",
            "Credentials can only be changed for web accounts",
        ),
        Ok(Err(SecurityError::InvalidInput)) => invalid_form_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn get_api_key(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match task::spawn_blocking(move || store.has_active_api_key(context.user_id)).await {
        Ok(Ok(exists)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "API key is not retrievable. Rotate it to issue a new key.",
                "exists": exists,
                "recoverable": false,
            })),
        )
            .into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn update_api_key(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match task::spawn_blocking(move || {
        store.rotate_api_key(context.user_id, Utc::now().timestamp())
    })
    .await
    {
        Ok(Ok(api_key)) => Json(serde_json::json!({ "apiKey": api_key.as_str() })).into_response(),
        Ok(Err(SecurityError::AccountDisabled | SecurityError::UserNotFound)) => {
            unauthorized_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn list_users_by_admin(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    match task::spawn_blocking(move || store.list_users(Utc::now().timestamp())).await {
        Ok(Ok(users)) => Json(serde_json::json!({ "users": users })).into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn fleet_usage_stats(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(config): Extension<SecurityHttpConfig>,
) -> Response {
    match task::spawn_blocking(move || {
        store.fleet_usage_stats(
            config.audit_enabled && config.audit_level >= AUDIT_LEVEL_STANDARD,
            Utc::now().timestamp(),
        )
    })
    .await
    {
        Ok(Ok(stats)) => Json(stats).into_response(),
        Ok(Err(_)) | Err(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not calculate fleet usage statistics",
        ),
    }
}

async fn list_signing_users(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match task::spawn_blocking(move || store.list_users(Utc::now().timestamp())).await {
        Ok(Ok(users)) => {
            let caller_team_name = users
                .iter()
                .find(|user| user.id == context.user_id)
                .and_then(|user| user.team_name.as_deref());
            let system_or_missing_team = caller_team_name.is_none_or(|name| {
                name.eq_ignore_ascii_case("Default") || name.eq_ignore_ascii_case("Internal")
            });
            let users = users
                .into_iter()
                .filter(|user| {
                    user.enabled
                        && if system_or_missing_team {
                            user.id == context.user_id
                        } else {
                            user.team_id == context.team_id
                        }
                })
                .map(|user| {
                    serde_json::json!({
                        "id": user.id,
                        "username": user.username,
                        "displayName": user.email,
                        "teamName": user.team_name,
                        "enabled": user.enabled,
                    })
                })
                .collect::<Vec<_>>();
            Json(users).into_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn save_user_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let (Some(username), Some(password), Some(role), Some(authentication_type)) = (
        required_form_field(&fields, "username"),
        required_form_field(&fields, "password"),
        required_form_field(&fields, "role"),
        required_form_field(&fields, "authType"),
    ) else {
        return invalid_form_response();
    };
    if !authentication_type.eq_ignore_ascii_case("WEB")
        || parsed_bool_form_field(&fields, "forceChange").unwrap_or(false)
        || parsed_bool_form_field(&fields, "forceMFA").unwrap_or(false)
    {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "unsupportedAuthenticationType",
            "Only web users without pending forced setup are currently supported",
        );
    }
    let username = username.to_owned();
    let password = Zeroizing::new(password.to_owned());
    let role = role.to_ascii_uppercase();
    let team_id = parsed_i64_form_field(&fields, "teamId");
    let result = task::spawn_blocking(move || match role.as_str() {
        "ROLE_USER" => store.create_local_user(&username, &password, ["ROLE_USER"], team_id),
        "ROLE_ADMIN" => store.create_local_user(&username, &password, ["ROLE_ADMIN"], team_id),
        "ROLE_DEMO_USER" => {
            store.create_local_user(&username, &password, ["ROLE_DEMO_USER"], team_id)
        }
        _ => Err(SecurityError::InvalidInput),
    })
    .await;
    match result {
        Ok(Ok(user_id)) => Json(serde_json::json!({
            "message": "User created successfully",
            "userId": user_id,
        }))
        .into_response(),
        Ok(Err(SecurityError::Conflict)) => named_json_error(
            StatusCode::CONFLICT,
            "Username already exists.",
            "Username already exists.",
        ),
        Ok(Err(SecurityError::UserLimitReached {
            max_allowed,
            available_slots,
        })) => json_error_owned(
            StatusCode::BAD_REQUEST,
            &format!(
                "Maximum number of users reached. Allowed: {max_allowed}, Available slots: {available_slots}"
            ),
        ),
        Ok(Err(SecurityError::InvalidInput | SecurityError::TeamNotFound)) => {
            invalid_form_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn invite_users_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(config): Extension<SecurityHttpConfig>,
    Extension(mail): Extension<SecurityMailState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(emails) = fields.get("emails") else {
        return invalid_form_response();
    };
    if !config.invites_enabled {
        return bulk_invite_error_response(
            StatusCode::BAD_REQUEST,
            "Email invites are not enabled",
        );
    }
    let Some(smtp) = mail.smtp else {
        return bulk_invite_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email service is not configured. Please configure SMTP settings.",
        );
    };
    let mut email_addresses = emails.split(',').map(str::to_owned).collect::<Vec<_>>();
    if !emails.is_empty() {
        while email_addresses.last().is_some_and(String::is_empty) {
            email_addresses.pop();
        }
    }
    if email_addresses.is_empty() {
        return no_email_addresses_response();
    }
    for email in &mut email_addresses {
        *email = email.trim().to_owned();
    }
    let requested_users = email_addresses.len();
    let store_for_prepare = Arc::clone(&store);
    let capacity = task::spawn_blocking(move || {
        store_for_prepare.ensure_bulk_user_invite_capacity(requested_users)
    })
    .await;
    match capacity {
        Ok(Ok(())) => {}
        Ok(Err(SecurityError::UserLimitReached {
            max_allowed,
            available_slots,
        })) => {
            let error = format!(
                "Not enough user slots available. Allowed: {max_allowed}, Available: {available_slots}, Requested: {requested_users}"
            );
            return bulk_invite_error_response(StatusCode::BAD_REQUEST, error);
        }
        Ok(Err(_)) | Err(_) => return service_unavailable_response(),
    }
    let role = required_form_field(&fields, "role")
        .unwrap_or("ROLE_USER")
        .to_ascii_uppercase();
    if !is_invitable_role(&role) {
        return bulk_invite_error_response(StatusCode::BAD_REQUEST, "Invalid role specified");
    }
    let requested_team_id = match fields.get("teamId") {
        Some(team_id) => match team_id.trim().parse::<i64>() {
            Ok(team_id) => Some(team_id),
            Err(_) => return invalid_form_response(),
        },
        None => None,
    };
    let store_for_team = Arc::clone(&store);
    let team = task::spawn_blocking(move || {
        store_for_team.resolve_bulk_user_invite_team(requested_team_id)
    })
    .await;
    let effective_team_id = match team {
        Ok(Ok(team_id)) => team_id,
        Ok(Err(SecurityError::ProtectedSystemState)) => {
            return bulk_invite_error_response(
                StatusCode::BAD_REQUEST,
                "Cannot assign users to Internal team",
            );
        }
        Ok(Err(SecurityError::InvalidInput | SecurityError::TeamNotFound)) => {
            return invalid_form_response();
        }
        Ok(Err(_)) | Err(_) => return service_unavailable_response(),
    };
    let login_url = password_login_url(&config, &headers);
    let (success_count, failure_count, errors) = process_user_invite_batch(
        store,
        smtp,
        email_addresses,
        role,
        effective_team_id,
        login_url,
    )
    .await;
    bulk_user_invite_response(success_count, failure_count, errors)
}

fn no_email_addresses_response() -> Response {
    bulk_invite_error_response(
        StatusCode::BAD_REQUEST,
        "At least one email address is required",
    )
}

fn bulk_invite_error_response(status: StatusCode, error: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": error.into() }))).into_response()
}

async fn process_user_invite_batch(
    store: Arc<SecurityStore>,
    smtp: Arc<SmtpMailService>,
    email_addresses: Vec<String>,
    role: String,
    team_id: i64,
    login_url: String,
) -> (usize, usize, String) {
    let mut success_count = 0_usize;
    let mut failure_count = 0_usize;
    let mut errors = String::new();
    for email in email_addresses {
        if email.is_empty() {
            continue;
        }
        match invite_one_user(
            Arc::clone(&store),
            Arc::clone(&smtp),
            email,
            role.clone(),
            team_id,
            &login_url,
        )
        .await
        {
            Ok(()) => success_count += 1,
            Err(error) => {
                failure_count += 1;
                errors.push_str(&error);
                errors.push_str("; ");
            }
        }
    }
    (success_count, failure_count, errors)
}

fn bulk_user_invite_response(
    success_count: usize,
    failure_count: usize,
    errors: String,
) -> Response {
    let mut response = serde_json::json!({
        "successCount": success_count,
        "failureCount": failure_count,
    });
    if failure_count > 0
        && let Some(response) = response.as_object_mut()
    {
        response.insert("errors".to_owned(), errors.into());
    }
    if success_count > 0 {
        if let Some(response) = response.as_object_mut() {
            response.insert(
                "message".to_owned(),
                format!("{success_count} user(s) invited successfully").into(),
            );
        }
        Json(response).into_response()
    } else {
        if let Some(response) = response.as_object_mut() {
            response.insert("error".to_owned(), "Failed to invite any users".into());
        }
        (StatusCode::BAD_REQUEST, Json(response)).into_response()
    }
}

fn is_invitable_role(role: &str) -> bool {
    matches!(
        role,
        "ROLE_ADMIN"
            | "ROLE_USER"
            | "ROLE_PRO_USER"
            | "ROLE_LIMITED_API_USER"
            | "ROLE_EXTRA_LIMITED_API_USER"
            | "ROLE_WEB_ONLY_USER"
            | "ROLE_DEMO_USER"
    )
}

async fn invite_one_user(
    store: Arc<SecurityStore>,
    smtp: Arc<SmtpMailService>,
    email: String,
    role: String,
    team_id: i64,
    login_url: &str,
) -> Result<(), String> {
    if !email.contains('@') || !email.contains('.') {
        return Err(format!("{email}: Invalid email format"));
    }
    let temporary_password = random_invite_password();
    let store_email = email.clone();
    let store_password = temporary_password.clone();
    let result = task::spawn_blocking(move || {
        store.create_invited_local_user(&store_email, &store_password, &role, team_id)
    })
    .await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(SecurityError::Conflict)) => {
            return Err(format!("{email}: User already exists"));
        }
        Ok(Err(SecurityError::UserLimitReached { .. })) => {
            return Err(format!("{email}: User limit reached"));
        }
        Ok(Err(SecurityError::InvalidInput)) => {
            return Err(format!("{email}: Invalid user data"));
        }
        Ok(Err(SecurityError::TeamNotFound)) => {
            return Err(format!("{email}: Invalid team ID: {team_id}"));
        }
        Ok(Err(SecurityError::ProtectedSystemState)) => {
            return Err(format!("{email}: Invalid team"));
        }
        Ok(Err(_)) | Err(_) => {
            return Err(format!("{email}: Failed to create user"));
        }
    }
    smtp.send_user_invite(&email, &email, &temporary_password, login_url)
        .await
        .map_err(|_| format!("{email}: User created but email failed to send"))
}

async fn change_user_role_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let (Some(username), Some(role)) = (
        required_form_field(&fields, "username"),
        required_form_field(&fields, "role"),
    ) else {
        return invalid_form_response();
    };
    if username.eq_ignore_ascii_case(&context.username) {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "Cannot change your own role.",
            "Cannot change your own role.",
        );
    }
    let username = username.to_owned();
    let role = role.to_owned();
    let team_id = parsed_i64_form_field(&fields, "teamId");
    let result = task::spawn_blocking(move || {
        store.set_user_role_and_team(&username, &role, team_id, Utc::now().timestamp())
    })
    .await;
    admin_user_mutation_response(&result, "User role updated successfully")
}

async fn change_user_password_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Extension(config): Extension<SecurityHttpConfig>,
    Extension(mail): Extension<SecurityMailState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let change = match parse_admin_password_change(&fields, &context.username) {
        Ok(change) => change,
        Err(error) => return error.into_response(),
    };
    let store_username = change.username.clone();
    let store_password = change.new_password.clone();
    let force_password_change = change.force_password_change;
    let result = task::spawn_blocking(move || {
        store.set_user_password_with_force_change(
            &store_username,
            &store_password,
            force_password_change,
            Utc::now().timestamp(),
        )
    })
    .await;
    if let Err(error) = password_change_mutation_result(&result) {
        return error.into_response();
    }
    if let Some(delivery) = change.delivery.as_ref()
        && let Err(error) =
            deliver_password_change(&mail, &config, &headers, &change, delivery).await
    {
        return error.into_response();
    }
    Json(serde_json::json!({ "message": "User password updated successfully" })).into_response()
}

fn parse_admin_password_change(
    fields: &BTreeMap<String, Zeroizing<String>>,
    current_username: &str,
) -> Result<AdminPasswordChangeInput, AdminPasswordChangeError> {
    let Some(username) = required_form_field(fields, "username") else {
        return Err(AdminPasswordChangeError::InvalidForm);
    };
    if username.eq_ignore_ascii_case(current_username) {
        return Err(AdminPasswordChangeError::SelfTarget);
    }
    let generate_random = optional_bool_form_field(fields, "generateRandom", false)
        .map_err(|()| AdminPasswordChangeError::InvalidForm)?;
    let send_email = optional_bool_form_field(fields, "sendEmail", false)
        .map_err(|()| AdminPasswordChangeError::InvalidForm)?;
    let include_password = optional_bool_form_field(fields, "includePassword", false)
        .map_err(|()| AdminPasswordChangeError::InvalidForm)?;
    let force_password_change = optional_bool_form_field(fields, "forcePasswordChange", false)
        .map_err(|()| AdminPasswordChangeError::InvalidForm)?;
    let new_password = if generate_random {
        random_temporary_password()
    } else {
        let Some(new_password) = fields
            .get("newPassword")
            .filter(|password| !password.trim().is_empty())
        else {
            return Err(AdminPasswordChangeError::MissingPassword);
        };
        Zeroizing::new(new_password.to_string())
    };
    Ok(AdminPasswordChangeInput {
        username: username.to_owned(),
        new_password,
        force_password_change,
        delivery: send_email.then_some(PasswordChangeDelivery { include_password }),
    })
}

fn password_change_mutation_result(
    result: &Result<Result<i64, SecurityError>, task::JoinError>,
) -> Result<(), AdminPasswordChangeError> {
    match result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(SecurityError::UserNotFound)) => Err(AdminPasswordChangeError::UserNotFound),
        Ok(Err(SecurityError::ProtectedSystemState)) => {
            Err(AdminPasswordChangeError::ProtectedState)
        }
        Ok(Err(SecurityError::InvalidInput | SecurityError::UnsupportedAuthenticationSource)) => {
            Err(AdminPasswordChangeError::InvalidForm)
        }
        Ok(Err(_)) | Err(_) => Err(AdminPasswordChangeError::ServiceUnavailable),
    }
}

async fn deliver_password_change(
    mail: &SecurityMailState,
    config: &SecurityHttpConfig,
    headers: &HeaderMap,
    change: &AdminPasswordChangeInput,
    delivery: &PasswordChangeDelivery,
) -> Result<(), AdminPasswordChangeError> {
    let Some(smtp) = mail.smtp.as_ref() else {
        return Err(AdminPasswordChangeError::EmailNotConfigured);
    };
    if !change.username.contains('@') || !is_valid_recipient(&change.username) {
        return Err(AdminPasswordChangeError::InvalidRecipient);
    }
    let login_url = password_login_url(config, headers);
    smtp.send_password_changed(
        &change.username,
        &change.username,
        delivery
            .include_password
            .then_some(change.new_password.as_str()),
        &login_url,
    )
    .await
    .map_err(|_| AdminPasswordChangeError::DeliveryFailed)
}

async fn change_user_enabled_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Path(username): Path<String>,
    multipart: Multipart,
) -> Response {
    if username.eq_ignore_ascii_case(&context.username) {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "Cannot disable your own account.",
            "Cannot disable your own account.",
        );
    }
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(enabled) = parsed_bool_form_field(&fields, "enabled") else {
        return invalid_form_response();
    };
    let result = task::spawn_blocking(move || {
        store.set_user_enabled(&username, enabled, Utc::now().timestamp())
    })
    .await;
    let message = if enabled {
        "User enabled successfully"
    } else {
        "User disabled successfully"
    };
    admin_user_mutation_response(&result, message)
}

async fn unlock_user_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Path(username): Path<String>,
) -> Response {
    let result = task::spawn_blocking(move || store.unlock_user(&username)).await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({
            "message": "User account unlocked successfully"
        }))
        .into_response(),
        Ok(Err(SecurityError::UserNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "User not found.", "User not found.")
        }
        Ok(Err(SecurityError::InvalidInput)) => invalid_form_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn delete_user_by_admin(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Path(username): Path<String>,
) -> Response {
    if username.eq_ignore_ascii_case(&context.username) {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "Cannot delete your own account.",
            "Cannot delete your own account.",
        );
    }
    let result = task::spawn_blocking(move || store.delete_user(&username)).await;
    admin_user_mutation_response(&result, "User deleted successfully")
}

fn admin_user_mutation_response<T>(
    result: &Result<Result<T, SecurityError>, task::JoinError>,
    success_message: &'static str,
) -> Response {
    match result {
        Ok(Ok(_)) => Json(serde_json::json!({ "message": success_message })).into_response(),
        Ok(Err(SecurityError::UserNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "User not found.", "User not found.")
        }
        Ok(Err(SecurityError::TeamNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "Team not found.", "Team not found.")
        }
        Ok(Err(SecurityError::ProtectedSystemState)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "Protected account state cannot be changed.",
            "Protected account state cannot be changed.",
        ),
        Ok(Err(SecurityError::InvalidInput | SecurityError::UnsupportedAuthenticationSource)) => {
            invalid_form_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn list_teams(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    match task::spawn_blocking(move || store.list_teams()).await {
        Ok(Ok(teams)) => Json(serde_json::json!({ "teams": teams })).into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn create_team(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(name) = required_form_field(&fields, "name") else {
        return invalid_form_response();
    };
    let name = name.to_owned();
    match task::spawn_blocking(move || store.create_team(&name)).await {
        Ok(Ok(team_id)) => Json(serde_json::json!({
            "message": "Team created successfully",
            "teamId": team_id,
        }))
        .into_response(),
        Ok(Err(SecurityError::Conflict)) => named_json_error(
            StatusCode::CONFLICT,
            "Team name already exists.",
            "Team name already exists.",
        ),
        Ok(Err(SecurityError::InvalidInput)) => invalid_form_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn rename_team(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(team_id) = parsed_i64_form_field(&fields, "teamId") else {
        return invalid_form_response();
    };
    let Some(new_name) = required_form_field(&fields, "newName") else {
        return invalid_form_response();
    };
    let new_name = new_name.to_owned();
    let result = task::spawn_blocking(move || store.rename_team(team_id, &new_name)).await;
    team_mutation_response(&result, "Team renamed successfully")
}

async fn delete_team(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(team_id) = parsed_i64_form_field(&fields, "teamId") else {
        return invalid_form_response();
    };
    let result = task::spawn_blocking(move || store.delete_team(team_id)).await;
    team_mutation_response(&result, "Team deleted successfully")
}

async fn set_team_owner(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    mutate_team_owner(store, multipart, true).await
}

async fn remove_team_owner(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    mutate_team_owner(store, multipart, false).await
}

async fn mutate_team_owner(
    store: Arc<SecurityStore>,
    multipart: Multipart,
    owner: bool,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let (Some(team_id), Some(user_id)) = (
        parsed_i64_form_field(&fields, "teamId"),
        parsed_i64_form_field(&fields, "userId"),
    ) else {
        return invalid_form_response();
    };
    let result = task::spawn_blocking(move || store.set_team_owner(team_id, user_id, owner)).await;
    let message = if owner {
        "Team owner assigned successfully"
    } else {
        "Team owner removed successfully"
    };
    team_mutation_response(&result, message)
}

async fn add_user_to_team(
    Extension(store): Extension<Arc<SecurityStore>>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let (Some(team_id), Some(user_id)) = (
        parsed_i64_form_field(&fields, "teamId"),
        parsed_i64_form_field(&fields, "userId"),
    ) else {
        return invalid_form_response();
    };
    let result = task::spawn_blocking(move || {
        store.assign_user_to_team_at(user_id, team_id, Utc::now().timestamp())
    })
    .await;
    team_mutation_response(&result, "User added to team successfully")
}

#[allow(clippy::too_many_lines)]
async fn generate_invite(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Extension(config): Extension<SecurityHttpConfig>,
    Extension(mail): Extension<SecurityMailState>,
    headers: HeaderMap,
    multipart: Multipart,
) -> Response {
    if !config.invites_enabled {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "Email invites are not enabled",
            "Email invites are not enabled",
        );
    }
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let send_email = match required_form_field(&fields, "sendEmail") {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => return invalid_form_response(),
    };
    let email = required_form_field(&fields, "email").map(str::to_owned);
    if send_email && email.is_none() {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "Cannot send email without an email address",
            "Cannot send email without an email address",
        );
    }
    let role = required_form_field(&fields, "role")
        .unwrap_or("ROLE_USER")
        .to_owned();
    let team_id = parsed_i64_form_field(&fields, "teamId");
    let expiry_hours = required_form_field(&fields, "expiryHours")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|hours| *hours > 0)
        .unwrap_or(config.invite_expiry_hours)
        .min(24 * 365);
    let now = Utc::now().timestamp();
    let Ok(expiry_seconds) = i64::try_from(expiry_hours.saturating_mul(60 * 60)) else {
        return invalid_form_response();
    };
    let expires_at = now.saturating_add(expiry_seconds);
    let result = task::spawn_blocking(move || {
        store.create_invite(&context, email.as_deref(), &role, team_id, now, expires_at)
    })
    .await;
    match result {
        Ok(Ok(invite)) => {
            let base_url = invite_base_url(&config, &fields, &headers);
            let invite_url = if base_url.is_empty() {
                format!("/invite/{}", invite.token.as_str())
            } else {
                format!("{base_url}/invite/{}", invite.token.as_str())
            };
            let expires_at = timestamp_string(invite.expires_at);
            let mut response = serde_json::json!({
                "token": invite.token.as_str(),
                "inviteUrl": &invite_url,
                "email": &invite.email,
                "expiresAt": &expires_at,
                "expiryHours": expiry_hours,
            });
            if send_email {
                let delivery = match (mail.smtp.as_ref(), invite.email.as_deref()) {
                    (Some(smtp), Some(recipient)) => smtp
                        .send_invite_link(recipient, &invite_url, &expires_at)
                        .await
                        .map_err(|error| error.to_string()),
                    _ => Err("Email service is not configured".to_owned()),
                };
                if let Some(response) = response.as_object_mut() {
                    response.insert("emailSent".to_owned(), delivery.is_ok().into());
                    if let Err(error) = delivery {
                        response.insert("emailError".to_owned(), error.into());
                    }
                }
            }
            Json(response).into_response()
        }
        Ok(Err(SecurityError::Conflict)) => named_json_error(
            StatusCode::CONFLICT,
            "An active invite or user already exists for this email address",
            "An active invite or user already exists for this email address",
        ),
        Ok(Err(
            SecurityError::InvalidInput
            | SecurityError::TeamNotFound
            | SecurityError::ProtectedSystemState,
        )) => invalid_form_response(),
        Ok(Err(SecurityError::UserLimitReached {
            max_allowed,
            available_slots,
        })) => {
            let occupied = max_allowed.saturating_sub(available_slots);
            json_error_owned(
                StatusCode::BAD_REQUEST,
                &format!(
                    "License limit reached ({occupied}/{max_allowed} users). Contact your administrator to upgrade your license."
                ),
            )
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

fn invite_base_url(
    config: &SecurityHttpConfig,
    fields: &BTreeMap<String, Zeroizing<String>>,
    headers: &HeaderMap,
) -> String {
    validated_http_base_url(&config.frontend_url)
        .or_else(|| {
            required_form_field(fields, "frontendBaseUrl").and_then(validated_http_base_url)
        })
        .or_else(|| validated_http_base_url(&config.backend_url))
        .or_else(|| request_base_url(headers))
        .unwrap_or_default()
}

fn validated_http_base_url(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches('/');
    (!url.is_empty()
        && (url.starts_with("https://") || url.starts_with("http://"))
        && !url.chars().any(char::is_control))
    .then(|| url.to_owned())
}

fn request_base_url(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?.trim();
    if host.is_empty() || host.chars().any(char::is_control) {
        return None;
    }
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    Some(format!("{scheme}://{host}"))
}

fn password_login_url(config: &SecurityHttpConfig, headers: &HeaderMap) -> String {
    let base_url = validated_http_base_url(&config.frontend_url)
        .or_else(|| request_base_url(headers))
        .unwrap_or_default();
    if base_url.is_empty() {
        "/login".to_owned()
    } else {
        format!("{base_url}/login")
    }
}

async fn list_invites(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    match task::spawn_blocking(move || store.list_active_invites(Utc::now().timestamp())).await {
        Ok(Ok(invites)) => {
            let invites = invites
                .into_iter()
                .map(|invite| {
                    serde_json::json!({
                        "id": invite.id,
                        "email": invite.email,
                        "role": invite.role,
                        "teamId": invite.team_id,
                        "createdBy": invite.created_by,
                        "createdAt": timestamp_string(invite.created_at),
                        "expiresAt": timestamp_string(invite.expires_at),
                    })
                })
                .collect::<Vec<_>>();
            Json(serde_json::json!({ "invites": invites })).into_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn revoke_invite(
    Extension(store): Extension<Arc<SecurityStore>>,
    Path(invite_id): Path<i64>,
) -> Response {
    let result =
        task::spawn_blocking(move || store.revoke_invite(invite_id, Utc::now().timestamp())).await;
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "message": "Invite link revoked successfully" }))
            .into_response(),
        Ok(Err(SecurityError::InvalidInvite)) => named_json_error(
            StatusCode::NOT_FOUND,
            "Invite not found",
            "Invite not found",
        ),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn cleanup_invites(Extension(store): Extension<Arc<SecurityStore>>) -> Response {
    match task::spawn_blocking(move || store.cleanup_invites(Utc::now().timestamp())).await {
        Ok(Ok(deleted_count)) => {
            Json(serde_json::json!({ "deletedCount": deleted_count })).into_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn validate_invite(
    Extension(store): Extension<Arc<SecurityStore>>,
    Path(token): Path<String>,
) -> Response {
    match task::spawn_blocking(move || store.validate_invite(&token, Utc::now().timestamp())).await
    {
        Ok(Ok(invite)) => Json(serde_json::json!({
            "email": invite.email,
            "role": invite.role,
            "teamId": invite.team_id,
            "expiresAt": timestamp_string(invite.expires_at),
            "emailRequired": invite.email_required,
        }))
        .into_response(),
        Ok(Err(_)) | Err(_) => invalid_invite_response(),
    }
}

async fn accept_invite(
    Extension(store): Extension<Arc<SecurityStore>>,
    Path(token): Path<String>,
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(password) = required_form_field(&fields, "password") else {
        return invalid_form_response();
    };
    let password = Zeroizing::new(password.to_owned());
    let email = required_form_field(&fields, "email").map(str::to_owned);
    let result = task::spawn_blocking(move || {
        store.accept_invite(&token, email.as_deref(), &password, Utc::now().timestamp())
    })
    .await;
    match result {
        Ok(Ok(username)) => Json(serde_json::json!({
            "message": "Account created successfully",
            "username": username,
        }))
        .into_response(),
        Ok(Err(SecurityError::InvalidInput)) => invalid_form_response(),
        Ok(Err(SecurityError::InvalidInvite | SecurityError::Conflict)) => {
            invalid_invite_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

fn invalid_invite_response() -> Response {
    named_json_error(
        StatusCode::BAD_REQUEST,
        "Invalid or expired invitation link",
        "Invalid or expired invitation link",
    )
}

fn timestamp_string(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map_or_else(String::new, |value| value.to_rfc3339())
}

fn team_mutation_response(
    result: &Result<Result<(), SecurityError>, task::JoinError>,
    success_message: &'static str,
) -> Response {
    match result {
        Ok(Ok(())) => Json(serde_json::json!({ "message": success_message })).into_response(),
        Ok(Err(SecurityError::TeamNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "Team not found.", "Team not found.")
        }
        Ok(Err(SecurityError::UserNotFound)) => {
            named_json_error(StatusCode::NOT_FOUND, "User not found.", "User not found.")
        }
        Ok(Err(SecurityError::Conflict)) => named_json_error(
            StatusCode::CONFLICT,
            "Team name already exists.",
            "Team name already exists.",
        ),
        Ok(Err(SecurityError::TeamNotEmpty)) => named_json_error(
            StatusCode::BAD_REQUEST,
            "Team must be empty before deletion. Please remove all members first.",
            "Team must be empty before deletion. Please remove all members first.",
        ),
        Ok(Err(SecurityError::ProtectedSystemState | SecurityError::InvalidInput)) => {
            invalid_form_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn bounded_multipart_fields(
    mut multipart: Multipart,
) -> Result<BTreeMap<String, Zeroizing<String>>, Response> {
    let mut fields = BTreeMap::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| invalid_form_response())?
    {
        if fields.len() >= 16 {
            return Err(invalid_form_response());
        }
        let name = field.name().ok_or_else(invalid_form_response)?.to_owned();
        if name.len() > 64 || fields.contains_key(&name) {
            return Err(invalid_form_response());
        }
        let value = field.text().await.map_err(|_| invalid_form_response())?;
        if value.len() > 4096 {
            return Err(invalid_form_response());
        }
        SecurityAuditContext::record_current_form_param(&name, &value);
        fields.insert(name, Zeroizing::new(value));
    }
    Ok(fields)
}

fn required_form_field<'a>(
    fields: &'a BTreeMap<String, Zeroizing<String>>,
    name: &str,
) -> Option<&'a str> {
    fields
        .get(name)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

fn parsed_i64_form_field(fields: &BTreeMap<String, Zeroizing<String>>, name: &str) -> Option<i64> {
    required_form_field(fields, name)?
        .parse()
        .ok()
        .filter(|value| *value > 0)
}

fn parsed_bool_form_field(
    fields: &BTreeMap<String, Zeroizing<String>>,
    name: &str,
) -> Option<bool> {
    match required_form_field(fields, name)? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn optional_bool_form_field(
    fields: &BTreeMap<String, Zeroizing<String>>,
    name: &str,
    default: bool,
) -> Result<bool, ()> {
    match required_form_field(fields, name) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(()),
    }
}

fn invalid_form_response() -> Response {
    named_json_error(
        StatusCode::BAD_REQUEST,
        "Invalid request",
        "Invalid request",
    )
}

async fn current_user(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    let user_id = context.user_id;
    // Report MFA status alongside the account so a UI can prompt to enable MFA
    // and warn when recovery codes are running low. Scoped to the caller.
    let mfa = task::spawn_blocking(move || {
        let enabled = store.mfa_is_enabled(user_id)?;
        let recovery_codes_remaining = store.remaining_recovery_codes(user_id)?;
        Ok::<_, SecurityError>((enabled, recovery_codes_remaining))
    })
    .await;
    match mfa {
        Ok(Ok((enabled, recovery_codes_remaining))) => Json(serde_json::json!({
            "user": authentication_user(&context),
            "mfa": {
                "enabled": enabled,
                "recoveryCodesRemaining": recovery_codes_remaining,
            },
        }))
        .into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn refresh(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(correlation): Extension<RequestCorrelation>,
    request: Request,
) -> Response {
    let bearer = match bearer_token(request.headers()) {
        Ok(token) => token.map(str::to_owned),
        Err(()) => return unauthorized_response(),
    };
    let Ok(body) = to_bytes(request.into_body(), MAX_AUTH_BODY_BYTES).await else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid request");
    };
    let refresh_request = if body.is_empty() {
        RefreshRequest::default()
    } else {
        match serde_json::from_slice::<RefreshRequest>(&body) {
            Ok(request) => request,
            Err(_) => return json_error(StatusCode::BAD_REQUEST, "Invalid request"),
        }
    };
    if bearer.is_some() == refresh_request.refresh_token.is_some() {
        return unauthorized_response();
    }
    let store_for_refresh = Arc::clone(&store);
    let correlation_id = correlation.0;
    let result = task::spawn_blocking(move || {
        let now = Utc::now().timestamp();
        let tokens = if let Some(token) = bearer {
            store_for_refresh.rotate_access_token(
                &token,
                now,
                REFRESH_GRACE,
                DEFAULT_ACCESS_TTL,
                DEFAULT_REFRESH_TTL,
            )?
        } else {
            store_for_refresh.rotate_refresh_token(
                refresh_request
                    .refresh_token
                    .as_ref()
                    .map_or("", |token| token.as_str()),
                now,
                DEFAULT_ACCESS_TTL,
                DEFAULT_REFRESH_TTL,
            )?
        };
        let context = store_for_refresh.authenticate_access_token(
            &tokens.access_token,
            now,
            &correlation_id,
        )?;
        Ok::<_, SecurityError>((context, tokens))
    })
    .await;
    match result {
        Ok(Ok((context, tokens))) => Json(AuthenticationResponse {
            user: authentication_user(&context),
            session: tokens,
        })
        .into_response(),
        Ok(Err(
            SecurityError::InvalidToken
            | SecurityError::ExpiredToken
            | SecurityError::AccountDisabled,
        )) => unauthorized_response(),
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
}

async fn logout(Extension(store): Extension<Arc<SecurityStore>>, request: Request) -> Response {
    let token = match bearer_token(request.headers()) {
        Ok(token) => token.map(|token| Zeroizing::new(token.to_owned())),
        Err(()) => return unauthorized_response(),
    };
    if let Some(token) = token.filter(|token| token.starts_with("spdf_at_")) {
        let result =
            task::spawn_blocking(move || store.revoke_access_token(&token, Utc::now().timestamp()))
                .await;
        if !matches!(result, Ok(Ok(()))) {
            return service_unavailable_response();
        }
    }
    Json(serde_json::json!({ "message": "Logged out successfully" })).into_response()
}

fn authentication_user(context: &AuthContext) -> AuthenticationUser {
    let authentication_type = match context.authentication_type.as_str() {
        "anonymous" => "anonymous",
        "oauth2" => "oauth2",
        "supabase" => "supabase",
        _ => "web",
    };
    AuthenticationUser {
        id: context.user_id,
        email: context.username.clone(),
        username: context.username.clone(),
        role: context.roles.iter().cloned().collect::<Vec<_>>().join(", "),
        enabled: true,
        portal_access: context.has_role("ROLE_ADMIN"),
        team_lead: false,
        authentication_type,
        app_metadata: AppMetadata {
            provider: authentication_type,
        },
        user_metadata: UserMetadata {
            first_login: false,
            force_password_change: context.force_password_change,
        },
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let Some(value) = single_header(headers, &header::AUTHORIZATION)? else {
        return Ok(None);
    };
    let token = value.strip_prefix("Bearer ").ok_or(())?;
    if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(());
    }
    Ok(Some(token))
}

fn single_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn random_request_id() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    format!("req_{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn random_temporary_password() -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 6];
    rand::rng().fill(&mut bytes);
    let mut password = String::with_capacity(12);
    for byte in bytes {
        password.push(char::from(HEX[usize::from(byte >> 4)]));
        password.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Zeroizing::new(password)
}

fn random_invite_password() -> Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 6];
    rand::rng().fill(&mut bytes);
    let mut password = String::with_capacity(12);
    for byte in &bytes[..4] {
        password.push(char::from(HEX[usize::from(byte >> 4)]));
        password.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    password.push('-');
    password.push(char::from(HEX[usize::from(bytes[4] >> 4)]));
    password.push(char::from(HEX[usize::from(bytes[4] & 0x0f)]));
    password.push(char::from(HEX[usize::from(bytes[5] >> 4)]));
    Zeroizing::new(password)
}

fn denial_response(denial: AuthorizationDenial, request_id: &str) -> Response {
    let (status, message) = match denial {
        AuthorizationDenial::AuthenticationRequired
        | AuthorizationDenial::ParticipantTokenRequired => {
            (StatusCode::UNAUTHORIZED, "Authentication required")
        }
        AuthorizationDenial::DemoUserRestricted => (
            StatusCode::FORBIDDEN,
            "This account cannot perform this action",
        ),
        AuthorizationDenial::AdministratorRequired => {
            (StatusCode::FORBIDDEN, "Administrator access required")
        }
    };
    with_request_id(json_error(status, message), request_id)
}

fn entitlement_denial_response(
    required: EndpointEntitlement,
    path: &str,
    request_id: &str,
) -> Response {
    let detail = match required {
        EndpointEntitlement::Enterprise => "This endpoint requires an Enterprise license",
        EndpointEntitlement::ServerOrEnterprise => {
            "This endpoint requires a Server or Enterprise license"
        }
        EndpointEntitlement::Unrestricted => "Forbidden",
    };
    let response = (
        StatusCode::FORBIDDEN,
        [(header::CONTENT_TYPE, "application/problem+json")],
        Json(serde_json::json!({
            "type": "/errors/403",
            "title": "Forbidden",
            "status": 403,
            "detail": detail,
            "timestamp": Utc::now().to_rfc3339(),
            "path": path,
        })),
    )
        .into_response();
    with_request_id(response, request_id)
}

fn unauthorized_response() -> Response {
    json_error(StatusCode::UNAUTHORIZED, "Authentication required")
}

fn service_unavailable_response() -> Response {
    json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Authentication service unavailable",
    )
}

fn json_error(status: StatusCode, message: &'static str) -> Response {
    json_error_owned(status, message)
}

fn json_error_owned(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": status.canonical_reason().unwrap_or("Request rejected"),
            "message": message,
            "status": status.as_u16(),
        })),
    )
        .into_response()
}

fn named_json_error(status: StatusCode, error: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "message": message,
            "status": status.as_u16(),
        })),
    )
        .into_response()
}

fn with_request_id(mut response: Response, request_id: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{
        API_KEY_HEADER, AUDIT_LEVEL_STANDARD, AUDIT_LEVEL_VERBOSE, AUTOMATION_HEADER,
        MAX_AUDIT_RESULT_CHARS, OIDC_CSRF_COOKIE, SecurityAuditFileCaptureConfig,
        SecurityHttpConfig, SecurityStartupError, audit_client_ip, bounded_operation_result,
        inferred_audit_event, initialize_security_store, oidc_binding_cookie,
        oidc_binding_cookie_value, oidc_redirect_origin, random_temporary_password, secure_router,
        secure_router_with_config, spa_redirect_path,
    };
    use crate::admin_settings::AdminSettingsService;
    use crate::job_manager::{JobManager, JobOwner};
    use crate::job_queue::{JobQueue, JobQueueConfig};
    use crate::runtime_config::RuntimeConfig;
    use crate::security::{SecurityAuditContext, SecurityAuditFilter, SecurityStore};
    use crate::security_crypto::totp_code_at;
    use crate::security_jwt::{SupabaseJwtConfig, SupabaseJwtVerifier};
    use crate::security_policy::LicenseTier;
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        extract::ConnectInfo,
        http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header},
        routing::{get, post},
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde::Serialize;
    use serde_json::Value;
    use std::{fs, net::SocketAddr, sync::Arc};
    use tempfile::tempdir;
    use tower::ServiceExt as _;

    #[test]
    fn storage_file_mutations_use_java_file_operation_category() {
        assert_eq!(
            inferred_audit_event(&axum::http::Method::POST, "/api/v1/storage/files"),
            "FILE_OPERATION"
        );
        assert_eq!(
            inferred_audit_event(&axum::http::Method::PUT, "/api/v1/storage/files/42"),
            "FILE_OPERATION"
        );
    }

    #[test]
    fn audit_client_ip_uses_java_proxy_then_peer_precedence()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut request = Request::get("/").body(Body::empty())?;
        request
            .extensions_mut()
            .insert(ConnectInfo("192.0.2.44:8443".parse::<SocketAddr>()?));
        request
            .headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("198.51.100.8"));
        request.headers_mut().insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.8"),
        );
        assert_eq!(audit_client_ip(&request).as_deref(), Some("203.0.113.9"));

        request.headers_mut().remove("x-forwarded-for");
        assert_eq!(audit_client_ip(&request).as_deref(), Some("198.51.100.8"));

        request.headers_mut().remove("x-real-ip");
        assert_eq!(audit_client_ip(&request).as_deref(), Some("192.0.2.44"));
        Ok(())
    }

    #[test]
    fn oidc_binding_cookie_carries_the_login_csrf_hardening_attributes()
    -> Result<(), Box<dyn std::error::Error>> {
        let cookie = oidc_binding_cookie("binding-value-abc", std::time::Duration::from_secs(600))
            .ok_or("cookie should build for a base64url value")?;
        let value = cookie.to_str()?;
        assert!(value.starts_with(&format!("{OIDC_CSRF_COOKIE}=binding-value-abc")));
        // Every attribute that makes this a server-enforced login-CSRF binding.
        assert!(
            value.contains("HttpOnly"),
            "cookie must be HttpOnly: {value}"
        );
        assert!(value.contains("Secure"), "cookie must be Secure: {value}");
        assert!(
            value.contains("SameSite=Lax"),
            "cookie must be SameSite=Lax: {value}"
        );
        assert!(
            value.contains("Path=/api/v1/auth/oidc"),
            "cookie must be path-scoped to the OIDC routes: {value}"
        );
        assert!(
            value.contains("Max-Age=600"),
            "cookie Max-Age must track the state TTL: {value}"
        );
        Ok(())
    }

    #[test]
    fn oidc_binding_cookie_value_is_read_from_a_multi_cookie_header()
    -> Result<(), Box<dyn std::error::Error>> {
        // Present among other cookies, with padding whitespace.
        let request = Request::get("/api/v1/auth/oidc/callback")
            .header(
                header::COOKIE,
                format!("session=xyz; {OIDC_CSRF_COOKIE}=the-binding ; theme=dark"),
            )
            .body(Body::empty())?;
        assert_eq!(
            oidc_binding_cookie_value(request.headers()).as_deref(),
            Some("the-binding")
        );

        // Absent ⇒ None (a callback with no binding cookie is rejected upstream).
        let no_cookie = Request::get("/api/v1/auth/oidc/callback")
            .header(header::COOKIE, "session=xyz; theme=dark")
            .body(Body::empty())?;
        assert_eq!(oidc_binding_cookie_value(no_cookie.headers()), None);

        // No Cookie header at all ⇒ None.
        let bare = Request::get("/api/v1/auth/oidc/callback").body(Body::empty())?;
        assert_eq!(oidc_binding_cookie_value(bare.headers()), None);
        Ok(())
    }

    #[tokio::test]
    async fn oidc_callback_without_a_binding_cookie_redirects_to_the_generic_error_location()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router_with_oidc()?;
        // A syntactically-valid callback (code+state present) but no binding
        // cookie: the route is public (reaches the handler, not the auth
        // middleware) and collapses to the single browser failure redirect —
        // never a 500, never a distinguishing error value (Java's failure
        // handler redirects this browser flow too, it does not answer JSON).
        let response = app
            .oneshot(
                Request::get("/api/v1/auth/oidc/callback?code=some-code&state=some-state")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/auth/callback?errorOAuth=oauth2AuthenticationError")
        );
        // The SPA redirect-path cookie is cleared with Java's exact attributes.
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("stirling_redirect_path=; Path=/; Max-Age=0; SameSite=Lax")
        );
        Ok(())
    }

    #[test]
    fn spa_redirect_path_honors_a_valid_cookie_and_rejects_hostile_ones()
    -> Result<(), Box<dyn std::error::Error>> {
        let with_cookie = |value: &str| -> Result<String, Box<dyn std::error::Error>> {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                HeaderValue::from_str(&format!("stirling_redirect_path={value}"))?,
            );
            Ok(spa_redirect_path(&headers))
        };
        // No cookie at all ⇒ the default SPA callback path.
        assert_eq!(spa_redirect_path(&HeaderMap::new()), "/auth/callback");
        // The SPA writes the path through encodeURIComponent, so `/` arrives
        // as `%2F` — decoded with URLDecoder semantics (`+` ⇒ space too).
        assert_eq!(with_cookie("%2Fdashboard")?, "/dashboard");
        assert_eq!(with_cookie("/plain/path")?, "/plain/path");
        assert_eq!(with_cookie("%2Fa+b")?, "/a b");
        // Not an absolute path ⇒ default (Java's startsWith("/") rule).
        assert_eq!(with_cookie("relative/path")?, "/auth/callback");
        assert_eq!(with_cookie("https%3A%2F%2Fevil.example")?, "/auth/callback");
        // Protocol-relative would be an open redirect on the context-relative
        // failure Location ⇒ rejected (hardening on top of Java).
        assert_eq!(with_cookie("%2F%2Fevil.example")?, "/auth/callback");
        assert_eq!(with_cookie("//evil.example")?, "/auth/callback");
        assert_eq!(with_cookie("%2F%5Cevil.example")?, "/auth/callback");
        // A truncated escape is where Java would throw ⇒ default here.
        assert_eq!(with_cookie("%2")?, "/auth/callback");
        assert_eq!(with_cookie("%zz")?, "/auth/callback");
        Ok(())
    }

    #[test]
    fn oidc_redirect_origin_follows_javas_forwarded_referer_host_precedence()
    -> Result<(), Box<dyn std::error::Error>> {
        let origin = |pairs: &[(&str, &str)]| -> Result<String, Box<dyn std::error::Error>> {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.insert(HeaderName::try_from(*name)?, HeaderValue::from_str(value)?);
            }
            Ok(oidc_redirect_origin(&headers))
        };

        // Forwarded host wins over referer and host; first entry of each list.
        assert_eq!(
            origin(&[
                ("x-forwarded-host", "app.example.test, inner.proxy"),
                ("x-forwarded-proto", "https, http"),
                ("referer", "https://elsewhere.example"),
                ("host", "127.0.0.1:8080"),
            ])?,
            "https://app.example.test"
        );
        // Forwarded port is appended only when the host has none and the port
        // is not the scheme default.
        assert_eq!(
            origin(&[
                ("x-forwarded-host", "app.example.test"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-port", "8443"),
            ])?,
            "https://app.example.test:8443"
        );
        assert_eq!(
            origin(&[
                ("x-forwarded-host", "app.example.test"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-port", "443"),
            ])?,
            "https://app.example.test"
        );
        assert_eq!(
            origin(&[
                ("x-forwarded-host", "app.example.test:9000"),
                ("x-forwarded-port", "8443"),
            ])?,
            "http://app.example.test:9000"
        );
        // No forwarded host ⇒ referer origin (explicit non-default port kept).
        assert_eq!(
            origin(&[
                ("referer", "https://spa.example.test:8443/login"),
                ("host", "127.0.0.1:8080"),
            ])?,
            "https://spa.example.test:8443"
        );
        // ...unless the referer is the IdP itself ⇒ fall through to Host.
        assert_eq!(
            origin(&[
                ("referer", "https://accounts.google.com/o/oauth2"),
                ("host", "127.0.0.1:8080"),
            ])?,
            "http://127.0.0.1:8080"
        );
        // Host alone: the engine speaks plain http; default port dropped.
        assert_eq!(
            origin(&[("host", "example.test:80")])?,
            "http://example.test"
        );
        // Nothing at all ⇒ empty origin, the Location stays context-relative.
        assert_eq!(origin(&[])?, "");
        Ok(())
    }

    #[tokio::test]
    async fn protects_default_routes_and_leaves_health_public()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let health = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty())?)
            .await?;
        assert_eq!(health.status(), StatusCode::OK);
        assert!(health.headers().contains_key("x-request-id"));

        let denied = app
            .oneshot(Request::get("/api/v1/general/protected").body(Body::empty())?)
            .await?;
        assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
        assert!(denied.headers().contains_key("x-request-id"));
        Ok(())
    }

    #[tokio::test]
    async fn commercial_routes_enforce_verified_tiers_and_enterprise_only_auditing()
    -> Result<(), Box<dyn std::error::Error>> {
        let (normal_app, normal_store) = test_router_with_license_tier(LicenseTier::Normal)?;
        let normal_login = response_json(login_request(&normal_app, None).await?).await?;
        let normal_token = normal_login["session"]["access_token"]
            .as_str()
            .ok_or("missing normal access token")?;
        let (content_type, body) = multipart_body(&[("name", "Normal Team")]);
        let denied_team = normal_app
            .clone()
            .oneshot(
                Request::post("/api/v1/team/create")
                    .header(header::AUTHORIZATION, format!("Bearer {normal_token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(denied_team.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            denied_team.headers()[header::CONTENT_TYPE],
            "application/problem+json"
        );
        let denied_team = response_json(denied_team).await?;
        assert_eq!(denied_team["type"], "/errors/403");
        assert_eq!(denied_team["title"], "Forbidden");
        assert_eq!(denied_team["status"], 403);
        assert_eq!(
            denied_team["detail"],
            "This endpoint requires a Server or Enterprise license"
        );
        assert_eq!(denied_team["path"], "/api/v1/team/create");
        assert!(denied_team["timestamp"].is_string());
        assert!(
            normal_store
                .export_audit_events(&SecurityAuditFilter::default())?
                .is_empty()
        );

        let (server_app, server_store) = test_router_with_license_tier(LicenseTier::Server)?;
        let server_login = response_json(login_request(&server_app, None).await?).await?;
        let server_token = server_login["session"]["access_token"]
            .as_str()
            .ok_or("missing server access token")?;
        let (content_type, body) = multipart_body(&[("name", "Server Team")]);
        let allowed_team = server_app
            .clone()
            .oneshot(
                Request::post("/api/v1/team/create")
                    .header(header::AUTHORIZATION, format!("Bearer {server_token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(allowed_team.status(), StatusCode::OK);
        let denied_audit = authorized_get(&server_app, "/api/v1/audit/data", server_token).await?;
        assert_eq!(denied_audit.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response_json(denied_audit).await?["detail"],
            "This endpoint requires an Enterprise license"
        );
        assert!(
            server_store
                .export_audit_events(&SecurityAuditFilter::default())?
                .is_empty()
        );

        let (enterprise_app, enterprise_store) =
            test_router_with_license_tier(LicenseTier::Enterprise)?;
        let enterprise_login = response_json(login_request(&enterprise_app, None).await?).await?;
        let enterprise_token = enterprise_login["session"]["access_token"]
            .as_str()
            .ok_or("missing enterprise access token")?;
        let (content_type, body) = multipart_body(&[("name", "Enterprise Team")]);
        let allowed_team = enterprise_app
            .clone()
            .oneshot(
                Request::post("/api/v1/team/create")
                    .header(header::AUTHORIZATION, format!("Bearer {enterprise_token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(allowed_team.status(), StatusCode::OK);
        let events = enterprise_store.export_audit_events(&SecurityAuditFilter::default())?;
        assert!(
            events
                .iter()
                .any(|event| audit_event_has_path(event, "/api/v1/team/create"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_mutations_write_one_typed_post_handler_audit_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, store) = test_router_with_store()?;
        let login = response_json(login_request(&app, None).await?).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        let rotated = app
            .clone()
            .oneshot(
                Request::post("/api/v1/user/update-api-key")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(rotated.status(), StatusCode::OK);
        assert_eq!(store.audit_event_count()?, 2);
        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        let mutation_events = events
            .iter()
            .filter(|event| audit_event_has_path(event, "/api/v1/user/update-api-key"))
            .collect::<Vec<_>>();
        assert_eq!(mutation_events.len(), 1);
        assert_eq!(mutation_events[0].event_type, "USER_PROFILE_UPDATE");
        // update-api-key is now an explicit (`explicit_audit_event`) event so its
        // freshly-rotated key is never captured as a raw result; Java leaves
        // `source` null for explicit @Audited events, matched here by "".
        assert_eq!(mutation_events[0].source, "");
        let details: Value = serde_json::from_str(&mutation_events[0].data)?;
        // Explicit/@Audited-equivalent events use "status" (not "outcome") and
        // never carry the verbose HTTP metadata (statusCode/sessionId/latencyMs)
        // reserved for `include_standard_data`, which is always false when
        // annotated - this is also what keeps the rotated key out of `data`.
        assert_eq!(details["status"], "success");
        assert_eq!(details["httpMethod"], "POST");
        assert!(details.get("statusCode").is_none());
        assert!(details.get("result").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn controller_audit_classifies_processing_sources_and_returned_errors_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, store) = test_router_with_store()?;
        let login = response_json(login_request(&app, None).await?).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;

        let returned_error = authorized_post(
            &app,
            "/api/v1/general/process",
            access_token,
            Some(("x-forwarded-for", "203.0.113.9, 198.51.100.8")),
        )
        .await?;
        assert_eq!(returned_error.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            authorized_post(&app, "/api/v1/ai/test", access_token, None)
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            authorized_post(
                &app,
                "/api/v1/ai/test",
                access_token,
                Some((AUTOMATION_HEADER.as_str(), "true")),
            )
            .await?
            .status(),
            StatusCode::OK
        );

        let rotated = response_json(
            authorized_post(&app, "/api/v1/user/update-api-key", access_token, None).await?,
        )
        .await?;
        let api_key = rotated["apiKey"].as_str().ok_or("missing API key")?;
        let api_response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/general/process")
                    .header(API_KEY_HEADER, api_key)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(api_response.status(), StatusCode::BAD_REQUEST);

        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        let processing_events = events
            .iter()
            .filter(|event| audit_event_has_path(event, "/api/v1/general/process"))
            .collect::<Vec<_>>();
        assert_eq!(processing_events.len(), 2);
        assert!(
            processing_events
                .iter()
                .all(|event| event.event_type == "PDF_PROCESS")
        );
        assert!(processing_events.iter().any(|event| event.source == "WEB"));
        assert!(processing_events.iter().any(|event| event.source == "API"));
        let web_details: Value = serde_json::from_str(
            &processing_events
                .iter()
                .find(|event| event.source == "WEB")
                .ok_or("missing WEB event")?
                .data,
        )?;
        assert_eq!(web_details["outcome"], "success");
        assert_eq!(web_details["statusCode"], 400);
        assert_eq!(web_details["clientIp"], "203.0.113.9");
        assert_eq!(web_details["__ipAddress"], "203.0.113.9");

        let ai_sources = events
            .iter()
            .filter(|event| audit_event_has_path(event, "/api/v1/ai/test"))
            .map(|event| event.source.as_str())
            .collect::<Vec<_>>();
        assert!(ai_sources.contains(&"AI"));
        assert!(ai_sources.contains(&"AUTOMATION"));

        let fleet = store.fleet_usage_stats(true, Utc::now().timestamp())?;
        assert_eq!(fleet.active_this_month, Some(1));
        assert_eq!(fleet.pdfs_processed, Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn controller_audit_merges_bounded_policy_context_after_handler_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, store) = test_router_with_store()?;
        let login = response_json(login_request(&app, None).await?).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;

        let response = authorized_post(&app, "/api/v1/policies/run", access_token, None).await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        let event = events
            .iter()
            .find(|event| audit_event_has_path(event, "/api/v1/policies/run"))
            .ok_or("missing policy audit event")?;
        let details: Value = serde_json::from_str(&event.data)?;
        assert_eq!(details["policyName"], "Nightly  run");
        assert_eq!(details["policySteps"].as_array().map(Vec::len), Some(50));
        assert_eq!(details["policySteps"][0], "/api/v1/general/rotate-pdf");
        assert!(details.get("automation").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn controller_audit_honors_enabled_level_and_exact_standard_polling()
    -> Result<(), Box<dyn std::error::Error>> {
        for (enabled, level) in [(false, AUDIT_LEVEL_VERBOSE), (true, 0)] {
            let (app, store) = test_router_with_audit_config(enabled, level, false)?;
            let login = response_json(login_request(&app, None).await?).await?;
            let token = login["session"]["access_token"]
                .as_str()
                .ok_or("missing access token")?;
            assert_eq!(
                authorized_post(&app, "/api/v1/general/process", token, None)
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
            assert_eq!(store.audit_event_count()?, 0);
        }

        let (standard_app, standard_store) =
            test_router_with_audit_config(true, AUDIT_LEVEL_STANDARD, false)?;
        let standard_login = response_json(login_request(&standard_app, None).await?).await?;
        let standard_token = standard_login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        assert_eq!(
            authorized_get(&standard_app, "/api/v1/auth/me", standard_token)
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(standard_store.audit_event_count()?, 1);

        let (verbose_app, verbose_store) =
            test_router_with_audit_config(true, AUDIT_LEVEL_VERBOSE, false)?;
        let verbose_login = response_json(login_request(&verbose_app, None).await?).await?;
        let verbose_token = verbose_login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        assert_eq!(
            authorized_get(&verbose_app, "/api/v1/auth/me", verbose_token)
                .await?
                .status(),
            StatusCode::OK
        );
        let verbose_events = verbose_store.export_audit_events(&SecurityAuditFilter::default())?;
        assert!(verbose_events.iter().any(|event| {
            event.event_type == "UI_DATA" && audit_event_has_path(event, "/api/v1/auth/me")
        }));
        Ok(())
    }

    #[tokio::test]
    async fn controller_audit_captures_only_enabled_non_ui_text_results()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, store) = test_router_with_audit_config(true, AUDIT_LEVEL_VERBOSE, true)?;
        let login = response_json(login_request(&app, None).await?).await?;
        let token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;

        let response = authorized_post(&app, "/api/v1/general/process", token, None).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await?.as_ref(),
            b"invalid"
        );
        let me = authorized_get(&app, "/api/v1/auth/me", token).await?;
        assert_eq!(me.status(), StatusCode::OK);

        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        let process = events
            .iter()
            .find(|event| audit_event_has_path(event, "/api/v1/general/process"))
            .ok_or("missing process audit event")?;
        let process_data: Value = serde_json::from_str(&process.data)?;
        assert_eq!(process_data["result"], "invalid");

        let me = events
            .iter()
            .find(|event| audit_event_has_path(event, "/api/v1/auth/me"))
            .ok_or("missing UI-data audit event")?;
        let me_data: Value = serde_json::from_str(&me.data)?;
        assert!(me_data.get("result").is_none());
        let login = events
            .iter()
            .find(|event| audit_event_has_path(event, "/api/v1/auth/login"))
            .ok_or("missing login audit event")?;
        let login_data: Value = serde_json::from_str(&login.data)?;
        assert!(login_data.get("result").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn invite_tokens_are_redacted_from_the_audit_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, store) = test_router_with_audit_config(true, AUDIT_LEVEL_VERBOSE, false)?;
        let login = response_json(login_request(&app, None).await?).await?;
        let token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;

        let invite = response_json(
            authorized_multipart_post(&app, "/api/v1/invite/generate", token, &[]).await?,
        )
        .await?;
        let invite_token = invite["token"].as_str().ok_or("missing invite token")?;

        let validate = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/invite/validate/{invite_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(validate.status(), StatusCode::OK);

        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        let redacted_path = "/api/v1/invite/validate/[REDACTED]";
        assert!(
            events
                .iter()
                .any(|event| audit_event_has_path(event, redacted_path)),
            "expected a redacted invite-validate audit event"
        );
        assert!(
            !events.iter().any(|event| audit_event_has_path(
                event,
                &format!("/api/v1/invite/validate/{invite_token}")
            )),
            "the raw invite token must never reach the audit trail"
        );
        Ok(())
    }

    #[tokio::test]
    async fn capture_operation_results_never_persists_fresh_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, store) = test_router_with_audit_config(true, AUDIT_LEVEL_VERBOSE, true)?;
        let login = response_json(login_request(&app, None).await?).await?;
        let token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;

        let rotated =
            response_json(authorized_post(&app, "/api/v1/user/update-api-key", token, None).await?)
                .await?;
        let api_key = rotated["apiKey"]
            .as_str()
            .ok_or("missing rotated api key")?
            .to_owned();

        let invite = response_json(
            authorized_multipart_post(&app, "/api/v1/invite/generate", token, &[]).await?,
        )
        .await?;
        let invite_token = invite["token"]
            .as_str()
            .ok_or("missing invite token")?
            .to_owned();

        let refreshed =
            response_json(authorized_post(&app, "/api/v1/auth/refresh", token, None).await?)
                .await?;
        let refreshed_access = refreshed["session"]["access_token"]
            .as_str()
            .ok_or("missing refreshed access token")?
            .to_owned();

        let events = store.export_audit_events(&SecurityAuditFilter::default())?;
        for (path, secret) in [
            ("/api/v1/user/update-api-key", api_key.as_str()),
            ("/api/v1/invite/generate", invite_token.as_str()),
            ("/api/v1/auth/refresh", refreshed_access.as_str()),
        ] {
            let event = events
                .iter()
                .find(|event| audit_event_has_path(event, path))
                .ok_or_else(|| format!("missing audit event for {path}"))?;
            assert!(
                !event.data.contains(secret),
                "audit event for {path} must not contain the freshly-issued secret"
            );
        }
        Ok(())
    }

    #[test]
    fn operation_result_bounds_match_java_safe_string_limit() {
        let value = "a".repeat(MAX_AUDIT_RESULT_CHARS + 1);
        let bounded = bounded_operation_result(&value);
        assert_eq!(bounded.chars().count(), MAX_AUDIT_RESULT_CHARS);
        assert!(bounded.ends_with("..."));
    }

    #[tokio::test]
    async fn job_routes_hide_resources_owned_by_another_authenticated_user()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let user_id = store.create_local_user(
            "user@example.test",
            "second test password",
            ["ROLE_USER"],
            None,
        )?;
        let jobs = Arc::new(JobManager::new());
        let queue = Arc::new(JobQueue::new(JobQueueConfig::default()));
        let admin_job = jobs.create_job(JobOwner::User(1))?;
        let user_job = jobs.create_job(JobOwner::User(user_id))?;
        let app = secure_router(
            crate::job_routes()
                .layer(Extension(Arc::clone(&jobs)))
                .layer(Extension(queue)),
            Arc::clone(&store),
        );
        let admin_login = response_json(login_request(&app, None).await?).await?;
        let admin_token = admin_login["session"]["access_token"]
            .as_str()
            .ok_or("missing admin token")?;
        let user_login = response_json(
            login_credentials(&app, "user@example.test", "second test password").await?,
        )
        .await?;
        let user_token = user_login["session"]["access_token"]
            .as_str()
            .ok_or("missing user token")?;

        assert_eq!(
            authorized_get(
                &app,
                &format!("/api/v1/general/job/{}", admin_job.job_id),
                admin_token,
            )
            .await?
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            authorized_get(
                &app,
                &format!("/api/v1/general/job/{}", admin_job.job_id),
                user_token,
            )
            .await?
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            authorized_get(
                &app,
                &format!("/api/v1/general/job/{}", user_job.job_id),
                admin_token,
            )
            .await?
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            authorized_get(&app, "/api/v1/admin/job/stats", admin_token)
                .await?
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            authorized_get(&app, "/api/v1/admin/job/queue/stats", user_token)
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );

        let _ = fs::remove_dir_all(admin_job.directory);
        let _ = fs::remove_dir_all(user_job.directory);
        Ok(())
    }

    #[tokio::test]
    async fn admin_settings_routes_require_admin_and_mask_persisted_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let settings_path = directory.path().join("settings.yml");
        fs::write(
            &settings_path,
            "security:\n  oauth2:\n    clientSecret: existing-secret\nui:\n  appName: Old\n",
        )?;
        let loaded = serde_yaml::from_str(&fs::read_to_string(&settings_path)?)?;
        let settings = Arc::new(AdminSettingsService::new(settings_path.clone(), loaded));
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        store.create_local_user(
            "user@example.test",
            "second test password",
            ["ROLE_USER"],
            None,
        )?;
        let app = secure_router(
            crate::admin_settings::routes().layer(Extension(settings)),
            Arc::clone(&store),
        );
        let admin_login = response_json(login_request(&app, None).await?).await?;
        let admin_token = admin_login["session"]["access_token"]
            .as_str()
            .ok_or("missing admin token")?;
        let user_login = response_json(
            login_credentials(&app, "user@example.test", "second test password").await?,
        )
        .await?;
        let user_token = user_login["session"]["access_token"]
            .as_str()
            .ok_or("missing user token")?;

        assert_eq!(
            authorized_get(&app, "/api/v1/admin/settings", user_token)
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        let current =
            response_json(authorized_get(&app, "/api/v1/admin/settings", admin_token).await?)
                .await?;
        assert_eq!(current["security"]["oauth2"]["clientSecret"], "********");
        let updated = app
            .clone()
            .oneshot(
                Request::put("/api/v1/admin/settings")
                    .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "settings": {
                                "ui.appName": "New",
                                "security.oauth2.clientSecret": "replacement-secret"
                            }
                        })
                        .to_string(),
                    ))?,
            )
            .await?;
        assert_eq!(updated.status(), StatusCode::OK);
        let pending =
            response_json(authorized_get(&app, "/api/v1/admin/settings/delta", admin_token).await?)
                .await?;
        assert_eq!(pending["count"], 2);
        assert_eq!(
            pending["pendingChanges"]["security.oauth2.clientSecret"],
            "********"
        );
        let persisted: Value = serde_yaml::from_str(&fs::read_to_string(settings_path)?)?;
        assert_eq!(persisted["ui"]["appName"], "New");
        Ok(())
    }

    #[tokio::test]
    async fn verified_supabase_bearer_provisions_one_live_scoped_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, token, store) = test_router_with_external_jwt()?;
        let me = authorized_get(&app, "/api/v1/auth/me", &token).await?;
        assert_eq!(me.status(), StatusCode::OK);
        let first = response_json(me).await?;
        assert_eq!(first["user"]["username"], "external@example.test");
        assert_eq!(first["user"]["authenticationType"], "oauth2");
        let first_id = first["user"]["id"].as_i64().ok_or("missing user id")?;

        let repeated =
            response_json(authorized_get(&app, "/api/v1/auth/me", &token).await?).await?;
        assert_eq!(repeated["user"]["id"], first_id);
        assert_eq!(
            authorized_get(&app, "/api/v1/user/admin/list", &token)
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        let signing_users =
            response_json(authorized_get(&app, "/api/v1/user/users", &token).await?).await?;
        assert_eq!(signing_users.as_array().map(Vec::len), Some(1));
        let external_events = store.export_audit_events(&SecurityAuditFilter {
            principals: vec!["external@example.test".to_owned()],
            ..SecurityAuditFilter::default()
        })?;
        assert!(external_events.iter().any(|event| {
            audit_event_has_path(event, "/api/v1/user/users")
                && event.event_type == "UI_DATA"
                && event.source == "WEB"
        }));

        let mut tampered = token;
        tampered.push('x');
        assert_eq!(
            authorized_get(&app, "/api/v1/auth/me", &tampered)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login_credentials(&app, "external@example.test", "any-password")
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }

    #[tokio::test]
    async fn login_refresh_me_and_logout_use_revocable_opaque_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let login = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"username":"admin","password":"test password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(login.status(), StatusCode::OK);
        let login = response_json(login).await?;
        let first_access = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?
            .to_owned();
        assert!(first_access.starts_with("spdf_at_"));
        assert!(
            login["session"]["refresh_token"]
                .as_str()
                .is_some_and(|token| token.starts_with("spdf_rt_"))
        );

        let me = authorized_get(&app, "/api/v1/auth/me", &first_access).await?;
        assert_eq!(me.status(), StatusCode::OK);
        assert_eq!(response_json(me).await?["user"]["username"], "admin");

        let refreshed = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/refresh")
                    .header(header::AUTHORIZATION, format!("Bearer {first_access}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(refreshed.status(), StatusCode::OK);
        let refreshed = response_json(refreshed).await?;
        let second_access = refreshed["session"]["access_token"]
            .as_str()
            .ok_or("missing refreshed token")?
            .to_owned();
        assert_ne!(first_access, second_access);
        assert_eq!(
            authorized_get(&app, "/api/v1/general/protected", &first_access)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            authorized_get(&app, "/api/v1/general/protected", &second_access)
                .await?
                .status(),
            StatusCode::OK
        );

        let logout = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header(header::AUTHORIZATION, format!("Bearer {second_access}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(logout.status(), StatusCode::OK);
        assert_eq!(
            authorized_get(&app, "/api/v1/general/protected", &second_access)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        Ok(())
    }

    #[tokio::test]
    async fn mfa_setup_enable_and_login_enforce_fresh_totp_steps()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let login = login_request(&app, None).await?;
        assert_eq!(login.status(), StatusCode::OK);
        let login = response_json(login).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?
            .to_owned();

        let setup = app
            .clone()
            .oneshot(
                Request::get("/api/v1/auth/mfa/setup")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(setup.status(), StatusCode::OK);
        let setup = response_json(setup).await?;
        let first_secret = setup["secret"].as_str().ok_or("missing MFA secret")?;
        assert!(
            setup["otpauthUri"]
                .as_str()
                .is_some_and(|uri| uri.contains(first_secret))
        );

        let cancel = app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/mfa/setup/cancel")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(cancel.status(), StatusCode::OK);

        let setup = app
            .clone()
            .oneshot(
                Request::get("/api/v1/auth/mfa/setup")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        let setup = response_json(setup).await?;
        let secret = setup["secret"]
            .as_str()
            .ok_or("missing replacement MFA secret")?
            .to_owned();
        assert_ne!(first_secret, secret);

        let now = Utc::now().timestamp();
        let enable_code = totp_code_at(&secret, now).ok_or("missing enable TOTP")?;
        let enable = authorized_json_post(
            &app,
            "/api/v1/auth/mfa/enable",
            &access_token,
            serde_json::json!({ "code": enable_code }),
        )
        .await?;
        assert_eq!(enable.status(), StatusCode::OK);

        let missing = login_request(&app, None).await?;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_json(missing).await?["error"], "mfa_required");

        let next_code = totp_code_at(&secret, now + 30).ok_or("missing login TOTP")?;
        let with_mfa = login_request(&app, Some(&next_code)).await?;
        assert_eq!(with_mfa.status(), StatusCode::OK);

        let replay = login_request(&app, Some(&next_code)).await?;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_json(replay).await?["error"], "invalid_mfa_code");
        Ok(())
    }

    const RECOVERY_REGENERATE_PATH: &str = "/api/v1/auth/mfa/recovery-codes/regenerate";

    fn recovery_codes_from(value: &Value) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        value
            .as_array()
            .ok_or("missing recovery codes")?
            .iter()
            .map(|code| code.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "non-string recovery code".into())
    }

    async fn access_token_of(
        response: axum::response::Response,
    ) -> Result<String, Box<dyn std::error::Error>> {
        response_json(response).await?["session"]["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "missing access token".into())
    }

    /// Drives the full HTTP setup -> enable flow for the given access token and
    /// returns the account's TOTP secret and the initial recovery-code set that
    /// the enable response hands back exactly once.
    async fn enable_mfa_over_http(
        app: &Router,
        access_token: &str,
        enable_at: i64,
    ) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
        let setup = authorized_get(app, "/api/v1/auth/mfa/setup", access_token).await?;
        assert_eq!(setup.status(), StatusCode::OK);
        let secret = response_json(setup).await?["secret"]
            .as_str()
            .ok_or("missing MFA secret")?
            .to_owned();
        let enable_code = totp_code_at(&secret, enable_at).ok_or("missing enable TOTP")?;
        let enable = authorized_json_post(
            app,
            "/api/v1/auth/mfa/enable",
            access_token,
            serde_json::json!({ "code": enable_code }),
        )
        .await?;
        assert_eq!(enable.status(), StatusCode::OK);
        let body = response_json(enable).await?;
        assert_eq!(body["enabled"], true);
        Ok((secret, recovery_codes_from(&body["recoveryCodes"])?))
    }

    async fn create_enabled_web_user(
        app: &Router,
        admin_token: &str,
        username: &str,
        password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let created = authorized_multipart_post(
            app,
            "/api/v1/user/admin/saveUser",
            admin_token,
            &[
                ("username", username),
                ("password", password),
                ("role", "ROLE_USER"),
                ("authType", "WEB"),
            ],
        )
        .await?;
        assert_eq!(created.status(), StatusCode::OK);
        Ok(())
    }

    async fn login_user(
        app: &Router,
        username: &str,
        password: &str,
        mfa_code: Option<&str>,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let mut body = serde_json::json!({ "username": username, "password": password });
        if let Some(code) = mfa_code {
            body["mfaCode"] = Value::String(code.to_owned());
        }
        Ok(app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body)?))?,
            )
            .await?)
    }

    #[tokio::test]
    async fn enabling_mfa_issues_recovery_codes_that_log_in_and_appear_in_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let access_token = access_token_of(login_request(&app, None).await?).await?;
        let now = Utc::now().timestamp();

        let (_secret, codes) = enable_mfa_over_http(&app, &access_token, now).await?;
        assert_eq!(codes.len(), 10);
        // The batch is internally distinct.
        assert_eq!(
            codes.iter().collect::<std::collections::HashSet<_>>().len(),
            10
        );

        // MFA status reports the codes exist as a COUNT only -- never the
        // plaintext, which is surfaced solely by the enable/regenerate response.
        let me =
            response_json(authorized_get(&app, "/api/v1/auth/me", &access_token).await?).await?;
        assert_eq!(me["mfa"]["enabled"], true);
        assert_eq!(me["mfa"]["recoveryCodesRemaining"], 10);
        assert!(me["mfa"].get("recoveryCodes").is_none());

        // MFA is now required at login, and a recovery code satisfies it.
        let missing = login_request(&app, None).await?;
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response_json(missing).await?["error"], "mfa_required");
        let with_code = login_request(&app, Some(&codes[0])).await?;
        assert_eq!(with_code.status(), StatusCode::OK);

        // Single-use: the consumed code is refused on replay, and the status
        // count decrements to reflect the spent code.
        let replay = login_request(&app, Some(&codes[0])).await?;
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
        let me =
            response_json(authorized_get(&app, "/api/v1/auth/me", &access_token).await?).await?;
        assert_eq!(me["mfa"]["recoveryCodesRemaining"], 9);
        Ok(())
    }

    #[tokio::test]
    async fn regenerating_recovery_codes_replaces_the_set_and_requires_a_fresh_totp()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let access_token = access_token_of(login_request(&app, None).await?).await?;
        let now = Utc::now().timestamp();
        let (secret, first_codes) = enable_mfa_over_http(&app, &access_token, now).await?;

        // Re-auth requirement (mirrors disable_mfa): a code that is not a valid
        // current TOTP is refused, leaving the existing set intact.
        let wrong = authorized_json_post(
            &app,
            RECOVERY_REGENERATE_PATH,
            &access_token,
            serde_json::json!({ "code": "not-a-totp" }),
        )
        .await?;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(wrong).await?["error"],
            "Invalid two-factor code"
        );
        // An empty code is a 400 before any store work.
        let empty = authorized_json_post(
            &app,
            RECOVERY_REGENERATE_PATH,
            &access_token,
            serde_json::json!({ "code": "" }),
        )
        .await?;
        assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
        // The original set still authenticates after the refused attempts.
        assert_eq!(
            login_request(&app, Some(&first_codes[0])).await?.status(),
            StatusCode::OK
        );

        // A fresh TOTP step (later than the enable step) yields a NEW set of ten,
        // fully disjoint from the superseded one.
        let regen_code = totp_code_at(&secret, now + 30).ok_or("missing regen TOTP")?;
        let regen = authorized_json_post(
            &app,
            RECOVERY_REGENERATE_PATH,
            &access_token,
            serde_json::json!({ "code": regen_code }),
        )
        .await?;
        assert_eq!(regen.status(), StatusCode::OK);
        let second_codes = recovery_codes_from(&response_json(regen).await?["recoveryCodes"])?;
        assert_eq!(second_codes.len(), 10);
        assert!(first_codes.iter().all(|code| !second_codes.contains(code)));

        // Drive invalidation end-to-end through login: a still-unconsumed code
        // from the OLD set no longer authenticates, while one from the new set
        // does. (first_codes[0] was consumed above, so probe first_codes[1].)
        let stale = login_request(&app, Some(&first_codes[1])).await?;
        assert_eq!(stale.status(), StatusCode::UNAUTHORIZED);
        let fresh = login_request(&app, Some(&second_codes[0])).await?;
        assert_eq!(fresh.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn recovery_code_routes_require_authentication_and_are_scoped_to_the_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;

        // Unauthenticated regeneration is rejected by the security boundary.
        let anonymous = app
            .clone()
            .oneshot(
                Request::post(RECOVERY_REGENERATE_PATH)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(
                        &serde_json::json!({ "code": "123456" }),
                    )?))?,
            )
            .await?;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        // Two independent web accounts, each with their own enabled MFA + codes.
        let admin_token = access_token_of(login_request(&app, None).await?).await?;
        create_enabled_web_user(&app, &admin_token, "second@example.test", "second-password")
            .await?;
        let user_token = access_token_of(
            login_user(&app, "second@example.test", "second-password", None).await?,
        )
        .await?;
        let now = Utc::now().timestamp();
        let (admin_secret, _admin_codes) = enable_mfa_over_http(&app, &admin_token, now).await?;
        let (_user_secret, user_codes) = enable_mfa_over_http(&app, &user_token, now).await?;

        // The admin regenerates ITS OWN codes. The request body carries only a
        // `code`, so the operation can only ever touch the authenticated caller.
        let regen_code = totp_code_at(&admin_secret, now + 30).ok_or("missing regen TOTP")?;
        let regen = authorized_json_post(
            &app,
            RECOVERY_REGENERATE_PATH,
            &admin_token,
            serde_json::json!({ "code": regen_code }),
        )
        .await?;
        assert_eq!(regen.status(), StatusCode::OK);

        // Caller-scoping: the OTHER user's codes are untouched -- one still
        // authenticates them at login.
        let scoped = login_user(
            &app,
            "second@example.test",
            "second-password",
            Some(&user_codes[0]),
        )
        .await?;
        assert_eq!(scoped.status(), StatusCode::OK);

        // A body that attempts to name another user is rejected outright: the
        // route accepts only `code`, so it can never be pointed elsewhere.
        let injected = authorized_json_post(
            &app,
            RECOVERY_REGENERATE_PATH,
            &admin_token,
            serde_json::json!({ "code": regen_code, "userId": 1 }),
        )
        .await?;
        assert!(injected.status().is_client_error());
        Ok(())
    }

    #[tokio::test]
    async fn administrator_team_routes_parse_bounded_multipart_and_enforce_uniqueness()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let login = response_json(login_request(&app, None).await?).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        let (content_type, body) = multipart_body(&[("name", "Project Alpha")]);
        let created = app
            .clone()
            .oneshot(
                Request::post("/api/v1/team/create")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .header(header::CONTENT_TYPE, content_type.clone())
                    .body(Body::from(body.clone()))?,
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK);

        let duplicate = app
            .clone()
            .oneshot(
                Request::post("/api/v1/team/create")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        let teams = authorized_get(&app, "/api/v1/team/list", access_token).await?;
        assert_eq!(teams.status(), StatusCode::OK);
        let teams = response_json(teams).await?;
        assert!(
            teams["teams"]
                .as_array()
                .is_some_and(|teams| teams.iter().any(|team| team["name"] == "Project Alpha"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn invitation_http_flow_is_public_only_for_validate_and_one_time_accept()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let login = response_json(login_request(&app, None).await?).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        let (content_type, body) = multipart_body(&[
            ("email", "invited@example.test"),
            ("role", "ROLE_USER"),
            ("frontendBaseUrl", "https://pdf.example.test"),
        ]);
        let generated = app
            .clone()
            .oneshot(
                Request::post("/api/v1/invite/generate")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(generated.status(), StatusCode::OK);
        let generated = response_json(generated).await?;
        let token = generated["token"]
            .as_str()
            .ok_or("missing invite token")?
            .to_owned();
        assert!(
            generated["inviteUrl"]
                .as_str()
                .is_some_and(|url| url == format!("https://pdf.example.test/invite/{token}"))
        );

        let validated = app
            .clone()
            .oneshot(Request::get(format!("/api/v1/invite/validate/{token}")).body(Body::empty())?)
            .await?;
        assert_eq!(validated.status(), StatusCode::OK);
        assert_eq!(
            response_json(validated).await?["email"],
            "invited@example.test"
        );

        let (content_type, body) = multipart_body(&[("password", "invite-password")]);
        let accepted = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/invite/accept/{token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(accepted.status(), StatusCode::OK);

        let replay = app
            .clone()
            .oneshot(Request::get(format!("/api/v1/invite/validate/{token}")).body(Body::empty())?)
            .await?;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

        let invited_login = app
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"username":"invited@example.test","password":"invite-password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(invited_login.status(), StatusCode::OK);
        Ok(())
    }

    #[tokio::test]
    async fn invitation_email_without_a_relay_reports_failure_and_keeps_the_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let login = response_json(login_request(&app, None).await?).await?;
        let access_token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing access token")?;
        let generated = authorized_multipart_post(
            &app,
            "/api/v1/invite/generate",
            access_token,
            &[
                ("email", "mail-unavailable@example.test"),
                ("sendEmail", "true"),
                ("frontendBaseUrl", "https://pdf.example.test"),
            ],
        )
        .await?;
        assert_eq!(generated.status(), StatusCode::OK);
        let generated = response_json(generated).await?;
        assert_eq!(generated["emailSent"], false);
        assert_eq!(generated["emailError"], "Email service is not configured");
        let token = generated["token"].as_str().ok_or("missing invite token")?;
        let validated = app
            .oneshot(Request::get(format!("/api/v1/invite/validate/{token}")).body(Body::empty())?)
            .await?;
        assert_eq!(validated.status(), StatusCode::OK);
        Ok(())
    }

    #[test]
    fn generated_temporary_passwords_match_the_legacy_shape() {
        let first = random_temporary_password();
        let second = random_temporary_password();
        assert_eq!(first.len(), 12);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(first.as_str(), second.as_str());
    }

    #[tokio::test]
    async fn admin_password_change_persists_before_missing_mail_is_reported()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let admin_login = response_json(login_request(&app, None).await?).await?;
        let admin_token = admin_login["session"]["access_token"]
            .as_str()
            .ok_or("missing admin token")?;
        let created = authorized_multipart_post(
            &app,
            "/api/v1/user/admin/saveUser",
            admin_token,
            &[
                ("username", "mail-change@example.test"),
                ("password", "old-mail-password"),
                ("role", "ROLE_USER"),
                ("authType", "WEB"),
            ],
        )
        .await?;
        assert_eq!(created.status(), StatusCode::OK);
        let user_login = response_json(
            login_credentials(&app, "mail-change@example.test", "old-mail-password").await?,
        )
        .await?;
        let user_token = user_login["session"]["access_token"]
            .as_str()
            .ok_or("missing user token")?;

        let changed = authorized_multipart_post(
            &app,
            "/api/v1/user/admin/changePasswordForUser",
            admin_token,
            &[
                ("username", "mail-change@example.test"),
                ("newPassword", "new-mail-password"),
                ("sendEmail", "true"),
                ("forcePasswordChange", "true"),
            ],
        )
        .await?;
        assert_eq!(changed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(changed).await?["error"],
            "Email is not configured."
        );
        assert_eq!(
            authorized_get(&app, "/api/v1/general/protected", user_token)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let replacement =
            login_credentials(&app, "mail-change@example.test", "new-mail-password").await?;
        assert_eq!(replacement.status(), StatusCode::OK);
        assert_eq!(
            response_json(replacement).await?["user"]["user_metadata"]["forcePasswordChange"],
            true
        );
        Ok(())
    }

    #[tokio::test]
    async fn user_administration_credentials_and_digest_only_api_keys_work_end_to_end()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = test_router()?;
        let admin_login = response_json(login_request(&app, None).await?).await?;
        let admin_token = admin_login["session"]["access_token"]
            .as_str()
            .ok_or("missing admin token")?
            .to_owned();
        let managed_token = provision_managed_user(&app, &admin_token).await?;
        assert_digest_only_api_key_http_flow(&app, &managed_token).await?;
        assert_managed_user_mutation_flow(&app, &admin_token, &managed_token).await?;
        Ok(())
    }

    async fn provision_managed_user(
        app: &Router,
        admin_token: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let created = authorized_multipart_post(
            app,
            "/api/v1/user/admin/saveUser",
            admin_token,
            &[
                ("username", "managed@example.test"),
                ("password", "managed-password"),
                ("role", "ROLE_USER"),
                ("authType", "WEB"),
            ],
        )
        .await?;
        assert_eq!(created.status(), StatusCode::OK);
        let login = login_credentials(app, "managed@example.test", "managed-password").await?;
        assert_eq!(login.status(), StatusCode::OK);
        let login = response_json(login).await?;
        let token = login["session"]["access_token"]
            .as_str()
            .ok_or("missing managed token")?
            .to_owned();
        assert_eq!(
            authorized_get(app, "/api/v1/user/admin/list", &token)
                .await?
                .status(),
            StatusCode::FORBIDDEN
        );
        let signing_users = authorized_get(app, "/api/v1/user/users", &token).await?;
        assert_eq!(signing_users.status(), StatusCode::OK);
        let signing_users = response_json(signing_users).await?;
        assert_eq!(signing_users.as_array().map(Vec::len), Some(1));
        assert_eq!(signing_users[0]["username"], "managed@example.test");
        Ok(token)
    }

    async fn assert_digest_only_api_key_http_flow(
        app: &Router,
        managed_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let first_key = app
            .clone()
            .oneshot(
                Request::post("/api/v1/user/update-api-key")
                    .header(header::AUTHORIZATION, format!("Bearer {managed_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(first_key.status(), StatusCode::OK);
        let first_key = response_json(first_key).await?["apiKey"]
            .as_str()
            .ok_or("missing API key")?
            .to_owned();
        let protected_with_key = app
            .clone()
            .oneshot(
                Request::get("/api/v1/general/protected")
                    .header("x-api-key", &first_key)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(protected_with_key.status(), StatusCode::OK);
        let unavailable_plaintext = app
            .clone()
            .oneshot(
                Request::post("/api/v1/user/get-api-key")
                    .header(header::AUTHORIZATION, format!("Bearer {managed_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unavailable_plaintext.status(), StatusCode::NOT_FOUND);
        let unavailable_plaintext = response_json(unavailable_plaintext).await?;
        assert_eq!(unavailable_plaintext["exists"], true);
        assert_eq!(unavailable_plaintext["recoverable"], false);
        let second_key = app
            .clone()
            .oneshot(
                Request::post("/api/v1/user/update-api-key")
                    .header(header::AUTHORIZATION, format!("Bearer {managed_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        let second_key = response_json(second_key).await?["apiKey"]
            .as_str()
            .ok_or("missing replacement API key")?
            .to_owned();
        assert_ne!(first_key, second_key);
        let revoked_key = app
            .clone()
            .oneshot(
                Request::get("/api/v1/general/protected")
                    .header("x-api-key", &first_key)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(revoked_key.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    async fn assert_managed_user_mutation_flow(
        app: &Router,
        admin_token: &str,
        managed_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let changed = authorized_multipart_post(
            app,
            "/api/v1/user/change-password",
            managed_token,
            &[
                ("currentPassword", "managed-password"),
                ("newPassword", "managed-password-two"),
            ],
        )
        .await?;
        assert_eq!(changed.status(), StatusCode::OK);
        assert_eq!(
            authorized_get(app, "/api/v1/general/protected", managed_token)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login_credentials(app, "managed@example.test", "managed-password-two")
                .await?
                .status(),
            StatusCode::OK
        );
        let role_changed = authorized_multipart_post(
            app,
            "/api/v1/user/admin/changeRole",
            admin_token,
            &[("username", "managed@example.test"), ("role", "ROLE_ADMIN")],
        )
        .await?;
        assert_eq!(role_changed.status(), StatusCode::OK);
        let disabled = authorized_multipart_post(
            app,
            "/api/v1/user/admin/changeUserEnabled/managed@example.test",
            admin_token,
            &[("enabled", "false")],
        )
        .await?;
        assert_eq!(disabled.status(), StatusCode::OK);
        assert_eq!(
            login_credentials(app, "managed@example.test", "managed-password-two")
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let deleted = app
            .clone()
            .oneshot(
                Request::post("/api/v1/user/admin/deleteUser/managed@example.test")
                    .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(deleted.status(), StatusCode::OK);
        let users = authorized_get(app, "/api/v1/user/admin/list", admin_token).await?;
        let users = response_json(users).await?;
        assert_eq!(users["users"].as_array().map(Vec::len), Some(1));
        Ok(())
    }

    #[test]
    fn durable_startup_requires_explicit_first_admin_then_reuses_existing_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let config_directory = directory.path().join("configs");
        fs::create_dir_all(&config_directory)?;
        let settings = config_directory.join("settings.yml");
        fs::write(
            &settings,
            "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n",
        )?;
        let config = RuntimeConfig::from_files(&settings, config_directory.join("missing.yml"));
        let store = initialize_security_store(&config)?;
        let context = store.authenticate_password(
            "ADMIN@example.test",
            "test-only-password",
            10_000,
            "startup-test",
        )?;
        assert!(context.has_role("ROLE_ADMIN"));
        drop(store);

        fs::write(&settings, "{}\n")?;
        let config = RuntimeConfig::from_files(&settings, config_directory.join("missing.yml"));
        assert!(initialize_security_store(&config)?.has_users()?);

        let empty_directory = tempdir()?;
        let empty_settings = empty_directory.path().join("settings.yml");
        fs::write(&empty_settings, "{}\n")?;
        let empty_config =
            RuntimeConfig::from_files(&empty_settings, empty_directory.path().join("missing.yml"));
        assert!(matches!(
            initialize_security_store(&empty_config),
            Err(SecurityStartupError::MissingInitialAdministrator)
        ));
        Ok(())
    }

    #[derive(Serialize)]
    struct ExternalTestClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        iat: u64,
        sub: &'a str,
        role: &'a str,
        aal: &'a str,
        session_id: &'a str,
        email: &'a str,
        is_anonymous: bool,
        app_metadata: Value,
    }

    fn test_router_with_external_jwt()
    -> Result<(Router, String, Arc<SecurityStore>), Box<dyn std::error::Error>> {
        let private_key = RsaPrivateKey::new(&mut rand::rng(), 2_048)?;
        let public_key = private_key.to_public_key();
        let private_der = private_key.to_pkcs1_der()?;
        let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());
        let modulus = minimal_unsigned_bytes(public_key.n().to_bytes(ByteOrder::BigEndian));
        let exponent = minimal_unsigned_bytes(public_key.e().to_bytes(ByteOrder::BigEndian));
        let jwks: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA", "use": "sig", "key_ops": ["verify"],
                "kid": "http-test-key", "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(modulus),
                "e": URL_SAFE_NO_PAD.encode(exponent)
            }]
        }))?;
        let verifier = Arc::new(SupabaseJwtVerifier::with_jwks(
            SupabaseJwtConfig {
                issuer: "https://project.supabase.co/auth/v1".to_owned(),
                expected_audience: Some("authenticated".to_owned()),
                clock_skew_seconds: 120,
                jwks_cache_seconds: 300,
            },
            jwks,
        )?);
        let token = external_test_token(&encoding_key)?;
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let router = Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/api/v1/general/protected", get(|| async { "ok" }));
        let app = secure_router_with_config(
            router,
            Arc::clone(&store),
            SecurityHttpConfig {
                totp_issuer: "Stirling PDF".to_owned(),
                invites_enabled: true,
                invite_expiry_hours: 168,
                frontend_url: String::new(),
                backend_url: String::new(),
                audit_enabled: true,
                audit_level: AUDIT_LEVEL_STANDARD,
                audit_file_capture: SecurityAuditFileCaptureConfig::default(),
                audit_capture_operation_results: false,
                license_tier: LicenseTier::Enterprise,
                external_jwt: Some(verifier),
                oidc_login_provider: None,
            },
        );
        Ok((app, token, store))
    }

    fn external_test_token(
        encoding_key: &EncodingKey,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let now = u64::try_from(Utc::now().timestamp())?;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("http-test-key".to_owned());
        Ok(encode(
            &header,
            &ExternalTestClaims {
                iss: "https://project.supabase.co/auth/v1",
                aud: "authenticated",
                exp: now + 300,
                iat: now,
                sub: "123e4567-e89b-12d3-a456-426614174222",
                role: "authenticated",
                aal: "aal1",
                session_id: "external-http-session",
                email: "external@example.test",
                is_anonymous: false,
                app_metadata: serde_json::json!({ "provider": "github" }),
            },
            encoding_key,
        )?)
    }

    fn minimal_unsigned_bytes(bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let bytes = bytes.as_ref();
        let first_nonzero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        bytes[first_nonzero..].to_vec()
    }

    fn test_router() -> Result<Router, Box<dyn std::error::Error>> {
        Ok(test_router_with_store()?.0)
    }

    fn test_router_with_store() -> Result<(Router, Arc<SecurityStore>), Box<dyn std::error::Error>>
    {
        test_router_with_license_tier(LicenseTier::Enterprise)
    }

    fn test_router_with_license_tier(
        license_tier: LicenseTier,
    ) -> Result<(Router, Arc<SecurityStore>), Box<dyn std::error::Error>> {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let router = Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/api/v1/general/protected", get(|| async { "ok" }))
            .route(
                "/api/v1/general/process",
                post(|| async { (StatusCode::BAD_REQUEST, "invalid") }),
            )
            .route(
                "/api/v1/policies/run",
                post(
                    |Extension(audit): Extension<SecurityAuditContext>| async move {
                        audit.set_policy(
                            "  Nightly\r\nrun  ",
                            (0..51).map(|index| {
                                if index == 0 {
                                    "/api/v1/general/rotate-pdf".to_owned()
                                } else {
                                    format!("/api/v1/tool/{index}")
                                }
                            }),
                        );
                        StatusCode::ACCEPTED
                    },
                ),
            )
            .route("/api/v1/ai/test", post(|| async { "ok" }));
        let app = secure_router_with_config(
            router,
            Arc::clone(&store),
            SecurityHttpConfig {
                totp_issuer: "Stirling PDF".to_owned(),
                invites_enabled: true,
                invite_expiry_hours: 168,
                frontend_url: String::new(),
                backend_url: String::new(),
                audit_enabled: true,
                audit_level: AUDIT_LEVEL_STANDARD,
                audit_file_capture: SecurityAuditFileCaptureConfig::default(),
                audit_capture_operation_results: false,
                license_tier,
                external_jwt: None,
                oidc_login_provider: None,
            },
        );
        Ok((app, store))
    }

    /// A router with the generic-OIDC login routes mounted (a structurally-valid
    /// provider config, enough to mount `/authorize` + `/callback`; no live `IdP`
    /// is contacted by the callback path when the state store is empty).
    fn test_router_with_oidc() -> Result<Router, Box<dyn std::error::Error>> {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let app = secure_router_with_config(
            Router::new().route("/health", get(|| async { "ok" })),
            Arc::clone(&store),
            SecurityHttpConfig {
                totp_issuer: "Stirling PDF".to_owned(),
                invites_enabled: true,
                invite_expiry_hours: 168,
                frontend_url: String::new(),
                backend_url: String::new(),
                audit_enabled: false,
                audit_level: AUDIT_LEVEL_STANDARD,
                audit_file_capture: SecurityAuditFileCaptureConfig::default(),
                audit_capture_operation_results: false,
                license_tier: LicenseTier::Enterprise,
                external_jwt: None,
                oidc_login_provider: Some(crate::oidc_login::OidcLoginProviderConfig {
                    issuer: "https://issuer.example.test".to_owned(),
                    client_id: "test-client".to_owned(),
                    redirect_uri: "https://app.example.test/login/oauth2/code/oidc".to_owned(),
                    scopes: vec!["openid".to_owned()],
                    client_secret: None,
                }),
            },
        );
        Ok(app)
    }

    fn test_router_with_audit_config(
        audit_enabled: bool,
        audit_level: u8,
        capture_operation_results: bool,
    ) -> Result<(Router, Arc<SecurityStore>), Box<dyn std::error::Error>> {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let router = Router::new()
            .route("/health", get(|| async { "ok" }))
            .route(
                "/api/v1/general/process",
                post(|| async { (StatusCode::BAD_REQUEST, "invalid") }),
            );
        let app = secure_router_with_config(
            router,
            Arc::clone(&store),
            SecurityHttpConfig {
                totp_issuer: "Stirling PDF".to_owned(),
                invites_enabled: true,
                invite_expiry_hours: 168,
                frontend_url: String::new(),
                backend_url: String::new(),
                audit_enabled,
                audit_level,
                audit_file_capture: SecurityAuditFileCaptureConfig::default(),
                audit_capture_operation_results: capture_operation_results,
                license_tier: LicenseTier::Enterprise,
                external_jwt: None,
                oidc_login_provider: None,
            },
        );
        Ok((app, store))
    }

    async fn authorized_post(
        app: &Router,
        path: &str,
        token: &str,
        extra_header: Option<(&str, &str)>,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let mut request =
            Request::post(path).header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some((name, value)) = extra_header {
            request = request.header(name, value);
        }
        Ok(app.clone().oneshot(request.body(Body::empty())?).await?)
    }

    fn audit_event_has_path(event: &crate::security::SecurityAuditEvent, path: &str) -> bool {
        serde_json::from_str::<Value>(&event.data)
            .ok()
            .and_then(|details| details["path"].as_str().map(str::to_owned))
            .is_some_and(|stored_path| stored_path == path)
    }

    async fn authorized_get(
        app: &Router,
        path: &str,
        token: &str,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        Ok(app
            .clone()
            .oneshot(
                Request::get(path)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())?,
            )
            .await?)
    }

    async fn login_request(
        app: &Router,
        mfa_code: Option<&str>,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let body = match mfa_code {
            Some(code) => serde_json::json!({
                "username": "admin",
                "password": "test password",
                "mfaCode": code,
            }),
            None => serde_json::json!({
                "username": "admin",
                "password": "test password",
            }),
        };
        Ok(app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body)?))?,
            )
            .await?)
    }

    async fn login_credentials(
        app: &Router,
        username: &str,
        password: &str,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        Ok(app
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "username": username,
                        "password": password,
                    }))?))?,
            )
            .await?)
    }

    async fn authorized_multipart_post(
        app: &Router,
        path: &str,
        token: &str,
        fields: &[(&str, &str)],
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let (content_type, body) = multipart_body(fields);
        Ok(app
            .clone()
            .oneshot(
                Request::post(path)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, content_type)
                    .body(Body::from(body))?,
            )
            .await?)
    }

    async fn authorized_json_post(
        app: &Router,
        path: &str,
        token: &str,
        body: Value,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        Ok(app
            .clone()
            .oneshot(
                Request::post(path)
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&body)?))?,
            )
            .await?)
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), 1024 * 1024).await?,
        )?)
    }

    fn multipart_body(fields: &[(&str, &str)]) -> (String, Vec<u8>) {
        use std::fmt::Write as _;

        let boundary = "stirling-security-test-boundary";
        let mut body = String::new();
        for (name, value) in fields {
            let _write_result = write!(
                body,
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            );
        }
        let _write_result = write!(body, "--{boundary}--\r\n");
        (
            format!("multipart/form-data; boundary={boundary}"),
            body.into_bytes(),
        )
    }
}
