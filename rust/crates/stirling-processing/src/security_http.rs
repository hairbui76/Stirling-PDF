//! Reviewed HTTP boundary for the local secured-mode foundation.
//!
//! This router is intentionally opt-in: the production binary continues to
//! refuse secured-mode startup until MFA, external identity, invitations,
//! tenant resources, and the remaining review gates are complete.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::to_bytes,
    extract::{DefaultBodyLimit, Extension, Multipart, Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::task;
use zeroize::Zeroizing;

use crate::{
    runtime_config::RuntimeConfig,
    security::{
        AuthContext, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL, SecurityError, SecurityStore,
        SessionTokens,
    },
    security_crypto::{ProtectedSecretCipher, totp_auth_uri},
    security_jwt::{SupabaseJwtError, SupabaseJwtVerifier},
    security_policy::{AuthorizationDenial, EndpointPolicy, authorize, endpoint_policy},
};

const MAX_AUTH_BODY_BYTES: usize = 8 * 1024;
const REFRESH_GRACE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");
const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
struct RequestCorrelation(String);

#[derive(Clone)]
pub struct SecurityHttpConfig {
    pub totp_issuer: String,
    pub invites_enabled: bool,
    pub invite_expiry_hours: u64,
    pub frontend_url: String,
    pub external_jwt: Option<Arc<SupabaseJwtVerifier>>,
}

#[derive(Clone)]
struct SecurityMiddlewareState {
    store: Arc<SecurityStore>,
    external_jwt: Option<Arc<SupabaseJwtVerifier>>,
}

#[derive(Debug, Error)]
pub enum SecurityStartupError {
    #[error("security repository initialization failed")]
    Repository(#[source] SecurityError),
    #[error("an empty security database requires configured initial administrator credentials")]
    MissingInitialAdministrator,
    #[error("external JWT verifier initialization failed")]
    ExternalJwt(#[source] SupabaseJwtError),
    #[error("server certificate initialization failed")]
    ServerCertificate(#[source] Box<dyn std::error::Error + Send + Sync>),
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
    app_metadata: AppMetadata,
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
            external_jwt: None,
        },
    )
}

/// Adds the secure boundary with a deployment-specific authenticator issuer.
pub fn secure_router_with_config(
    router: Router,
    store: Arc<SecurityStore>,
    config: SecurityHttpConfig,
) -> Router {
    let middleware_state = SecurityMiddlewareState {
        store: Arc::clone(&store),
        external_jwt: config.external_jwt.clone(),
    };
    router
        .merge(auth_routes())
        .layer(middleware::from_fn_with_state(
            middleware_state,
            enforce_security,
        ))
        .layer(Extension(store))
        .layer(Extension(config))
}

fn auth_routes() -> Router {
    Router::new()
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
        .route("/api/v1/user/change-username", post(change_username))
        .route("/api/v1/user/change-password", post(change_password))
        .route(
            "/api/v1/user/change-password-on-login",
            post(change_password_on_login),
        )
        .route("/api/v1/user/get-api-key", post(get_api_key))
        .route("/api/v1/user/update-api-key", post(update_api_key))
        .route("/api/v1/user/users", get(list_signing_users))
        .route("/api/v1/user/admin/list", get(list_users_by_admin))
        .route("/api/v1/user/admin/saveUser", post(save_user_by_admin))
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
        .route("/api/v1/invite/accept/{token}", post(accept_invite))
        .layer(DefaultBodyLimit::max(MAX_AUTH_BODY_BYTES))
}

async fn enforce_security(
    State(state): State<SecurityMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    let correlation = RequestCorrelation(random_request_id());
    request.extensions_mut().insert(correlation.clone());
    let policy = endpoint_policy(request.method(), request.uri().path());
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
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let audit_context = context.clone();
    if should_audit_request(&method, &path)
        && let Some(context) = audit_context.as_ref()
    {
        let store_for_audit = Arc::clone(&state.store);
        let context = context.clone();
        let path = path.clone();
        let result = task::spawn_blocking(move || {
            store_for_audit.record_audit(
                &context,
                "HTTP_MUTATION",
                &path,
                "attempt",
                Utc::now().timestamp(),
            )
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            return with_request_id(service_unavailable_response(), &correlation.0);
        }
    }
    if let Some(context) = context {
        request.extensions_mut().insert(context);
    }
    let response = next.run(request).await;
    if should_audit_request(&method, &path)
        && let Some(context) = audit_context
    {
        let status = format!("status:{}", response.status().as_u16());
        let store_for_audit = Arc::clone(&state.store);
        let result = task::spawn_blocking(move || {
            store_for_audit.record_audit(
                &context,
                "HTTP_MUTATION",
                &path,
                &status,
                Utc::now().timestamp(),
            )
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            return with_request_id(service_unavailable_response(), &correlation.0);
        }
    }
    with_request_id(response, &correlation.0)
}

fn should_audit_request(method: &axum::http::Method, path: &str) -> bool {
    matches!(
        *method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    ) || (method == axum::http::Method::GET && path == "/api/v1/auth/mfa/setup")
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
        Ok(Ok(())) => Json(serde_json::json!({ "enabled": true })).into_response(),
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
        Ok(Err(SecurityError::InvalidInput | SecurityError::TeamNotFound)) => {
            invalid_form_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
    }
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
    multipart: Multipart,
) -> Response {
    let fields = match bounded_multipart_fields(multipart).await {
        Ok(fields) => fields,
        Err(response) => return response,
    };
    let Some(username) = required_form_field(&fields, "username") else {
        return invalid_form_response();
    };
    if username.eq_ignore_ascii_case(&context.username) {
        return named_json_error(
            StatusCode::BAD_REQUEST,
            "Cannot change your own password.",
            "Cannot change your own password.",
        );
    }
    if parsed_bool_form_field(&fields, "sendEmail").unwrap_or(false)
        || parsed_bool_form_field(&fields, "generateRandom").unwrap_or(false)
    {
        return named_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email-based password delivery is not configured",
            "Email-based password delivery is not configured",
        );
    }
    let Some(new_password) = required_form_field(&fields, "newPassword") else {
        return invalid_form_response();
    };
    let username = username.to_owned();
    let new_password = Zeroizing::new(new_password.to_owned());
    let result = task::spawn_blocking(move || {
        store.set_user_password(&username, &new_password, Utc::now().timestamp())
    })
    .await;
    admin_user_mutation_response(&result, "User password updated successfully")
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

async fn generate_invite(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Extension(config): Extension<SecurityHttpConfig>,
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
    if required_form_field(&fields, "sendEmail").is_some_and(|value| value == "true") {
        return named_json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Email service is not configured",
            "Email service is not configured",
        );
    }
    let email = required_form_field(&fields, "email").map(str::to_owned);
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
            let base_url = required_form_field(&fields, "frontendBaseUrl")
                .filter(|url| url.starts_with("https://") || url.starts_with("http://"))
                .unwrap_or(&config.frontend_url)
                .trim_end_matches('/');
            let invite_url = if base_url.is_empty() {
                format!("/invite/{}", invite.token.as_str())
            } else {
                format!("{base_url}/invite/{}", invite.token.as_str())
            };
            Json(serde_json::json!({
                "token": invite.token.as_str(),
                "inviteUrl": invite_url,
                "email": invite.email,
                "expiresAt": timestamp_string(invite.expires_at),
                "expiryHours": expiry_hours,
                "emailSent": false,
            }))
            .into_response()
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
        Ok(Err(_)) | Err(_) => service_unavailable_response(),
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

fn invalid_form_response() -> Response {
    named_json_error(
        StatusCode::BAD_REQUEST,
        "Invalid request",
        "Invalid request",
    )
}

async fn current_user(Extension(context): Extension<AuthContext>) -> Response {
    Json(serde_json::json!({ "user": authentication_user(&context) })).into_response()
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
        user_metadata: UserMetadata { first_login: false },
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
        SecurityHttpConfig, SecurityStartupError, initialize_security_store, secure_router,
        secure_router_with_config,
    };
    use crate::admin_settings::AdminSettingsService;
    use crate::job_manager::{JobManager, JobOwner};
    use crate::job_queue::{JobQueue, JobQueueConfig};
    use crate::runtime_config::RuntimeConfig;
    use crate::security::SecurityStore;
    use crate::security_crypto::totp_code_at;
    use crate::security_jwt::{SupabaseJwtConfig, SupabaseJwtVerifier};
    use axum::{
        Extension, Router,
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
        routing::get,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde::Serialize;
    use serde_json::Value;
    use std::{fs, sync::Arc};
    use tempfile::tempdir;
    use tower::ServiceExt as _;

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
    async fn authenticated_mutations_write_attempt_and_outcome_audit_events()
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
        Ok(())
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
        let (app, token) = test_router_with_external_jwt()?;
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

    fn test_router_with_external_jwt() -> Result<(Router, String), Box<dyn std::error::Error>> {
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
            store,
            SecurityHttpConfig {
                totp_issuer: "Stirling PDF".to_owned(),
                invites_enabled: true,
                invite_expiry_hours: 168,
                frontend_url: String::new(),
                external_jwt: Some(verifier),
            },
        );
        Ok((app, token))
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
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "test password")?);
        let router = Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/api/v1/general/protected", get(|| async { "ok" }));
        Ok((secure_router(router, Arc::clone(&store)), store))
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
