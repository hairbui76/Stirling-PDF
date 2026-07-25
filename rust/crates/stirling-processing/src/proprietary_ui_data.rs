//! Read-only proprietary UI-data projections for the secured client.
//!
//! Mirrors the non-mutating endpoints of Java's `ProprietaryUIDataController`
//! under `/api/v1/proprietary/ui-data`. Every route is a thin read over
//! already-ported stores (`SecurityStore`) and server-owned configuration; no
//! route makes a UI decision or mutates state.
//!
//! Authorization mirrors the sibling proprietary routes (see
//! `integration_http`): the secured middleware injects the trusted
//! [`AuthContext`] and the shared [`SecurityStore`] / [`SecurityHttpConfig`]
//! extensions, and each handler performs its own role / entitlement / demo gate
//! so it is correct regardless of the coarse path policy.
//!
//! Deliberate partial (by decision): SAML2 login is **deferred** in this port.
//! SAML2 provider entries are **omitted** from the login `providerList` and no
//! SAML2 handshake is served; `OAuth2` providers (the generic provider plus the
//! Google / GitHub / Keycloak clients) are still emitted. Because of this the
//! `altLogin` flag is **OAuth2-only** here — it is true iff `providerList` holds
//! at least one (`OAuth2`) provider. This is a known divergence from Java for a
//! SAML2-only configuration: Java computes
//! `altLogin = !providerList.isEmpty() && isAltLogin()`, where `providerList`
//! also carries a SAML redirect entry (when `isSaml2Active() && premium.enabled`)
//! and `isAltLogin() == saml2.enabled || oauth2.enabled`. So a config with only
//! SAML2 enabled yields `altLogin=true` in Java but `false` here. Once SAML2
//! login lands, `altLogin` must again reflect a configured SAML2 provider.
//!
//! Parity notes:
//! - Unknown `teams/{id}` returns HTTP 404 (`not_found`). This is a **deliberate
//!   correctness improvement** over the Java oracle, which throws a bare
//!   `RuntimeException("Team not found")` with no cause; `GlobalExceptionHandler`
//!   falls through every `cause instanceof` branch to its unexpected-error path
//!   and returns HTTP 500. The frontend `teamService.getTeamDetails` issues a
//!   plain GET and does not distinguish 404 from 500, so the client behaviour is
//!   unchanged while the returned status is the semantically correct one.
//! - The login provider URLs use Java's `/oauth2/authorization/{name}` shape;
//!   the Rust runtime's actual OIDC login handshake lives on a different route
//!   (`/api/v1/auth/oidc/*`). The list is reported for UI parity.
//! - Session "last activity" is derived from each session's `created_at` (the
//!   Rust store records no per-request `lastRequest`); it is emitted in epoch
//!   milliseconds to match Java's `Date` serialization the client expects.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Extension, Json, Router,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::task;

use crate::{
    runtime_config::RuntimeConfig,
    security::{
        AuthContext, INTERNAL_TEAM_NAME, SecurityError, SecurityStore, SecurityUserSummary,
    },
    security_http::SecurityHttpConfig,
    security_policy::LicenseTier,
};

const LOGIN_PATH: &str = "/api/v1/proprietary/ui-data/login";
const ACCOUNT_PATH: &str = "/api/v1/proprietary/ui-data/account";
const AUDIT_DASHBOARD_PATH: &str = "/api/v1/proprietary/ui-data/audit-dashboard";
const TEAMS_PATH: &str = "/api/v1/proprietary/ui-data/teams";
const TEAM_DETAILS_PATH: &str = "/api/v1/proprietary/ui-data/teams/{id}";

/// Fixed `AuditEventType` vocabulary in Java declaration order, mirroring
/// `stirling.software.proprietary.audit.AuditEventType.values()`. Declared here
/// (rather than reusing the private, sorted, observed-types list in
/// `security_audit_http`) because the dashboard enumerates the full enum, not
/// the types actually seen in the audit log.
const AUDIT_EVENT_TYPES: [&str; 9] = [
    "USER_LOGIN",
    "USER_LOGOUT",
    "USER_FAILED_LOGIN",
    "USER_PROFILE_UPDATE",
    "SETTINGS_CHANGED",
    "FILE_OPERATION",
    "PDF_PROCESS",
    "UI_DATA",
    "HTTP_REQUEST",
];

/// Startup snapshot of the server-owned configuration the read projections need.
/// Built once from [`RuntimeConfig`] so handlers never re-parse settings.
pub(crate) struct UiDataConfig {
    login: LoginStaticConfig,
    audit: AuditStaticConfig,
}

struct LoginStaticConfig {
    enable_login: bool,
    sso_auto_login: bool,
    login_method: String,
    alt_login: bool,
    provider_list: BTreeMap<String, String>,
    languages: Vec<String>,
    default_locale: String,
}

#[allow(clippy::struct_excessive_bools)] // Independent audit-configuration flags.
struct AuditStaticConfig {
    audit_enabled: bool,
    audit_level: u8,
    retention_days: i64,
    capture_file_hash: bool,
    capture_pdf_author: bool,
    capture_operation_results: bool,
}

impl UiDataConfig {
    pub(crate) fn from_runtime_config(runtime_config: &RuntimeConfig) -> Self {
        let settings = runtime_config.settings_snapshot();
        // `defaultLocale` already resolves env-over-YAML through `app_config`.
        let default_locale = runtime_config
            .app_config(None, None)
            .get("defaultLocale")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let login = LoginStaticConfig::from_settings(
            &settings,
            runtime_config.ui_languages(),
            default_locale,
        );
        let audit = AuditStaticConfig {
            audit_enabled: runtime_config.security_audit_enabled(),
            audit_level: runtime_config.security_audit_level(),
            retention_days: runtime_config.security_audit_retention_days(),
            capture_file_hash: runtime_config.security_audit_capture_file_hash(),
            capture_pdf_author: runtime_config.security_audit_capture_pdf_author(),
            capture_operation_results: runtime_config.security_audit_capture_operation_results(),
        };
        Self { login, audit }
    }
}

impl LoginStaticConfig {
    fn from_settings(settings: &Value, languages: Vec<String>, default_locale: String) -> Self {
        let enable_login = config_bool(
            settings,
            &["security", "enableLogin"],
            "SECURITY_ENABLELOGIN",
        );
        let sso_auto_login = config_bool(
            settings,
            &["premium", "proFeatures", "ssoAutoLogin"],
            "PREMIUM_PROFEATURES_SSOAUTOLOGIN",
        );
        let login_method = config_string(
            settings,
            &["security", "loginMethod"],
            "SECURITY_LOGINMETHOD",
            "all",
        );
        let oauth2_enabled = config_bool(
            settings,
            &["security", "oauth2", "enabled"],
            "SECURITY_OAUTH2_ENABLED",
        );

        let provider_list = build_provider_list(settings, oauth2_enabled, &login_method);
        // Java: `altLogin = !providerList.isEmpty() && isAltLogin()`, where
        // `isAltLogin() == saml2.enabled || oauth2.enabled`. SAML2 login is
        // deferred here (no SAML entry is ever added to `provider_list`, and no
        // handshake exists), so `provider_list` is non-empty only when OAuth2
        // contributes a valid provider — which already implies `oauth2.enabled`.
        // altLogin is therefore OAuth2-only; the `saml2.enabled` term is dropped
        // rather than left as dead code. See the module header for the
        // SAML2-only divergence this intentionally accepts.
        let alt_login = !provider_list.is_empty();

        Self {
            enable_login,
            sso_auto_login,
            login_method,
            alt_login,
            provider_list,
            languages,
            default_locale,
        }
    }
}

pub(crate) fn routes(config: UiDataConfig) -> Router {
    Router::new()
        .route(LOGIN_PATH, get(login_data))
        .route(ACCOUNT_PATH, get(account_data))
        .route(AUDIT_DASHBOARD_PATH, get(audit_dashboard_data))
        .route(TEAMS_PATH, get(teams_data))
        .route(TEAM_DETAILS_PATH, get(team_details_data))
        .layer(Extension(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// GET /login (public)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent fields of the Java LoginData contract.
struct LoginData {
    enable_login: bool,
    sso_auto_login: bool,
    provider_list: BTreeMap<String, String>,
    login_method: String,
    alt_login: bool,
    first_time_setup: bool,
    show_default_credentials: bool,
    languages: Vec<String>,
    default_locale: String,
}

async fn login_data(
    Extension(config): Extension<Arc<UiDataConfig>>,
    Extension(store): Extension<Arc<SecurityStore>>,
) -> Response {
    let setup_store = Arc::clone(&store);
    let Ok(Ok(show)) = task::spawn_blocking(move || setup_store.first_time_setup_required()).await
    else {
        return service_unavailable();
    };
    let login = &config.login;
    Json(LoginData {
        enable_login: login.enable_login,
        sso_auto_login: login.sso_auto_login,
        provider_list: login.provider_list.clone(),
        login_method: login.login_method.clone(),
        alt_login: login.alt_login,
        first_time_setup: show,
        show_default_credentials: show,
        languages: login.languages.clone(),
        default_locale: login.default_locale.clone(),
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// GET /account (non-demo user); superset of /auth/me
// ---------------------------------------------------------------------------

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountUser {
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
#[serde(rename_all = "camelCase")]
struct MfaStatus {
    enabled: bool,
    recovery_codes_remaining: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent fields of the Java AccountData contract.
struct AccountData {
    // /auth/me superset: identical `user` + `mfa` blocks as `current_user`.
    user: AccountUser,
    mfa: MfaStatus,
    // Account-page fields (Java `AccountData` + frontend `accountService`).
    username: String,
    role: String,
    settings: String,
    change_creds_flag: bool,
    #[serde(rename = "oAuth2Login")]
    o_auth2_login: bool,
    saml2_login: bool,
    mfa_enabled: bool,
    mfa_required: bool,
}

struct AccountFacts {
    mfa_enabled: bool,
    mfa_required: bool,
    recovery_codes_remaining: i64,
    initial_setup_complete: bool,
    settings: BTreeMap<String, String>,
}

async fn account_data(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    // Java: @PreAuthorize("!hasAuthority('ROLE_DEMO_USER')").
    if context.has_role("ROLE_DEMO_USER") {
        return forbidden();
    }
    let user_id = context.user_id;
    let facts_store = Arc::clone(&store);
    let facts = task::spawn_blocking(move || {
        Ok::<_, SecurityError>(AccountFacts {
            mfa_enabled: facts_store.mfa_is_enabled(user_id)?,
            mfa_required: facts_store.mfa_is_required(user_id)?,
            recovery_codes_remaining: facts_store.remaining_recovery_codes(user_id)?,
            initial_setup_complete: facts_store.initial_setup_is_complete(user_id)?,
            settings: facts_store.user_settings(user_id)?,
        })
    })
    .await;
    let facts = match facts {
        Ok(Ok(facts)) => facts,
        Ok(Err(SecurityError::UserNotFound)) => return not_found(),
        Ok(Err(_)) | Err(_) => return service_unavailable(),
    };

    let authentication_type = authentication_type_label(&context.authentication_type);
    let role = context.roles.iter().cloned().collect::<Vec<_>>().join(", ");
    // Java: `isFirstLogin || forcePasswordChange`; first-login ⇔ setup incomplete.
    let change_creds_flag = !facts.initial_setup_complete || context.force_password_change;

    Json(AccountData {
        user: AccountUser {
            id: context.user_id,
            email: context.username.clone(),
            username: context.username.clone(),
            role: role.clone(),
            enabled: true,
            portal_access: context.has_role("ROLE_ADMIN"),
            team_lead: false,
            authentication_type,
            app_metadata: AppMetadata {
                provider: authentication_type,
            },
            // Mirrors /auth/me exactly (first_login is not surfaced there); the
            // real first-login state is carried by `changeCredsFlag`.
            user_metadata: UserMetadata {
                first_login: false,
                force_password_change: context.force_password_change,
            },
        },
        mfa: MfaStatus {
            enabled: facts.mfa_enabled,
            recovery_codes_remaining: facts.recovery_codes_remaining,
        },
        username: context.username.clone(),
        role,
        settings: masked_settings_json(facts.settings),
        change_creds_flag,
        // SAML2 login is omitted (deferred); a SAML principal never reaches here.
        o_auth2_login: authentication_type == "oauth2",
        saml2_login: false,
        mfa_enabled: facts.mfa_enabled,
        mfa_required: facts.mfa_required,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// GET /audit-dashboard (admin + Enterprise)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent fields of the Java AuditDashboardData contract.
struct AuditDashboardData {
    audit_enabled: bool,
    audit_level: &'static str,
    audit_level_int: u8,
    retention_days: i64,
    audit_levels: Vec<&'static str>,
    audit_event_types: Vec<&'static str>,
    pdf_metadata_enabled: bool,
    capture_file_hash: bool,
    capture_pdf_author: bool,
    capture_operation_results: bool,
}

async fn audit_dashboard_data(
    Extension(config): Extension<Arc<UiDataConfig>>,
    Extension(context): Extension<AuthContext>,
    Extension(http_config): Extension<SecurityHttpConfig>,
) -> Response {
    if !context.has_role("ROLE_ADMIN") {
        return forbidden();
    }
    // Java: @EnterpriseEndpoint. Gate on the verified tier, not config intent.
    if http_config.license_tier != LicenseTier::Enterprise {
        return enterprise_required();
    }
    let audit = &config.audit;
    let levels = RuntimeConfig::audit_levels();
    let level_name = levels
        .get(usize::from(audit.audit_level))
        .copied()
        .unwrap_or("STANDARD");
    Json(AuditDashboardData {
        audit_enabled: audit.audit_enabled,
        audit_level: level_name,
        audit_level_int: audit.audit_level,
        retention_days: audit.retention_days,
        audit_levels: levels.to_vec(),
        audit_event_types: AUDIT_EVENT_TYPES.to_vec(),
        // Java: file hash OR pdf author.
        pdf_metadata_enabled: audit.capture_file_hash || audit.capture_pdf_author,
        capture_file_hash: audit.capture_file_hash,
        capture_pdf_author: audit.capture_pdf_author,
        capture_operation_results: audit.capture_operation_results,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// GET /teams (admin)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamWithUserCount {
    id: i64,
    name: String,
    user_count: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamsData {
    teams_with_counts: Vec<TeamWithUserCount>,
    team_last_request: BTreeMap<i64, Option<i64>>,
    team_owners: BTreeMap<i64, Vec<String>>,
}

async fn teams_data(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    if !context.has_role("ROLE_ADMIN") {
        return forbidden();
    }
    let query_store = Arc::clone(&store);
    let result = task::spawn_blocking(move || {
        let teams = query_store.list_teams()?;
        let activity = query_store.latest_session_activity_per_team()?;
        let leaders = query_store.team_leaders()?;
        Ok::<_, SecurityError>((teams, activity, leaders))
    })
    .await;
    let Ok(Ok((teams, activity, leaders))) = result else {
        return service_unavailable();
    };

    let teams_with_counts = teams
        .into_iter()
        .filter(|team| !team.name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        .map(|team| TeamWithUserCount {
            id: team.id,
            name: team.name,
            user_count: team.member_count,
        })
        .collect::<Vec<_>>();

    let team_last_request = activity
        .into_iter()
        .map(|(team_id, activity)| (team_id, activity.map(to_epoch_millis)))
        .collect::<BTreeMap<_, _>>();

    let mut team_owners: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for (team_id, _user_id, username) in leaders {
        team_owners.entry(team_id).or_default().push(username);
    }

    Json(TeamsData {
        teams_with_counts,
        team_last_request,
        team_owners,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// GET /teams/{id} (admin)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamRef {
    id: i64,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamDetailsData {
    team: TeamRef,
    team_users: Vec<SecurityUserSummary>,
    available_users: Vec<SecurityUserSummary>,
    user_last_request: BTreeMap<String, Option<i64>>,
    owner_user_ids: Vec<i64>,
}

enum TeamLookup {
    NotFound,
    Internal,
    Found {
        name: String,
        all_users: Vec<SecurityUserSummary>,
        sessions: Vec<(String, Option<i64>)>,
        leaders: Vec<(i64, i64, String)>,
    },
}

async fn team_details_data(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Path(team_id): Path<i64>,
) -> Response {
    if !context.has_role("ROLE_ADMIN") {
        return forbidden();
    }
    let query_store = Arc::clone(&store);
    let result = task::spawn_blocking(move || {
        let Some(name) = query_store.team_name(team_id)? else {
            return Ok::<_, SecurityError>(TeamLookup::NotFound);
        };
        if name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME) {
            return Ok(TeamLookup::Internal);
        }
        let all_users = query_store.list_users(Utc::now().timestamp())?;
        let sessions = query_store.latest_session_by_team(team_id)?;
        let leaders = query_store.team_leaders()?;
        Ok(TeamLookup::Found {
            name,
            all_users,
            sessions,
            leaders,
        })
    })
    .await;

    match result {
        // Deliberate 404 (vs Java's accidental 500 from a bare `RuntimeException`
        // with no cause). See the module-header parity note.
        Ok(Ok(TeamLookup::NotFound)) => not_found(),
        // Java returns 403 for the internal team.
        Ok(Ok(TeamLookup::Internal)) => forbidden(),
        Ok(Ok(TeamLookup::Found {
            name,
            all_users,
            sessions,
            leaders,
        })) => {
            let team_users = all_users
                .iter()
                .filter(|user| user.team_id == Some(team_id))
                .cloned()
                .collect::<Vec<_>>();
            // Available: not on this team and not on the internal team.
            let available_users = all_users
                .into_iter()
                .filter(|user| {
                    user.team_id != Some(team_id)
                        && !user
                            .team_name
                            .as_deref()
                            .is_some_and(|team| team.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
                })
                .collect::<Vec<_>>();
            let user_last_request = sessions
                .into_iter()
                .map(|(username, activity)| (username, activity.map(to_epoch_millis)))
                .collect::<BTreeMap<_, _>>();
            let owner_user_ids = leaders
                .into_iter()
                .filter(|(owner_team_id, _, _)| *owner_team_id == team_id)
                .map(|(_, user_id, _)| user_id)
                .collect::<Vec<_>>();
            Json(TeamDetailsData {
                team: TeamRef { id: team_id, name },
                team_users,
                available_users,
                user_last_request,
                owner_user_ids,
            })
            .into_response()
        }
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Java `Date` serializes as epoch milliseconds; the store records seconds.
fn to_epoch_millis(seconds: i64) -> i64 {
    seconds.saturating_mul(1000)
}

/// Maps the stored authentication type onto the fixed labels `/auth/me` uses.
fn authentication_type_label(authentication_type: &str) -> &'static str {
    match authentication_type {
        "anonymous" => "anonymous",
        "oauth2" => "oauth2",
        "supabase" => "supabase",
        _ => "web",
    }
}

/// Serializes the user settings to a JSON string with any `mfaSecret` masked,
/// mirroring Java `maskSecrets`. In this port the TOTP secret lives in a
/// separate table, so this is defensive rather than load-bearing.
fn masked_settings_json(mut settings: BTreeMap<String, String>) -> String {
    if settings.contains_key("mfaSecret") {
        settings.insert("mfaSecret".to_owned(), "********".to_owned());
    }
    serde_json::to_string(&settings).unwrap_or_else(|_| "{}".to_owned())
}

fn build_provider_list(
    settings: &Value,
    oauth2_enabled: bool,
    login_method: &str,
) -> BTreeMap<String, String> {
    let mut provider_list = BTreeMap::new();
    // Java: `oauth.getEnabled() && isOauth2Active()`, where isOauth2Active is
    // `enabled && loginMethod != "normal"`.
    if !oauth2_enabled || login_method.eq_ignore_ascii_case("normal") {
        return provider_list;
    }
    if oauth2_settings_valid(settings) {
        let provider = yaml_string(settings, &["security", "oauth2", "provider"]);
        let provider = provider.trim();
        // Java would throw on an empty provider (`charAt(0)`); we skip instead.
        if !provider.is_empty() {
            provider_list.insert(
                format!("/oauth2/authorization/{provider}"),
                capitalize_first(provider),
            );
        }
    }
    // Fixed provider names/display names (Google/GitHub/KeycloakProvider).
    for (client, name, display) in [
        ("google", "google", "Google"),
        ("github", "github", "GitHub"),
        ("keycloak", "keycloak", "Keycloak"),
    ] {
        if validate_client(settings, client) {
            provider_list.insert(format!("/oauth2/authorization/{name}"), display.to_owned());
        }
    }
    provider_list
}

/// Java `OAUTH2.isSettingsValid()`: issuer, clientId, clientSecret, scopes and
/// useAsUsername all present.
fn oauth2_settings_valid(settings: &Value) -> bool {
    !yaml_string(settings, &["security", "oauth2", "issuer"])
        .trim()
        .is_empty()
        && !yaml_string(settings, &["security", "oauth2", "clientId"])
            .trim()
            .is_empty()
        && !yaml_string(settings, &["security", "oauth2", "clientSecret"])
            .trim()
            .is_empty()
        && collection_present(settings, &["security", "oauth2", "scopes"])
        && !yaml_string(settings, &["security", "oauth2", "useAsUsername"])
            .trim()
            .is_empty()
}

/// Java `ProviderUtils.validateProvider`: a client provider is valid when its
/// clientId, clientSecret and scopes are all non-empty.
fn validate_client(settings: &Value, client: &str) -> bool {
    !yaml_string(
        settings,
        &["security", "oauth2", "client", client, "clientId"],
    )
    .trim()
    .is_empty()
        && !yaml_string(
            settings,
            &["security", "oauth2", "client", client, "clientSecret"],
        )
        .trim()
        .is_empty()
        && collection_present(
            settings,
            &["security", "oauth2", "client", client, "scopes"],
        )
}

fn capitalize_first(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
}

/// A scope collection is "present" when it is a non-empty YAML list or a
/// non-blank string (Java accepts both a comma string and a list).
fn collection_present(settings: &Value, path: &[&str]) -> bool {
    match value_at(settings, path) {
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::String(text)) => !text.trim().is_empty(),
        _ => false,
    }
}

fn yaml_string(settings: &Value, path: &[&str]) -> String {
    value_at(settings, path)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_default()
}

/// Env-first, then YAML, then `false` — mirroring `RuntimeConfig::boolean`.
fn config_bool(settings: &Value, path: &[&str], environment: &str) -> bool {
    if let Ok(value) = std::env::var(environment) {
        match value.trim().to_ascii_lowercase().as_str() {
            "true" => return true,
            "false" => return false,
            _ => {}
        }
    }
    value_at(settings, path)
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Env-first, then YAML, then default — mirroring `RuntimeConfig::string`.
fn config_string(settings: &Value, path: &[&str], environment: &str, default: &str) -> String {
    if let Ok(value) = std::env::var(environment) {
        return value;
    }
    value_at(settings, path)
        .and_then(Value::as_str)
        .map_or_else(|| default.to_owned(), ToOwned::to_owned)
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn forbidden() -> Response {
    json_error(StatusCode::FORBIDDEN, "Forbidden")
}

fn enterprise_required() -> Response {
    json_error(
        StatusCode::FORBIDDEN,
        "This endpoint requires an Enterprise license",
    )
}

fn not_found() -> Response {
    json_error(StatusCode::NOT_FOUND, "Team not found")
}

fn service_unavailable() -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "UI data service unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AUDIT_EVENT_TYPES, LoginStaticConfig, build_provider_list, capitalize_first,
        collection_present, config_bool, config_string, masked_settings_json, to_epoch_millis,
        validate_client,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn capitalizes_first_character_only() {
        assert_eq!(capitalize_first("keycloak"), "Keycloak");
        assert_eq!(capitalize_first("authentik"), "Authentik");
        assert_eq!(capitalize_first("a"), "A");
        assert_eq!(capitalize_first(""), "");
    }

    #[test]
    fn epoch_millis_scales_seconds() {
        assert_eq!(to_epoch_millis(0), 0);
        assert_eq!(to_epoch_millis(1_700_000_000), 1_700_000_000_000);
        // Never overflows into a panic on an absurd value.
        assert_eq!(to_epoch_millis(i64::MAX), i64::MAX);
    }

    #[test]
    fn masks_mfa_secret_when_present() {
        let mut settings = BTreeMap::new();
        settings.insert("mfaSecret".to_owned(), "TOTPSECRET".to_owned());
        settings.insert("theme".to_owned(), "dark".to_owned());
        let json = masked_settings_json(settings);
        assert!(json.contains("\"mfaSecret\":\"********\""));
        assert!(!json.contains("TOTPSECRET"));
        assert!(json.contains("\"theme\":\"dark\""));
    }

    #[test]
    fn masks_nothing_without_secret() {
        assert_eq!(masked_settings_json(BTreeMap::new()), "{}");
    }

    #[test]
    fn config_bool_prefers_yaml_when_env_absent() {
        let settings = json!({ "security": { "enableLogin": true } });
        // Use an env name guaranteed unset in the test process.
        assert!(config_bool(
            &settings,
            &["security", "enableLogin"],
            "PROP_UI_DATA_TEST_UNSET_ENABLE"
        ));
        assert!(!config_bool(
            &settings,
            &["security", "missing"],
            "PROP_UI_DATA_TEST_UNSET_MISSING"
        ));
    }

    #[test]
    fn config_string_defaults_when_missing() {
        let settings = json!({ "security": {} });
        assert_eq!(
            config_string(
                &settings,
                &["security", "loginMethod"],
                "PROP_UI_DATA_TEST_UNSET_METHOD",
                "all"
            ),
            "all"
        );
    }

    #[test]
    fn collection_present_accepts_list_and_string() {
        let list = json!({ "s": ["openid", "email"] });
        assert!(collection_present(&list, &["s"]));
        let empty_list = json!({ "s": [] });
        assert!(!collection_present(&empty_list, &["s"]));
        let comma = json!({ "s": "openid,email" });
        assert!(collection_present(&comma, &["s"]));
        let blank = json!({ "s": "  " });
        assert!(!collection_present(&blank, &["s"]));
        let missing = json!({});
        assert!(!collection_present(&missing, &["s"]));
    }

    #[test]
    fn validate_client_requires_id_secret_and_scopes() {
        let complete = json!({
            "security": { "oauth2": { "client": { "google": {
                "clientId": "id", "clientSecret": "secret", "scopes": ["openid"]
            } } } }
        });
        assert!(validate_client(&complete, "google"));

        let no_secret = json!({
            "security": { "oauth2": { "client": { "github": {
                "clientId": "id", "scopes": ["openid"]
            } } } }
        });
        assert!(!validate_client(&no_secret, "github"));

        assert!(!validate_client(&json!({}), "keycloak"));
    }

    #[test]
    fn provider_list_empty_when_oauth2_disabled() {
        let settings = json!({ "security": { "oauth2": { "enabled": false } } });
        assert!(build_provider_list(&settings, false, "all").is_empty());
    }

    #[test]
    fn provider_list_empty_for_normal_login_method() {
        let settings = json!({
            "security": { "oauth2": {
                "client": { "google": {
                    "clientId": "id", "clientSecret": "secret", "scopes": ["openid"]
                } }
            } }
        });
        // oauth2 enabled but loginMethod=normal → no providers.
        assert!(build_provider_list(&settings, true, "normal").is_empty());
    }

    #[test]
    fn provider_list_includes_generic_and_clients() {
        let settings = json!({
            "security": { "oauth2": {
                "issuer": "https://issuer.example.com",
                "clientId": "cid",
                "clientSecret": "csecret",
                "useAsUsername": "email",
                "scopes": ["openid", "email"],
                "provider": "authentik",
                "client": {
                    "google": {
                        "clientId": "gid", "clientSecret": "gsecret", "scopes": ["openid"]
                    },
                    "github": { "clientId": "", "clientSecret": "", "scopes": [] },
                    "keycloak": {
                        "clientId": "kid", "clientSecret": "ksecret", "scopes": ["openid"]
                    }
                }
            } }
        });
        let providers = build_provider_list(&settings, true, "all");
        assert_eq!(
            providers
                .get("/oauth2/authorization/authentik")
                .map(String::as_str),
            Some("Authentik")
        );
        assert_eq!(
            providers
                .get("/oauth2/authorization/google")
                .map(String::as_str),
            Some("Google")
        );
        assert_eq!(
            providers
                .get("/oauth2/authorization/keycloak")
                .map(String::as_str),
            Some("Keycloak")
        );
        // GitHub was incompletely configured → excluded.
        assert!(!providers.contains_key("/oauth2/authorization/github"));
    }

    #[test]
    fn generic_provider_skipped_when_settings_incomplete() {
        // Missing useAsUsername → generic entry not emitted, but a valid client is.
        let settings = json!({
            "security": { "oauth2": {
                "issuer": "https://issuer.example.com",
                "clientId": "cid",
                "clientSecret": "csecret",
                "scopes": ["openid"],
                "provider": "authentik",
                "client": { "google": {
                    "clientId": "gid", "clientSecret": "gsecret", "scopes": ["openid"]
                } }
            } }
        });
        let providers = build_provider_list(&settings, true, "all");
        assert!(!providers.contains_key("/oauth2/authorization/authentik"));
        assert!(providers.contains_key("/oauth2/authorization/google"));
    }

    #[test]
    fn alt_login_is_oauth2_only() {
        // oauth2 enabled + valid client → providers present → altLogin true.
        let with_providers = json!({
            "security": {
                "oauth2": {
                    "enabled": true,
                    "client": { "google": {
                        "clientId": "gid", "clientSecret": "gsecret", "scopes": ["openid"]
                    } }
                }
            }
        });
        let login = LoginStaticConfig::from_settings(&with_providers, vec![], String::new());
        assert!(login.alt_login);
        assert_eq!(login.login_method, "all");

        // Nothing enabled → no providers → altLogin false.
        let none = json!({ "security": { "oauth2": { "enabled": false } } });
        let login = LoginStaticConfig::from_settings(&none, vec![], String::new());
        assert!(!login.alt_login);
        assert!(login.provider_list.is_empty());

        // SAML2-only (oauth2 disabled, saml2 enabled + configured): SAML2 login
        // is deferred, so altLogin is OAuth2-only and stays false, and no SAML
        // entry ever reaches the provider list. This is the documented
        // divergence from Java's `isAltLogin()` (which would be true here).
        let saml2_only = json!({
            "security": {
                "oauth2": { "enabled": false },
                "saml2": {
                    "enabled": true,
                    "provider": "Corp IdP",
                    "registrationId": "stirling"
                }
            }
        });
        let login = LoginStaticConfig::from_settings(&saml2_only, vec![], String::new());
        assert!(!login.alt_login);
        assert!(login.provider_list.is_empty());
    }

    #[test]
    fn audit_event_types_match_java_enum() {
        assert_eq!(AUDIT_EVENT_TYPES.len(), 9);
        assert_eq!(AUDIT_EVENT_TYPES[0], "USER_LOGIN");
        assert_eq!(AUDIT_EVENT_TYPES[8], "HTTP_REQUEST");
    }

    #[test]
    fn saml2_omission_does_not_drop_oauth2_providers() {
        // Adversarial: a config that also configures SAML2 must not cause the
        // OAuth2 providers to be lost. SAML2 entries are deliberately omitted
        // (deferred), but every valid OAuth2 provider is still emitted and no
        // SAML redirect path leaks into the list.
        let settings = json!({
            "security": {
                "oauth2": {
                    "enabled": true,
                    "issuer": "https://issuer.example.com",
                    "clientId": "cid",
                    "clientSecret": "csecret",
                    "useAsUsername": "email",
                    "scopes": ["openid", "email"],
                    "provider": "authentik",
                    "client": { "google": {
                        "clientId": "gid", "clientSecret": "gsecret", "scopes": ["openid"]
                    } }
                },
                "saml2": { "enabled": true, "provider": "Corp IdP", "registrationId": "stirling" }
            }
        });
        let providers = build_provider_list(&settings, true, "all");
        assert!(providers.contains_key("/oauth2/authorization/authentik"));
        assert!(providers.contains_key("/oauth2/authorization/google"));
        // No SAML2 redirect path is ever emitted.
        assert!(
            providers
                .keys()
                .all(|key| key.starts_with("/oauth2/authorization/"))
        );
    }
}

#[cfg(test)]
mod route_tests {
    //! End-to-end handler tests: they drive the real `routes()` router with an
    //! injected [`AuthContext`], exercising the authorization gates, the
    //! not-found / forbidden paths and the available-users filter that the
    //! store-level tests cannot reach. `enforce_security` is intentionally not
    //! layered here so each test can present an arbitrary trusted context; the
    //! coarse-policy classification is asserted separately against
    //! `security_policy::endpoint_policy`.

    use super::{
        ACCOUNT_PATH, AUDIT_DASHBOARD_PATH, AUDIT_EVENT_TYPES, AuditStaticConfig, LOGIN_PATH,
        LoginStaticConfig, TEAMS_PATH, UiDataConfig, routes,
    };
    use crate::security::{AuthContext, AuthenticationSource, INTERNAL_TEAM_NAME, SecurityStore};
    use crate::security_http::{SecurityAuditFileCaptureConfig, SecurityHttpConfig};
    use crate::security_policy::{EndpointPolicy, LicenseTier, endpoint_policy};
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use axum::{Extension, Router};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn context(user_id: i64, username: &str, roles: &[&str]) -> AuthContext {
        AuthContext {
            user_id,
            username: username.to_owned(),
            authentication_source: AuthenticationSource::AccessToken,
            authentication_type: "web".to_owned(),
            roles: roles
                .iter()
                .copied()
                .map(str::to_owned)
                .collect::<BTreeSet<String>>(),
            team_id: None,
            permissions: BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        }
    }

    fn test_ui_data_config() -> UiDataConfig {
        // OAuth2 disabled + SAML2 deferred → no providers; audit fully populated.
        let settings = json!({ "security": { "oauth2": { "enabled": false } } });
        let login = LoginStaticConfig::from_settings(
            &settings,
            vec!["en-US".to_owned()],
            "en-US".to_owned(),
        );
        let audit = AuditStaticConfig {
            audit_enabled: true,
            audit_level: 2,
            retention_days: 90,
            capture_file_hash: true,
            capture_pdf_author: false,
            capture_operation_results: false,
        };
        UiDataConfig { login, audit }
    }

    fn test_http_config(license_tier: LicenseTier) -> SecurityHttpConfig {
        SecurityHttpConfig {
            totp_issuer: "Stirling PDF".to_owned(),
            invites_enabled: false,
            invite_expiry_hours: 168,
            frontend_url: String::new(),
            backend_url: String::new(),
            audit_enabled: true,
            audit_level: 2,
            audit_file_capture: SecurityAuditFileCaptureConfig::default(),
            audit_capture_operation_results: false,
            license_tier,
            external_jwt: None,
            oidc_login_provider: None,
        }
    }

    fn build_router(store: &Arc<SecurityStore>, license_tier: LicenseTier) -> Router {
        routes(test_ui_data_config())
            .layer(Extension(Arc::clone(store)))
            .layer(Extension(test_http_config(license_tier)))
    }

    async fn send(
        app: &Router,
        context: Option<AuthContext>,
        path: &str,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let mut request = Request::get(path).body(Body::empty())?;
        if let Some(context) = context {
            request.extensions_mut().insert(context);
        }
        Ok(app.clone().oneshot(request).await?)
    }

    async fn response_json(
        response: axum::response::Response,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), 1024 * 1024).await?,
        )?)
    }

    fn usernames(value: &Value) -> Vec<String> {
        value
            .as_array()
            .map(|users| {
                users
                    .iter()
                    .filter_map(|user| user["username"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn routing_policy_matches_java_authorization() {
        // Login is public: the frontend fetches it before any session exists.
        assert_eq!(
            endpoint_policy(&Method::GET, LOGIN_PATH),
            EndpointPolicy::Public
        );
        // Account is any-authenticated at the edge; the handler enforces the
        // non-demo rule (Java `@PreAuthorize("!hasAuthority('ROLE_DEMO_USER')")`).
        assert_eq!(
            endpoint_policy(&Method::GET, ACCOUNT_PATH),
            EndpointPolicy::Authenticated
        );
        // The audit dashboard is admin-only at the edge (the `audit-` prefix).
        assert_eq!(
            endpoint_policy(&Method::GET, AUDIT_DASHBOARD_PATH),
            EndpointPolicy::Administrator
        );
        // Teams are any-authenticated at the edge; the handlers enforce admin.
        assert_eq!(
            endpoint_policy(&Method::GET, TEAMS_PATH),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/proprietary/ui-data/teams/5"),
            EndpointPolicy::Authenticated
        );
    }

    #[tokio::test]
    async fn login_is_public_and_surfaces_first_time_setup() -> TestResult {
        // Empty store: no real users → the login page must offer default creds.
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        // No AuthContext is injected: the handler must serve without one.
        let response = send(&app, None, LOGIN_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body["firstTimeSetup"].as_bool(), Some(true));
        assert_eq!(body["showDefaultCredentials"].as_bool(), Some(true));
        // OAuth2 disabled + SAML2 deferred → no providers, so altLogin is false.
        assert_eq!(body["altLogin"].as_bool(), Some(false));
        assert!(
            body["providerList"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        );
        Ok(())
    }

    #[tokio::test]
    async fn account_rejects_demo_user() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        let demo = context(1, "demo", &["ROLE_DEMO_USER"]);
        let response = send(&app, Some(demo), ACCOUNT_PATH).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn account_unknown_user_is_not_found() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        // A non-demo principal whose user row does not exist → 404 (Java parity).
        let ghost = context(999_999, "ghost", &["ROLE_USER"]);
        let response = send(&app, Some(ghost), ACCOUNT_PATH).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn account_superset_mirrors_auth_me_for_admin() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let admin = store.authenticate_password("admin", "admin-test-password", 1_000, "acct")?;
        let app = build_router(&store, LicenseTier::Enterprise);
        let admin_context = context(admin.user_id, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin_context), ACCOUNT_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        // /auth/me `user` block, reproduced field-for-field by `authentication_user`.
        assert_eq!(body["user"]["id"].as_i64(), Some(admin.user_id));
        assert_eq!(body["user"]["username"].as_str(), Some("admin"));
        assert_eq!(body["user"]["email"].as_str(), Some("admin"));
        assert_eq!(body["user"]["role"].as_str(), Some("ROLE_ADMIN"));
        assert_eq!(body["user"]["portalAccess"].as_bool(), Some(true));
        assert_eq!(body["user"]["teamLead"].as_bool(), Some(false));
        assert_eq!(body["user"]["authenticationType"].as_str(), Some("web"));
        assert_eq!(
            body["user"]["app_metadata"]["provider"].as_str(),
            Some("web")
        );
        assert_eq!(
            body["user"]["user_metadata"]["firstLogin"].as_bool(),
            Some(false)
        );
        // /auth/me `mfa` block.
        assert_eq!(body["mfa"]["enabled"].as_bool(), Some(false));
        assert_eq!(body["mfa"]["recoveryCodesRemaining"].as_i64(), Some(0));
        // Account-page superset fields.
        assert_eq!(body["role"].as_str(), Some("ROLE_ADMIN"));
        assert_eq!(body["oAuth2Login"].as_bool(), Some(false));
        assert_eq!(body["saml2Login"].as_bool(), Some(false));
        assert_eq!(body["mfaEnabled"].as_bool(), Some(false));
        assert_eq!(body["mfaRequired"].as_bool(), Some(false));
        // Admin has not completed initial setup → change-creds prompt is on.
        assert_eq!(body["changeCredsFlag"].as_bool(), Some(true));
        // Settings serialize as a JSON string (empty object here).
        assert_eq!(body["settings"].as_str(), Some("{}"));
        Ok(())
    }

    #[tokio::test]
    async fn audit_dashboard_forbidden_for_non_admin() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        let user = context(1, "user", &["ROLE_USER"]);
        let response = send(&app, Some(user), AUDIT_DASHBOARD_PATH).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn audit_dashboard_requires_enterprise_license() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        // Admin, but only a Server-tier license → the Enterprise gate returns 403.
        let app = build_router(&store, LicenseTier::Server);
        let admin = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin), AUDIT_DASHBOARD_PATH).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn audit_dashboard_lists_java_enums_for_admin_enterprise() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        let admin = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin), AUDIT_DASHBOARD_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let levels = body["auditLevels"].as_array().ok_or("auditLevels array")?;
        let level_names = levels.iter().filter_map(Value::as_str).collect::<Vec<_>>();
        assert_eq!(level_names, ["OFF", "BASIC", "STANDARD", "VERBOSE"]);
        let types = body["auditEventTypes"]
            .as_array()
            .ok_or("auditEventTypes array")?;
        let type_names = types.iter().filter_map(Value::as_str).collect::<Vec<_>>();
        assert_eq!(type_names, AUDIT_EVENT_TYPES);
        assert_eq!(body["auditLevel"].as_str(), Some("STANDARD"));
        assert_eq!(body["auditLevelInt"].as_i64(), Some(2));
        assert_eq!(body["retentionDays"].as_i64(), Some(90));
        // pdfMetadataEnabled = captureFileHash || capturePdfAuthor (true || false).
        assert_eq!(body["pdfMetadataEnabled"].as_bool(), Some(true));
        Ok(())
    }

    #[tokio::test]
    async fn teams_forbidden_for_non_admin() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        let user = context(1, "user", &["ROLE_USER"]);
        let response = send(&app, Some(user), TEAMS_PATH).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn teams_excludes_internal_and_reports_counts() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let alpha = store.create_team("Alpha")?;
        store.create_local_user(
            "alphamember",
            "alpha-member-password",
            ["ROLE_USER"],
            Some(alpha),
        )?;
        let app = build_router(&store, LicenseTier::Enterprise);
        let admin = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin), TEAMS_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        let teams = body["teamsWithCounts"]
            .as_array()
            .ok_or("teamsWithCounts array")?;
        // The Internal team is never surfaced.
        assert!(
            teams
                .iter()
                .all(|team| team["name"].as_str() != Some("Internal"))
        );
        // Alpha reports the single member counted by `list_teams`.
        let alpha_entry = teams
            .iter()
            .find(|team| team["name"].as_str() == Some("Alpha"))
            .ok_or("Alpha team present")?;
        assert_eq!(alpha_entry["userCount"].as_i64(), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn team_details_unknown_id_is_not_found() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        let admin = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(
            &app,
            Some(admin),
            "/api/v1/proprietary/ui-data/teams/999999",
        )
        .await?;
        // Deliberate 404 (documented divergence from Java's accidental 500).
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn team_details_internal_team_is_forbidden() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let internal_id = store
            .list_teams()?
            .into_iter()
            .find(|team| team.name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
            .map(|team| team.id)
            .ok_or("internal team seeded")?;
        let app = build_router(&store, LicenseTier::Enterprise);
        let admin = context(1, "admin", &["ROLE_ADMIN"]);
        let path = format!("/api/v1/proprietary/ui-data/teams/{internal_id}");
        let response = send(&app, Some(admin), &path).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn team_details_available_users_exclude_current_and_internal() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let internal_id = store
            .list_teams()?
            .into_iter()
            .find(|team| team.name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
            .map(|team| team.id)
            .ok_or("internal team seeded")?;
        let alpha = store.create_team("Alpha")?;
        let beta = store.create_team("Beta")?;
        let alpha_member = store.create_local_user(
            "alphamember",
            "alpha-member-password",
            ["ROLE_USER"],
            Some(alpha),
        )?;
        store.create_local_user(
            "betamember",
            "beta-member-password",
            ["ROLE_USER"],
            Some(beta),
        )?;
        store.create_local_user(
            "internalmember",
            "internal-member-password",
            ["ROLE_USER"],
            Some(internal_id),
        )?;
        store.set_team_owner(alpha, alpha_member, true)?;

        let app = build_router(&store, LicenseTier::Enterprise);
        let admin = context(1, "admin", &["ROLE_ADMIN"]);
        let path = format!("/api/v1/proprietary/ui-data/teams/{alpha}");
        let response = send(&app, Some(admin), &path).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;

        // team_users is exactly this team's members.
        let team_users = usernames(&body["teamUsers"]);
        assert_eq!(team_users, ["alphamember"]);

        // available_users excludes this team's members and every internal member.
        let available = usernames(&body["availableUsers"]);
        assert!(available.iter().any(|name| name == "betamember"));
        assert!(!available.iter().any(|name| name == "alphamember"));
        assert!(!available.iter().any(|name| name == "internalmember"));

        // The owner is reported via the leaders query.
        let owner_ids = body["ownerUserIds"]
            .as_array()
            .ok_or("ownerUserIds array")?
            .iter()
            .filter_map(Value::as_i64)
            .collect::<Vec<_>>();
        assert_eq!(owner_ids, [alpha_member]);
        Ok(())
    }
}
