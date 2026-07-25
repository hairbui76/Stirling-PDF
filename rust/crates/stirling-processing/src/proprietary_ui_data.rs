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

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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
        AuthContext, INTERNAL_API_USERNAME, INTERNAL_TEAM_NAME, SecurityError, SecurityStore,
        SecurityTeam, SecurityUserSummary, UserSeatMetrics,
    },
    security_http::SecurityHttpConfig,
    security_policy::LicenseTier,
};

const LOGIN_PATH: &str = "/api/v1/proprietary/ui-data/login";
const ACCOUNT_PATH: &str = "/api/v1/proprietary/ui-data/account";
const ADMIN_SETTINGS_PATH: &str = "/api/v1/proprietary/ui-data/admin-settings";
const AUDIT_DASHBOARD_PATH: &str = "/api/v1/proprietary/ui-data/audit-dashboard";
const TEAMS_PATH: &str = "/api/v1/proprietary/ui-data/teams";
const TEAM_DETAILS_PATH: &str = "/api/v1/proprietary/ui-data/teams/{id}";

/// Role-id → translation-key map mirroring Java `Role.getAllRoleDetails()`
/// (`stirling.software.common.model.enumeration.Role`) in declaration order.
/// Used verbatim for `roleDetails` and to resolve each user's `roleName`.
const ROLE_DETAILS: [(&str, &str); 8] = [
    ("ROLE_ADMIN", "adminUserSettings.admin"),
    ("ROLE_USER", "adminUserSettings.user"),
    ("ROLE_PRO_USER", "adminUserSettings.proUser"),
    ("ROLE_LIMITED_API_USER", "adminUserSettings.apiUser"),
    (
        "ROLE_EXTRA_LIMITED_API_USER",
        "adminUserSettings.extraApiUser",
    ),
    ("ROLE_WEB_ONLY_USER", "adminUserSettings.webOnlyUser"),
    (INTERNAL_API_USERNAME, "adminUserSettings.internalApiUser"),
    ("ROLE_DEMO_USER", "adminUserSettings.demoUser"),
];

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
    admin: AdminStaticConfig,
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

/// Server-owned configuration the admin-settings projection reports verbatim
/// (Java `applicationProperties.getMail()` / `getPremium()`); everything
/// user-specific is read live from the store per request.
struct AdminStaticConfig {
    mail_enabled: bool,
    email_invites_enabled: bool,
    max_paid_users: i64,
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
        // Java: `mail.isEnabled()`, `mail.isEnableInvites() && mail.isEnabled()`,
        // `premium.getMaxUsers()`. The mail flags reuse the runtime's exact
        // env-over-YAML resolution; `premium.maxUsers` mirrors the license
        // reader's `PREMIUM_MAXUSERS`-first lookup (default `0`).
        let mail_enabled = runtime_config.smtp_mail_config().enabled;
        let admin = AdminStaticConfig {
            mail_enabled,
            email_invites_enabled: runtime_config.security_invites_enabled() && mail_enabled,
            max_paid_users: config_i64(&settings, &["premium", "maxUsers"], "PREMIUM_MAXUSERS", 0),
        };
        Self {
            login,
            audit,
            admin,
        }
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
        .route(ADMIN_SETTINGS_PATH, get(admin_settings_data))
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
// GET /admin-settings (admin)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminTeamRef {
    id: i64,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent fields of the Java AdminUserSummary contract.
struct AdminUserSummary {
    id: i64,
    username: String,
    email: String,
    role_name: String,
    roles_as_string: String,
    enabled: bool,
    is_first_login: bool,
    authentication_type: String,
    // Java `@JsonInclude(NON_NULL)`: a user with no team omits the field, and
    // there is no `updated_at` column so Java's `updatedAt` has no analogue here
    // (both documented divergences; see `ui-data.md`).
    #[serde(skip_serializing_if = "Option::is_none")]
    team: Option<AdminTeamRef>,
    team_lead: bool,
    portal_access: bool,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)] // Independent fields of the Java AdminSettingsData contract.
struct AdminSettingsData {
    users: Vec<AdminUserSummary>,
    current_username: String,
    role_details: BTreeMap<String, String>,
    user_sessions: BTreeMap<String, bool>,
    user_last_request: BTreeMap<String, i64>,
    total_users: i64,
    active_users: i64,
    disabled_users: i64,
    teams: Vec<AdminTeamRef>,
    max_paid_users: i64,
    max_allowed_users: i64,
    available_slots: i64,
    grandfathered_user_count: i64,
    license_max_users: i64,
    premium_enabled: bool,
    mail_enabled: bool,
    email_invites_enabled: bool,
    user_settings: BTreeMap<String, BTreeMap<String, String>>,
    locked_users: Vec<String>,
}

/// Raw store reads gathered once on the blocking pool; all visibility
/// filtering, sorting and projection happen on the async side from this
/// snapshot (mirroring `account_data`'s split of I/O from assembly).
struct AdminRosterFacts {
    roster: Vec<SecurityUserSummary>,
    lifecycle: BTreeMap<i64, (String, bool)>,
    active_principals: BTreeSet<String>,
    last_request: BTreeMap<String, i64>,
    leaders: Vec<(i64, i64, String)>,
    teams: Vec<SecurityTeam>,
    seat: UserSeatMetrics,
    settings_by_id: BTreeMap<i64, BTreeMap<String, String>>,
}

async fn admin_settings_data(
    Extension(config): Extension<Arc<UiDataConfig>>,
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    // Java: @PreAuthorize("hasRole('ADMIN')"). The coarse path policy already
    // classifies `.../ui-data/admin*` as Administrator; this is defensive.
    if !context.has_role("ROLE_ADMIN") {
        return forbidden();
    }
    let query_store = Arc::clone(&store);
    let facts = task::spawn_blocking(move || {
        let now = Utc::now().timestamp();
        let roster = query_store.list_users(now)?;
        let lifecycle = query_store
            .admin_roster_lifecycle()?
            .into_iter()
            .map(|(id, created_at, initial_setup)| (id, (created_at, initial_setup)))
            .collect::<BTreeMap<_, _>>();
        let active_principals = query_store
            .active_principals_since(now)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let last_request = query_store
            .latest_request_per_principal()?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let leaders = query_store.team_leaders()?;
        let teams = query_store.list_teams()?;
        let seat = query_store.user_seat_metrics()?;
        // Per-user settings (masked below): one lookup per roster user, kept in
        // the same blocking hop rather than issuing N async round-trips.
        let mut settings_by_id = BTreeMap::new();
        for user in &roster {
            settings_by_id.insert(user.id, query_store.user_settings(user.id)?);
        }
        Ok::<_, SecurityError>(AdminRosterFacts {
            roster,
            lifecycle,
            active_principals,
            last_request,
            leaders,
            teams,
            seat,
            settings_by_id,
        })
    })
    .await;
    let Ok(Ok(facts)) = facts else {
        return service_unavailable();
    };

    Json(build_admin_settings(&config.admin, &context, facts)).into_response()
}

#[allow(clippy::too_many_lines)] // One cohesive Java-parity projection; splitting would obscure it.
fn build_admin_settings(
    admin_config: &AdminStaticConfig,
    context: &AuthContext,
    facts: AdminRosterFacts,
) -> AdminSettingsData {
    let AdminRosterFacts {
        roster,
        lifecycle,
        active_principals,
        last_request,
        leaders,
        teams,
        seat,
        settings_by_id,
    } = facts;

    // lockedUsers mirrors Java `LoginAttemptService.getAllBlockedUsers()`:
    // every blocked account, not only the visible ones. See `ui-data.md` for
    // the persistent-lock vs in-memory-threshold parity note.
    let locked_users = roster
        .iter()
        .filter(|user| user.credential_state.locked)
        .map(|user| user.username.clone())
        .collect::<Vec<_>>();

    // Drop the internal API user and internal-team members: the roster never
    // shows them. The internal API user is username-identified in this store
    // (mirroring `real_user_count`), where the Java oracle keys on its authority.
    let mut has_internal_api_user = false;
    let mut visible = Vec::with_capacity(roster.len());
    for user in roster {
        if user.username.eq_ignore_ascii_case(INTERNAL_API_USERNAME) {
            has_internal_api_user = true;
            continue;
        }
        if user
            .team_name
            .as_deref()
            .is_some_and(|team| team.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        {
            continue;
        }
        visible.push(user);
    }

    // roleDetails: the full static map, minus the internal-API entry when such a
    // user exists (Java removes it in exactly that case).
    let mut role_details = ROLE_DETAILS
        .iter()
        .map(|(id, key)| ((*id).to_owned(), (*key).to_owned()))
        .collect::<BTreeMap<_, _>>();
    if has_internal_api_user {
        role_details.remove(INTERNAL_API_USERNAME);
    }

    // teamLead (display) counts leadership of any team; the portal shortcut
    // (admin OR leads their own active team) mirrors `account_data`'s
    // simplification of the ADMINS_AND_TEAM_LEADS default.
    let leader_user_ids = leaders
        .iter()
        .map(|(_, user_id, _)| *user_id)
        .collect::<BTreeSet<_>>();
    let leader_team_by_user = leaders
        .iter()
        .map(|(team_id, user_id, _)| (*user_id, *team_id))
        .collect::<BTreeMap<_, _>>();

    // Per-username projections over the visible roster.
    let user_sessions = visible
        .iter()
        .map(|user| {
            (
                user.username.clone(),
                active_principals.contains(&user.username),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let user_last_request = visible
        .iter()
        .map(|user| {
            (
                user.username.clone(),
                last_request
                    .get(&user.username)
                    .copied()
                    .map_or(0, to_epoch_millis),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let user_settings = visible
        .iter()
        .map(|user| {
            let settings = settings_by_id.get(&user.id).cloned().unwrap_or_default();
            (user.username.clone(), masked_settings_map(settings))
        })
        .collect::<BTreeMap<_, _>>();

    let total_users = i64::try_from(visible.len()).unwrap_or(i64::MAX);
    let active_users =
        i64::try_from(user_sessions.values().filter(|&&active| active).count()).unwrap_or(i64::MAX);
    let disabled_users =
        i64::try_from(visible.iter().filter(|user| !user.enabled).count()).unwrap_or(i64::MAX);

    // Sort active-session-first, then latest activity (ms) descending; the
    // stable sort keeps the list_users username order for ties.
    visible.sort_by(|a, b| {
        let a_active = active_principals.contains(&a.username);
        let b_active = active_principals.contains(&b.username);
        b_active.cmp(&a_active).then_with(|| {
            let a_last = user_last_request.get(&a.username).copied().unwrap_or(0);
            let b_last = user_last_request.get(&b.username).copied().unwrap_or(0);
            b_last.cmp(&a_last)
        })
    });

    let users = visible
        .into_iter()
        .map(|user| {
            let SecurityUserSummary {
                id,
                email: _,
                username,
                role: _,
                roles,
                enabled,
                authentication_type,
                team_id,
                team_name,
                credential_state: _,
            } = user;
            let (created_at, initial_setup) = lifecycle
                .get(&id)
                .cloned()
                .unwrap_or_else(|| (String::new(), false));
            let team = team_id
                .zip(team_name)
                .map(|(tid, name)| AdminTeamRef { id: tid, name });
            let is_admin = roles.iter().any(|role| role == "ROLE_ADMIN");
            let leads_own_team = matches!(
                (leader_team_by_user.get(&id).copied(), team_id),
                (Some(led), Some(own)) if led == own
            );
            AdminUserSummary {
                id,
                email: username.clone(),
                role_name: role_name_for(&roles),
                roles_as_string: roles.join(", "),
                enabled,
                // Java `isFirstLogin`; first-login ⇔ initial setup incomplete.
                is_first_login: !initial_setup,
                authentication_type,
                team,
                team_lead: leader_user_ids.contains(&id),
                portal_access: is_admin || leads_own_team,
                created_at,
                username,
            }
        })
        .collect::<Vec<_>>();

    let teams = teams
        .into_iter()
        .filter(|team| !team.name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
        .map(|team| AdminTeamRef {
            id: team.id,
            name: team.name,
        })
        .collect::<Vec<_>>();

    AdminSettingsData {
        users,
        current_username: context.username.clone(),
        role_details,
        user_sessions,
        user_last_request,
        total_users,
        active_users,
        disabled_users,
        teams,
        max_paid_users: admin_config.max_paid_users,
        max_allowed_users: seat.max_allowed_users,
        available_slots: seat.available_slots,
        grandfathered_user_count: seat.grandfathered_user_count,
        license_max_users: seat.license_max_users,
        premium_enabled: seat.premium_enabled,
        mail_enabled: admin_config.mail_enabled,
        email_invites_enabled: admin_config.email_invites_enabled,
        user_settings,
        locked_users,
    }
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

/// Copies the user settings with any `mfaSecret` masked, mirroring Java
/// `maskSecrets`. In this port the TOTP secret lives in a separate table, so
/// this is defensive rather than load-bearing.
fn masked_settings_map(mut settings: BTreeMap<String, String>) -> BTreeMap<String, String> {
    if settings.contains_key("mfaSecret") {
        settings.insert("mfaSecret".to_owned(), "********".to_owned());
    }
    settings
}

/// Serializes the masked user settings to a JSON string (the `account`
/// projection's `settings` field is a string; `admin-settings` emits the map).
fn masked_settings_json(settings: BTreeMap<String, String>) -> String {
    serde_json::to_string(&masked_settings_map(settings)).unwrap_or_else(|_| "{}".to_owned())
}

/// Resolves a user's `roleName` translation key, mirroring Java
/// `Role.getRoleNameByRoleId(rolesAsString)`: a case-insensitive exact match of
/// the joined authority string against a single roleId. For the common
/// single-authority user this is that role's key; it falls back to the first
/// mappable role, then to empty (where Java would raise and 500).
fn role_name_for(roles: &[String]) -> String {
    let joined = roles.join(", ");
    role_translation_key(&joined)
        .or_else(|| roles.iter().find_map(|role| role_translation_key(role)))
        .unwrap_or_default()
        .to_owned()
}

fn role_translation_key(role_id: &str) -> Option<&'static str> {
    ROLE_DETAILS
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(role_id))
        .map(|(_, key)| *key)
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

/// Env-first (parsed as an integer), then YAML, then default — mirroring the
/// license reader's `PREMIUM_MAXUSERS` lookup for `premium.maxUsers`.
fn config_i64(settings: &Value, path: &[&str], environment: &str, default: i64) -> i64 {
    let from_env = std::env::var(environment)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    if let Some(parsed) = from_env {
        return parsed;
    }
    value_at(settings, path)
        .and_then(Value::as_i64)
        .unwrap_or(default)
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
        ACCOUNT_PATH, ADMIN_SETTINGS_PATH, AUDIT_DASHBOARD_PATH, AUDIT_EVENT_TYPES,
        AdminStaticConfig, AuditStaticConfig, LOGIN_PATH, LoginStaticConfig, TEAMS_PATH,
        UiDataConfig, routes,
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
        let admin = AdminStaticConfig {
            mail_enabled: true,
            email_invites_enabled: true,
            max_paid_users: 25,
        };
        UiDataConfig {
            login,
            audit,
            admin,
        }
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
        // Admin-settings is admin-only at the edge (the `ui-data/admin` prefix),
        // matching Java `@PreAuthorize("hasRole('ADMIN')")`.
        assert_eq!(
            endpoint_policy(&Method::GET, ADMIN_SETTINGS_PATH),
            EndpointPolicy::Administrator
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

    #[tokio::test]
    async fn admin_settings_forbidden_for_non_admin() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let app = build_router(&store, LicenseTier::Enterprise);
        let user = context(1, "user", &["ROLE_USER"]);
        let response = send(&app, Some(user), ADMIN_SETTINGS_PATH).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    fn user_named<'a>(body: &'a Value, username: &str) -> Option<&'a Value> {
        body["users"]
            .as_array()?
            .iter()
            .find(|user| user["username"].as_str() == Some(username))
    }

    #[tokio::test]
    async fn admin_settings_projects_roster_sessions_and_config() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let alpha = store.create_team("Alpha")?;
        let lead = store.create_local_user(
            "alphalead",
            "alpha-lead-password",
            ["ROLE_USER"],
            Some(alpha),
        )?;
        store.set_team_owner(alpha, lead, true)?;
        let _member = store.create_local_user(
            "member",
            "member-strong-password",
            ["ROLE_USER"],
            Some(alpha),
        )?;

        // Give `member` a live session so it is the single active principal; use
        // real "now" so the default 30-day refresh window is still open when the
        // handler evaluates `Utc::now()`.
        let now = chrono::Utc::now().timestamp();
        let member_ctx =
            store.authenticate_password("member", "member-strong-password", now, "login")?;
        store.issue_session(
            &member_ctx,
            now,
            crate::security::DEFAULT_ACCESS_TTL,
            crate::security::DEFAULT_REFRESH_TTL,
        )?;

        let app = build_router(&store, LicenseTier::Enterprise);
        let admin_ctx = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin_ctx), ADMIN_SETTINGS_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;

        assert_eq!(body["currentUsername"].as_str(), Some("admin"));
        assert_eq!(body["totalUsers"].as_i64(), Some(3));
        assert_eq!(body["activeUsers"].as_i64(), Some(1));
        assert_eq!(body["disabledUsers"].as_i64(), Some(0));

        // The active member sorts first and reports its session/activity.
        assert_eq!(body["users"][0]["username"].as_str(), Some("member"));
        assert_eq!(body["userSessions"]["member"].as_bool(), Some(true));
        assert_eq!(body["userSessions"]["admin"].as_bool(), Some(false));
        assert_eq!(body["userLastRequest"]["member"].as_i64(), Some(now * 1000));
        assert_eq!(body["userLastRequest"]["admin"].as_i64(), Some(0));

        // Admin: seeded onto the Default team, portal access, admin role key.
        let admin_row = user_named(&body, "admin").ok_or("admin row")?;
        assert_eq!(admin_row["team"]["name"].as_str(), Some("Default"));
        assert_eq!(admin_row["portalAccess"].as_bool(), Some(true));
        assert_eq!(admin_row["teamLead"].as_bool(), Some(false));
        assert_eq!(admin_row["rolesAsString"].as_str(), Some("ROLE_ADMIN"));
        assert_eq!(
            admin_row["roleName"].as_str(),
            Some("adminUserSettings.admin")
        );
        assert_eq!(admin_row["email"].as_str(), Some("admin"));
        // Fresh admin has not completed initial setup → firstLogin true.
        assert_eq!(admin_row["isFirstLogin"].as_bool(), Some(true));
        assert!(
            admin_row["createdAt"]
                .as_str()
                .is_some_and(|s| s.contains('T'))
        );

        // The team leader gets teamLead + own-team portal access.
        let lead_row = user_named(&body, "alphalead").ok_or("lead row")?;
        assert_eq!(lead_row["teamLead"].as_bool(), Some(true));
        assert_eq!(lead_row["portalAccess"].as_bool(), Some(true));
        assert_eq!(lead_row["team"]["name"].as_str(), Some("Alpha"));

        // A plain member on a team gets neither.
        let member_row = user_named(&body, "member").ok_or("member row")?;
        assert_eq!(member_row["teamLead"].as_bool(), Some(false));
        assert_eq!(member_row["portalAccess"].as_bool(), Some(false));

        // Config-sourced fields come from the startup snapshot.
        assert_eq!(body["maxPaidUsers"].as_i64(), Some(25));
        assert_eq!(body["mailEnabled"].as_bool(), Some(true));
        assert_eq!(body["emailInvitesEnabled"].as_bool(), Some(true));
        // License block is present (values derive from the store's seat metrics).
        assert!(body["maxAllowedUsers"].is_number());
        assert!(body["availableSlots"].is_number());
        assert!(body["premiumEnabled"].is_boolean());
        // roleDetails carries the full catalogue (no internal user here).
        assert_eq!(
            body["roleDetails"]["ROLE_ADMIN"].as_str(),
            Some("adminUserSettings.admin")
        );
        assert!(
            body["lockedUsers"]
                .as_array()
                .is_some_and(std::vec::Vec::is_empty)
        );
        Ok(())
    }

    #[tokio::test]
    async fn admin_settings_excludes_internal_users_and_trims_role_details() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        // An internal API user (username-identified) and an internal-team member
        // are both hidden from the roster.
        store.create_local_user(
            "STIRLING-PDF-BACKEND-API-USER",
            "internal-api-password",
            ["ROLE_USER"],
            None,
        )?;
        let internal_id = store
            .list_teams()?
            .into_iter()
            .find(|team| team.name.eq_ignore_ascii_case(INTERNAL_TEAM_NAME))
            .map(|team| team.id)
            .ok_or("internal team seeded")?;
        store.create_local_user(
            "internaluser",
            "internal-user-password",
            ["ROLE_USER"],
            Some(internal_id),
        )?;

        let app = build_router(&store, LicenseTier::Enterprise);
        let admin_ctx = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin_ctx), ADMIN_SETTINGS_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;

        let names = usernames(&body["users"]);
        assert_eq!(names, ["admin"]);
        assert_eq!(body["totalUsers"].as_i64(), Some(1));
        // The internal-API entry is dropped from roleDetails because such a user
        // exists, while ordinary roles remain.
        assert!(body["roleDetails"]["STIRLING-PDF-BACKEND-API-USER"].is_null());
        assert_eq!(
            body["roleDetails"]["ROLE_USER"].as_str(),
            Some("adminUserSettings.user")
        );
        Ok(())
    }

    #[tokio::test]
    async fn admin_settings_masks_mfa_secret_but_preserves_other_settings() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        assert!(store.bootstrap_admin("admin", "admin-test-password")?);
        let user = store.create_local_user(
            "settingsuser",
            "settings-strong-password",
            ["ROLE_USER"],
            None,
        )?;
        // A user whose durable settings include a secret alongside a plain
        // preference. `mfaSecret` must be masked; the other value must survive.
        let mut settings = std::collections::BTreeMap::new();
        settings.insert("mfaSecret".to_owned(), "TOPSECRETTOTPSEED".to_owned());
        settings.insert("theme".to_owned(), "dark".to_owned());
        store.replace_user_settings(user, &settings)?;

        let app = build_router(&store, LicenseTier::Enterprise);
        let admin_ctx = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin_ctx), ADMIN_SETTINGS_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;

        let user_settings = &body["userSettings"]["settingsuser"];
        assert_eq!(user_settings["mfaSecret"].as_str(), Some("********"));
        assert!(!user_settings.to_string().contains("TOPSECRETTOTPSEED"));
        assert_eq!(user_settings["theme"].as_str(), Some("dark"));
        Ok(())
    }

    #[tokio::test]
    async fn admin_settings_yields_empty_roster_when_only_internal_users_exist() -> TestResult {
        // Adversarial: a roster made up entirely of hidden users must project an
        // empty visible roster with zeroed counts (no underflow / panic).
        let store = Arc::new(SecurityStore::in_memory()?);
        store.create_local_user(
            "STIRLING-PDF-BACKEND-API-USER",
            "internal-api-password",
            ["ROLE_USER"],
            None,
        )?;

        let app = build_router(&store, LicenseTier::Enterprise);
        let admin_ctx = context(1, "admin", &["ROLE_ADMIN"]);
        let response = send(&app, Some(admin_ctx), ADMIN_SETTINGS_PATH).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;

        assert!(
            body["users"]
                .as_array()
                .is_some_and(std::vec::Vec::is_empty)
        );
        assert_eq!(body["totalUsers"].as_i64(), Some(0));
        assert_eq!(body["activeUsers"].as_i64(), Some(0));
        assert_eq!(body["disabledUsers"].as_i64(), Some(0));
        assert!(
            body["userSessions"]
                .as_object()
                .is_some_and(serde_json::Map::is_empty)
        );
        Ok(())
    }
}
