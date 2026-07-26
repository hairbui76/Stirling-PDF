//! Central endpoint authorization policy for secured deployments.
//!
//! The Java runtime authenticates every request by default and exempts a small
//! set of bootstrap, health, invitation, scanner, and participant-token paths.
//! Keeping that decision in one typed function prevents routes from becoming
//! public merely because a handler forgot an authorization annotation.

use axum::http::Method;

use crate::security::AuthContext;

/// Authentication and authorization required before a handler may run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPolicy {
    Public,
    ParticipantToken,
    Authenticated,
    NonDemoUser,
    Administrator,
}

/// Verified commercial license tier available to the secured HTTP boundary.
///
/// Configuration intent (`premium.enabled`) and the presence of a key are not
/// evidence of entitlement. Callers must therefore supply `Server` or
/// `Enterprise` only after the license has been cryptographically or remotely
/// verified.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LicenseTier {
    #[default]
    Normal,
    Server,
    Enterprise,
}

/// License requirement attached to an exact Java controller route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointEntitlement {
    Unrestricted,
    ServerOrEnterprise,
    Enterprise,
}

/// A stable denial category which an HTTP boundary can map without exposing
/// user, session, or policy internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDenial {
    AuthenticationRequired,
    ParticipantTokenRequired,
    DemoUserRestricted,
    AdministratorRequired,
}

/// Resolves the commercial entitlement required by a reviewed route.
///
/// This deliberately uses an exact method/path matrix. Broad prefixes would
/// incorrectly license-gate unannotated endpoints such as Java's team list UI
/// data and would let future routes inherit a paid tier without review.
#[must_use]
pub fn endpoint_entitlement(method: &Method, path: &str) -> EndpointEntitlement {
    if method == Method::POST
        && matches!(
            path,
            "/api/v1/team/create"
                | "/api/v1/team/rename"
                | "/api/v1/team/delete"
                | "/api/v1/team/setOwner"
                | "/api/v1/team/removeOwner"
                | "/api/v1/team/addUser"
        )
    {
        return EndpointEntitlement::ServerOrEnterprise;
    }

    let enterprise = (method == Method::GET
        && matches!(
            path,
            "/api/v1/audit/data"
                | "/api/v1/audit/stats"
                | "/api/v1/audit/types"
                | "/api/v1/audit/export/csv"
                | "/api/v1/audit/export/json"
                | "/api/v1/proprietary/ui-data/audit-events"
                | "/api/v1/proprietary/ui-data/audit-charts"
                | "/api/v1/proprietary/ui-data/audit-event-types"
                | "/api/v1/proprietary/ui-data/audit-users"
                | "/api/v1/proprietary/ui-data/audit-stats"
                | "/api/v1/proprietary/ui-data/audit-export"
                | "/api/v1/proprietary/ui-data/usage-endpoint-statistics"
                | "/api/v1/usage/fleet-stats"
                // Portal audit-derived surfaces (portal_audit::{DOCUMENTS_PATH,
                // INFRA_AUDIT_LOG_PATH}); @EnterpriseEndpoint in Java.
                | "/api/v1/proprietary/ui-data/documents"
                | "/api/v1/proprietary/ui-data/infrastructure/audit-log"
        ))
        || (method == Method::DELETE && path == "/api/v1/audit/cleanup/before")
        || (method == Method::POST && path == "/api/v1/proprietary/ui-data/audit-clear-all");
    if enterprise {
        EndpointEntitlement::Enterprise
    } else {
        EndpointEntitlement::Unrestricted
    }
}

/// Checks a previously verified license tier against one route requirement.
///
/// # Errors
///
/// Returns the unmet entitlement when the verified tier is insufficient.
pub fn authorize_entitlement(
    tier: LicenseTier,
    entitlement: EndpointEntitlement,
) -> Result<(), EndpointEntitlement> {
    let allowed = match entitlement {
        EndpointEntitlement::Unrestricted => true,
        EndpointEntitlement::ServerOrEnterprise => {
            matches!(tier, LicenseTier::Server | LicenseTier::Enterprise)
        }
        EndpointEntitlement::Enterprise => tier == LicenseTier::Enterprise,
    };
    if allowed { Ok(()) } else { Err(entitlement) }
}

/// Resolves one normalized request path to its secured-mode policy.
#[must_use]
pub fn endpoint_policy(method: &Method, path: &str) -> EndpointPolicy {
    if is_public_health(method, path)
        || is_public_static(method, path)
        || is_public_auth(method, path)
        || is_public_invitation(method, path)
        || is_public_webhook(method, path)
        || path.starts_with("/api/v1/mobile-scanner/")
    {
        return EndpointPolicy::Public;
    }
    if path.starts_with("/api/v1/workflow/participant/") {
        return EndpointPolicy::ParticipantToken;
    }
    if path == "/api/v1/classification/labels"
        && (method == Method::PUT || method == Method::DELETE)
    {
        return EndpointPolicy::Administrator;
    }
    if is_administrator_path(path) {
        return EndpointPolicy::Administrator;
    }
    if is_non_demo_path(path) {
        return EndpointPolicy::NonDemoUser;
    }
    EndpointPolicy::Authenticated
}

/// Evaluates an already-authenticated request context against a route policy.
///
/// # Errors
///
/// Returns a stable denial category when the route requires another
/// authentication mechanism, a signed-in principal, a non-demo account, or an
/// administrator role that the trusted context does not provide.
pub fn authorize(
    policy: EndpointPolicy,
    context: Option<&AuthContext>,
) -> Result<(), AuthorizationDenial> {
    match policy {
        EndpointPolicy::Public => Ok(()),
        EndpointPolicy::ParticipantToken => Err(AuthorizationDenial::ParticipantTokenRequired),
        EndpointPolicy::Authenticated => context
            .map(|_| ())
            .ok_or(AuthorizationDenial::AuthenticationRequired),
        EndpointPolicy::NonDemoUser => {
            let context = context.ok_or(AuthorizationDenial::AuthenticationRequired)?;
            if context.has_role("ROLE_DEMO_USER") {
                Err(AuthorizationDenial::DemoUserRestricted)
            } else {
                Ok(())
            }
        }
        EndpointPolicy::Administrator => {
            let context = context.ok_or(AuthorizationDenial::AuthenticationRequired)?;
            if context.has_role("ROLE_ADMIN") {
                Ok(())
            } else {
                Err(AuthorizationDenial::AdministratorRequired)
            }
        }
    }
}

fn is_public_health(method: &Method, path: &str) -> bool {
    method == Method::GET
        && (matches!(
            path,
            "/health" | "/healthz" | "/liveness" | "/readiness" | "/api/v1/info/status"
        ) || path.starts_with("/actuator/health"))
}

fn is_public_static(method: &Method, path: &str) -> bool {
    method == Method::GET
        && (matches!(path, "/robots.txt" | "/favicon.ico" | "/manifest.json")
            || path.starts_with("/assets/")
            || path.starts_with("/locales/")
            || path.starts_with("/api/v1/ui-data/footer-info")
            || path.starts_with("/api/v1/proprietary/ui-data/login"))
}

fn is_public_auth(method: &Method, path: &str) -> bool {
    (method == Method::POST
        && matches!(
            path,
            "/api/v1/auth/login"
                | "/api/v1/auth/refresh"
                | "/api/v1/auth/logout"
                | "/api/v1/user/register"
                // Begins an OIDC login; the browser has no session yet.
                | "/api/v1/auth/oidc/authorize"
        ))
        // The provider's callback is a GET redirect carrying `code`+`state`;
        // it authenticates via the single-use state, so it must be public too.
        || (method == Method::GET && path == "/api/v1/auth/oidc/callback")
}

fn is_public_invitation(method: &Method, path: &str) -> bool {
    (method == Method::GET && path.starts_with("/api/v1/invite/validate/"))
        || (method == Method::POST && path.starts_with("/api/v1/invite/accept/"))
}

/// The inbound webhook-source receiver is authenticated by an HMAC signature over
/// its raw body rather than by a login session, so the endpoint boundary must let
/// the request reach the handler unauthenticated. Mirrors Java's
/// `RequestUriUtils.isStaticResource` allowlisting of `/api/v1/webhooks/`, but is
/// deliberately narrowed to `POST` (the only verb `WebhookReceiverController`
/// exposes) so no other method inherits the public exemption.
fn is_public_webhook(method: &Method, path: &str) -> bool {
    method == Method::POST && path.starts_with("/api/v1/webhooks/")
}

fn is_administrator_path(path: &str) -> bool {
    path.starts_with("/api/v1/admin/")
        || path == "/api/v1/admin"
        || matches!(
            path,
            "/api/v1/ui-data/tessdata-languages" | "/api/v1/ui-data/tessdata/download"
        )
        || path.starts_with("/api/v1/audit/")
        || path.starts_with("/api/v1/proprietary/ui-data/audit-")
        || path == "/api/v1/proprietary/ui-data/usage-endpoint-statistics"
        || path.starts_with("/api/v1/database/")
        || path == "/api/v1/usage/fleet-stats"
        || path.starts_with("/api/v1/team/")
        || path.starts_with("/api/v1/user/admin/")
        || path.starts_with("/api/v1/auth/mfa/disable/admin/")
        || matches!(
            path,
            "/api/v1/invite/generate" | "/api/v1/invite/list" | "/api/v1/invite/cleanup"
        )
        || path.starts_with("/api/v1/invite/revoke/")
        || path.starts_with("/api/v1/proprietary/ui-data/admin")
}

fn is_non_demo_path(path: &str) -> bool {
    path.starts_with("/api/v1/proprietary/signatures")
        || path.starts_with("/api/v1/user/")
        || matches!(
            path,
            "/api/v1/auth/me"
                | "/api/v1/auth/mfa/setup"
                | "/api/v1/auth/mfa/enable"
                | "/api/v1/auth/mfa/disable"
                | "/api/v1/auth/mfa/setup/cancel"
                | "/api/v1/auth/mfa/recovery-codes/regenerate"
        )
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorizationDenial, EndpointEntitlement, EndpointPolicy, LicenseTier, authorize,
        authorize_entitlement, endpoint_entitlement, endpoint_policy,
    };
    use crate::security::{AuthContext, AuthenticationSource};
    use axum::http::Method;
    use std::collections::BTreeSet;

    #[test]
    fn exposes_only_the_frozen_public_bootstrap_surface() {
        for (method, path) in [
            (Method::GET, "/health"),
            (Method::GET, "/api/v1/info/status"),
            (Method::POST, "/api/v1/auth/login"),
            (Method::POST, "/api/v1/auth/refresh"),
            (Method::POST, "/api/v1/auth/logout"),
            (Method::POST, "/api/v1/user/register"),
            (Method::POST, "/api/v1/auth/oidc/authorize"),
            (Method::GET, "/api/v1/auth/oidc/callback"),
            (Method::GET, "/api/v1/invite/validate/token"),
            (Method::POST, "/api/v1/invite/accept/token"),
            (Method::GET, "/api/v1/mobile-scanner/files/id"),
            (Method::GET, "/api/v1/ui-data/footer-info"),
            // The inbound webhook receiver authenticates by HMAC, not a session.
            (Method::POST, "/api/v1/webhooks/receivertestid12"),
        ] {
            assert_eq!(endpoint_policy(&method, path), EndpointPolicy::Public);
        }
        // The webhook receiver is public only for POST; any other verb on the
        // same prefix stays authenticated so nothing else inherits the exemption.
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            assert_eq!(
                endpoint_policy(&method, "/api/v1/webhooks/receivertestid12"),
                EndpointPolicy::Authenticated
            );
        }
        // The OIDC login routes are public only on their intended verb: a GET on
        // the authorize route (or POST on the callback) is not part of the frozen
        // public surface.
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/auth/oidc/authorize"),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(&Method::POST, "/api/v1/auth/oidc/callback"),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/config/app-config"),
            EndpointPolicy::Authenticated
        );
        // Portal audit surfaces authenticate every caller, then resolve the
        // per-caller audit scope in the handler (admin/team-leader/denied).
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/proprietary/ui-data/documents"),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(
                &Method::GET,
                "/api/v1/proprietary/ui-data/infrastructure/audit-log"
            ),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/auth/login"),
            EndpointPolicy::Authenticated
        );
    }

    #[test]
    fn separates_participant_admin_and_demo_restricted_routes() {
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/workflow/participant/document"),
            EndpointPolicy::ParticipantToken
        );
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/admin/job/stats"),
            EndpointPolicy::Administrator
        );
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/usage/fleet-stats"),
            EndpointPolicy::Administrator
        );
        assert_eq!(
            endpoint_policy(&Method::POST, "/api/v1/user/change-password"),
            EndpointPolicy::NonDemoUser
        );
        // Regenerating one's own recovery codes is a sensitive self-service MFA
        // action, classified exactly like the sibling enable/disable routes.
        assert_eq!(
            endpoint_policy(&Method::POST, "/api/v1/auth/mfa/recovery-codes/regenerate"),
            EndpointPolicy::NonDemoUser
        );
        for path in [
            "/api/v1/team/create",
            "/api/v1/user/admin/saveUser",
            "/api/v1/auth/mfa/disable/admin/user@example.test",
            "/api/v1/invite/generate",
            "/api/v1/invite/revoke/7",
            "/api/v1/proprietary/ui-data/admin-settings",
            "/api/v1/audit/data",
            "/api/v1/proprietary/ui-data/audit-events",
            "/api/v1/proprietary/ui-data/usage-endpoint-statistics",
            "/api/v1/ui-data/tessdata-languages",
            "/api/v1/ui-data/tessdata/download",
        ] {
            assert_eq!(
                endpoint_policy(&Method::POST, path),
                EndpointPolicy::Administrator
            );
        }
        assert_eq!(
            endpoint_policy(&Method::PUT, "/api/v1/classification/labels"),
            EndpointPolicy::Administrator
        );
        assert_eq!(
            endpoint_policy(&Method::DELETE, "/api/v1/classification/labels"),
            EndpointPolicy::Administrator
        );
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/classification/labels"),
            EndpointPolicy::Authenticated
        );
    }

    #[test]
    fn evaluates_roles_without_accepting_caller_supplied_identity() {
        let user = context(["ROLE_USER"]);
        let admin = context(["ROLE_ADMIN"]);
        let demo = context(["ROLE_DEMO_USER"]);
        assert_eq!(
            authorize(EndpointPolicy::Authenticated, Some(&user)),
            Ok(())
        );
        assert_eq!(
            authorize(EndpointPolicy::Administrator, Some(&user)),
            Err(AuthorizationDenial::AdministratorRequired)
        );
        assert_eq!(
            authorize(EndpointPolicy::Administrator, Some(&admin)),
            Ok(())
        );
        assert_eq!(
            authorize(EndpointPolicy::NonDemoUser, Some(&demo)),
            Err(AuthorizationDenial::DemoUserRestricted)
        );
        assert_eq!(
            authorize(EndpointPolicy::Authenticated, None),
            Err(AuthorizationDenial::AuthenticationRequired)
        );
    }

    #[test]
    fn exact_commercial_route_matrix_enforces_both_java_license_tiers() {
        for path in [
            "/api/v1/team/create",
            "/api/v1/team/rename",
            "/api/v1/team/delete",
            "/api/v1/team/setOwner",
            "/api/v1/team/removeOwner",
            "/api/v1/team/addUser",
        ] {
            let entitlement = endpoint_entitlement(&Method::POST, path);
            assert_eq!(entitlement, EndpointEntitlement::ServerOrEnterprise);
            assert_eq!(
                authorize_entitlement(LicenseTier::Normal, entitlement),
                Err(EndpointEntitlement::ServerOrEnterprise)
            );
            assert_eq!(
                authorize_entitlement(LicenseTier::Server, entitlement),
                Ok(())
            );
            assert_eq!(
                authorize_entitlement(LicenseTier::Enterprise, entitlement),
                Ok(())
            );
        }

        for (method, path) in [
            (Method::GET, "/api/v1/audit/data"),
            (Method::GET, "/api/v1/audit/stats"),
            (Method::GET, "/api/v1/audit/types"),
            (Method::GET, "/api/v1/audit/export/csv"),
            (Method::GET, "/api/v1/audit/export/json"),
            (Method::DELETE, "/api/v1/audit/cleanup/before"),
            (Method::GET, "/api/v1/proprietary/ui-data/audit-events"),
            (Method::GET, "/api/v1/proprietary/ui-data/audit-charts"),
            (Method::GET, "/api/v1/proprietary/ui-data/audit-event-types"),
            (Method::GET, "/api/v1/proprietary/ui-data/audit-users"),
            (Method::GET, "/api/v1/proprietary/ui-data/audit-stats"),
            (Method::GET, "/api/v1/proprietary/ui-data/audit-export"),
            (Method::POST, "/api/v1/proprietary/ui-data/audit-clear-all"),
            (
                Method::GET,
                "/api/v1/proprietary/ui-data/usage-endpoint-statistics",
            ),
            (Method::GET, "/api/v1/usage/fleet-stats"),
            (Method::GET, "/api/v1/proprietary/ui-data/documents"),
            (
                Method::GET,
                "/api/v1/proprietary/ui-data/infrastructure/audit-log",
            ),
        ] {
            let entitlement = endpoint_entitlement(&method, path);
            assert_eq!(entitlement, EndpointEntitlement::Enterprise);
            assert_eq!(
                authorize_entitlement(LicenseTier::Normal, entitlement),
                Err(EndpointEntitlement::Enterprise)
            );
            assert_eq!(
                authorize_entitlement(LicenseTier::Server, entitlement),
                Err(EndpointEntitlement::Enterprise)
            );
            assert_eq!(
                authorize_entitlement(LicenseTier::Enterprise, entitlement),
                Ok(())
            );
        }

        for (method, path) in [
            (Method::GET, "/api/v1/team/list"),
            (Method::POST, "/api/v1/team/list"),
            (Method::GET, "/api/v1/proprietary/ui-data/teams"),
            (Method::GET, "/api/v1/audit/not-reviewed"),
            (Method::POST, "/api/v1/audit/data"),
        ] {
            assert_eq!(
                endpoint_entitlement(&method, path),
                EndpointEntitlement::Unrestricted
            );
        }
    }

    fn context<const N: usize>(roles: [&str; N]) -> AuthContext {
        AuthContext {
            user_id: 7,
            username: "user@example.test".to_owned(),
            authentication_source: AuthenticationSource::Password,
            authentication_type: "web".to_owned(),
            roles: roles
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
            team_id: None,
            permissions: BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        }
    }
}
