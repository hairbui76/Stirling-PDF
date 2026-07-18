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

/// A stable denial category which an HTTP boundary can map without exposing
/// user, session, or policy internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDenial {
    AuthenticationRequired,
    ParticipantTokenRequired,
    DemoUserRestricted,
    AdministratorRequired,
}

/// Resolves one normalized request path to its secured-mode policy.
#[must_use]
pub fn endpoint_policy(method: &Method, path: &str) -> EndpointPolicy {
    if is_public_health(method, path)
        || is_public_static(method, path)
        || is_public_auth(method, path)
        || is_public_invitation(method, path)
        || path.starts_with("/api/v1/mobile-scanner/")
    {
        return EndpointPolicy::Public;
    }
    if path.starts_with("/api/v1/workflow/participant/") {
        return EndpointPolicy::ParticipantToken;
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
    method == Method::POST
        && matches!(
            path,
            "/api/v1/auth/login" | "/api/v1/auth/refresh" | "/api/v1/auth/logout"
        )
}

fn is_public_invitation(method: &Method, path: &str) -> bool {
    (method == Method::GET && path.starts_with("/api/v1/invite/validate/"))
        || (method == Method::POST && path.starts_with("/api/v1/invite/accept/"))
}

fn is_administrator_path(path: &str) -> bool {
    path.starts_with("/api/v1/admin/")
        || path == "/api/v1/admin"
        || path.starts_with("/api/v1/audit/")
        || path.starts_with("/api/v1/database/")
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
        )
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationDenial, EndpointPolicy, authorize, endpoint_policy};
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
            (Method::GET, "/api/v1/invite/validate/token"),
            (Method::POST, "/api/v1/invite/accept/token"),
            (Method::GET, "/api/v1/mobile-scanner/files/id"),
            (Method::GET, "/api/v1/ui-data/footer-info"),
        ] {
            assert_eq!(endpoint_policy(&method, path), EndpointPolicy::Public);
        }
        assert_eq!(
            endpoint_policy(&Method::GET, "/api/v1/config/app-config"),
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
            endpoint_policy(&Method::POST, "/api/v1/user/change-password"),
            EndpointPolicy::NonDemoUser
        );
        for path in [
            "/api/v1/team/create",
            "/api/v1/user/admin/saveUser",
            "/api/v1/auth/mfa/disable/admin/user@example.test",
            "/api/v1/invite/generate",
            "/api/v1/invite/revoke/7",
            "/api/v1/proprietary/ui-data/admin-settings",
        ] {
            assert_eq!(
                endpoint_policy(&Method::POST, path),
                EndpointPolicy::Administrator
            );
        }
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
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        }
    }
}
