use std::sync::Arc;

use axum::Router;
use stirling_processing::{
    TimestampSettings, app_with_runtime_config,
    runtime_config::RuntimeConfig,
    security_http::{
        SecurityHttpConfig, SecurityStartupError, initialize_security_store,
        secure_router_with_config,
    },
    security_jwt::SupabaseJwtVerifier,
    security_policy::LicenseTier,
};

pub(crate) fn reviewed_security_app_at_tier(
    max_upload_bytes: usize,
    timestamp_settings: TimestampSettings,
    runtime_config: RuntimeConfig,
    license_tier: LicenseTier,
) -> Result<Router, SecurityStartupError> {
    let store = initialize_security_store(&runtime_config)?;
    let external_jwt = runtime_config
        .security_supabase_jwt_config()
        .map(SupabaseJwtVerifier::new)
        .transpose()
        .map_err(SecurityStartupError::ExternalJwt)?
        .map(Arc::new);
    let config = SecurityHttpConfig {
        totp_issuer: runtime_config.security_totp_issuer(),
        invites_enabled: runtime_config.security_invites_enabled(),
        invite_expiry_hours: runtime_config.security_invite_expiry_hours(),
        frontend_url: runtime_config.security_frontend_url(),
        backend_url: runtime_config.security_backend_url(),
        audit_enabled: runtime_config.security_audit_enabled(),
        audit_level: runtime_config.security_audit_level(),
        audit_file_capture: stirling_processing::security_http::SecurityAuditFileCaptureConfig {
            file_hash: runtime_config.security_audit_capture_file_hash(),
            pdf_author: runtime_config.security_audit_capture_pdf_author(),
        },
        audit_capture_operation_results: runtime_config.security_audit_capture_operation_results(),
        license_tier,
        external_jwt,
        oidc_login_provider: runtime_config.oidc_login_provider_config(),
    };
    let router = app_with_runtime_config(max_upload_bytes, timestamp_settings, runtime_config);
    Ok(secure_router_with_config(router, store, config))
}
