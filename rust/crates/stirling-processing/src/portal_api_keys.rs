//! Portal-facing CRUD for named, personal API keys.
//!
//! Ports Java's `PortalApiKeysController` + `ApiKeyManagementService`: the
//! Infrastructure → API Keys tab lists, creates, and revokes the caller's own
//! keys under `/api/v1/proprietary/ui-data/infrastructure/api-keys`. Every key
//! belongs to exactly one user and authenticates as that user; there is no
//! sharing and no secret is ever re-shown after creation.
//!
//! Authorization mirrors the Java `@ProprietaryUiDataApi` annotation: this is
//! **not** Enterprise/admin/demo-gated. The path classifies as
//! [`EndpointPolicy::Authenticated`](crate::security_policy::EndpointPolicy),
//! so the secured middleware injects a trusted [`AuthContext`] for any
//! authenticated, non-anonymous caller and rejects everyone else at the edge;
//! each handler simply operates on `context.user_id`. The shared
//! [`SecurityStore`] extension is layered by `with_reviewed_security`.
//!
//! Parity notes:
//! - The key `id` is the store's opaque `key_id` string (Java exposes the DB
//!   autoincrement id as a string); the DELETE path param is that same id.
//! - An unknown **or** cross-user id on DELETE returns `404` (never `403`), so a
//!   caller cannot probe other users' key ids — matching Java's not-found guard.
//! - Legacy single-column keys have no analogue in the digest-only Rust store,
//!   so the Java "lazy legacy migration" step is intentionally absent.

use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::task;

use crate::security::{ApiKeyRecord, AuthContext, SecurityError, SecurityStore};

const API_KEYS_PATH: &str = "/api/v1/proprietary/ui-data/infrastructure/api-keys";
const API_KEY_ITEM_PATH: &str = "/api/v1/proprietary/ui-data/infrastructure/api-keys/{id}";

/// Bounds a key name so it can't bloat storage or the audit/processor feed
/// (mirrors Java `ApiKeyManagementService.MAX_NAME_LENGTH`).
const MAX_API_KEY_NAME_LENGTH: usize = 100;

/// Seconds per day, for deriving the UTC epoch day the usage windows measure
/// against (matches the store's `unixepoch() / 86400`).
const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) fn routes() -> Router {
    Router::new()
        .route(API_KEYS_PATH, get(list_keys).post(create_key))
        .route(API_KEY_ITEM_PATH, delete(revoke_key))
}

// ---------------------------------------------------------------------------
// Wire contracts (serde camelCase, matching the Java DTOs)
// ---------------------------------------------------------------------------

/// One API key as the portal lists it. Never carries the secret.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PortalApiKeyDto {
    id: String,
    name: String,
    prefix: String,
    /// `yyyy-MM-dd`, UTC.
    created: String,
    /// `yyyy-MM-dd HH:mm` UTC, or `"Never"`.
    last_used: String,
    /// `"active"` | `"revoked"`.
    status: String,
    usage_today: i64,
    usage_month: i64,
    usage_total: i64,
}

#[derive(Serialize)]
struct PortalApiKeysResponse {
    keys: Vec<PortalApiKeyDto>,
}

/// Returned once at creation: the row plus the plaintext secret, never persisted.
#[derive(Serialize)]
struct CreatedApiKeyDto {
    key: PortalApiKeyDto,
    secret: String,
}

/// Create-key request body: just a display name for the new personal key.
#[derive(Deserialize)]
struct CreateApiKeyRequest {
    #[serde(default)]
    name: Option<String>,
}

impl PortalApiKeyDto {
    fn from_record(record: ApiKeyRecord) -> Self {
        let status = if record.revoked_at.is_none() {
            "active"
        } else {
            "revoked"
        };
        Self {
            id: record.key_id,
            name: record.name,
            prefix: record.prefix,
            created: format_created(record.created_at),
            last_used: format_last_used(record.last_used_at),
            status: status.to_owned(),
            usage_today: record.usage_today,
            usage_month: record.usage_month,
            usage_total: record.usage_total,
        }
    }
}

// ---------------------------------------------------------------------------
// GET .../api-keys — the caller's personal keys, newest first.
// ---------------------------------------------------------------------------

async fn list_keys(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    // A `tier` query param is accepted for symmetry with the other infra tabs
    // and ignored here (unextracted params are simply dropped by axum).
) -> Response {
    let user_id = context.user_id;
    let today = today_epoch_day();
    let result = task::spawn_blocking(move || store.list_api_keys(user_id, today)).await;
    match result {
        Ok(Ok(records)) => Json(PortalApiKeysResponse {
            keys: records
                .into_iter()
                .map(PortalApiKeyDto::from_record)
                .collect(),
        })
        .into_response(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

// ---------------------------------------------------------------------------
// POST .../api-keys — mint a personal key, return its one-time secret.
// ---------------------------------------------------------------------------

async fn create_key(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    body: Bytes,
) -> Response {
    // Tolerate an absent or malformed body: any parse failure collapses to a
    // blank name, which fails the "name is required" guard below with 400.
    let name = serde_json::from_slice::<CreateApiKeyRequest>(&body)
        .ok()
        .and_then(|request| request.name)
        .unwrap_or_default();
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return bad_request("Key name is required");
    }
    if trimmed.chars().count() > MAX_API_KEY_NAME_LENGTH {
        return bad_request(&format!(
            "Key name must be {MAX_API_KEY_NAME_LENGTH} characters or fewer"
        ));
    }
    let name = trimmed.to_owned();
    let user_id = context.user_id;
    let result = task::spawn_blocking(move || {
        store.create_named_api_key(user_id, &name, Utc::now().timestamp())
    })
    .await;
    match result {
        Ok(Ok((record, secret))) => Json(CreatedApiKeyDto {
            key: PortalApiKeyDto::from_record(record),
            secret: secret.as_str().to_owned(),
        })
        .into_response(),
        Ok(Err(SecurityError::TooManyApiKeys)) => json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "You have reached the maximum number of active API keys; \
             revoke one before creating another",
        ),
        // Defensive: the store validates the cap; a rejected input maps to 400.
        Ok(Err(SecurityError::InvalidInput)) => bad_request("Key name is required"),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

// ---------------------------------------------------------------------------
// DELETE .../api-keys/{id} — soft-revoke a key the caller owns.
// ---------------------------------------------------------------------------

async fn revoke_key(
    Extension(store): Extension<Arc<SecurityStore>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Response {
    let user_id = context.user_id;
    let result =
        task::spawn_blocking(move || store.revoke_api_key(user_id, &id, Utc::now().timestamp()))
            .await;
    match result {
        // Found and revoked (idempotent) → 204.
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        // Unknown or owned by another user → 404, never 403.
        Ok(Ok(false)) => not_found(),
        Ok(Err(_)) | Err(_) => service_unavailable(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The current UTC epoch day, matching the store's `unixepoch() / 86400`.
fn today_epoch_day() -> i64 {
    Utc::now().timestamp().div_euclid(SECONDS_PER_DAY)
}

/// `yyyy-MM-dd` in UTC (Java `CREATED_FORMAT`). `created_at` is never null.
fn format_created(epoch_seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(epoch_seconds, 0)
        .map(|moment| moment.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// `yyyy-MM-dd HH:mm` in UTC (Java `LAST_USED_FORMAT`), or `"Never"` when the
/// key has never authenticated.
fn format_last_used(epoch_seconds: Option<i64>) -> String {
    epoch_seconds
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .map_or_else(
            || "Never".to_owned(),
            |moment| moment.format("%Y-%m-%d %H:%M").to_string(),
        )
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn bad_request(message: &str) -> Response {
    json_error(StatusCode::BAD_REQUEST, message)
}

fn not_found() -> Response {
    json_error(StatusCode::NOT_FOUND, "No key")
}

fn service_unavailable() -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "API key service unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::{format_created, format_last_used};

    #[test]
    fn created_formats_utc_date() {
        // 2023-11-14T22:13:20Z
        assert_eq!(format_created(1_700_000_000), "2023-11-14");
        // Epoch day 0.
        assert_eq!(format_created(0), "1970-01-01");
    }

    #[test]
    fn last_used_formats_minute_precision_or_never() {
        assert_eq!(format_last_used(None), "Never");
        assert_eq!(format_last_used(Some(1_700_000_000)), "2023-11-14 22:13");
        // A value outside the representable range degrades to "Never" rather
        // than panicking.
        assert_eq!(format_last_used(Some(i64::MAX)), "Never");
    }
}

#[cfg(test)]
mod route_tests {
    //! End-to-end handler tests driving the real `routes()` router with an
    //! injected [`AuthContext`] and a real in-memory [`SecurityStore`].
    //! `enforce_security` is intentionally not layered so each test presents an
    //! arbitrary trusted context; the coarse path policy is asserted separately.

    use super::{API_KEYS_PATH, MAX_API_KEY_NAME_LENGTH, routes};
    use crate::security::{AuthContext, AuthenticationSource, SecurityStore};
    use crate::security_policy::{EndpointPolicy, endpoint_policy};
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use axum::{Extension, Router};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn context(user_id: i64, roles: &[&str]) -> AuthContext {
        AuthContext {
            user_id,
            username: format!("user-{user_id}"),
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

    fn build_router(store: &Arc<SecurityStore>) -> Router {
        routes().layer(Extension(Arc::clone(store)))
    }

    async fn send(
        app: &Router,
        method: Method,
        path: &str,
        context: Option<AuthContext>,
        body: Option<Value>,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let mut builder = Request::builder().method(method).uri(path);
        let request_body = if let Some(value) = body {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value)?)
        } else {
            Body::empty()
        };
        let mut request = builder.body(request_body)?;
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

    fn seed_user(store: &SecurityStore, name: &str) -> Result<i64, Box<dyn std::error::Error>> {
        Ok(store.create_local_user(name, "test-only-password", ["ROLE_USER"], None)?)
    }

    #[test]
    fn api_keys_path_is_any_authenticated_not_admin() {
        // Java `@ProprietaryUiDataApi` without an Enterprise/admin gate: the
        // path must NOT classify as Administrator, only Authenticated.
        assert_eq!(
            endpoint_policy(&Method::GET, API_KEYS_PATH),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(&Method::POST, API_KEYS_PATH),
            EndpointPolicy::Authenticated
        );
        assert_eq!(
            endpoint_policy(
                &Method::DELETE,
                "/api/v1/proprietary/ui-data/infrastructure/api-keys/akid_x"
            ),
            EndpointPolicy::Authenticated
        );
    }

    #[tokio::test]
    async fn create_list_and_revoke_round_trip() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let user = seed_user(&store, "owner@example.test")?;
        let app = build_router(&store);

        // Create returns the one-time secret and a zero-usage active row.
        let created = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            Some(json!({ "name": "  Production ingest  " })),
        )
        .await?;
        assert_eq!(created.status(), StatusCode::OK);
        let body = response_json(created).await?;
        let secret = body["secret"].as_str().ok_or("secret present")?;
        assert!(secret.starts_with("spdf_ak_"));
        // Name is persisted trimmed; prefix is the non-secret leading fragment.
        assert_eq!(body["key"]["name"].as_str(), Some("Production ingest"));
        assert_eq!(body["key"]["status"].as_str(), Some("active"));
        assert_eq!(body["key"]["lastUsed"].as_str(), Some("Never"));
        assert_eq!(body["key"]["usageToday"].as_i64(), Some(0));
        assert_eq!(body["key"]["usageMonth"].as_i64(), Some(0));
        assert_eq!(body["key"]["usageTotal"].as_i64(), Some(0));
        let prefix = body["key"]["prefix"].as_str().ok_or("prefix present")?;
        assert_eq!(prefix.len(), 11);
        assert!(secret.starts_with(prefix));
        // The secret is never re-derivable from the listing.
        let key_id = body["key"]["id"].as_str().ok_or("id present")?.to_owned();

        // Authenticating with the secret bumps usage and stamps last-used.
        store.authenticate_api_key(secret, "req")?;

        // List reflects the key with usage today = 1.
        let listed = send(
            &app,
            Method::GET,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            None,
        )
        .await?;
        assert_eq!(listed.status(), StatusCode::OK);
        let body = response_json(listed).await?;
        let keys = body["keys"].as_array().ok_or("keys array")?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["id"].as_str(), Some(key_id.as_str()));
        assert_eq!(keys[0]["usageToday"].as_i64(), Some(1));
        assert_eq!(keys[0]["usageMonth"].as_i64(), Some(1));
        assert_eq!(keys[0]["usageTotal"].as_i64(), Some(1));
        assert_ne!(keys[0]["lastUsed"].as_str(), Some("Never"));
        // The plaintext secret never appears in the listing.
        assert!(!serde_json::to_string(&body)?.contains(secret));

        // Revoke → 204; the key then lists as revoked and the secret stops
        // authenticating.
        let path = format!("{API_KEYS_PATH}/{key_id}");
        let revoked = send(
            &app,
            Method::DELETE,
            &path,
            Some(context(user, &["ROLE_USER"])),
            None,
        )
        .await?;
        assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
        assert!(store.authenticate_api_key(secret, "after-revoke").is_err());

        let listed = send(
            &app,
            Method::GET,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            None,
        )
        .await?;
        let body = response_json(listed).await?;
        assert_eq!(body["keys"][0]["status"].as_str(), Some("revoked"));
        Ok(())
    }

    #[tokio::test]
    async fn create_rejects_blank_absent_and_overlong_names() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let user = seed_user(&store, "owner@example.test")?;
        let app = build_router(&store);

        // Blank name → 400 with the exact message.
        let blank = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            Some(json!({ "name": "   " })),
        )
        .await?;
        assert_eq!(blank.status(), StatusCode::BAD_REQUEST);
        let body = response_json(blank).await?;
        assert_eq!(body["error"].as_str(), Some("Key name is required"));

        // Absent name field → 400.
        let absent = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            Some(json!({})),
        )
        .await?;
        assert_eq!(absent.status(), StatusCode::BAD_REQUEST);

        // Empty/malformed body → 400 (not a 500 or panic).
        let empty = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            None,
        )
        .await?;
        assert_eq!(empty.status(), StatusCode::BAD_REQUEST);

        // 101-char name → 400; the boundary (100) is accepted separately.
        let overlong = "x".repeat(101);
        let response = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            Some(json!({ "name": overlong })),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn create_accepts_a_name_at_the_length_boundary() -> TestResult {
        // The reject guard is `> MAX`, so a name of exactly MAX characters is
        // accepted and persisted verbatim (the 101-char case is rejected above).
        let store = Arc::new(SecurityStore::in_memory()?);
        let user = seed_user(&store, "owner@example.test")?;
        let app = build_router(&store);
        let exactly_max = "x".repeat(MAX_API_KEY_NAME_LENGTH);
        let response = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            Some(json!({ "name": exactly_max })),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await?;
        assert_eq!(body["key"]["name"].as_str(), Some(exactly_max.as_str()));
        Ok(())
    }

    #[tokio::test]
    async fn create_enforces_active_key_cap_with_429() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let user = seed_user(&store, "owner@example.test")?;
        let now = 1_000;
        for index in 0..50 {
            store.create_named_api_key(user, &format!("key-{index}"), now)?;
        }
        let app = build_router(&store);
        let response = send(
            &app,
            Method::POST,
            API_KEYS_PATH,
            Some(context(user, &["ROLE_USER"])),
            Some(json!({ "name": "one too many" })),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        Ok(())
    }

    #[tokio::test]
    async fn revoke_unknown_or_cross_user_is_not_found() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let owner = seed_user(&store, "owner@example.test")?;
        let attacker = seed_user(&store, "attacker@example.test")?;
        let (record, _secret) = store.create_named_api_key(owner, "owned", 1_000)?;
        let app = build_router(&store);

        // Unknown id → 404.
        let unknown = send(
            &app,
            Method::DELETE,
            &format!("{API_KEYS_PATH}/akid_does_not_exist"),
            Some(context(owner, &["ROLE_USER"])),
            None,
        )
        .await?;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        // Another user's real key → 404 (never 403), so ids can't be probed.
        let path = format!("{API_KEYS_PATH}/{}", record.key_id);
        let cross_user = send(
            &app,
            Method::DELETE,
            &path,
            Some(context(attacker, &["ROLE_USER"])),
            None,
        )
        .await?;
        assert_eq!(cross_user.status(), StatusCode::NOT_FOUND);
        // The owner's key is untouched and still authenticates-listable as active.
        let listed = store.list_api_keys(owner, 100)?;
        assert_eq!(listed.len(), 1);
        assert!(listed[0].revoked_at.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn list_scopes_to_the_caller_only() -> TestResult {
        let store = Arc::new(SecurityStore::in_memory()?);
        let owner = seed_user(&store, "owner@example.test")?;
        let other = seed_user(&store, "other@example.test")?;
        store.create_named_api_key(owner, "mine", 1_000)?;
        store.create_named_api_key(other, "theirs", 1_000)?;
        let app = build_router(&store);
        let response = send(
            &app,
            Method::GET,
            API_KEYS_PATH,
            Some(context(owner, &["ROLE_USER"])),
            None,
        )
        .await?;
        let body = response_json(response).await?;
        let keys = body["keys"].as_array().ok_or("keys array")?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["name"].as_str(), Some("mine"));
        Ok(())
    }
}
