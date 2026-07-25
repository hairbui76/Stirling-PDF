//! Public inbound webhook-source receiver.
//!
//! This is the non-UI backend counterpart of a `webhook` policy input source. An
//! external system delivers a raw document to `POST /api/v1/webhooks/{webhookId}`,
//! signing the body with the source's shared secret. The endpoint is reachable
//! without a login session (see [`crate::security_policy::endpoint_policy`]); the
//! HMAC signature over the exact body is the only authenticator, so the ordering
//! of the checks below is a security property, not a stylistic choice.
//!
//! Mirrors Java's `WebhookReceiverController` / `WebhookSignatures` / `WebhookSpool`
//! / `WebhookIds`. It is deliberately absent from every OpenAPI/tool/operation
//! catalog (`@Hidden` parity) and never logs the `webhookId` or the signing secret.

use std::{
    io,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use data_encoding::HEXLOWER_PERMISSIVE;
use hmac::{Hmac, KeyInit as _, Mac};
use rand::RngExt as _;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;
use tokio::time::timeout;
use tracing::{error, info};

use crate::{policy_config::PolicyConfigService, policy_triggers::PolicyTriggerRuntime};

const SPOOL_DIR: &str = "policy-webhook-spool";
const TEMP_SUFFIX: &str = ".part";
const DEFAULT_DELIVERY_NAME: &str = "document.pdf";
/// Length of the 128-bit unique prefix once rendered as dashless lowercase hex,
/// matching Java's `UUID.randomUUID().toString().replace("-", "")` (32 chars).
const UNIQUE_PREFIX_LEN: usize = 32;

const SIGNATURE_HEADER: &str = "X-Stirling-Signature";
const FILENAME_HEADER: &str = "X-Stirling-Filename";
const SHA256_PREFIX: &str = "sha256=";

/// Upper bound on the wall-clock time allowed to buffer one delivery body before
/// HMAC verification. The size gate (`413`) is enforced before a byte is read
/// and the router applies a per-frame body read timeout; this total-time ceiling
/// additionally bounds a body that trickles in just under the per-frame timeout,
/// so a slowloris can neither hold the connection open nor buffer toward
/// `webhookMaxBytes` ahead of the signature check.
const WEBHOOK_ASSEMBLE_TIMEOUT: Duration = Duration::from_secs(30);

// Response bodies. The two 404s are byte-for-byte identical so a probe cannot
// tell "id malformed" from "no such source" — that is the anti-enumeration
// property of this endpoint.
const NO_SUCH_WEBHOOK: &str = "No such webhook";
const MISCONFIGURED: &str = "Webhook source is misconfigured";
const LENGTH_REQUIRED_MSG: &str = "A Content-Length header is required";
const BODY_EXCEEDS_DECLARED: &str = "Body exceeds the declared Content-Length";
const INVALID_SIGNATURE: &str = "Invalid signature";
const PAUSED: &str = "Webhook source is paused; deliveries are not accepted";
const EMPTY_BODY: &str = "Empty request body";
const COULD_NOT_STORE: &str = "Could not store delivery";
const RECEIVER_UNAVAILABLE: &str = "Webhook receiver unavailable";
const SLOW_BODY: &str = "Delivery body was not received in time";

/// Route state. [`PolicyTriggerRuntime`] is cheap to clone (it is internally
/// `Arc`-backed) and owns the `fire_for_webhook` dispatch loop.
#[derive(Clone)]
pub(crate) struct WebhookReceiverState {
    config: Arc<PolicyConfigService>,
    triggers: PolicyTriggerRuntime,
    install_root: PathBuf,
    max_bytes: u64,
}

/// The 202 body, serialized as `{"accepted":true,"filename":..,"bytes":..}` to
/// match Java's `WebhookReceiverController.WebhookDeliveryResponse`.
#[derive(Debug, Serialize)]
struct WebhookDeliveryResponse {
    accepted: bool,
    filename: String,
    bytes: usize,
}

/// Builds the public receiver router. It carries its own [`DefaultBodyLimit`]
/// override — disabled — because the handler enforces its own bound manually via
/// the declared `Content-Length` and a capped read, exactly as the Java servlet
/// reads at most `Content-Length` bytes. Mount this OUTSIDE the shared upload
/// body-limit layer.
pub(crate) fn routes(
    config: Arc<PolicyConfigService>,
    triggers: PolicyTriggerRuntime,
    install_root: PathBuf,
    max_bytes: u64,
) -> Router {
    Router::new()
        .route("/api/v1/webhooks/{webhook_id}", post(receive))
        // The body is read through the raw `Body` extractor + an explicit
        // `to_bytes(body, declared)` cap, so no framework body limit is relied
        // upon; disabling it keeps a smaller declared length from being clamped
        // by an outer limit and documents that this route owns its own bound.
        .layer(DefaultBodyLimit::disable())
        .with_state(WebhookReceiverState {
            config,
            triggers,
            install_root,
            max_bytes,
        })
}

/// Handles one inbound delivery. The check order below is fixed and must not be
/// reordered — it is what prevents webhook-id enumeration and what guarantees a
/// forged body is never spooled or allowed to fire a policy.
async fn receive(
    State(state): State<WebhookReceiverState>,
    AxumPath(webhook_id): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // 1. A malformed id is indistinguishable from an unknown one.
    if !is_valid_webhook_id(&webhook_id) {
        return reject(StatusCode::NOT_FOUND, NO_SUCH_WEBHOOK);
    }
    // 2. Resolve the source across ALL teams (a delivery is authenticated by its
    //    signed id/secret, not by a caller's team). Same 404 body as step 1.
    let source = match state.config.find_webhook_source(&webhook_id) {
        Ok(Some(source)) => source,
        Ok(None) => return reject(StatusCode::NOT_FOUND, NO_SUCH_WEBHOOK),
        Err(_) => return reject(StatusCode::INTERNAL_SERVER_ERROR, RECEIVER_UNAVAILABLE),
    };
    // 3. A source with no usable signing secret is a server misconfiguration.
    //    Fail closed (500) — an absent secret must never become a bypass.
    let Some(signing_secret) = webhook_signing_secret(&source.options) else {
        return reject(StatusCode::INTERNAL_SERVER_ERROR, MISCONFIGURED);
    };
    // 4. Bound the body BEFORE any signature work. A missing/unparseable
    //    Content-Length is rejected (chunked bodies cannot be pre-buffered
    //    safely); an over-limit declaration is rejected before a byte is read;
    //    the read itself is capped at the declared length.
    let Some(declared) = parse_content_length(&headers) else {
        return reject(StatusCode::LENGTH_REQUIRED, LENGTH_REQUIRED_MSG);
    };
    if declared > state.max_bytes {
        return reject(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("Delivery exceeds the {}-byte limit", state.max_bytes),
        );
    }
    let declared_cap = usize::try_from(declared).unwrap_or(usize::MAX);
    // A body longer than the declared length (or an unreadable one) is a bad
    // request; a body that cannot finish buffering within the assemble ceiling
    // is a timed-out delivery. Nothing beyond `declared` bytes is ever buffered,
    // and neither rejection runs any signature work.
    let body = match assemble_body(body, declared_cap, WEBHOOK_ASSEMBLE_TIMEOUT).await {
        BodyAssembly::Body(bytes) => bytes,
        BodyAssembly::TooLong => return reject(StatusCode::BAD_REQUEST, BODY_EXCEEDS_DECLARED),
        BodyAssembly::TimedOut => return reject(StatusCode::REQUEST_TIMEOUT, SLOW_BODY),
    };
    // 5–7. Verify the signature over the ACTUAL received bytes, then reject a
    //       paused source, then an empty body — in that order.
    let signature = header_value(&headers, SIGNATURE_HEADER);
    match decide_delivery(&signing_secret, source.enabled, signature, &body) {
        PostBodyDecision::InvalidSignature => {
            return reject(StatusCode::UNAUTHORIZED, INVALID_SIGNATURE);
        }
        PostBodyDecision::Paused => return reject(StatusCode::FORBIDDEN, PAUSED),
        PostBodyDecision::EmptyBody => return reject(StatusCode::BAD_REQUEST, EMPTY_BODY),
        PostBodyDecision::Accept => {}
    }
    // 8. Atomically stage the delivery under the per-webhook spool directory.
    let filename = header_value(&headers, FILENAME_HEADER);
    let stored_name = match store_delivery(&state.install_root, &webhook_id, filename, &body).await
    {
        Ok(stored_name) => stored_name,
        Err(error) => {
            // Never log the webhook id or secret.
            error!(%error, "could not store webhook delivery");
            return reject(StatusCode::INTERNAL_SERVER_ERROR, COULD_NOT_STORE);
        }
    };
    // 9. Let every referencing policy see the delivery. Errors are swallowed
    //    inside fire_for_webhook so a broken policy cannot fail the response.
    state.triggers.fire_for_webhook(&webhook_id).await;

    let bytes = body.len();
    info!(bytes, "accepted webhook delivery");
    // 10. Report the display name (the unique prefix stripped) and byte count.
    (
        StatusCode::ACCEPTED,
        Json(WebhookDeliveryResponse {
            accepted: true,
            filename: display_name(&stored_name),
            bytes,
        }),
    )
        .into_response()
}

fn reject(status: StatusCode, message: &str) -> Response {
    (status, message.to_owned()).into_response()
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// `^[A-Za-z0-9_-]{16,128}$`, mirroring Java's `WebhookIds.VALID_ID`. The valid
/// alphabet is ASCII-only, so byte length equals character length here. Shared
/// with the policy-source runner, whose webhook arm mirrors `WebhookConfig.from`'s
/// `WebhookIds.isValidId` guard on the same id.
pub(crate) fn is_valid_webhook_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Extracts the trimmed, non-blank `signingSecret`, mirroring the secret half of
/// Java's `WebhookConfig.from`. Returns `None` (→ 500 misconfig) when the option
/// is missing, non-string, or blank.
fn webhook_signing_secret(options: &Map<String, Value>) -> Option<String> {
    let secret = options.get("signingSecret")?.as_str()?.trim();
    (!secret.is_empty()).then(|| secret.to_owned())
}

/// Outcome of buffering a delivery body under both a size cap and a wall-clock
/// ceiling. Keeping the three cases distinct lets the caller preserve the exact
/// reject ordering (`413` size gate first, then `400` over-declared, then `408`
/// too-slow) with no signature work on any rejection path.
enum BodyAssembly {
    Body(Bytes),
    TooLong,
    TimedOut,
}

/// Buffers at most `declared_cap` bytes, aborting if assembly outruns
/// `assemble_timeout`. The caller has already rejected an over-limit declared
/// length with `413` before calling this, so nothing beyond the declared length
/// is ever read here.
async fn assemble_body(
    body: Body,
    declared_cap: usize,
    assemble_timeout: Duration,
) -> BodyAssembly {
    match timeout(assemble_timeout, to_bytes(body, declared_cap)).await {
        Ok(Ok(bytes)) => BodyAssembly::Body(bytes),
        Ok(Err(_)) => BodyAssembly::TooLong,
        Err(_elapsed) => BodyAssembly::TimedOut,
    }
}

/// Parses a non-negative `Content-Length`, mirroring the servlet's
/// `getContentLengthLong()` (absent, negative, or unparseable → rejected).
fn parse_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
}

/// Constant-time HMAC-SHA256 signature check over the raw body, mirroring Java's
/// `WebhookSignatures.verify`:
/// - a missing header fails;
/// - the value is trimmed and an optional case-insensitive `sha256=` prefix is
///   stripped (a bare hex digest is also accepted);
/// - the remainder is hex-decoded (mixed case allowed); non-hex or wrong length
///   fails;
/// - the decoded bytes are compared to the computed MAC in constant time.
fn verify_signature(signing_secret: &str, body: &[u8], presented: Option<&str>) -> bool {
    let Some(presented) = presented else {
        return false;
    };
    let trimmed = presented.trim();
    let prefix = SHA256_PREFIX.as_bytes();
    let hex = if trimmed.len() >= prefix.len()
        && trimmed.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix)
    {
        // The prefix is ASCII, so byte index prefix.len() is a char boundary.
        &trimmed[prefix.len()..]
    } else {
        trimmed
    };
    let Ok(presented_bytes) = HEXLOWER_PERMISSIVE.decode(hex.as_bytes()) else {
        return false;
    };
    let Some(expected) = hmac_sha256(signing_secret.as_bytes(), body) else {
        return false;
    };
    // ct_eq already returns false on a length mismatch; the explicit guard just
    // short-circuits the (non-secret) length comparison first.
    expected.len() == presented_bytes.len() && expected.ct_eq(presented_bytes.as_slice()).into()
}

/// HMAC-SHA256 of `body` under `secret`. `Hmac::new_from_slice` never rejects a
/// key length in practice, but the fallible constructor is surfaced as `None`
/// (→ signature verification fails) rather than unwrapped, so a key-init failure
/// can never be mistaken for a match.
fn hmac_sha256(secret: &[u8], body: &[u8]) -> Option<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).ok()?;
    mac.update(body);
    let output = mac.finalize().into_bytes();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&output);
    Some(digest)
}

#[derive(Debug, Eq, PartialEq)]
enum PostBodyDecision {
    InvalidSignature,
    Paused,
    EmptyBody,
    Accept,
}

/// The signature → enabled → empty-body decision, factored out so the ordering is
/// unit-testable. Signature is verified FIRST so a paused or empty delivery still
/// cannot be distinguished from a valid one without the secret.
fn decide_delivery(
    signing_secret: &str,
    source_enabled: bool,
    signature: Option<&str>,
    body: &[u8],
) -> PostBodyDecision {
    if !verify_signature(signing_secret, body, signature) {
        return PostBodyDecision::InvalidSignature;
    }
    if !source_enabled {
        return PostBodyDecision::Paused;
    }
    if body.is_empty() {
        return PostBodyDecision::EmptyBody;
    }
    PostBodyDecision::Accept
}

/// `<32-hex UUID no dashes>-<sanitized filename>`, mirroring
/// `WebhookSpool.spoolName`.
fn spool_name(filename: Option<&str>) -> String {
    format!(
        "{}-{}",
        unique_prefix(),
        sanitize_delivery_filename(filename)
    )
}

/// Recovers the display name by stripping the unique prefix and its separator,
/// mirroring `WebhookSpool.displayName` (only when the first `-` sits exactly at
/// the prefix boundary and something follows it).
pub(crate) fn display_name(stored_name: &str) -> String {
    match stored_name.find('-') {
        Some(dash) if dash == UNIQUE_PREFIX_LEN && dash + 1 < stored_name.len() => {
            stored_name[dash + 1..].to_owned()
        }
        _ => stored_name.to_owned(),
    }
}

/// 16 random bytes (v4-tagged) as dashless lowercase hex — 32 chars, never a
/// `-` — so the first `-` in a spool name is always the display separator.
fn unique_prefix() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    data_encoding::HEXLOWER.encode(&bytes)
}

/// Reduces an untrusted `X-Stirling-Filename` to a safe basename, mirroring
/// `WebhookSpool.sanitize`: take the basename (treating `\` as `/`), map every
/// character outside `[A-Za-z0-9._-]` to `_`, trim, strip ALL leading dots, and
/// fall back to `document.pdf` when nothing usable remains.
fn sanitize_delivery_filename(filename: Option<&str>) -> String {
    let Some(filename) = filename else {
        return DEFAULT_DELIVERY_NAME.to_owned();
    };
    let normalized = filename.replace('\\', "/");
    let base = normalized.rsplit('/').next().unwrap_or("");
    let replaced: String = base
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let stripped = replaced.trim().trim_start_matches('.');
    if stripped.is_empty() {
        DEFAULT_DELIVERY_NAME.to_owned()
    } else {
        stripped.to_owned()
    }
}

struct SpoolPaths {
    dir: PathBuf,
    temp: PathBuf,
    target: PathBuf,
}

/// Resolves and containment-checks the per-webhook spool directory, mirroring
/// `WebhookSpool.dirFor`. The path is lexically normalized and MUST be a direct
/// child of the spool root — a `webhook_id` carrying separators or `..` would
/// break this parent-equality guard. Returns `None` if the guard fails. Single
/// source of truth for the spool layout, shared with the policy-source runner
/// (which reads what this receiver writes).
pub(crate) fn spool_dir(install_root: &Path, webhook_id: &str) -> Option<PathBuf> {
    let spool_root = normalize_absolute(&install_root.join(SPOOL_DIR));
    let dir = normalize_absolute(&spool_root.join(webhook_id));
    (dir.parent() == Some(spool_root.as_path())).then_some(dir)
}

/// Resolves and containment-checks the spool directory and the temp/target files
/// for a delivery, mirroring `WebhookSpool.dirFor` + `store`'s guards. Every path
/// is lexically normalized and both the temp and target must resolve strictly
/// inside the per-webhook directory. Returns `None` if any guard fails.
fn spool_paths(install_root: &Path, webhook_id: &str, final_name: &str) -> Option<SpoolPaths> {
    let dir = spool_dir(install_root, webhook_id)?;
    let target = normalize_absolute(&dir.join(final_name));
    let temp = normalize_absolute(&dir.join(format!(".{final_name}{TEMP_SUFFIX}")));
    if !target.starts_with(&dir) || !temp.starts_with(&dir) {
        return None;
    }
    Some(SpoolPaths { dir, temp, target })
}

/// Writes the delivery to a hidden temp file then atomically renames it into
/// place, mirroring `WebhookSpool.store`. Returns the final on-disk file name.
///
/// `std`/`tokio` `rename` performs an atomic in-directory replace on both Unix
/// and Windows, so the Java `ATOMIC_MOVE`→`REPLACE_EXISTING` fallback collapses
/// to a single rename here (temp and target always share a directory).
async fn store_delivery(
    install_root: &Path,
    webhook_id: &str,
    filename: Option<&str>,
    body: &[u8],
) -> io::Result<String> {
    let final_name = spool_name(filename);
    let paths = spool_paths(install_root, webhook_id, &final_name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid webhook spool path"))?;
    tokio::fs::create_dir_all(&paths.dir).await?;
    tokio::fs::write(&paths.temp, body).await?;
    if let Err(rename_error) = tokio::fs::rename(&paths.temp, &paths.target).await {
        // Best-effort cleanup so a failed delivery never leaves a stray temp file.
        let _ = tokio::fs::remove_file(&paths.temp).await;
        return Err(rename_error);
    }
    Ok(final_name)
}

/// Absolute, lexical path normalization (resolves `.`/`..` without touching the
/// filesystem), matching Java's `toAbsolutePath().normalize()`.
fn normalize_absolute(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::{
        BodyAssembly, DEFAULT_DELIVERY_NAME, PostBodyDecision, UNIQUE_PREFIX_LEN, assemble_body,
        decide_delivery, display_name, hmac_sha256, is_valid_webhook_id, parse_content_length,
        routes, sanitize_delivery_filename, spool_name, spool_paths, store_delivery,
        verify_signature, webhook_signing_secret,
    };
    use axum::{
        Router,
        body::{Body, Bytes, to_bytes},
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    };
    use serde_json::{Map, Value};
    use tower::ServiceExt as _;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const SECRET: &str = "topsecret";
    const BODY: &[u8] = b"a pdf";

    /// Java's `WebhookSignatures.sign`: `"sha256=" + lowercase-hex(HMAC)`. The
    /// `unwrap_or_default` fallback is never taken (HMAC key-init is infallible).
    fn sign(secret: &str, body: &[u8]) -> String {
        let digest = hmac_sha256(secret.as_bytes(), body).unwrap_or_default();
        format!("sha256={}", data_encoding::HEXLOWER.encode(&digest))
    }

    #[test]
    fn webhook_id_matches_the_java_regex_bounds_and_alphabet() {
        assert!(is_valid_webhook_id("receivertestid12")); // 16 chars
        assert!(is_valid_webhook_id(&"a".repeat(16)));
        assert!(is_valid_webhook_id(&"a".repeat(128)));
        assert!(is_valid_webhook_id("Aa0_-Aa0_-Aa0_-x"));
        // Too short / too long.
        assert!(!is_valid_webhook_id(&"a".repeat(15)));
        assert!(!is_valid_webhook_id(&"a".repeat(129)));
        assert!(!is_valid_webhook_id(""));
        // Disallowed characters (path separators, dots, unicode).
        assert!(!is_valid_webhook_id("../secret-attempt1"));
        assert!(!is_valid_webhook_id("has/slash/inside0"));
        assert!(!is_valid_webhook_id("has.dot.inside.000"));
        assert!(!is_valid_webhook_id("hasunicodeµµµµµµµ"));
    }

    #[test]
    fn signature_round_trips_and_rejects_every_forgery() {
        // A signature produced exactly like Java verifies.
        assert!(verify_signature(SECRET, BODY, Some(&sign(SECRET, BODY))));
        // A bare (prefix-less) lowercase hex digest is accepted.
        let bare = data_encoding::HEXLOWER
            .encode(&hmac_sha256(SECRET.as_bytes(), BODY).unwrap_or_default());
        assert!(verify_signature(SECRET, BODY, Some(&bare)));
        // The prefix match is case-insensitive and the value is trimmed.
        let upper_prefixed = format!("  SHA256={bare}  ");
        assert!(verify_signature(SECRET, BODY, Some(&upper_prefixed)));
        // Uppercase hex digits decode too (HEXLOWER_PERMISSIVE).
        let upper_hex = format!("sha256={}", bare.to_uppercase());
        assert!(verify_signature(SECRET, BODY, Some(&upper_hex)));

        // Missing header.
        assert!(!verify_signature(SECRET, BODY, None));
        // Empty / blank value.
        assert!(!verify_signature(SECRET, BODY, Some("")));
        assert!(!verify_signature(SECRET, BODY, Some("   ")));
        assert!(!verify_signature(SECRET, BODY, Some("sha256=")));
        // Non-hex and odd-length hex.
        assert!(!verify_signature(SECRET, BODY, Some("sha256=nothexxx")));
        assert!(!verify_signature(SECRET, BODY, Some("sha256=abc")));
        // Right shape, wrong digest.
        assert!(!verify_signature(SECRET, BODY, Some("sha256=deadbeef")));
        // Tampered body.
        assert!(!verify_signature(
            SECRET,
            b"a PDF",
            Some(&sign(SECRET, BODY))
        ));
        // Wrong secret.
        assert!(!verify_signature(
            "othersecret",
            BODY,
            Some(&sign(SECRET, BODY))
        ));
    }

    #[test]
    fn signing_secret_requires_a_non_blank_string() {
        let mut options = Map::new();
        assert_eq!(webhook_signing_secret(&options), None);
        options.insert("signingSecret".to_owned(), Value::String("  ".to_owned()));
        assert_eq!(webhook_signing_secret(&options), None);
        options.insert("signingSecret".to_owned(), Value::Number(7.into()));
        assert_eq!(webhook_signing_secret(&options), None);
        options.insert(
            "signingSecret".to_owned(),
            Value::String("  topsecret  ".to_owned()),
        );
        assert_eq!(
            webhook_signing_secret(&options).as_deref(),
            Some("topsecret")
        );
    }

    #[test]
    fn content_length_parses_only_non_negative_integers() {
        let mut headers = HeaderMap::new();
        assert_eq!(parse_content_length(&headers), None);
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        assert_eq!(parse_content_length(&headers), Some(5));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("-5"));
        assert_eq!(parse_content_length(&headers), None);
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("abc"));
        assert_eq!(parse_content_length(&headers), None);
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        assert_eq!(parse_content_length(&headers), Some(0));
    }

    #[test]
    fn delivery_decision_verifies_signature_before_paused_or_empty() {
        let good = sign(SECRET, BODY);
        // A wrong signature on a PAUSED source still reports InvalidSignature —
        // "paused" must not leak to an unauthenticated caller.
        assert_eq!(
            decide_delivery(SECRET, false, Some("sha256=deadbeef"), BODY),
            PostBodyDecision::InvalidSignature
        );
        // Valid signature, paused source.
        assert_eq!(
            decide_delivery(SECRET, false, Some(&good), BODY),
            PostBodyDecision::Paused
        );
        // Valid signature over an EMPTY body on an enabled source: the empty body
        // must itself be signed, then it is rejected as empty.
        let empty_sig = sign(SECRET, b"");
        assert_eq!(
            decide_delivery(SECRET, true, Some(&empty_sig), b""),
            PostBodyDecision::EmptyBody
        );
        assert_eq!(
            decide_delivery(SECRET, true, Some(&good), BODY),
            PostBodyDecision::Accept
        );
    }

    #[test]
    fn filename_sanitization_matches_java() {
        assert_eq!(sanitize_delivery_filename(None), DEFAULT_DELIVERY_NAME);
        assert_eq!(
            sanitize_delivery_filename(Some("invoice.pdf")),
            "invoice.pdf"
        );
        // Basename only, backslashes normalized to slashes first.
        assert_eq!(
            sanitize_delivery_filename(Some("../../etc/passwd")),
            "passwd"
        );
        assert_eq!(
            sanitize_delivery_filename(Some("C:\\Windows\\evil.pdf")),
            "evil.pdf"
        );
        // Disallowed characters become underscores.
        assert_eq!(
            sanitize_delivery_filename(Some("na me?*.pdf")),
            "na_me__.pdf"
        );
        // ALL leading dots stripped (defeats hidden-file / traversal tricks).
        assert_eq!(sanitize_delivery_filename(Some("...hidden")), "hidden");
        assert_eq!(
            sanitize_delivery_filename(Some("..")),
            DEFAULT_DELIVERY_NAME
        );
        // Nothing usable → default.
        assert_eq!(
            sanitize_delivery_filename(Some("///")),
            DEFAULT_DELIVERY_NAME
        );
        assert_eq!(sanitize_delivery_filename(Some("")), DEFAULT_DELIVERY_NAME);
    }

    #[test]
    fn spool_name_and_display_name_round_trip() {
        let name = spool_name(Some("invoice.pdf"));
        // 32 hex chars + '-' + sanitized name.
        assert_eq!(name.len(), UNIQUE_PREFIX_LEN + 1 + "invoice.pdf".len());
        assert_eq!(name.as_bytes()[UNIQUE_PREFIX_LEN], b'-');
        assert!(
            name[..UNIQUE_PREFIX_LEN]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_eq!(display_name(&name), "invoice.pdf");
        // Two mints differ (random prefix).
        assert_ne!(spool_name(Some("invoice.pdf")), name);
        // A name without the prefix shape is returned unchanged.
        assert_eq!(display_name("plain.pdf"), "plain.pdf");
    }

    #[test]
    fn spool_paths_are_contained_and_reject_traversal() -> TestResult {
        let root = std::path::Path::new("/srv/stirling");
        let Some(paths) = spool_paths(root, "receivertestid12", "abc-invoice.pdf") else {
            return Err("a valid webhook id must resolve to a spool path".into());
        };
        let expected_dir = root.join("policy-webhook-spool").join("receivertestid12");
        assert_eq!(paths.dir, expected_dir);
        assert!(paths.target.starts_with(&paths.dir));
        assert!(paths.temp.starts_with(&paths.dir));
        let temp_name = paths
            .temp
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or("temp path must have a file name")?;
        assert_eq!(temp_name, ".abc-invoice.pdf.part");
        // Defense in depth: even if a traversal id reached here, the parent-equality
        // guard rejects it (the handler already rejects it at step 1).
        assert!(spool_paths(root, "..", "x").is_none());
        assert!(spool_paths(root, "a/b", "x").is_none());
        Ok(())
    }

    #[tokio::test]
    async fn store_delivery_writes_atomically_and_leaves_no_temp() -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        let stored =
            store_delivery(root.path(), "receivertestid12", Some("invoice.pdf"), BODY).await?;
        let dir = root
            .path()
            .join("policy-webhook-spool")
            .join("receivertestid12");
        let target = dir.join(&stored);
        assert_eq!(tokio::fs::read(&target).await?, BODY);
        assert_eq!(display_name(&stored), "invoice.pdf");
        // No leftover hidden .part temp file.
        let mut entries = tokio::fs::read_dir(&dir).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        assert_eq!(names, vec![stored]);
        Ok(())
    }

    #[tokio::test]
    async fn store_delivery_defaults_a_missing_filename() -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        let stored = store_delivery(root.path(), "receivertestid12", None, BODY).await?;
        assert_eq!(display_name(&stored), DEFAULT_DELIVERY_NAME);
        Ok(())
    }

    // ---- TESTER: HTTP-level coverage of the `receive` handler ----
    // The unit tests above lock the pure helpers; these drive the mounted router
    // end-to-end (oneshot, the crate convention in security_http.rs) so the fixed
    // check ORDER, the status mapping, the declared/actual body bounds, and the
    // fire-for-webhook dispatch are all exercised against a real signed request —
    // the security properties that only exist once the pieces are wired together.

    type HttpResult = Result<(), Box<dyn std::error::Error>>;

    const UNKNOWN_ID: &str = "unknownwebhookid00"; // valid shape, never persisted
    const MALFORMED_ID: &str = "short"; // fails the id format check

    fn admin_ctx() -> crate::security::AuthContext {
        crate::security::AuthContext {
            user_id: 1,
            username: "admin".to_owned(),
            authentication_source: crate::security::AuthenticationSource::AccessToken,
            authentication_type: "web".to_owned(),
            roles: ["ROLE_ADMIN"]
                .into_iter()
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>(),
            team_id: Some(1),
            permissions: std::collections::BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        }
    }

    /// The shared config service, its backing store, and an admin context.
    type ConfigEnv = (
        std::sync::Arc<super::PolicyConfigService>,
        std::sync::Arc<crate::security::SecurityStore>,
        crate::security::AuthContext,
    );

    /// A fresh in-memory config service plus its store and an admin context.
    fn config_env() -> Result<ConfigEnv, Box<dyn std::error::Error>> {
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let integrations =
            std::sync::Arc::new(crate::integration_config::IntegrationConfigService::new(
                std::sync::Arc::clone(&store),
                crate::resource_access::DefaultAccessPolicy::ExplicitOnly,
                false,
                false,
                false,
                false,
            ));
        let config = std::sync::Arc::new(super::PolicyConfigService::new(
            std::sync::Arc::clone(&store),
            integrations,
            Vec::new(),
            std::path::Path::new("/srv/configs"),
            Vec::new(),
        ));
        Ok((config, store, admin_ctx()))
    }

    /// A real (cheap) trigger runtime over `config`. The pipeline dispatcher is an
    /// empty router, so a fired webhook policy's run consumes the spooled deliveries
    /// but submits them to a no-op pipeline that always reports success. The runner
    /// shares `install_root` with the receiver so the fired run reads exactly the
    /// spool directory the receiver wrote to.
    fn trigger_runtime(
        config: &std::sync::Arc<super::PolicyConfigService>,
        store: &std::sync::Arc<crate::security::SecurityStore>,
        install_root: std::path::PathBuf,
    ) -> crate::policy_triggers::PolicyTriggerRuntime {
        let ledger = std::sync::Arc::new(crate::policy_ledger::ProcessedLedger::new(
            std::sync::Arc::clone(store),
        ));
        let s3 = crate::policy_s3::S3ConnectionPool::new();
        let outputs = std::sync::Arc::new(crate::policy_outputs::PolicyOutputService::new(
            std::sync::Arc::clone(config),
            std::sync::Arc::clone(&ledger),
            s3.clone(),
        ));
        let execution = std::sync::Arc::new(crate::policy_execution::PolicyExecutionService::new(
            std::sync::Arc::clone(config),
            crate::pipeline::PipelineDispatcher::new(Router::new()),
            std::sync::Arc::new(crate::job_manager::JobManager::new()),
            std::sync::Arc::new(crate::job_queue::JobQueue::new(
                crate::job_queue::JobQueueConfig::default(),
            )),
            outputs,
            None,
        ));
        let readiness = crate::runtime_config::FileReadinessConfig {
            enabled: false,
            settle_time: std::time::Duration::ZERO,
            size_check_delay: std::time::Duration::ZERO,
            allowed_extensions: std::collections::BTreeSet::new(),
        };
        let runner = std::sync::Arc::new(crate::policy_sources::PolicySourceRunner::new(
            std::sync::Arc::clone(config),
            execution,
            ledger,
            readiness,
            s3,
            install_root,
        ));
        let settings = crate::runtime_config::PolicyTriggerSettings {
            schedule_sweep: std::time::Duration::from_secs(60),
            watch_reconcile: std::time::Duration::from_secs(60),
            watch_quiet_period: std::time::Duration::from_secs(1),
        };
        crate::policy_triggers::PolicyTriggerRuntime::new(
            std::sync::Arc::clone(config),
            runner,
            settings,
            crate::policy_triggers::PolicyChangeNotifier::default(),
        )
    }

    /// Mount the public receiver router over `config`, exactly as `lib.rs` does.
    fn receiver_app(
        config: &std::sync::Arc<super::PolicyConfigService>,
        store: &std::sync::Arc<crate::security::SecurityStore>,
        install_root: std::path::PathBuf,
        max_bytes: u64,
    ) -> Router {
        routes(
            std::sync::Arc::clone(config),
            trigger_runtime(config, store, install_root.clone()),
            install_root,
            max_bytes,
        )
    }

    fn source_input(enabled: bool) -> crate::policy_config::PolicySource {
        crate::policy_config::PolicySource {
            id: String::new(),
            name: "Inbound hook".to_owned(),
            source_type: "webhook".to_owned(),
            options: Map::new(),
            enabled,
            owner: None,
            team_id: None,
        }
    }

    fn policy_input(
        source_ids: Vec<String>,
        enabled: bool,
    ) -> crate::policy_config::PolicyDefinition {
        crate::policy_config::PolicyDefinition {
            id: String::new(),
            name: "Inbound pipeline".to_owned(),
            owner: None,
            enabled,
            trigger: Some(crate::policy_config::TriggerConfig {
                trigger_type: "webhook".to_owned(),
                options: Map::new(),
            }),
            source_ids,
            steps: Vec::new(),
            output: crate::policy_config::OutputSpec::default(),
            team_id: None,
        }
    }

    /// Persist a webhook source and return `(source_id, webhookId, signingSecret)`
    /// — the plaintext pair revealed once on create.
    fn create_source(
        config: &super::PolicyConfigService,
        ctx: &crate::security::AuthContext,
        enabled: bool,
    ) -> Result<(String, String, String), Box<dyn std::error::Error>> {
        let created = config.save_source(source_input(enabled), ctx)?;
        let webhook_id = created
            .options
            .get("webhookId")
            .and_then(Value::as_str)
            .ok_or("create dropped webhookId")?
            .to_owned();
        let secret = created
            .options
            .get("signingSecret")
            .and_then(Value::as_str)
            .ok_or("create dropped signingSecret")?
            .to_owned();
        Ok((created.id, webhook_id, secret))
    }

    /// One inbound POST. `content_length`/`signature`/`filename` are optional so a
    /// test can drop a header (an absent `Content-Length` → 411, etc.).
    async fn deliver(
        app: &Router,
        webhook_id: &str,
        content_length: Option<&str>,
        signature: Option<&str>,
        filename: Option<&str>,
        body: Vec<u8>,
    ) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
        let mut builder = Request::post(format!("/api/v1/webhooks/{webhook_id}"));
        if let Some(value) = content_length {
            builder = builder.header(header::CONTENT_LENGTH, value);
        }
        if let Some(value) = signature {
            builder = builder.header(super::SIGNATURE_HEADER, value);
        }
        if let Some(value) = filename {
            builder = builder.header(super::FILENAME_HEADER, value);
        }
        Ok(app.clone().oneshot(builder.body(Body::from(body))?).await?)
    }

    async fn status_and_body(
        response: axum::response::Response,
    ) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await?.to_vec();
        Ok((status, body))
    }

    /// Assert exactly one file is spooled under the per-webhook directory and
    /// return its on-disk name and contents.
    async fn spooled_delivery(
        install_root: &std::path::Path,
        webhook_id: &str,
    ) -> Result<(String, Vec<u8>), Box<dyn std::error::Error>> {
        let dir = install_root.join("policy-webhook-spool").join(webhook_id);
        let mut entries = tokio::fs::read_dir(&dir).await?;
        let mut names = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        let name = match names.as_slice() {
            [only] => only.clone(),
            _ => return Err(format!("expected one spooled file, found {names:?}").into()),
        };
        let content = tokio::fs::read(dir.join(&name)).await?;
        Ok((name, content))
    }

    #[tokio::test]
    async fn http_accepts_a_valid_signed_delivery_spools_it_and_reports_the_display_name()
    -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (_source_id, webhook_id, secret) = create_source(&config, &ctx, true)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        let signature = sign(&secret, BODY);
        let (status, body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some(&BODY.len().to_string()),
                Some(&signature),
                Some("invoice.pdf"),
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;

        assert_eq!(status, StatusCode::ACCEPTED);
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(payload["accepted"], Value::Bool(true));
        assert_eq!(payload["filename"], Value::String("invoice.pdf".to_owned()));
        assert_eq!(payload["bytes"], Value::from(BODY.len()));

        // The body is on disk under the webhook's spool dir, and the reported name
        // is the display name (unique prefix stripped) of the stored file.
        let (stored_name, stored_body) = spooled_delivery(root.path(), &webhook_id).await?;
        assert_eq!(stored_body, BODY);
        assert_eq!(display_name(&stored_name), "invoice.pdf");
        Ok(())
    }

    #[tokio::test]
    async fn http_rejects_a_forged_signature_with_401() -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (_source_id, webhook_id, _secret) = create_source(&config, &ctx, true)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        let (status, body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some(&BODY.len().to_string()),
                Some("sha256=deadbeef"),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, super::INVALID_SIGNATURE.as_bytes());
        // Nothing is ever spooled for a forged delivery.
        assert!(!root.path().join("policy-webhook-spool").exists());
        Ok(())
    }

    #[tokio::test]
    async fn http_unknown_and_malformed_ids_return_the_same_404_body() -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        // A real source exists, but neither id below resolves to it.
        create_source(&config, &ctx, true)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        let (unknown_status, unknown_body) = status_and_body(
            deliver(
                &app,
                UNKNOWN_ID,
                Some("5"),
                Some("sha256=deadbeef"),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        let (malformed_status, malformed_body) = status_and_body(
            deliver(
                &app,
                MALFORMED_ID,
                Some("5"),
                Some("sha256=deadbeef"),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;

        assert_eq!(unknown_status, StatusCode::NOT_FOUND);
        assert_eq!(malformed_status, StatusCode::NOT_FOUND);
        // Byte-for-byte identical: a probe cannot tell "no such source" from
        // "malformed id" — the anti-enumeration property.
        assert_eq!(unknown_body, malformed_body);
        assert_eq!(unknown_body, super::NO_SUCH_WEBHOOK.as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn http_gates_paused_and_empty_strictly_after_the_signature() -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        // Paused source: a validly signed, non-empty delivery is refused 403.
        let (_paused_id, paused_hook, paused_secret) = create_source(&config, &ctx, false)?;
        // Enabled source: used for the empty-body case.
        let (_live_id, live_hook, live_secret) = create_source(&config, &ctx, true)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        // Valid signature + paused → 403.
        let (status, body) = status_and_body(
            deliver(
                &app,
                &paused_hook,
                Some(&BODY.len().to_string()),
                Some(&sign(&paused_secret, BODY)),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, super::PAUSED.as_bytes());

        // ORDERING LOCK: paused source + BAD signature → 401, not 403. "Paused"
        // must never leak to a caller who cannot sign.
        let (status, _body) = status_and_body(
            deliver(
                &app,
                &paused_hook,
                Some(&BODY.len().to_string()),
                Some("sha256=deadbeef"),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Signed EMPTY body on an enabled source → 400 (the empty body is itself
        // signed, then rejected as empty).
        let (status, body) = status_and_body(
            deliver(
                &app,
                &live_hook,
                Some("0"),
                Some(&sign(&live_secret, b"")),
                None,
                Vec::new(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, super::EMPTY_BODY.as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn http_content_length_bounds_are_checked_before_the_signature() -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (_source_id, webhook_id, _secret) = create_source(&config, &ctx, true)?;
        // A deliberately tiny cap so a modest declared length overruns it.
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 8);

        // ORDERING LOCK: declared > max + a bad signature → 413. The size bound is
        // enforced before any signature work, so the bad signature never matters.
        let (status, body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some("16"),
                Some("sha256=deadbeef"),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body, b"Delivery exceeds the 8-byte limit");

        // ORDERING LOCK: absent Content-Length + a bad signature → 411, again
        // before the signature check (a chunked body cannot be pre-bounded safely).
        let (status, body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                None,
                Some("sha256=deadbeef"),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::LENGTH_REQUIRED);
        assert_eq!(body, super::LENGTH_REQUIRED_MSG.as_bytes());
        Ok(())
    }

    #[tokio::test]
    async fn http_actual_body_length_is_bounded_by_the_declared_length() -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (_source_id, webhook_id, secret) = create_source(&config, &ctx, true)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        // Actual > declared → 400 before the signature (nothing past `declared`
        // bytes is ever buffered).
        let (status, body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some("3"),
                Some("sha256=deadbeef"),
                None,
                vec![b'x'; 6],
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, super::BODY_EXCEEDS_DECLARED.as_bytes());

        // Actual < declared → accepted; the signature is verified over the ACTUAL
        // received bytes, not the padded declared length.
        let (status, _body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some("100"),
                Some(&sign(&secret, BODY)),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::ACCEPTED);
        Ok(())
    }

    #[tokio::test]
    async fn http_declared_length_limit_is_inclusive() -> HttpResult {
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (_source_id, webhook_id, secret) = create_source(&config, &ctx, true)?;
        let max_bytes: u64 = 32;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), max_bytes);

        // A body of exactly the cap, declared == cap → accepted (the bound is
        // `declared > max`, so equality passes).
        let at_limit = vec![b'x'; 32];
        let (status, _body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some(&max_bytes.to_string()),
                Some(&sign(&secret, &at_limit)),
                None,
                at_limit,
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::ACCEPTED);

        // Declared one byte over the cap → 413 (independent of the body/signature).
        let (status, _body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some("33"),
                Some("sha256=deadbeef"),
                None,
                vec![b'x'; 33],
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    #[tokio::test]
    async fn http_receiver_accepts_bodies_above_the_default_upload_limit() -> HttpResult {
        // The router carries `DefaultBodyLimit::disable()` and is mounted OUTSIDE
        // the shared upload limit, so a legitimate delivery well above axum's 2 MiB
        // default must go through when it is within `webhookMaxBytes`.
        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (_source_id, webhook_id, secret) = create_source(&config, &ctx, true)?;
        let max_bytes: u64 = 4 * 1024 * 1024;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), max_bytes);

        let big = vec![b'x'; 3 * 1024 * 1024];
        let (status, _body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some(&big.len().to_string()),
                Some(&sign(&secret, &big)),
                None,
                big.clone(),
            )
            .await?,
        )
        .await?;
        assert_eq!(status, StatusCode::ACCEPTED);
        let (_name, stored) = spooled_delivery(root.path(), &webhook_id).await?;
        assert_eq!(stored.len(), big.len());
        Ok(())
    }

    #[tokio::test]
    async fn http_enabled_webhook_policy_is_dispatched_on_delivery() -> HttpResult {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        let (source_id, webhook_id, secret) = create_source(&config, &ctx, true)?;
        // An ENABLED webhook policy that references the delivered source.
        config.save_policy(policy_input(vec![source_id], true), &ctx)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        // Capture the trigger runtime's dispatch decision. `fire_for_webhook` emits
        // this the instant it selects a referencing enabled policy — a direct,
        // observable signal that the delivery dispatched.
        let messages = capture::Messages::default();
        let guard = tracing_subscriber::registry()
            .with(messages.clone())
            .set_default();

        let (status, body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some(&BODY.len().to_string()),
                Some(&sign(&secret, BODY)),
                Some("invoice.pdf"),
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        drop(guard);

        assert_eq!(status, StatusCode::ACCEPTED);
        let payload: Value = serde_json::from_slice(&body)?;
        assert_eq!(payload["filename"], Value::String("invoice.pdf".to_owned()));
        // Delivery was spooled AND dispatched to the referencing policy.
        let (_name, stored) = spooled_delivery(root.path(), &webhook_id).await?;
        assert_eq!(stored, BODY);
        assert!(
            messages.contains("saw a delivery"),
            "an enabled referencing policy must be dispatched"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_disabled_webhook_policy_spools_without_dispatch() -> HttpResult {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        let root = tempfile::tempdir()?;
        let (config, store, ctx) = config_env()?;
        // The SOURCE stays enabled (so the delivery is accepted) but the POLICY is
        // disabled — the receiver still spools, but nothing must be dispatched.
        let (source_id, webhook_id, secret) = create_source(&config, &ctx, true)?;
        config.save_policy(policy_input(vec![source_id], false), &ctx)?;
        let app = receiver_app(&config, &store, root.path().to_path_buf(), 1024);

        let messages = capture::Messages::default();
        let guard = tracing_subscriber::registry()
            .with(messages.clone())
            .set_default();

        let (status, _body) = status_and_body(
            deliver(
                &app,
                &webhook_id,
                Some(&BODY.len().to_string()),
                Some(&sign(&secret, BODY)),
                None,
                BODY.to_vec(),
            )
            .await?,
        )
        .await?;
        drop(guard);

        assert_eq!(status, StatusCode::ACCEPTED);
        // Still spooled...
        let (_name, stored) = spooled_delivery(root.path(), &webhook_id).await?;
        assert_eq!(stored, BODY);
        // ...but a disabled policy is excluded from the fan-out, so no dispatch.
        assert!(
            !messages.contains("saw a delivery"),
            "a disabled policy must never be dispatched"
        );
        Ok(())
    }

    /// A minimal `tracing` layer that records event messages into a shared buffer,
    /// so a test can assert whether `fire_for_webhook` dispatched a delivery.
    mod capture {
        use std::fmt;
        use std::sync::{Arc, Mutex};

        use tracing::field::{Field, Visit};
        use tracing::{Event, Subscriber};
        use tracing_subscriber::layer::{Context, Layer};

        #[derive(Clone, Default)]
        pub(super) struct Messages {
            seen: Arc<Mutex<Vec<String>>>,
        }

        impl Messages {
            pub(super) fn contains(&self, needle: &str) -> bool {
                match self.seen.lock() {
                    Ok(seen) => seen.iter().any(|message| message.contains(needle)),
                    Err(_poisoned) => false,
                }
            }
        }

        struct MessageVisitor<'a> {
            message: &'a mut String,
        }

        impl Visit for MessageVisitor<'_> {
            fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
                if field.name() == "message" {
                    use fmt::Write as _;
                    let _write_result = write!(self.message, "{value:?}");
                }
            }
        }

        impl<S: Subscriber> Layer<S> for Messages {
            fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
                let mut message = String::new();
                event.record(&mut MessageVisitor {
                    message: &mut message,
                });
                if message.is_empty() {
                    return;
                }
                if let Ok(mut seen) = self.seen.lock() {
                    seen.push(message);
                }
            }
        }
    }

    // FINDING #2 (DoS): the body assemble step must be bounded in time so a
    // slowloris cannot hold a connection open while dribbling bytes toward the
    // webhook size limit ahead of the HMAC check.
    #[tokio::test]
    async fn assemble_body_aborts_a_stalled_stream() {
        use std::time::Duration;

        use futures_util::stream;

        // A body that yields no frames and never completes models a client that
        // opens the connection and then stalls. With a real per-frame timeout it
        // errors; the assemble ceiling guarantees it cannot hang the handler.
        let body = Body::from_stream(stream::pending::<Result<Bytes, std::io::Error>>());
        let outcome = assemble_body(body, 1_024, Duration::from_millis(50)).await;
        assert!(matches!(outcome, BodyAssembly::TimedOut));
    }

    #[tokio::test]
    async fn assemble_body_returns_a_prompt_body_within_the_ceiling() {
        use std::time::Duration;

        let body = Body::from(vec![1_u8, 2, 3, 4]);
        let outcome = assemble_body(body, 1_024, Duration::from_secs(5)).await;
        match outcome {
            BodyAssembly::Body(bytes) => assert_eq!(&bytes[..], &[1, 2, 3, 4]),
            other => panic!("expected a buffered body, got {}", assembly_label(&other)),
        }
    }

    #[tokio::test]
    async fn assemble_body_rejects_a_body_over_the_declared_cap() {
        use std::time::Duration;

        // Ten bytes offered against a four-byte declared cap: the over-declared
        // body is rejected before any signature work, exactly as `to_bytes` caps.
        let body = Body::from(vec![0_u8; 10]);
        let outcome = assemble_body(body, 4, Duration::from_secs(5)).await;
        assert!(matches!(outcome, BodyAssembly::TooLong));
    }

    fn assembly_label(outcome: &BodyAssembly) -> &'static str {
        match outcome {
            BodyAssembly::Body(_) => "Body",
            BodyAssembly::TooLong => "TooLong",
            BodyAssembly::TimedOut => "TimedOut",
        }
    }
}
