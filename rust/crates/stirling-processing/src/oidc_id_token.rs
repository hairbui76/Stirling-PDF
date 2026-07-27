//! OIDC ID-token verification: the slice that finally turns the token
//! exchange's opaque `id_token` string (see [`crate::oidc_token`] /
//! [`crate::oidc_live_token`]) into a typed, *verified* identity.
//!
//! # Sibling to, not a fork of, the Supabase verifier
//!
//! This deliberately mirrors [`crate::security_jwt`]'s Supabase bearer-JWT
//! verifier for the shared JWT rigor — the same `jsonwebtoken` wiring
//! ([`decode_header`] to pick a key/algorithm, a public-key-only algorithm
//! allowlist, [`DecodingKey::from_jwk`], a [`Validation`] configured for
//! issuer/audience/expiry, and a `with_jwks`-style test seam) — but is a
//! separate module, not a modification of it, because the two are genuinely
//! different verifiers:
//!
//! - **Discovery-driven JWKS.** Supabase hardcodes its JWKS URL to
//!   `{issuer}/.well-known/jwks.json`; a generic OIDC provider advertises an
//!   arbitrary `jwks_uri` in its discovery document, which is
//!   *provider-controlled* and therefore fetched through
//!   [`crate::oidc_live_token`]'s SSRF-safe resolve-and-pin GET.
//! - **Different claims.** An OIDC ID token's claims
//!   (`OpenID` Connect Core 1.0 section 2) are nothing like `SupabaseClaims`.
//! - **The `nonce` check Supabase lacks.** An OIDC ID token carries a `nonce`
//!   claim that MUST equal the `nonce` this login generated in
//!   [`crate::oidc_authorization`] (replay/CSRF binding). `jsonwebtoken` treats
//!   `nonce` as an ordinary, non-registered claim and does *not* validate it, so
//!   this module checks it explicitly.
//!
//! # What is verified
//!
//! Given the discovered [`OidcProviderMetadata`] (for `jwks_uri` + `issuer`),
//! the `client_id`, the `expected_nonce` from
//! [`crate::oidc_authorization::OidcAuthorizationRequest`], and the raw
//! `id_token`, [`verify_oidc_id_token`]:
//!
//! 1. fetches the JWKS from `provider.jwks_uri` via the SSRF-safe GET;
//! 2. selects the signing key by the token header's `kid` and rejects any
//!    non-public-key algorithm **before** decoding — the public-key-only
//!    allowlist is what prevents the classic `alg=HS256`-against-an-RSA-public-key
//!    confusion bypass (an attacker HMAC-signing with the public key bytes);
//! 3. verifies the signature and that `iss` == `provider.issuer` (exact),
//!    `client_id` is in `aud`, and `exp` is not past (with the same leeway
//!    convention as [`crate::security_jwt`]);
//! 4. requires the `nonce` claim to be present and equal to `expected_nonce`;
//! 5. returns a typed [`VerifiedOidcIdentity`].
//!
//! # Scope
//!
//! Library functions only. [`verify_oidc_id_token`] fetches the JWKS per
//! verification; the callback route goes through
//! [`verify_oidc_id_token_cached`] and an [`OidcJwksCache`] — a bounded TTL
//! cache modeled on [`crate::oidc_discovery::OidcDiscoveryCache`]'s shape
//! (`Mutex<HashMap>`, fetch outside the lock, retain-unexpired admission,
//! poisoned-lock degrades to uncached) plus [`crate::security_jwt`]'s
//! kid-miss-triggered refresh under a per-entry cooldown, so a signing-key
//! rotation is picked up promptly while a fabricated `kid` cannot amplify
//! outbound fetches. There is no callback route, no session creation, and no
//! `state`/`nonce` *persistence* here — the caller supplies the
//! `expected_nonce` it stored when it built the authorization request.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, DecodingKey, Header, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use serde::Deserialize;
use subtle::ConstantTimeEq as _;
use thiserror::Error;

use crate::{oidc_discovery::OidcProviderMetadata, oidc_live_token::ssrf_safe_get};

/// Upper bound on the raw compact JWT, mirroring [`crate::security_jwt`].
const MAX_JWT_BYTES: usize = 16 * 1024;
/// JWKS response-body cap, matching [`crate::security_jwt`]'s `MAX_JWKS_BYTES`.
const MAX_JWKS_RESPONSE_BYTES: u64 = 256 * 1024;
/// Ceiling on the number of keys in a JWKS, mirroring [`crate::security_jwt`].
const MAX_JWKS_KEYS: usize = 32;
/// Ceiling on a key id, mirroring [`crate::security_jwt`].
const MAX_KEY_ID_BYTES: usize = 128;
/// `OpenID` Connect Core 1.0 section 2 caps `sub` at 255 ASCII characters.
const MAX_SUBJECT_BYTES: usize = 255;
/// Ceiling on the `nonce` claim; the tokens this codebase issues are 43-char
/// base64url, so 512 is generous headroom while bounding a hostile value.
const MAX_NONCE_BYTES: usize = 512;
/// Ceiling on the `sid` claim, matching `security.rs`'s
/// `MAX_EXTERNAL_SESSION_ID_BYTES` so a value that verifies here also fits the
/// external-identity session-id bound a downstream login flow enforces.
const MAX_SID_BYTES: usize = 256;
/// Ceiling on an email claim, mirroring [`crate::security_jwt`].
const MAX_EMAIL_BYTES: usize = 320;
/// Generic ceiling for the optional human-readable string claims.
const MAX_CLAIM_BYTES: usize = 1_024;
/// Clock-skew leeway for `exp`, matching [`crate::security_jwt`]'s explicit
/// leeway convention (and `jsonwebtoken`'s own default).
const CLOCK_SKEW_SECONDS: u64 = 60;
/// Lifetime of a cached JWKS entry in [`OidcJwksCache`], matching the discovery
/// cache's TTL and [`crate::security_jwt`]'s default `jwks_cache_seconds` (both
/// 5 minutes): staleness after an un-signalled key rotation is bounded by this,
/// and the kid-miss refresh below usually picks a rotation up sooner.
const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
/// Cap on distinct `jwks_uri` entries held in an [`OidcJwksCache`], matching
/// the discovery cache's bound. The key comes from admin-trusted discovery
/// metadata, never request input, so a full cache degrades to uncached fetches
/// rather than needing eviction.
const DEFAULT_JWKS_CACHE_MAX_ENTRIES: usize = 64;
/// Minimum interval between kid-miss-triggered refreshes of one cache entry,
/// mirroring [`crate::security_jwt`]'s `MIN_REFRESH_INTERVAL` idea: a genuine
/// key rotation (a fresh `kid` signed by the provider) refreshes at most once
/// per cooldown, so an attacker fabricating `kid` values cannot turn each
/// callback into an outbound JWKS fetch.
const DEFAULT_JWKS_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

/// A verified OIDC end-user identity — every field below has passed signature,
/// `iss`, `aud`, `exp`, and `nonce` verification. Typed, never a raw JSON value,
/// so a caller wiring up a session can't accidentally trust an unverified claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedOidcIdentity {
    /// The provider's issuer identifier (`iss`), equal to `provider.issuer`.
    pub issuer: String,
    /// The stable, provider-scoped subject identifier (`sub`).
    pub subject: String,
    /// The audience this token was verified against — the `client_id`.
    pub audience: String,
    /// The end-user's email (`email`), lowercased, if present and well-formed.
    pub email: Option<String>,
    /// The provider's `email_verified` flag, if present.
    pub email_verified: Option<bool>,
    /// The end-user's display name (`name`), if present.
    pub name: Option<String>,
    /// The end-user's preferred username (`preferred_username`), if present.
    pub preferred_username: Option<String>,
    /// The provider's session identifier (`sid`, `OpenID` Connect Core 1.0 /
    /// Session Management), if present. A login flow may adopt this as the
    /// external session id it records rather than minting a fresh one.
    pub sid: Option<String>,
    /// Issued-at (`iat`) as a Unix timestamp.
    pub issued_at: u64,
    /// Expiry (`exp`) as a Unix timestamp.
    pub expires_at: u64,
}

/// Why an ID-token verification failed. Signature/`iss`/`aud`/`exp` failures are
/// collapsed into one generic [`InvalidToken`](OidcIdTokenError::InvalidToken)
/// (fail-closed, no oracle about *which* check failed, matching
/// [`crate::security_jwt`]). A [`NonceMismatch`](OidcIdTokenError::NonceMismatch)
/// is kept distinct: it is a server-side signal a caller may want to log as a
/// possible cross-session replay, and reaching it already requires a fully valid
/// signature + `iss`/`aud`/`exp` for *this* client, so it is not a useful
/// attacker oracle.
#[derive(Debug, Error)]
pub enum OidcIdTokenError {
    /// The JWKS could not be fetched (unreachable, blocked by the SSRF guard,
    /// over the size cap, or a non-2xx response).
    #[error("OIDC JWKS is unavailable")]
    JwksUnavailable,
    /// The fetched JWKS was not a valid, non-empty, public-key key set.
    #[error("OIDC JWKS is invalid")]
    InvalidJwks,
    /// The ID token was malformed, unsigned, wrongly-signed, used a disallowed
    /// algorithm, or failed `iss`/`aud`/`exp`/claim validation.
    #[error("OIDC ID token is invalid")]
    InvalidToken,
    /// The ID token's `nonce` claim was absent or did not equal the expected
    /// nonce for this login.
    #[error("OIDC ID token nonce does not match")]
    NonceMismatch,
}

/// Verifies a raw `id_token` against `provider`'s live JWKS and returns a typed
/// [`VerifiedOidcIdentity`].
///
/// Fetches `provider.jwks_uri` through [`crate::oidc_live_token`]'s SSRF-safe
/// GET, then performs the full verification described in the module docs,
/// including the OIDC-specific `nonce` equality check against `expected_nonce`.
///
/// # Errors
///
/// Returns [`OidcIdTokenError::JwksUnavailable`] if the JWKS can't be fetched
/// (including when the SSRF guard blocks a `jwks_uri` that resolves into a
/// reserved range), [`OidcIdTokenError::InvalidJwks`] for a malformed key set,
/// [`OidcIdTokenError::InvalidToken`] for any signature/`iss`/`aud`/`exp`/claim
/// failure or a disallowed algorithm, and [`OidcIdTokenError::NonceMismatch`]
/// when the `nonce` claim is missing or unequal.
pub fn verify_oidc_id_token(
    provider: &OidcProviderMetadata,
    client_id: &str,
    expected_nonce: &str,
    id_token: &str,
) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
    let jwks = fetch_jwks(&provider.jwks_uri)?;
    verify_id_token_with_jwks(provider, client_id, expected_nonce, id_token, &jwks)
}

/// One cached key set and when it was fetched (both TTL expiry and the kid-miss
/// refresh cooldown are measured from `fetched_at`).
struct CachedJwks {
    set: JwkSet,
    fetched_at: Instant,
}

/// Bounded, TTL'd cache of fetched [`JwkSet`]s, keyed by `jwks_uri`, combining
/// the two in-repo caching models:
///
/// - the [`crate::oidc_discovery::OidcDiscoveryCache`] shape — `Mutex<HashMap>`
///   with a TTL and an entry cap, the network fetch performed **outside** the
///   lock, retain-unexpired admission on store, and a poisoned lock degrading
///   to uncached fetching rather than failing verification; and
/// - [`crate::security_jwt`]'s kid-miss-triggered refresh — a token whose `kid`
///   is not in the fresh cached set forces one early refetch (a genuine key
///   rotation is picked up before the TTL runs out), but at most once per
///   [`DEFAULT_JWKS_REFRESH_COOLDOWN`] per entry, so a flood of fabricated
///   `kid`s cannot amplify into an outbound fetch per callback.
///
/// **Caching never weakens verification.** Only sets that already passed
/// [`validate_jwks`] are stored (the fetch path validates before returning),
/// and every signature/claim check still runs per token against whichever set
/// is served. Built once and shared behind an `Arc` for the lifetime of the
/// secured router, like the discovery cache and login-state store beside it.
pub struct OidcJwksCache {
    ttl: Duration,
    max_entries: usize,
    refresh_cooldown: Duration,
    entries: Mutex<HashMap<String, CachedJwks>>,
}

impl Default for OidcJwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcJwksCache {
    /// A cache with the default [`DEFAULT_JWKS_CACHE_TTL`],
    /// [`DEFAULT_JWKS_CACHE_MAX_ENTRIES`], and
    /// [`DEFAULT_JWKS_REFRESH_COOLDOWN`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl_capacity_and_cooldown(
            DEFAULT_JWKS_CACHE_TTL,
            DEFAULT_JWKS_CACHE_MAX_ENTRIES,
            DEFAULT_JWKS_REFRESH_COOLDOWN,
        )
    }

    /// A cache with explicit knobs — a test seam (zero TTL disables caching, a
    /// zero cooldown makes every kid miss refresh, a tiny capacity exercises
    /// the bound) as much as a deployment tuning point.
    #[must_use]
    pub fn with_ttl_capacity_and_cooldown(
        ttl: Duration,
        max_entries: usize,
        refresh_cooldown: Duration,
    ) -> Self {
        Self {
            ttl,
            max_entries,
            refresh_cooldown,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns a validated key set for `jwks_uri` suitable for looking up
    /// `kid`: a live cached copy when it is fresh and either contains `kid` or
    /// is inside the kid-miss refresh cooldown; otherwise the result of a fresh
    /// `fetch` (cached for the next caller). The returned set is *not*
    /// guaranteed to contain `kid` — a bogus `kid` inside the cooldown is
    /// served the cached set and fails key selection in the caller, which is
    /// exactly the no-amplification behaviour.
    ///
    /// # Errors
    ///
    /// Propagates the `fetch` error when a fetch was needed and failed. A
    /// poisoned cache lock is *not* fatal: the set is fetched uncached instead.
    fn jwks_for(
        &self,
        jwks_uri: &str,
        kid: &str,
        fetch: impl Fn(&str) -> Result<JwkSet, OidcIdTokenError>,
    ) -> Result<JwkSet, OidcIdTokenError> {
        if let Some(cached) = self.cached_set_for(jwks_uri, kid) {
            return Ok(cached);
        }
        // Miss, expiry, or a cooldown-cleared kid miss: fetch OUTSIDE the lock
        // (blocking network I/O), then admit the validated result.
        let set = fetch(jwks_uri)?;
        self.store(jwks_uri, &set);
        Ok(set)
    }

    /// The cached set to serve without fetching, if any: fresh AND (contains
    /// `kid` OR its kid-miss refresh is still cooling down). A poisoned lock is
    /// treated as a miss (degrade to uncached).
    fn cached_set_for(&self, jwks_uri: &str, kid: &str) -> Option<JwkSet> {
        let entries = self.entries.lock().ok()?;
        let cached = entries.get(jwks_uri)?;
        let now = Instant::now();
        if now.duration_since(cached.fetched_at) >= self.ttl {
            return None;
        }
        let kid_present = cached.set.find(kid).is_some();
        let refresh_allowed = now.duration_since(cached.fetched_at) >= self.refresh_cooldown;
        (kid_present || !refresh_allowed).then(|| cached.set.clone())
    }

    /// Records a freshly fetched, already-validated set under `jwks_uri`,
    /// stamping `fetched_at` and opportunistically dropping expired entries
    /// first. At capacity a *new* URI is simply not admitted (the next lookup
    /// re-fetches); refreshing an existing entry is always allowed since it
    /// does not grow the map. A poisoned lock is a no-op (uncached).
    fn store(&self, jwks_uri: &str, set: &JwkSet) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        let ttl = self.ttl;
        entries.retain(|_, cached| now.duration_since(cached.fetched_at) < ttl);
        if entries.contains_key(jwks_uri) || entries.len() < self.max_entries {
            entries.insert(
                jwks_uri.to_owned(),
                CachedJwks {
                    set: set.clone(),
                    fetched_at: now,
                },
            );
        }
    }
}

/// [`verify_oidc_id_token`] with the JWKS resolved through `cache` instead of
/// fetched per call — the path the OIDC callback route uses. The token's shape,
/// algorithm, and `kid` are validated **before** the cache is consulted, so a
/// malformed or disallowed token can never trigger an outbound fetch.
///
/// # Errors
///
/// Exactly as [`verify_oidc_id_token`]; a `kid` absent from the (possibly
/// cooldown-served) key set surfaces as [`OidcIdTokenError::InvalidToken`].
pub fn verify_oidc_id_token_cached(
    cache: &OidcJwksCache,
    provider: &OidcProviderMetadata,
    client_id: &str,
    expected_nonce: &str,
    id_token: &str,
) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
    verify_oidc_id_token_cached_with_fetch(
        cache,
        provider,
        client_id,
        expected_nonce,
        id_token,
        fetch_jwks,
    )
}

/// [`verify_oidc_id_token_cached`] with the JWKS fetch injected, so tests can
/// drive the cache's hit/refresh/cooldown behaviour with a counting stub
/// instead of a live endpoint — the same injection seam pattern as
/// [`crate::oidc_live_token`]'s resolver. Production always passes
/// [`fetch_jwks`].
fn verify_oidc_id_token_cached_with_fetch(
    cache: &OidcJwksCache,
    provider: &OidcProviderMetadata,
    client_id: &str,
    expected_nonce: &str,
    id_token: &str,
    fetch: impl Fn(&str) -> Result<JwkSet, OidcIdTokenError>,
) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
    // The same fail-closed pre-checks verify_id_token_with_jwks runs, applied
    // BEFORE any cache/network interaction (they are re-run afterwards inside
    // it; both orderings must hold, so the shared helpers keep them identical).
    if expected_nonce.is_empty() || expected_nonce.len() > MAX_NONCE_BYTES {
        return Err(OidcIdTokenError::NonceMismatch);
    }
    let (_, kid) = validated_header_and_kid(id_token)?;
    let jwks = cache.jwks_for(&provider.jwks_uri, &kid, fetch)?;
    verify_id_token_with_jwks(provider, client_id, expected_nonce, id_token, &jwks)
}

/// Fetches and validates the provider's JWKS via the SSRF-safe GET.
fn fetch_jwks(jwks_uri: &str) -> Result<JwkSet, OidcIdTokenError> {
    // Every fetch failure — unreachable, timeout, over-cap, and crucially the
    // SSRF BlockedAddress rejection — collapses to JwksUnavailable (fail-closed;
    // no distinction leaked about why the provider-controlled URL was refused).
    let (status, body) = ssrf_safe_get(jwks_uri, MAX_JWKS_RESPONSE_BYTES)
        .map_err(|_| OidcIdTokenError::JwksUnavailable)?;
    if !(200..300).contains(&status) {
        return Err(OidcIdTokenError::JwksUnavailable);
    }
    let set: JwkSet = serde_json::from_slice(&body).map_err(|_| OidcIdTokenError::InvalidJwks)?;
    validate_jwks(&set)?;
    Ok(set)
}

/// The `with_jwks`-style seam: the full verification given an already-obtained
/// [`JwkSet`], with no network call. [`verify_oidc_id_token`] calls it after
/// fetching the JWKS; tests call it directly with an injected set and a
/// self-signed token.
fn verify_id_token_with_jwks(
    provider: &OidcProviderMetadata,
    client_id: &str,
    expected_nonce: &str,
    id_token: &str,
    jwks: &JwkSet,
) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
    // Fail closed on a caller that supplies no nonce to check against, so a
    // token with no nonce can never "match" an empty expectation.
    if expected_nonce.is_empty() || expected_nonce.len() > MAX_NONCE_BYTES {
        return Err(OidcIdTokenError::NonceMismatch);
    }
    let (header, kid) = validated_header_and_kid(id_token)?;
    let jwk = jwks.find(&kid).ok_or(OidcIdTokenError::InvalidToken)?;
    validate_jwk(jwk, header.alg)?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| OidcIdTokenError::InvalidToken)?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = CLOCK_SKEW_SECONDS;
    validation.set_issuer(&[provider.issuer.as_str()]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    let claims = decode::<OidcIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| OidcIdTokenError::InvalidToken)?
        .claims;

    // The OIDC check `jsonwebtoken` does not do: the `nonce` must be present,
    // bounded, and equal (constant-time) to the nonce this login generated.
    match claims.nonce.as_deref() {
        Some(nonce) if nonce.len() <= MAX_NONCE_BYTES && nonce_matches(nonce, expected_nonce) => {}
        _ => return Err(OidcIdTokenError::NonceMismatch),
    }

    claims.into_identity(client_id)
}

/// The subset of an OIDC ID token's claims this verifier reads. `iss`/`sub`/
/// `exp`/`iat` are required (a missing one fails deserialization → rejection);
/// `aud` is validated by `jsonwebtoken` itself, so it is not deserialized here.
#[derive(Deserialize)]
struct OidcIdTokenClaims {
    iss: String,
    sub: String,
    exp: u64,
    iat: u64,
    #[serde(default)]
    nonce: Option<String>,
    /// Authorized party (`OpenID` Connect Core 1.0 section 2). When present it
    /// MUST be the `client_id`; a mismatch means the token's primary audience is
    /// a different client.
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    sid: Option<String>,
}

impl OidcIdTokenClaims {
    /// Applies the OIDC-specific claim sanity checks `jsonwebtoken` doesn't
    /// cover and builds the typed identity. `iss`/`aud`/`exp` were already
    /// verified by `jsonwebtoken`; `client_id` is passed so `azp` and the
    /// returned audience are exact.
    fn into_identity(self, client_id: &str) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
        let now = u64::try_from(chrono::Utc::now().timestamp())
            .map_err(|_| OidcIdTokenError::InvalidToken)?;
        if self.exp <= self.iat
            || self.iat > now.saturating_add(CLOCK_SKEW_SECONDS)
            || !bounded_claim(&self.sub, MAX_SUBJECT_BYTES)
            || self.azp.as_deref().is_some_and(|azp| azp != client_id)
        {
            return Err(OidcIdTokenError::InvalidToken);
        }
        let email = self
            .email
            .map(|email| email.trim().to_lowercase())
            .filter(|email| !email.is_empty());
        if email
            .as_deref()
            .is_some_and(|email| !valid_email_claim(email))
        {
            return Err(OidcIdTokenError::InvalidToken);
        }
        Ok(VerifiedOidcIdentity {
            issuer: self.iss,
            subject: self.sub,
            audience: client_id.to_owned(),
            email,
            email_verified: self.email_verified,
            name: bounded_optional(self.name, MAX_CLAIM_BYTES)?,
            preferred_username: bounded_optional(self.preferred_username, MAX_CLAIM_BYTES)?,
            sid: bounded_optional(self.sid, MAX_SID_BYTES)?,
            issued_at: self.iat,
            expires_at: self.exp,
        })
    }
}

/// Shape-validates the raw compact JWT and returns its decoded header plus the
/// bounded `kid`, applying the alg-confusion defense: anything that is not a
/// public-key signature algorithm — critically `alg=HS256`/`HS384`/`HS512` — is
/// rejected here, BEFORE a `Validation` is built, a key is selected, or (on the
/// cached path) the cache/network is touched. Shared by
/// [`verify_id_token_with_jwks`] and [`verify_oidc_id_token_cached_with_fetch`]
/// so the two paths' pre-key gates cannot drift apart.
fn validated_header_and_kid(id_token: &str) -> Result<(Header, String), OidcIdTokenError> {
    validate_token_shape(id_token)?;
    let header = decode_header(id_token).map_err(|_| OidcIdTokenError::InvalidToken)?;
    if !algorithm_is_allowed(header.alg)
        || header
            .typ
            .as_deref()
            .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("JWT"))
    {
        return Err(OidcIdTokenError::InvalidToken);
    }
    let kid = header
        .kid
        .as_deref()
        .filter(|kid| !kid.is_empty() && kid.len() <= MAX_KEY_ID_BYTES)
        .ok_or(OidcIdTokenError::InvalidToken)?
        .to_owned();
    Ok((header, kid))
}

/// Constant-time `nonce` equality. The nonce is single-use and server-stored, so
/// a timing side-channel is not a realistic oracle here, but a constant-time
/// compare (over equal-length inputs) is cheap defense-in-depth.
fn nonce_matches(actual: &str, expected: &str) -> bool {
    let (actual, expected) = (actual.as_bytes(), expected.as_bytes());
    actual.len() == expected.len() && actual.ct_eq(expected).into()
}

/// The public-key-only algorithm allowlist. Deliberately identical to
/// [`crate::security_jwt`]'s: it admits RSA (PKCS#1 v1.5 and PSS), ECDSA, and
/// `EdDSA`, and — critically — **no HMAC family**. An `alg=HS256`/`HS384`/`HS512`
/// header is rejected here, before any key is selected or `Validation` is built,
/// which is the primary defense against the alg-confusion bypass where an
/// attacker HMAC-signs a token using an RSA/EC public key's bytes as the secret.
fn algorithm_is_allowed(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

/// Rejects a JWT that is empty, over-long, non-ASCII, whitespace-bearing, or not
/// exactly three dot-separated segments. Mirrors [`crate::security_jwt`].
fn validate_token_shape(token: &str) -> Result<(), OidcIdTokenError> {
    if token.is_empty()
        || token.len() > MAX_JWT_BYTES
        || !token.is_ascii()
        || token.bytes().filter(|byte| *byte == b'.').count() != 2
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(OidcIdTokenError::InvalidToken);
    }
    Ok(())
}

/// Rejects a selected JWK that is symmetric, or whose declared use/operations/
/// algorithm are incompatible with verifying a signature with `algorithm`.
/// Mirrors [`crate::security_jwt`].
fn validate_jwk(jwk: &Jwk, algorithm: Algorithm) -> Result<(), OidcIdTokenError> {
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_))
        || jwk
            .common
            .public_key_use
            .as_ref()
            .is_some_and(|key_use| key_use != &PublicKeyUse::Signature)
        || jwk
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
        || jwk
            .common
            .key_algorithm
            .is_some_and(|key_algorithm| key_algorithm.to_string() != format!("{algorithm:?}"))
    {
        return Err(OidcIdTokenError::InvalidToken);
    }
    Ok(())
}

/// Rejects an empty, oversized, symmetric-key-bearing, or duplicate-`kid` key
/// set. Mirrors [`crate::security_jwt`].
fn validate_jwks(set: &JwkSet) -> Result<(), OidcIdTokenError> {
    if set.keys.is_empty() || set.keys.len() > MAX_JWKS_KEYS {
        return Err(OidcIdTokenError::InvalidJwks);
    }
    let mut key_ids = std::collections::BTreeSet::new();
    for key in &set.keys {
        let key_id = key
            .common
            .key_id
            .as_deref()
            .filter(|key_id| !key_id.is_empty() && key_id.len() <= MAX_KEY_ID_BYTES)
            .ok_or(OidcIdTokenError::InvalidJwks)?;
        if !key_ids.insert(key_id) || matches!(key.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(OidcIdTokenError::InvalidJwks);
        }
    }
    Ok(())
}

/// A non-empty string bounded in length and free of control characters.
fn bounded_claim(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

/// Trims an optional string claim, dropping it if empty and rejecting it if it
/// exceeds `max_bytes` or carries control characters.
fn bounded_optional(
    value: Option<String>,
    max_bytes: usize,
) -> Result<Option<String>, OidcIdTokenError> {
    match value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    {
        Some(value) if !bounded_claim(&value, max_bytes) => Err(OidcIdTokenError::InvalidToken),
        other => Ok(other),
    }
}

/// A minimally well-formed email claim: bounded, with a non-empty local part and
/// a dotted domain. Mirrors [`crate::security_jwt`].
fn valid_email_claim(email: &str) -> bool {
    bounded_claim(email, MAX_EMAIL_BYTES)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde::Serialize;

    use super::{
        OidcIdTokenError, OidcJwksCache, VerifiedOidcIdentity, algorithm_is_allowed, validate_jwks,
        verify_id_token_with_jwks, verify_oidc_id_token_cached_with_fetch,
    };
    use crate::oidc_discovery::OidcProviderMetadata;

    const ISSUER: &str = "https://issuer.example.com";
    const CLIENT_ID: &str = "test-client-id";
    const NONCE: &str = "the-expected-login-nonce-value-000000000000";
    const KID: &str = "oidc-test-key";

    /// `aud` serialized as a single string or an array, so a test can exercise
    /// both the `Single` and `Multiple` audience shapes.
    #[derive(Serialize)]
    #[serde(untagged)]
    enum Aud<'a> {
        Single(&'a str),
        Multiple(Vec<&'a str>),
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: Aud<'a>,
        exp: u64,
        iat: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        azp: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email_verified: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sid: Option<&'a str>,
    }

    fn now_secs() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default()
    }

    /// A baseline set of valid claims each test tweaks one field of.
    fn valid_claims() -> TestClaims<'static> {
        let now = now_secs();
        TestClaims {
            iss: ISSUER,
            sub: "oidc-subject-123",
            aud: Aud::Single(CLIENT_ID),
            exp: now + 300,
            iat: now,
            nonce: Some(NONCE),
            azp: None,
            email: Some("User@Example.Test"),
            email_verified: Some(true),
            name: Some("Test User"),
            sid: None,
        }
    }

    fn provider() -> OidcProviderMetadata {
        OidcProviderMetadata {
            issuer: ISSUER.to_owned(),
            authorization_endpoint: format!("{ISSUER}/authorize"),
            token_endpoint: format!("{ISSUER}/token"),
            jwks_uri: format!("{ISSUER}/jwks.json"),
        }
    }

    struct Fixture {
        jwks: JwkSet,
        encoding_key: EncodingKey,
        /// The RSA public modulus bytes — the material an attacker would use as
        /// the HMAC secret in the alg-confusion forgery.
        public_modulus: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let private_key = RsaPrivateKey::new(&mut rand::rng(), 2_048)?;
            let public_key = private_key.to_public_key();
            let private_der = private_key.to_pkcs1_der()?;
            let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());
            let modulus = minimal_unsigned_bytes(public_key.n().to_bytes(ByteOrder::BigEndian));
            let exponent = minimal_unsigned_bytes(public_key.e().to_bytes(ByteOrder::BigEndian));
            let jwks: JwkSet = serde_json::from_value(serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "kid": KID,
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&modulus),
                    "e": URL_SAFE_NO_PAD.encode(exponent)
                }]
            }))?;
            Ok(Self {
                jwks,
                encoding_key,
                public_modulus: modulus,
            })
        }

        fn sign(&self, claims: &TestClaims) -> Result<String, jsonwebtoken::errors::Error> {
            self.sign_rs256_with_kid(KID, claims)
        }

        fn sign_rs256_with_kid(
            &self,
            kid: &str,
            claims: &TestClaims,
        ) -> Result<String, jsonwebtoken::errors::Error> {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(kid.to_owned());
            encode(&header, claims, &self.encoding_key)
        }

        fn verify(&self, token: &str) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
            verify_id_token_with_jwks(&provider(), CLIENT_ID, NONCE, token, &self.jwks)
        }
    }

    // ---- happy path --------------------------------------------------------

    #[test]
    fn verifies_a_fully_valid_id_token() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.sign(&valid_claims())?;
        let identity = fixture.verify(&token)?;
        assert_eq!(identity.issuer, ISSUER);
        assert_eq!(identity.subject, "oidc-subject-123");
        assert_eq!(identity.audience, CLIENT_ID);
        assert_eq!(identity.email.as_deref(), Some("user@example.test"));
        assert_eq!(identity.email_verified, Some(true));
        assert_eq!(identity.name.as_deref(), Some("Test User"));
        // No `sid` claim in the baseline token, so it is absent.
        assert_eq!(identity.sid, None);
        Ok(())
    }

    #[test]
    fn extracts_the_optional_sid_session_claim() -> Result<(), Box<dyn std::error::Error>> {
        // A provider that participates in OIDC session management sends `sid`;
        // it must be extracted (bounded) so a downstream login flow can adopt it
        // as the external session id rather than minting a fresh one.
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.sid = Some("provider-session-42");
        let token = fixture.sign(&claims)?;
        let identity = fixture.verify(&token)?;
        assert_eq!(identity.sid.as_deref(), Some("provider-session-42"));
        Ok(())
    }

    #[test]
    fn accepts_an_audience_array_that_contains_the_client_id()
    -> Result<(), Box<dyn std::error::Error>> {
        // Multi-audience is legal; membership of client_id is what matters, and
        // OIDC then recommends azp — set correctly here.
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.aud = Aud::Multiple(vec![CLIENT_ID, "https://some-other-resource"]);
        claims.azp = Some(CLIENT_ID);
        let token = fixture.sign(&claims)?;
        assert!(fixture.verify(&token).is_ok());
        Ok(())
    }

    // ---- signature / key selection ----------------------------------------

    #[test]
    fn rejects_a_token_with_a_tampered_signature() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut token = fixture.sign(&valid_claims())?;
        token.push('x');
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_token_signed_by_a_different_key_with_a_known_kid()
    -> Result<(), Box<dyn std::error::Error>> {
        // A token whose header claims the JWKS's kid but was signed by a
        // DIFFERENT private key: proves the signature is actually checked
        // against the key the kid selects, not merely that a kid is present.
        let fixture = Fixture::new()?;
        let attacker = Fixture::new()?;
        let token = attacker.sign_rs256_with_kid(KID, &valid_claims())?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_token_whose_kid_is_not_in_the_jwks() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.sign_rs256_with_kid("unknown-kid", &valid_claims())?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    // ---- iss / aud / exp ---------------------------------------------------

    #[test]
    fn rejects_a_token_with_the_wrong_issuer() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.iss = "https://evil.example.com";
        let token = fixture.sign(&claims)?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_token_with_the_wrong_audience() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.aud = Aud::Single("some-other-client");
        let token = fixture.sign(&claims)?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_token_whose_azp_is_a_different_client() -> Result<(), Box<dyn std::error::Error>> {
        // aud still contains client_id, but azp names a different primary
        // client: the token was minted for someone else.
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.azp = Some("a-different-client");
        let token = fixture.sign(&claims)?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    #[test]
    fn rejects_an_expired_token() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let now = now_secs();
        let mut claims = valid_claims();
        // Far enough in the past to clear the 60s leeway.
        claims.iat = now - 7_200;
        claims.exp = now - 3_600;
        let token = fixture.sign(&claims)?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    // ---- nonce (the OIDC-specific check) -----------------------------------

    #[test]
    fn rejects_a_token_missing_the_nonce_claim() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.nonce = None;
        let token = fixture.sign(&claims)?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::NonceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_token_with_a_wrong_nonce() -> Result<(), Box<dyn std::error::Error>> {
        // Everything else — signature, iss, aud, exp — is valid; ONLY the nonce
        // differs. This is the case that passes verification if the nonce check
        // is removed, so it is the load-bearing regression guard for that check.
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.nonce = Some("a-different-nonce-than-this-login-expected00");
        let token = fixture.sign(&claims)?;
        assert!(matches!(
            fixture.verify(&token),
            Err(OidcIdTokenError::NonceMismatch)
        ));
        Ok(())
    }

    // ---- alg-confusion (the classic public-key bypass) ---------------------

    #[test]
    fn the_algorithm_allowlist_excludes_every_hmac_variant() {
        // The direct, load-bearing regression guard for the alg-confusion
        // defense: if HS256/384/512 were ever added to the allowlist this fails.
        for hmac in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            assert!(!algorithm_is_allowed(hmac), "{hmac:?} must not be allowed");
        }
        for public_key in [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::EdDSA,
        ] {
            assert!(
                algorithm_is_allowed(public_key),
                "{public_key:?} must be allowed"
            );
        }
    }

    #[test]
    fn rejects_an_hs256_token_forged_with_the_public_key_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        // The alg-confusion attack end-to-end: an HS256 token whose HMAC secret
        // is the RSA public key's own modulus bytes, with a header kid that
        // selects the RSA JWK. It MUST be rejected. The allowlist refuses
        // alg=HS256 before the key is ever touched.
        let fixture = Fixture::new()?;
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_owned());
        let forged = encode(
            &header,
            &valid_claims(),
            &EncodingKey::from_secret(&fixture.public_modulus),
        )?;
        assert!(matches!(
            fixture.verify(&forged),
            Err(OidcIdTokenError::InvalidToken)
        ));
        Ok(())
    }

    // ---- JWKS validation ---------------------------------------------------

    #[test]
    fn rejects_a_symmetric_jwks() -> Result<(), Box<dyn std::error::Error>> {
        // A key set carrying an HMAC (oct) key is refused at the JWKS layer, so
        // a symmetric key can never even be selected for verification.
        let symmetric: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "oct",
                "k": URL_SAFE_NO_PAD.encode([7_u8; 32]),
                "kid": "symmetric",
                "alg": "HS256"
            }]
        }))?;
        assert!(matches!(
            validate_jwks(&symmetric),
            Err(OidcIdTokenError::InvalidJwks)
        ));
        Ok(())
    }

    fn minimal_unsigned_bytes(bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let bytes = bytes.as_ref();
        let first_nonzero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        bytes[first_nonzero..].to_vec()
    }

    // ---- JWKS cache (bounded TTL + kid-miss refresh cooldown) --------------

    /// A counting JWKS source: the fetch seam the cache tests inject. `slot`
    /// is the set "the provider" currently serves (swap it to simulate a key
    /// rotation); `fetches` counts outbound fetches the cache performed.
    struct CountingJwksSource {
        slot: Mutex<JwkSet>,
        fetches: AtomicUsize,
    }

    impl CountingJwksSource {
        fn new(set: JwkSet) -> Self {
            Self {
                slot: Mutex::new(set),
                fetches: AtomicUsize::new(0),
            }
        }

        fn rotate_to(&self, set: JwkSet) -> Result<(), Box<dyn std::error::Error>> {
            *self.slot.lock().map_err(|_| "slot poisoned")? = set;
            Ok(())
        }

        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }

        /// Verifies `token` through the cache with this source as the fetch.
        fn verify(
            &self,
            cache: &OidcJwksCache,
            token: &str,
        ) -> Result<VerifiedOidcIdentity, OidcIdTokenError> {
            verify_oidc_id_token_cached_with_fetch(
                cache,
                &provider(),
                CLIENT_ID,
                NONCE,
                token,
                |_jwks_uri| {
                    self.fetches.fetch_add(1, Ordering::SeqCst);
                    self.slot
                        .lock()
                        .map(|set| set.clone())
                        .map_err(|_| OidcIdTokenError::JwksUnavailable)
                },
            )
        }
    }

    #[test]
    fn a_cache_hit_avoids_a_second_jwks_fetch() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let source = CountingJwksSource::new(fixture.jwks.clone());
        let cache = OidcJwksCache::new();

        // Two verifications inside the TTL: one outbound fetch, both succeed.
        for _ in 0..2 {
            let token = fixture.sign(&valid_claims())?;
            source.verify(&cache, &token)?;
        }
        assert_eq!(
            source.fetches(),
            1,
            "the second verification must be served from the cache"
        );
        Ok(())
    }

    #[test]
    fn a_rotated_kid_triggers_exactly_one_refresh() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let source = CountingJwksSource::new(fixture.jwks.clone());
        // Zero cooldown: a kid miss may always refresh, isolating the rotation
        // behaviour from the amplification guard tested separately below.
        let cache = OidcJwksCache::with_ttl_capacity_and_cooldown(
            Duration::from_secs(300),
            64,
            Duration::ZERO,
        );

        // Prime the cache with the pre-rotation set.
        let token = fixture.sign(&valid_claims())?;
        source.verify(&cache, &token)?;
        assert_eq!(source.fetches(), 1);

        // The provider rotates its signing key (new kid, new key material) and
        // signs the next token with it. The cached set misses the new kid, so
        // the cache refreshes ONCE and the token verifies against the new set.
        let mut rotated = Fixture::new()?;
        rotated.jwks.keys[0].common.key_id = Some("rotated-oidc-key".to_owned());
        source.rotate_to(rotated.jwks.clone())?;
        let token = rotated.sign_rs256_with_kid("rotated-oidc-key", &valid_claims())?;
        source.verify(&cache, &token)?;
        assert_eq!(source.fetches(), 2, "the rotation must cost one refresh");

        // The rotated set is now cached: another token on the new kid is a hit.
        let token = rotated.sign_rs256_with_kid("rotated-oidc-key", &valid_claims())?;
        source.verify(&cache, &token)?;
        assert_eq!(source.fetches(), 2);
        Ok(())
    }

    #[test]
    fn a_bogus_kid_inside_the_cooldown_cannot_amplify_fetches()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let source = CountingJwksSource::new(fixture.jwks.clone());
        // The default cooldown (60s) is far longer than this test runs.
        let cache = OidcJwksCache::new();

        // Prime the cache with one honest verification.
        let token = fixture.sign(&valid_claims())?;
        source.verify(&cache, &token)?;
        assert_eq!(source.fetches(), 1);

        // A flood of tokens with fabricated kids: each is rejected against the
        // cached set, and NONE triggers an outbound fetch — the amplification
        // an attacker would otherwise get from a fetch-per-unknown-kid policy.
        for index in 0..5 {
            let token =
                fixture.sign_rs256_with_kid(&format!("bogus-kid-{index}"), &valid_claims())?;
            assert!(matches!(
                source.verify(&cache, &token),
                Err(OidcIdTokenError::InvalidToken)
            ));
        }
        assert_eq!(
            source.fetches(),
            1,
            "bogus kids inside the cooldown must not refetch"
        );
        Ok(())
    }

    #[test]
    fn an_expired_cache_entry_is_refetched() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let source = CountingJwksSource::new(fixture.jwks.clone());
        // A zero TTL disables caching: every verification refetches — the red
        // control proving the hit test above is the cache at work.
        let cache = OidcJwksCache::with_ttl_capacity_and_cooldown(
            Duration::ZERO,
            64,
            Duration::from_secs(60),
        );

        for _ in 0..2 {
            let token = fixture.sign(&valid_claims())?;
            source.verify(&cache, &token)?;
        }
        assert_eq!(source.fetches(), 2, "an expired entry must be refetched");
        Ok(())
    }

    #[test]
    fn a_poisoned_cache_lock_degrades_to_uncached_verification()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let source = CountingJwksSource::new(fixture.jwks.clone());
        let cache = OidcJwksCache::new();

        // Poison the cache mutex: a thread panics while holding the lock (the
        // guard lives inside the held `Result`, so unwinding drops it mid-panic
        // and marks the mutex poisoned).
        std::thread::scope(|scope| {
            let poisoner = scope.spawn(|| {
                let _guard = cache.entries.lock();
                panic!("deliberately poison the JWKS cache lock");
            });
            assert!(
                poisoner.join().is_err(),
                "the poisoning thread must have panicked"
            );
        });

        // Verification still succeeds — twice, each with its own (uncached)
        // fetch, proving the degrade path fetches rather than serving nothing.
        for _ in 0..2 {
            let token = fixture.sign(&valid_claims())?;
            source.verify(&cache, &token)?;
        }
        assert_eq!(
            source.fetches(),
            2,
            "a poisoned lock must degrade to uncached fetching"
        );
        Ok(())
    }

    #[test]
    fn at_capacity_a_new_jwks_uri_is_served_uncached_not_admitted_by_eviction()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let source = CountingJwksSource::new(fixture.jwks.clone());
        let cache = OidcJwksCache::with_ttl_capacity_and_cooldown(
            Duration::from_secs(300),
            1,
            Duration::from_secs(60),
        );
        let second_provider = OidcProviderMetadata {
            jwks_uri: format!("{ISSUER}/other-jwks.json"),
            ..provider()
        };
        let verify_with = |provider: &OidcProviderMetadata| {
            let token = fixture.sign(&valid_claims())?;
            verify_oidc_id_token_cached_with_fetch(
                &cache,
                provider,
                CLIENT_ID,
                NONCE,
                &token,
                |_jwks_uri| {
                    source.fetches.fetch_add(1, Ordering::SeqCst);
                    source
                        .slot
                        .lock()
                        .map(|set| set.clone())
                        .map_err(|_| OidcIdTokenError::JwksUnavailable)
                },
            )
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
        };

        // The first URI takes the single slot; the second is refused admission
        // (each of its verifications refetches) but still verifies fine, and
        // the first URI's entry keeps serving hits — bounded, never evicting.
        verify_with(&provider())?;
        assert_eq!(source.fetches(), 1);
        verify_with(&second_provider)?;
        verify_with(&second_provider)?;
        assert_eq!(source.fetches(), 3, "an unadmitted URI refetches each time");
        verify_with(&provider())?;
        assert_eq!(source.fetches(), 3, "the admitted URI still serves hits");
        Ok(())
    }
}
