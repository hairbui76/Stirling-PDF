//! Generic OIDC login orchestration: the slice that finally wires the
//! previously-built OIDC primitives — discovery ([`crate::oidc_discovery`]), the
//! authorization redirect + PKCE secrets ([`crate::oidc_authorization`]), the
//! SSRF-safe token exchange ([`crate::oidc_live_token`]), and the ID-token
//! verifier ([`crate::oidc_id_token`]) — into an actual, completable login flow,
//! at the library level (no HTTP routes here; those are a separate follow-up).
//!
//! # What this adds over the primitives
//!
//! Two things the primitives deliberately left to a "later ticket":
//!
//! 1. **Server-side, single-use `state` persistence** ([`OidcLoginStateStore`]).
//!    [`crate::oidc_authorization`] generates `state`/`nonce`/`code_verifier` but
//!    persists nothing; a real login must remember them between the redirect and
//!    the callback. This store keeps exactly what the callback needs, keyed by the
//!    CSPRNG `state`, for a bounded few minutes, and hands each entry out **once**.
//! 2. **Session issuance for a verified OIDC identity**
//!    ([`crate::security::SecurityStore::authenticate_oidc_identity`] →
//!    [`crate::security::SecurityStore::issue_session`]), reusing the same opaque
//!    rotating-session machinery every other login path uses — no parallel
//!    session system.
//!
//! # The two entry points
//!
//! - [`initiate_oidc_login`]: discover → build authorization request → **store**
//!   the state entry → return the redirect URL + `state`.
//! - [`complete_oidc_login`]: **consume** the state entry (single-use; unknown or
//!   expired ⇒ reject) → require the callback's browser-binding cookie to equal
//!   the one stored for this login (login-CSRF defense, RFC 9700; unknown/absent
//!   ⇒ reject) → exchange the code → verify the id token (including the `nonce`
//!   bound to the stored one) → authenticate the identity → issue a session →
//!   return the session tokens + verified identity.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use subtle::ConstantTimeEq as _;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    oidc_authorization::{
        OidcAuthorizationError, build_oidc_authorization_request, random_url_safe_token,
    },
    oidc_discovery::{OidcDiscoveryCache, OidcDiscoveryError, OidcProviderMetadata},
    oidc_id_token::{
        OidcIdTokenError, OidcJwksCache, VerifiedOidcIdentity, verify_oidc_id_token_cached,
    },
    oidc_live_token::{OidcLiveTokenError, exchange_oidc_token},
    oidc_token::build_oidc_token_request,
    security::{
        AuthContext, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL, SecurityError, SecurityStore,
        SessionTokens,
    },
};

/// Bounded lifetime of a pending login's server-side `state` entry. A login is a
/// human clicking through an `IdP`'s consent screen, so a few minutes is ample; the
/// bound is what keeps an abandoned login from lingering (and what an [`ExpiredState`]
/// callback trips over).
///
/// [`ExpiredState`]: OidcLoginError::ExpiredState
const DEFAULT_LOGIN_STATE_TTL: Duration = Duration::from_secs(10 * 60);

/// Absolute cap on the number of pending logins [`OidcLoginStateStore`] holds at
/// once. The TTL alone bounds a *single* honest login's footprint, but nothing
/// stops an attacker spamming `/authorize` from growing the map to
/// (request-rate × TTL) entries between sweeps; this cap makes that growth
/// bounded regardless of rate. A few thousand is comfortably above any plausible
/// count of genuinely-concurrent in-flight logins (each entry is a human part-way
/// through an `IdP` consent screen within [`DEFAULT_LOGIN_STATE_TTL`]) while
/// keeping the worst-case memory footprint small (order of a few MB). When the
/// store is full it **refuses** a new login rather than evicting a pending one —
/// see [`OidcLoginStateStore::store`] for why eviction is the wrong move.
const DEFAULT_MAX_LOGIN_STATE_ENTRIES: usize = 4_096;

/// Length ceilings for the admin-configured provider fields, applied by
/// [`OidcLoginProviderConfig::validate`]. `issuer` mirrors
/// [`crate::oidc_discovery`]'s own issuer bound.
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_CLIENT_ID_BYTES: usize = 512;
const MAX_REDIRECT_URI_BYTES: usize = 2_048;
const MAX_CLIENT_SECRET_BYTES: usize = 512;

/// A single generic-OIDC provider's login configuration. Mirrors the fields of
/// Java's `ClientRegistration` that the discovery-driven
/// `oidcClientRegistration()` path uses: an `issuer` to discover, a
/// `client_id`, the `redirect_uri` the provider will call back, the requested
/// `scopes`, and — for a confidential client — the optional `client_secret`
/// (Java's `security.oauth2.clientSecret`), sent as RFC 6749 section 2.3.1
/// Basic credentials on the token exchange. `None` is the public-client PKCE
/// case; PKCE stays on in *both* cases (RFC 9700), where Spring would drop it
/// for a confidential client.
///
/// [`crate::runtime_config::RuntimeConfig::oidc_login_provider_config`] builds
/// this from the crate's usual env/YAML config, returning `None` when no issuer
/// is configured (the provider is simply disabled) — the same "absent ⇒ off,
/// present-but-invalid ⇒ rejected at the boundary" convention the Supabase JWT
/// config follows. Here the fail-closed boundary is [`Self::validate`], called
/// at the top of [`initiate_oidc_login`].
#[derive(Clone, Eq, PartialEq)]
pub struct OidcLoginProviderConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    /// The confidential-client secret, or [`None`] for a public client.
    /// Zeroized on drop, like every comparable credential in this crate.
    pub client_secret: Option<Zeroizing<String>>,
}

/// Manual so the derived output can never print the client secret — `Zeroizing`
/// zeroes memory on drop but its `Debug` passes straight through to the inner
/// value.
impl std::fmt::Debug for OidcLoginProviderConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcLoginProviderConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl OidcLoginProviderConfig {
    /// Fail-closed structural validation, run before any network call. Rejects an
    /// empty/over-long issuer or client id, an empty/over-long/unparseable
    /// redirect URI, and any scope that is empty or carries internal whitespace
    /// (scopes are space-joined in the authorization request, so a whitespace-
    /// bearing scope would split into two).
    ///
    /// The issuer's *scheme/host policy* (HTTPS-first, loopback-only HTTP) is not
    /// re-checked here — [`discover_oidc_provider`] enforces it, and re-encoding
    /// that policy in a second place would risk the two drifting apart.
    ///
    /// [`discover_oidc_provider`]: crate::oidc_discovery::discover_oidc_provider
    ///
    /// # Errors
    ///
    /// Returns [`OidcLoginError::InvalidProviderConfig`] if any field is unusable.
    pub fn validate(&self) -> Result<(), OidcLoginError> {
        let issuer = self.issuer.trim();
        let client_id = self.client_id.trim();
        let redirect_uri = self.redirect_uri.trim();
        if issuer.is_empty()
            || self.issuer.len() > MAX_ISSUER_BYTES
            || client_id.is_empty()
            || self.client_id.len() > MAX_CLIENT_ID_BYTES
            || redirect_uri.is_empty()
            || self.redirect_uri.len() > MAX_REDIRECT_URI_BYTES
            || reqwest::Url::parse(redirect_uri).is_err()
            || self
                .scopes
                .iter()
                .any(|scope| scope.trim().is_empty() || scope.contains(char::is_whitespace))
            // A configured-but-blank or over-long secret is a broken config,
            // not a public client — reject rather than silently downgrade the
            // client to unauthenticated token exchanges.
            || self.client_secret.as_ref().is_some_and(|secret| {
                secret.trim().is_empty() || secret.len() > MAX_CLIENT_SECRET_BYTES
            })
        {
            return Err(OidcLoginError::InvalidProviderConfig);
        }
        Ok(())
    }
}

/// One pending login's server-side secrets and context, held between the
/// authorization redirect and the callback. Keyed by the CSPRNG `state` in
/// [`OidcLoginStateStore`]; never leaves this module.
struct PendingLogin {
    /// Login-CSRF binding to the browser that started this login (RFC 9700). A
    /// fresh CSPRNG value set as an `HttpOnly` cookie at `/authorize`; the
    /// callback must present it back (via that cookie) and it must equal this.
    /// Unlike `state` — which travels through the `IdP` and the redirect URL —
    /// this never leaves the browser↔server channel, so a cross-site forged
    /// callback (which cannot read or set the victim's cookie) can't reproduce
    /// it. Verified by [`complete_oidc_login`] before any token exchange.
    browser_binding: String,
    /// Replay/CSRF binding: the eventual id token's `nonce` must equal this.
    nonce: String,
    /// PKCE code verifier, sent in the token exchange.
    code_verifier: Zeroizing<String>,
    /// The redirect URI presented at authorization; echoed in the token request.
    redirect_uri: String,
    /// The discovered provider metadata — carried forward so the callback uses
    /// the exact `token_endpoint`/`jwks_uri`/`issuer` discovered at initiation,
    /// not a re-discovery that could differ.
    provider: OidcProviderMetadata,
    /// The client id this login was started for.
    client_id: String,
    /// The confidential-client secret captured at initiation ([`None`] for a
    /// public client), so the callback's token exchange authenticates with the
    /// secret that was configured when this login began.
    client_secret: Option<Zeroizing<String>>,
    /// Wall-clock-independent expiry (monotonic [`Instant`]). Set by
    /// [`OidcLoginStateStore::store`]; a placeholder at construction.
    expires_at: Instant,
}

/// In-memory, single-use, TTL-bounded store of pending logins, keyed by `state`.
///
/// Modeled on [`crate::mobile_scanner`]'s session store (a `Mutex<HashMap>` over
/// a monotonic [`Instant`] clock), specialized for the OIDC login handshake:
///
/// - **Single-use.** [`Self::consume`] `remove`s the entry — a second lookup of
///   the same `state` finds nothing.
/// - **CSRF defense.** `state` is CSPRNG (from [`build_oidc_authorization_request`]).
///   A callback whose `state` is not a live entry — because it was never issued
///   (a forged/replayed callback) or already consumed or expired — is rejected.
///   That rejection *is* the CSRF check: only a login this server actually started
///   has a matching entry.
/// - **Bounded TTL.** Entries live [`DEFAULT_LOGIN_STATE_TTL`] (tunable via
///   [`Self::with_ttl`]); an opportunistic sweep on each `store` keeps abandoned
///   logins from accumulating.
/// - **Bounded size.** At most [`DEFAULT_MAX_LOGIN_STATE_ENTRIES`] pending logins
///   (tunable via [`Self::with_ttl_and_capacity`]); at capacity a new [`Self::store`]
///   is refused so `/authorize` spam can't grow the map without bound.
pub struct OidcLoginStateStore {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<String, PendingLogin>>,
}

impl Default for OidcLoginStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcLoginStateStore {
    /// A store with the default [`DEFAULT_LOGIN_STATE_TTL`] and
    /// [`DEFAULT_MAX_LOGIN_STATE_ENTRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl_and_capacity(DEFAULT_LOGIN_STATE_TTL, DEFAULT_MAX_LOGIN_STATE_ENTRIES)
    }

    /// A store with an explicit entry TTL and the default size cap (a deployment
    /// tuning knob; also lets a test drive the expiry path deterministically
    /// with a zero TTL).
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_ttl_and_capacity(ttl, DEFAULT_MAX_LOGIN_STATE_ENTRIES)
    }

    /// A store with an explicit entry TTL and size cap. The capacity seam lets a
    /// test force the cap small enough to exercise the at-capacity rejection
    /// without inserting thousands of entries.
    #[must_use]
    pub fn with_ttl_and_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Inserts a pending login under `state`, stamping its expiry from the store's
    /// TTL and opportunistically dropping any already-expired entries first.
    ///
    /// If the store is still at [`Self::max_entries`] capacity *after* that
    /// sweep, a new `state` is refused with [`OidcLoginError::AtCapacity`] rather
    /// than evicting an existing entry: every live entry is an in-flight honest
    /// login's single-use CSRF `state`, and evicting one would silently break
    /// that user's callback. Refusing the newcomer (which the caller surfaces as
    /// a retryable error) is the safe direction. Replacing an *already-present*
    /// `state` is always allowed — it doesn't grow the map — though in practice
    /// `state` is a fresh CSPRNG value that never collides.
    fn store(&self, state: String, mut entry: PendingLogin) -> Result<(), OidcLoginError> {
        let now = Instant::now();
        entry.expires_at = now.checked_add(self.ttl).unwrap_or(now);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OidcLoginError::StateUnavailable)?;
        entries.retain(|_, pending| pending.expires_at > now);
        if entries.len() >= self.max_entries && !entries.contains_key(&state) {
            return Err(OidcLoginError::AtCapacity);
        }
        entries.insert(state, entry);
        Ok(())
    }

    /// Delete-on-lookup: removes and returns the entry for `state`, enforcing
    /// single use. An absent `state` (never issued, or already consumed) is
    /// [`OidcLoginError::UnknownState`]; a present-but-expired one is removed
    /// anyway and reported as [`OidcLoginError::ExpiredState`]. Both are hard
    /// rejections — the difference is only which distinct error the caller sees.
    fn consume(&self, state: &str) -> Result<PendingLogin, OidcLoginError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OidcLoginError::StateUnavailable)?;
        // Remove FIRST so the entry is single-use even when it turns out to be
        // expired (it must never be re-lookup-able after this call either way).
        let entry = entries.remove(state).ok_or(OidcLoginError::UnknownState)?;
        if entry.expires_at <= Instant::now() {
            return Err(OidcLoginError::ExpiredState);
        }
        Ok(entry)
    }

    /// The TTL each pending-login entry is stored with. The authorize route uses
    /// it as the browser-binding cookie's `Max-Age`, so the cookie expires in
    /// lockstep with the server-side state entry it is bound to.
    #[must_use]
    pub fn state_ttl(&self) -> Duration {
        self.ttl
    }

    /// Number of live (not-yet-consumed) entries. Test-only visibility into the
    /// store, e.g. to assert an entry survived a rejected callback.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }
}

/// What [`initiate_oidc_login`] returns: the URL to send the browser to, the
/// `state` the server correlates the eventual callback against (already stored
/// server-side), and the login-CSRF `browser_binding` the route MUST set as a
/// cookie so the callback can require it back.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiatedOidcLogin {
    pub authorization_url: String,
    pub state: String,
    /// Login-CSRF browser-binding value (see [`PendingLogin::browser_binding`]).
    /// The route MUST set this as an `HttpOnly`, `Secure`, `SameSite=Lax` cookie
    /// scoped to the callback path, and the callback (via [`complete_oidc_login`])
    /// requires the browser to present it back. This is the server-enforced
    /// login-CSRF defense (RFC 9700), not an optional hardening step.
    pub browser_binding: String,
}

/// What [`complete_oidc_login`] returns: the freshly issued opaque session
/// tokens, the resulting [`AuthContext`], and the verified OIDC identity that
/// produced them.
pub struct CompletedOidcLogin {
    pub tokens: SessionTokens,
    pub context: AuthContext,
    pub identity: VerifiedOidcIdentity,
}

/// Everything that can go wrong across the login orchestration, keeping each
/// underlying stage's typed error distinguishable while adding the store's own
/// unknown/expired-state cases.
#[derive(Debug, Error)]
pub enum OidcLoginError {
    /// The provider configuration failed [`OidcLoginProviderConfig::validate`].
    #[error("OIDC login provider configuration is invalid")]
    InvalidProviderConfig,
    /// Provider discovery failed (see [`OidcDiscoveryError`]).
    #[error(transparent)]
    Discovery(#[from] OidcDiscoveryError),
    /// The authorization request could not be built (see [`OidcAuthorizationError`]).
    #[error(transparent)]
    Authorization(#[from] OidcAuthorizationError),
    /// The token exchange failed (see [`OidcLiveTokenError`]).
    #[error(transparent)]
    TokenExchange(#[from] OidcLiveTokenError),
    /// The id token failed verification (see [`OidcIdTokenError`]) — including a
    /// `nonce` that did not match the one stored for this login.
    #[error(transparent)]
    IdToken(#[from] OidcIdTokenError),
    /// The callback `state` matched no live entry: never issued (forged/replayed
    /// callback) or already consumed. This is the CSRF/single-use rejection.
    #[error("OIDC login state is unknown")]
    UnknownState,
    /// The callback did not present the browser-binding cookie set at
    /// `/authorize`, or presented a value that did not equal the one stored for
    /// this login. This is the login-CSRF rejection (RFC 9700): a genuine
    /// callback rides the initiating browser's cookie; a cross-site forged one
    /// (attacker's `state`+`code`, victim's browser) cannot. The route collapses
    /// it into the same generic 401 as every other callback rejection.
    #[error("OIDC login browser binding did not match")]
    BrowserBindingMismatch,
    /// The callback `state` matched an entry that had passed its TTL.
    #[error("OIDC login state has expired")]
    ExpiredState,
    /// The state store's lock was poisoned.
    #[error("OIDC login state store is unavailable")]
    StateUnavailable,
    /// The pending-login store is at its [`DEFAULT_MAX_LOGIN_STATE_ENTRIES`]
    /// capacity. A new login is refused rather than evicting an in-flight honest
    /// login's single-use `state`, so this is transient and retryable — the
    /// authorize route maps it to the same generic 503 every other initiate
    /// failure produces, revealing nothing about which limit was hit.
    #[error("OIDC login state store is at capacity")]
    AtCapacity,
    /// Authenticating the verified identity or issuing the session failed (see
    /// [`SecurityError`]).
    #[error(transparent)]
    Identity(#[from] SecurityError),
}

/// Begins a generic-OIDC login: validates the provider config (fail-closed),
/// resolves the provider metadata through `discovery` (a live cached entry when
/// one exists, otherwise the SSRF-safe discovery fetch), builds the authorization
/// request with fresh `state`/`nonce`/PKCE secrets, mints a fresh login-CSRF
/// `browser_binding`, **persists** the state entry (holding the discovered
/// metadata, nonce, code verifier, redirect URI, client id, and browser
/// binding), and returns the authorization redirect URL, the `state`, and the
/// `browser_binding`.
///
/// The caller redirects the browser to [`InitiatedOidcLogin::authorization_url`],
/// sets [`InitiatedOidcLogin::browser_binding`] as an `HttpOnly` cookie, and,
/// when the provider calls back, passes the callback's `state` + `code` **and
/// that cookie's value** to [`complete_oidc_login`] with the same `store`.
///
/// # Errors
///
/// Returns [`OidcLoginError::InvalidProviderConfig`] for a bad config,
/// [`OidcLoginError::Discovery`] if discovery fails,
/// [`OidcLoginError::Authorization`] if the authorization URL can't be built,
/// [`OidcLoginError::AtCapacity`] if the state store is full, and
/// [`OidcLoginError::StateUnavailable`] if the store lock is poisoned.
pub fn initiate_oidc_login(
    provider: &OidcLoginProviderConfig,
    store: &OidcLoginStateStore,
    discovery: &OidcDiscoveryCache,
) -> Result<InitiatedOidcLogin, OidcLoginError> {
    provider.validate()?;
    let metadata = discovery.discover(&provider.issuer)?;
    let scopes: Vec<&str> = provider.scopes.iter().map(String::as_str).collect();
    let request = build_oidc_authorization_request(
        &metadata,
        &provider.client_id,
        &provider.redirect_uri,
        &scopes,
    )?;
    // A fresh secret, independent of `state`/`nonce`, bound to the initiating
    // browser via an HttpOnly cookie the route sets from `InitiatedOidcLogin`.
    let browser_binding = random_url_safe_token();
    store.store(
        request.state.clone(),
        PendingLogin {
            browser_binding: browser_binding.clone(),
            nonce: request.nonce,
            code_verifier: request.code_verifier,
            redirect_uri: provider.redirect_uri.clone(),
            provider: metadata,
            client_id: provider.client_id.clone(),
            client_secret: provider.client_secret.clone(),
            // Overwritten by `store` with the TTL-stamped expiry.
            expires_at: Instant::now(),
        },
    )?;
    Ok(InitiatedOidcLogin {
        authorization_url: request.redirect_url,
        state: request.state,
        browser_binding,
    })
}

/// Completes a generic-OIDC login from a callback's `state` + `code` and the
/// browser-binding cookie value.
///
/// Consumes the single-use `state` entry (rejecting an unknown/expired one — the
/// single-use defense), requires `browser_binding` (the value of the cookie set
/// at initiation) to equal the one stored for this login — the login-CSRF
/// defense (RFC 9700) — then exchanges `code` at the stored `token_endpoint`
/// using the stored PKCE verifier (plus the stored `client_secret` as Basic
/// credentials, when this login's provider is a confidential client), verifies
/// the returned id token against the stored provider metadata and the stored
/// `nonce` — resolving the provider's JWKS through `jwks_cache` rather than
/// refetching per callback — authenticates the resulting identity through
/// [`SecurityStore::authenticate_oidc_identity`], and issues an opaque session
/// with the crate's default access/refresh TTLs.
///
/// `browser_binding` is [`None`] when the callback carried no such cookie, which
/// is treated exactly like a wrong value: rejected.
///
/// # Errors
///
/// Returns [`OidcLoginError::UnknownState`]/[`OidcLoginError::ExpiredState`] for
/// a bad `state`, [`OidcLoginError::BrowserBindingMismatch`] if the browser
/// binding is absent or wrong, [`OidcLoginError::TokenExchange`] if the code
/// exchange fails, [`OidcLoginError::IdToken`] if the id token (or its `nonce`)
/// fails verification, [`OidcLoginError::Identity`] if authentication or session
/// issuance fails, and [`OidcLoginError::StateUnavailable`] on a poisoned store.
#[allow(clippy::too_many_arguments)]
pub fn complete_oidc_login(
    state: &str,
    code: &str,
    browser_binding: Option<&str>,
    store: &OidcLoginStateStore,
    jwks_cache: &OidcJwksCache,
    security: &SecurityStore,
    now: i64,
    correlation_id: &str,
) -> Result<CompletedOidcLogin, OidcLoginError> {
    // Consume BEFORE any network call: an unknown/expired/forged state is
    // rejected here, so a bogus callback never reaches the provider at all.
    let pending = store.consume(state)?;
    // Login-CSRF binding (RFC 9700): the callback must ride the initiating
    // browser's cookie. A cross-site forged callback carries a valid `state`
    // (and `code`) but not the victim browser's cookie, so `browser_binding` is
    // absent or wrong and the login is rejected here — still before any token
    // exchange. Consuming the state first keeps it single-use even on this path.
    if !browser_binding.is_some_and(|value| binding_matches(value, &pending.browser_binding)) {
        return Err(OidcLoginError::BrowserBindingMismatch);
    }
    let token_request = build_oidc_token_request(
        &pending.provider.token_endpoint,
        &pending.client_id,
        pending.client_secret.as_ref().map(|secret| secret.as_str()),
        code,
        &pending.redirect_uri,
        &pending.code_verifier,
    );
    let token_response = exchange_oidc_token(&token_request)?;
    let identity = verify_oidc_id_token_cached(
        jwks_cache,
        &pending.provider,
        &pending.client_id,
        &pending.nonce,
        &token_response.id_token,
    )?;
    let context = security.authenticate_oidc_identity(&identity, now, correlation_id)?;
    let tokens = security.issue_session(&context, now, DEFAULT_ACCESS_TTL, DEFAULT_REFRESH_TTL)?;
    Ok(CompletedOidcLogin {
        tokens,
        context,
        identity,
    })
}

/// Constant-time equality for the login-CSRF browser binding. The binding is
/// single-use and server-stored (each pending entry is consumed on the first
/// callback), so a timing side-channel is not a realistic oracle here, but a
/// constant-time compare (over equal-length inputs) is cheap defense-in-depth —
/// mirroring [`crate::oidc_id_token`]'s `nonce` check.
fn binding_matches(actual: &str, expected: &str) -> bool {
    let (actual, expected) = (actual.as_bytes(), expected.as_bytes());
    actual.len() == expected.len() && actual.ct_eq(expected).into()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde_json::{Value, json};
    use zeroize::Zeroizing;

    use super::{
        CompletedOidcLogin, DEFAULT_LOGIN_STATE_TTL, OidcLoginError, OidcLoginProviderConfig,
        OidcLoginStateStore, PendingLogin, complete_oidc_login, initiate_oidc_login,
    };
    use crate::{
        oidc_discovery::{OidcDiscoveryCache, OidcProviderMetadata},
        oidc_id_token::{OidcIdTokenError, OidcJwksCache},
        security::AuthenticationSource,
    };

    const CLIENT_ID: &str = "oidc-login-test-client";
    const SUBJECT: &str = "oidc-subject-oidc-login-1";
    const KID: &str = "oidc-login-test-key";
    /// A fixed positive logical timestamp handed to the security store. It is
    /// independent of the id token's wall-clock `exp`/`iat` (which the verifier
    /// checks against the real clock), so any positive value works.
    const NOW: i64 = 2_000_000_000;

    // ---- RSA signing fixture (mirrors oidc_id_token's test fixture) ---------

    struct SigningFixture {
        encoding_key: EncodingKey,
        jwks_json: String,
    }

    impl SigningFixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let private_key = RsaPrivateKey::new(&mut rand::rng(), 2_048)?;
            let public_key = private_key.to_public_key();
            let private_der = private_key.to_pkcs1_der()?;
            let encoding_key = EncodingKey::from_rsa_der(private_der.as_bytes());
            let modulus = minimal_unsigned_bytes(public_key.n().to_bytes(ByteOrder::BigEndian));
            let exponent = minimal_unsigned_bytes(public_key.e().to_bytes(ByteOrder::BigEndian));
            let jwks_json = json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "kid": KID,
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&modulus),
                    "e": URL_SAFE_NO_PAD.encode(&exponent)
                }]
            })
            .to_string();
            Ok(Self {
                encoding_key,
                jwks_json,
            })
        }

        fn sign(&self, claims: &Value) -> Result<String, Box<dyn std::error::Error>> {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(KID.to_owned());
            Ok(encode(&header, claims, &self.encoding_key)?)
        }
    }

    fn minimal_unsigned_bytes(bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let bytes = bytes.as_ref();
        let first_nonzero = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len().saturating_sub(1));
        bytes[first_nonzero..].to_vec()
    }

    /// Baseline valid id-token claims for this issuer/client, echoing `nonce` the
    /// way a real `IdP` echoes the `nonce` it received in the authorization request.
    fn id_token_claims(issuer: &str, nonce: &str) -> Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "iss": issuer,
            "sub": SUBJECT,
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
            "preferred_username": "oidc-user",
            "email": "oidc-user@example.test",
            "sid": "provider-session-abc"
        })
    }

    // ---- mock IdP (discovery + token + jwks on one loopback listener) -------

    struct MockIdp {
        issuer: String,
        id_token_slot: Arc<Mutex<String>>,
        discovery_hits: Arc<AtomicUsize>,
        token_authorization: Arc<Mutex<Option<String>>>,
        _handle: JoinHandle<()>,
    }

    impl MockIdp {
        /// Sets the id token the `/token` endpoint will return on the next call.
        fn set_id_token(&self, id_token: String) {
            if let Ok(mut slot) = self.id_token_slot.lock() {
                *slot = id_token;
            }
        }

        /// How many discovery-document fetches this mock has served — used to
        /// prove the discovery cache collapses repeat initiations to one fetch.
        fn discovery_hits(&self) -> usize {
            self.discovery_hits.load(Ordering::SeqCst)
        }

        /// The `Authorization` header value the most recent `/token` request
        /// carried, if any — used to prove a confidential client's Basic
        /// credentials actually reach the token endpoint.
        fn last_token_authorization(&self) -> Option<String> {
            self.token_authorization
                .lock()
                .ok()
                .and_then(|slot| slot.clone())
        }
    }

    /// Starts a loopback mock `IdP` serving the three endpoints the login arc needs
    /// (`GET /.well-known/openid-configuration`, `GET /jwks.json`, `POST /token`)
    /// and returns its issuer plus a settable id-token slot. The server loops over
    /// incoming connections on a background thread; each test uses its own port.
    fn start_mock_idp(jwks_json: String) -> Result<MockIdp, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let issuer = format!("http://{address}");
        let discovery = json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks.json")
        })
        .to_string();
        let id_token_slot = Arc::new(Mutex::new(String::new()));
        let slot_for_server = Arc::clone(&id_token_slot);
        let discovery_hits = Arc::new(AtomicUsize::new(0));
        let hits_for_server = Arc::clone(&discovery_hits);
        let token_authorization = Arc::new(Mutex::new(None));
        let authorization_for_server = Arc::clone(&token_authorization);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = handle_connection(
                    &mut stream,
                    &discovery,
                    &jwks_json,
                    &slot_for_server,
                    &hits_for_server,
                    &authorization_for_server,
                );
            }
        });
        Ok(MockIdp {
            issuer,
            id_token_slot,
            discovery_hits,
            token_authorization,
            _handle: handle,
        })
    }

    fn handle_connection(
        stream: &mut TcpStream,
        discovery: &str,
        jwks: &str,
        id_token_slot: &Arc<Mutex<String>>,
        discovery_hits: &Arc<AtomicUsize>,
        token_authorization: &Arc<Mutex<Option<String>>>,
    ) -> std::io::Result<()> {
        // Read until the request quiesces (short read timeout) so a POST body is
        // fully drained before the response — avoids a mid-request reset. Mirrors
        // oidc_live_token's serve-once fixture.
        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
        let mut data = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            match stream.read(&mut buffer) {
                Ok(read) if read > 0 => {
                    data.extend_from_slice(&buffer[..read]);
                    if data.len() > 64 * 1024 {
                        break;
                    }
                }
                _ => break,
            }
        }
        let request = String::from_utf8_lossy(&data);
        let first_line = request.lines().next().unwrap_or("");
        let body = if first_line.starts_with("GET /.well-known/openid-configuration ") {
            discovery_hits.fetch_add(1, Ordering::SeqCst);
            discovery.to_owned()
        } else if first_line.starts_with("GET /jwks.json ") {
            jwks.to_owned()
        } else if first_line.starts_with("POST /token ") {
            // Record the Authorization header (if any) this token request
            // carried, so a test can assert confidential-client credentials.
            let authorization = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            });
            if let Ok(mut slot) = token_authorization.lock() {
                *slot = authorization;
            }
            let id_token = id_token_slot
                .lock()
                .map(|slot| slot.clone())
                .unwrap_or_default();
            json!({
                "access_token": "at-oidc-login",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": id_token
            })
            .to_string()
        } else {
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )?;
            return stream.flush();
        };
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        stream.write_all(body.as_bytes())?;
        stream.flush()
    }

    // ---- test helpers -------------------------------------------------------

    fn provider_config(issuer: &str) -> OidcLoginProviderConfig {
        OidcLoginProviderConfig {
            issuer: issuer.to_owned(),
            client_id: CLIENT_ID.to_owned(),
            redirect_uri: "http://127.0.0.1/login/oauth2/code/oidc".to_owned(),
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            client_secret: None,
        }
    }

    fn query_param(url: &str, key: &str) -> Option<String> {
        reqwest::Url::parse(url)
            .ok()?
            .query_pairs()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.into_owned())
    }

    /// Runs a full initiate → complete against the mock, minting an id token whose
    /// `nonce` is chosen by `nonce_for_token(login_nonce)` (usually the identity
    /// echo, but a wrong value for the mismatch test).
    fn run_login(
        idp: &MockIdp,
        fixture: &SigningFixture,
        store: &OidcLoginStateStore,
        discovery: &OidcDiscoveryCache,
        security: &crate::security::SecurityStore,
        nonce_for_token: impl Fn(&str) -> String,
    ) -> Result<Result<CompletedOidcLogin, OidcLoginError>, Box<dyn std::error::Error>> {
        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, store, discovery)?;
        // The state carried in the redirect URL is exactly the stored state.
        assert_eq!(
            query_param(&initiated.authorization_url, "state").as_deref(),
            Some(initiated.state.as_str())
        );
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        let id_token = fixture.sign(&id_token_claims(
            &idp.issuer,
            &nonce_for_token(&login_nonce),
        ))?;
        idp.set_id_token(id_token);
        Ok(complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            // The genuine callback rides the browser-binding cookie set at
            // initiation; the CSRF-scenario tests below drive the absent/wrong
            // cases directly instead of through this happy-path helper.
            Some(&initiated.browser_binding),
            store,
            &OidcJwksCache::new(),
            security,
            NOW,
            "corr-oidc",
        ))
    }

    // ---- happy path end-to-end ---------------------------------------------

    #[test]
    fn completes_a_login_and_provisions_the_issuer_subject_user()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let completed = run_login(&idp, &fixture, &store, &discovery, &security, str::to_owned)??;

        // Identity + context.
        assert_eq!(completed.identity.subject, SUBJECT);
        assert_eq!(completed.identity.issuer, idp.issuer);
        assert_eq!(
            completed.context.authentication_source,
            AuthenticationSource::Oidc
        );
        // username = preferred_username; session id = the id token's `sid`.
        assert_eq!(completed.context.username, "oidc-user");
        assert_eq!(completed.context.session_id, "provider-session-abc");
        assert_eq!(completed.context.external_subject.as_deref(), Some(SUBJECT));
        assert!(completed.context.has_role("ROLE_USER"));
        assert!(completed.context.permissions.is_empty());

        // A real opaque session was issued (same prefixes every login path mints).
        assert!(completed.tokens.access_token.starts_with("spdf_at_"));
        assert!(completed.tokens.refresh_token.starts_with("spdf_rt_"));

        // The (issuer, subject) user was provisioned as an oauth2 external user.
        let users = security.list_users(NOW + 1)?;
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "oidc-user");
        assert_eq!(users[0].authentication_type, "oauth2");

        // The single-use state was consumed — nothing left in the store.
        assert_eq!(store.len(), 0);
        Ok(())
    }

    // ---- confidential client (client_secret) end-to-end --------------------

    #[test]
    fn a_secret_configured_provider_completes_and_authenticates_with_basic_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let mut provider = provider_config(&idp.issuer);
        provider.client_secret = Some(Zeroizing::new("the client secret".to_owned()));

        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);
        let completed = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            Some(&initiated.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc-confidential",
        )?;
        assert_eq!(completed.identity.subject, SUBJECT);

        // The token exchange authenticated as a confidential client: the /token
        // request carried the RFC 6749 section 2.3.1 Basic credentials, with
        // id and secret form-urlencoded (space -> '+') BEFORE base64.
        // base64("oidc-login-test-client:the+client+secret")
        let authorization = idp
            .last_token_authorization()
            .ok_or("the token request carried no Authorization header")?;
        assert_eq!(
            authorization,
            "Basic b2lkYy1sb2dpbi10ZXN0LWNsaWVudDp0aGUrY2xpZW50K3NlY3JldA=="
        );
        Ok(())
    }

    // ---- single-use (red/green target) -------------------------------------

    #[test]
    fn a_state_is_single_use_a_replayed_callback_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);

        // First completion succeeds.
        let first = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            Some(&initiated.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc",
        )?;
        assert_eq!(first.identity.subject, SUBJECT);

        // Replaying the SAME state (with the same still-valid id token available)
        // must be rejected as unknown, because the entry was deleted on first
        // lookup. If `consume` used `.get` instead of `.remove`, this would
        // succeed — this is the load-bearing single-use guard.
        let replay = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            Some(&initiated.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW + 1,
            "corr-oidc-replay",
        );
        assert!(
            matches!(replay, Err(OidcLoginError::UnknownState)),
            "replayed state should be rejected as unknown, got {:?}",
            replay.as_ref().err()
        );
        Ok(())
    }

    // ---- CSRF: a state that was never issued -------------------------------

    #[test]
    fn a_callback_state_that_was_never_issued_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        // A legitimate login is in flight...
        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;

        // ...but a forged callback arrives carrying a state this server never
        // issued. It is rejected as unknown BEFORE any token exchange (the CSRF
        // defense), and the store still holds the one legitimate pending login.
        let forged = complete_oidc_login(
            "attacker-forged-state-value",
            "auth-code-xyz",
            None,
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc-forged",
        );
        assert!(
            matches!(forged, Err(OidcLoginError::UnknownState)),
            "a never-issued state should be rejected, got {:?}",
            forged.as_ref().err()
        );
        assert_eq!(
            store.len(),
            1,
            "the forged callback must not disturb the real pending login"
        );
        // No user was provisioned by the rejected callback.
        assert!(security.list_users(NOW)?.is_empty());

        // The genuine callback still completes afterward (the forged attempt did
        // not consume or corrupt the real state).
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);
        let completed = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            Some(&initiated.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc",
        )?;
        assert_eq!(completed.identity.subject, SUBJECT);
        Ok(())
    }

    // ---- login-CSRF: browser binding (RFC 9700) ----------------------------

    /// The core login-CSRF closure. Everything a cross-site forged callback CAN
    /// carry is valid here — a live `state`, a usable `code`, an id token whose
    /// `nonce` matches — yet the callback presents NO browser-binding cookie (the
    /// victim's browser never held the attacker's cookie). It must be rejected
    /// *before* any token exchange, and the pending state must be consumed so it
    /// can't be retried.
    #[test]
    fn a_callback_without_the_browser_binding_cookie_is_rejected_login_csrf()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);

        let forged = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            // No cookie ⇒ no binding presented.
            None,
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc-csrf",
        );
        assert!(
            matches!(forged, Err(OidcLoginError::BrowserBindingMismatch)),
            "a callback lacking the browser-binding cookie must be rejected, got {:?}",
            forged.as_ref().err()
        );
        // Rejected before provisioning any user and the single-use state burned.
        assert!(security.list_users(NOW)?.is_empty());
        assert_eq!(store.len(), 0);
        Ok(())
    }

    /// The classic login-CSRF attack shape: the attacker starts their OWN login
    /// (obtaining `state_a` + cookie `binding_a`) and lures the victim's browser
    /// to the callback with `state_a`. The victim's browser sends its own OIDC
    /// cookie (or none) — never `binding_a` — so the binding presented does not
    /// equal the one stored for `state_a`, and the login is rejected.
    #[test]
    fn a_callback_with_a_wrong_browser_binding_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);

        let rejected = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            // A binding value from some other browser — not the one stored.
            Some("some-other-browsers-binding-value-000000000"),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc-csrf",
        );
        assert!(
            matches!(rejected, Err(OidcLoginError::BrowserBindingMismatch)),
            "a callback presenting the wrong browser binding must be rejected, got {:?}",
            rejected.as_ref().err()
        );
        assert!(security.list_users(NOW)?.is_empty());
        assert_eq!(store.len(), 0);
        Ok(())
    }

    /// The binding is a distinct secret from `state` (so a `state` leaked via the
    /// URL/`IdP`/referer does not hand an attacker the binding), and presenting
    /// the correct binding completes the login — the green control proving the
    /// two rejections above are the binding check, not some unrelated failure.
    #[test]
    fn the_browser_binding_is_a_distinct_secret_and_the_correct_one_completes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;
        assert!(
            !initiated.browser_binding.is_empty(),
            "a binding must be minted"
        );
        assert_ne!(
            initiated.browser_binding, initiated.state,
            "the browser binding must not equal the state that travels in the URL"
        );

        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);
        let completed = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            Some(&initiated.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc",
        )?;
        assert_eq!(completed.identity.subject, SUBJECT);
        assert_eq!(store.len(), 0);
        Ok(())
    }

    /// Two concurrent logins mint two independent bindings, so one login's cookie
    /// can't complete the other — the bindings aren't a shared/static value.
    #[test]
    fn two_logins_get_independent_bindings() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;
        let provider = provider_config(&idp.issuer);

        let first = initiate_oidc_login(&provider, &store, &discovery)?;
        let second = initiate_oidc_login(&provider, &store, &discovery)?;
        assert_ne!(
            first.browser_binding, second.browser_binding,
            "distinct logins must mint distinct bindings"
        );

        // The FIRST login's binding must not complete the SECOND login's state.
        let second_nonce = query_param(&second.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &second_nonce))?);
        let crossed = complete_oidc_login(
            &second.state,
            "auth-code-xyz",
            Some(&first.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc",
        );
        assert!(
            matches!(crossed, Err(OidcLoginError::BrowserBindingMismatch)),
            "one login's binding must not satisfy another login's callback, got {:?}",
            crossed.as_ref().err()
        );
        Ok(())
    }

    // ---- expired state ------------------------------------------------------

    #[test]
    fn an_expired_state_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        // A zero TTL: the entry is expired by the time the callback consumes it.
        let store = OidcLoginStateStore::with_ttl(Duration::from_secs(0));
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store, &discovery)?;
        // No id token need be prepared: consume rejects before any network call.
        let result = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            Some(&initiated.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc",
        );
        assert!(
            matches!(result, Err(OidcLoginError::ExpiredState)),
            "an expired state should be rejected, got {:?}",
            result.as_ref().err()
        );
        Ok(())
    }

    // ---- state-store size cap ----------------------------------------------

    /// A throwaway pending login for the store-level cap test, so it can be
    /// driven without standing up a mock `IdP` or a real discovery/token flow.
    fn dummy_pending() -> PendingLogin {
        PendingLogin {
            browser_binding: "browser-binding".to_owned(),
            nonce: "nonce".to_owned(),
            code_verifier: Zeroizing::new("code-verifier".to_owned()),
            client_secret: None,
            redirect_uri: "http://127.0.0.1/login/oauth2/code/oidc".to_owned(),
            provider: OidcProviderMetadata {
                issuer: "https://issuer.example.test".to_owned(),
                authorization_endpoint: "https://issuer.example.test/authorize".to_owned(),
                token_endpoint: "https://issuer.example.test/token".to_owned(),
                jwks_uri: "https://issuer.example.test/jwks.json".to_owned(),
            },
            client_id: CLIENT_ID.to_owned(),
            expires_at: Instant::now(),
        }
    }

    #[test]
    fn the_state_store_refuses_new_entries_at_capacity_and_recovers_after_a_consume()
    -> Result<(), Box<dyn std::error::Error>> {
        // A tiny cap (2) makes the boundary trivial to reach directly, without
        // inserting thousands of entries.
        let store = OidcLoginStateStore::with_ttl_and_capacity(DEFAULT_LOGIN_STATE_TTL, 2);
        store.store("state-1".to_owned(), dummy_pending())?;
        store.store("state-2".to_owned(), dummy_pending())?;

        // At capacity (2/2) a THIRD distinct state is refused — the two
        // in-flight logins are left untouched rather than one being evicted.
        assert!(
            matches!(
                store.store("state-3".to_owned(), dummy_pending()),
                Err(OidcLoginError::AtCapacity)
            ),
            "a new state at capacity must be refused, not admitted by eviction"
        );
        assert_eq!(
            store.len(),
            2,
            "the refused store must not disturb existing entries"
        );

        // Consuming one frees a slot, after which a new store succeeds again.
        store.consume("state-1")?;
        store.store("state-3".to_owned(), dummy_pending())?;
        assert_eq!(store.len(), 2);
        Ok(())
    }

    #[test]
    fn at_capacity_a_new_initiation_is_rejected_until_a_slot_is_freed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        // A cap of one pending login makes the boundary trivial to hit through
        // the real `initiate_oidc_login` path.
        let store = OidcLoginStateStore::with_ttl_and_capacity(DEFAULT_LOGIN_STATE_TTL, 1);
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;
        let provider = provider_config(&idp.issuer);

        // The first login fills the single slot.
        let first = initiate_oidc_login(&provider, &store, &discovery)?;
        assert_eq!(store.len(), 1);

        // The second is rejected as AtCapacity — evicting `first` would destroy
        // an in-flight honest user's CSRF state, so the store refuses instead.
        let rejected = initiate_oidc_login(&provider, &store, &discovery);
        assert!(
            matches!(rejected, Err(OidcLoginError::AtCapacity)),
            "at capacity a new initiation must be rejected, got {:?}",
            rejected.as_ref().err()
        );
        // The already-in-flight login is untouched.
        assert_eq!(store.len(), 1);

        // Completing the first login frees its slot...
        let login_nonce = query_param(&first.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);
        complete_oidc_login(
            &first.state,
            "auth-code-xyz",
            Some(&first.browser_binding),
            &store,
            &OidcJwksCache::new(),
            &security,
            NOW,
            "corr-oidc",
        )?;
        assert_eq!(store.len(), 0);

        // ...so a fresh initiation succeeds again.
        initiate_oidc_login(&provider, &store, &discovery)?;
        assert_eq!(store.len(), 1);
        Ok(())
    }

    // ---- discovery metadata cache ------------------------------------------

    #[test]
    fn repeated_initiations_for_one_issuer_share_a_single_discovery_fetch()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let provider = provider_config(&idp.issuer);

        let first = initiate_oidc_login(&provider, &store, &discovery)?;
        let second = initiate_oidc_login(&provider, &store, &discovery)?;

        // Two distinct pending logins (distinct CSPRNG `state`)...
        assert_ne!(first.state, second.state);
        // ...but only ONE outbound discovery fetch: the second reused the cache.
        assert_eq!(
            idp.discovery_hits(),
            1,
            "the second initiation for the same issuer must reuse the cached discovery"
        );
        Ok(())
    }

    #[test]
    fn with_the_discovery_cache_disabled_each_initiation_refetches()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        // A zero-TTL cache disables caching — the red control proving the cache
        // above is what collapses the fetch count, not some other coincidence.
        let discovery = OidcDiscoveryCache::with_ttl_and_capacity(Duration::from_secs(0), 64);
        let provider = provider_config(&idp.issuer);

        initiate_oidc_login(&provider, &store, &discovery)?;
        initiate_oidc_login(&provider, &store, &discovery)?;

        assert_eq!(
            idp.discovery_hits(),
            2,
            "with caching disabled each initiation must refetch discovery"
        );
        Ok(())
    }

    // ---- nonce mismatch end-to-end -----------------------------------------

    #[test]
    fn an_id_token_whose_nonce_differs_from_the_stored_one_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let discovery = OidcDiscoveryCache::new();
        let security = crate::security::SecurityStore::in_memory()?;

        // The IdP returns an otherwise-valid id token, but its `nonce` is NOT the
        // one this login generated — the replay-binding check must reject it.
        let result = run_login(
            &idp,
            &fixture,
            &store,
            &discovery,
            &security,
            |_login_nonce| "a-different-nonce-not-the-login-one-00000000".to_owned(),
        )?;
        assert!(
            matches!(
                result,
                Err(OidcLoginError::IdToken(OidcIdTokenError::NonceMismatch))
            ),
            "a mismatched nonce should be rejected end-to-end, got {:?}",
            result.as_ref().err()
        );
        Ok(())
    }

    // ---- provider config validation ----------------------------------------

    #[test]
    fn provider_config_validation_is_fail_closed() {
        // Valid.
        assert!(
            provider_config("https://issuer.example.com")
                .validate()
                .is_ok()
        );
        // Empty issuer / client id / redirect uri each fail.
        let mut empty_issuer = provider_config("https://issuer.example.com");
        empty_issuer.issuer = "   ".to_owned();
        assert!(matches!(
            empty_issuer.validate(),
            Err(OidcLoginError::InvalidProviderConfig)
        ));
        let mut empty_client = provider_config("https://issuer.example.com");
        empty_client.client_id = String::new();
        assert!(matches!(
            empty_client.validate(),
            Err(OidcLoginError::InvalidProviderConfig)
        ));
        let mut bad_redirect = provider_config("https://issuer.example.com");
        bad_redirect.redirect_uri = "not a url".to_owned();
        assert!(matches!(
            bad_redirect.validate(),
            Err(OidcLoginError::InvalidProviderConfig)
        ));
        // A scope with internal whitespace would split into two scopes.
        let mut bad_scope = provider_config("https://issuer.example.com");
        bad_scope.scopes = vec!["openid profile".to_owned()];
        assert!(matches!(
            bad_scope.validate(),
            Err(OidcLoginError::InvalidProviderConfig)
        ));
        // A configured-but-blank secret is a broken config, not a silent
        // downgrade to a public client.
        let mut blank_secret = provider_config("https://issuer.example.com");
        blank_secret.client_secret = Some(Zeroizing::new("   ".to_owned()));
        assert!(matches!(
            blank_secret.validate(),
            Err(OidcLoginError::InvalidProviderConfig)
        ));
        // A well-formed secret keeps the config valid.
        let mut with_secret = provider_config("https://issuer.example.com");
        with_secret.client_secret = Some(Zeroizing::new("a-real-secret".to_owned()));
        assert!(with_secret.validate().is_ok());
    }
}
