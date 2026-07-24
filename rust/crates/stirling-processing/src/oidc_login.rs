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
//!   expired ⇒ reject — this is the CSRF defense) → exchange the code → verify the
//!   id token (including the `nonce` bound to the stored one) → authenticate the
//!   identity → issue a session → return the session tokens + verified identity.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    oidc_authorization::{OidcAuthorizationError, build_oidc_authorization_request},
    oidc_discovery::{OidcDiscoveryError, OidcProviderMetadata, discover_oidc_provider},
    oidc_id_token::{OidcIdTokenError, VerifiedOidcIdentity, verify_oidc_id_token},
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

/// Length ceilings for the admin-configured provider fields, applied by
/// [`OidcLoginProviderConfig::validate`]. `issuer` mirrors
/// [`crate::oidc_discovery`]'s own issuer bound.
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_CLIENT_ID_BYTES: usize = 512;
const MAX_REDIRECT_URI_BYTES: usize = 2_048;

/// A single generic-OIDC provider's login configuration, for the public-client
/// PKCE case (no `client_secret` in this slice). Mirrors the fields of Java's
/// `ClientRegistration` that the discovery-driven `oidcClientRegistration()`
/// path uses: an `issuer` to discover, a public `client_id`, the `redirect_uri`
/// the provider will call back, and the requested `scopes`.
///
/// [`crate::runtime_config::RuntimeConfig::oidc_login_provider_config`] builds
/// this from the crate's usual env/YAML config, returning `None` when no issuer
/// is configured (the provider is simply disabled) — the same "absent ⇒ off,
/// present-but-invalid ⇒ rejected at the boundary" convention the Supabase JWT
/// config follows. Here the fail-closed boundary is [`Self::validate`], called
/// at the top of [`initiate_oidc_login`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLoginProviderConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
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
    /// The public client id this login was started for.
    client_id: String,
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
pub struct OidcLoginStateStore {
    ttl: Duration,
    entries: Mutex<HashMap<String, PendingLogin>>,
}

impl Default for OidcLoginStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcLoginStateStore {
    /// A store with the default [`DEFAULT_LOGIN_STATE_TTL`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_LOGIN_STATE_TTL)
    }

    /// A store with an explicit entry TTL (a deployment tuning knob; also lets a
    /// test drive the expiry path deterministically with a zero TTL).
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Inserts a pending login under `state`, stamping its expiry from the store's
    /// TTL and opportunistically dropping any already-expired entries first.
    fn store(&self, state: String, mut entry: PendingLogin) -> Result<(), OidcLoginError> {
        let now = Instant::now();
        entry.expires_at = now.checked_add(self.ttl).unwrap_or(now);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| OidcLoginError::StateUnavailable)?;
        entries.retain(|_, pending| pending.expires_at > now);
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

    /// Number of live (not-yet-consumed) entries. Test-only visibility into the
    /// store, e.g. to assert an entry survived a rejected callback.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().map_or(0, |entries| entries.len())
    }
}

/// What [`initiate_oidc_login`] returns: the URL to send the browser to, and the
/// `state` the server must correlate the eventual callback against (already
/// stored server-side; returned so a route can also, e.g., mirror it into a
/// cookie if it wants defense in depth).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiatedOidcLogin {
    pub authorization_url: String,
    pub state: String,
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
    /// The callback `state` matched an entry that had passed its TTL.
    #[error("OIDC login state has expired")]
    ExpiredState,
    /// The state store's lock was poisoned.
    #[error("OIDC login state store is unavailable")]
    StateUnavailable,
    /// Authenticating the verified identity or issuing the session failed (see
    /// [`SecurityError`]).
    #[error(transparent)]
    Identity(#[from] SecurityError),
}

/// Begins a generic-OIDC login: validates the provider config (fail-closed),
/// discovers the provider over the SSRF-safe fetch, builds the authorization
/// request with fresh `state`/`nonce`/PKCE secrets, **persists** the state entry
/// (with the discovered metadata + nonce + code verifier + redirect URI + client
/// id), and returns the authorization redirect URL and the `state`.
///
/// The caller redirects the browser to [`InitiatedOidcLogin::authorization_url`]
/// and, when the provider calls back, passes the callback's `state` + `code` to
/// [`complete_oidc_login`] with the same `store`.
///
/// # Errors
///
/// Returns [`OidcLoginError::InvalidProviderConfig`] for a bad config,
/// [`OidcLoginError::Discovery`] if discovery fails,
/// [`OidcLoginError::Authorization`] if the authorization URL can't be built, and
/// [`OidcLoginError::StateUnavailable`] if the store lock is poisoned.
pub fn initiate_oidc_login(
    provider: &OidcLoginProviderConfig,
    store: &OidcLoginStateStore,
) -> Result<InitiatedOidcLogin, OidcLoginError> {
    provider.validate()?;
    let metadata = discover_oidc_provider(&provider.issuer)?;
    let scopes: Vec<&str> = provider.scopes.iter().map(String::as_str).collect();
    let request = build_oidc_authorization_request(
        &metadata,
        &provider.client_id,
        &provider.redirect_uri,
        &scopes,
    )?;
    store.store(
        request.state.clone(),
        PendingLogin {
            nonce: request.nonce,
            code_verifier: request.code_verifier,
            redirect_uri: provider.redirect_uri.clone(),
            provider: metadata,
            client_id: provider.client_id.clone(),
            // Overwritten by `store` with the TTL-stamped expiry.
            expires_at: Instant::now(),
        },
    )?;
    Ok(InitiatedOidcLogin {
        authorization_url: request.redirect_url,
        state: request.state,
    })
}

/// Completes a generic-OIDC login from a callback's `state` + `code`.
///
/// Consumes the single-use `state` entry (rejecting an unknown/expired one — the
/// CSRF/single-use defense), exchanges `code` at the stored `token_endpoint`
/// using the stored PKCE verifier, verifies the returned id token against the
/// stored provider metadata and the stored `nonce`, authenticates the resulting
/// identity through [`SecurityStore::authenticate_oidc_identity`], and issues an
/// opaque session with the crate's default access/refresh TTLs.
///
/// # Errors
///
/// Returns [`OidcLoginError::UnknownState`]/[`OidcLoginError::ExpiredState`] for
/// a bad `state`, [`OidcLoginError::TokenExchange`] if the code exchange fails,
/// [`OidcLoginError::IdToken`] if the id token (or its `nonce`) fails
/// verification, [`OidcLoginError::Identity`] if authentication or session
/// issuance fails, and [`OidcLoginError::StateUnavailable`] on a poisoned store.
pub fn complete_oidc_login(
    state: &str,
    code: &str,
    store: &OidcLoginStateStore,
    security: &SecurityStore,
    now: i64,
    correlation_id: &str,
) -> Result<CompletedOidcLogin, OidcLoginError> {
    // Consume BEFORE any network call: an unknown/expired/forged state is
    // rejected here, so a bogus callback never reaches the provider at all.
    let pending = store.consume(state)?;
    let token_request = build_oidc_token_request(
        &pending.provider.token_endpoint,
        &pending.client_id,
        code,
        &pending.redirect_uri,
        &pending.code_verifier,
    );
    let token_response = exchange_oidc_token(&token_request)?;
    let identity = verify_oidc_id_token(
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

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde_json::{Value, json};

    use super::{
        CompletedOidcLogin, OidcLoginError, OidcLoginProviderConfig, OidcLoginStateStore,
        complete_oidc_login, initiate_oidc_login,
    };
    use crate::{oidc_id_token::OidcIdTokenError, security::AuthenticationSource};

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
        _handle: JoinHandle<()>,
    }

    impl MockIdp {
        /// Sets the id token the `/token` endpoint will return on the next call.
        fn set_id_token(&self, id_token: String) {
            if let Ok(mut slot) = self.id_token_slot.lock() {
                *slot = id_token;
            }
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
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = handle_connection(&mut stream, &discovery, &jwks_json, &slot_for_server);
            }
        });
        Ok(MockIdp {
            issuer,
            id_token_slot,
            _handle: handle,
        })
    }

    fn handle_connection(
        stream: &mut TcpStream,
        discovery: &str,
        jwks: &str,
        id_token_slot: &Arc<Mutex<String>>,
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
            discovery.to_owned()
        } else if first_line.starts_with("GET /jwks.json ") {
            jwks.to_owned()
        } else if first_line.starts_with("POST /token ") {
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
        security: &crate::security::SecurityStore,
        nonce_for_token: impl Fn(&str) -> String,
    ) -> Result<Result<CompletedOidcLogin, OidcLoginError>, Box<dyn std::error::Error>> {
        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, store)?;
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
            store,
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
        let security = crate::security::SecurityStore::in_memory()?;

        let completed = run_login(&idp, &fixture, &store, &security, str::to_owned)??;

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

    // ---- single-use (red/green target) -------------------------------------

    #[test]
    fn a_state_is_single_use_a_replayed_callback_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store)?;
        let login_nonce = query_param(&initiated.authorization_url, "nonce")
            .ok_or("authorization url has no nonce")?;
        idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &login_nonce))?);

        // First completion succeeds.
        let first = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            &store,
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
            &store,
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
        let security = crate::security::SecurityStore::in_memory()?;

        // A legitimate login is in flight...
        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store)?;

        // ...but a forged callback arrives carrying a state this server never
        // issued. It is rejected as unknown BEFORE any token exchange (the CSRF
        // defense), and the store still holds the one legitimate pending login.
        let forged = complete_oidc_login(
            "attacker-forged-state-value",
            "auth-code-xyz",
            &store,
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
            &store,
            &security,
            NOW,
            "corr-oidc",
        )?;
        assert_eq!(completed.identity.subject, SUBJECT);
        Ok(())
    }

    // ---- expired state ------------------------------------------------------

    #[test]
    fn an_expired_state_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        // A zero TTL: the entry is expired by the time the callback consumes it.
        let store = OidcLoginStateStore::with_ttl(Duration::from_secs(0));
        let security = crate::security::SecurityStore::in_memory()?;

        let provider = provider_config(&idp.issuer);
        let initiated = initiate_oidc_login(&provider, &store)?;
        // No id token need be prepared: consume rejects before any network call.
        let result = complete_oidc_login(
            &initiated.state,
            "auth-code-xyz",
            &store,
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

    // ---- nonce mismatch end-to-end -----------------------------------------

    #[test]
    fn an_id_token_whose_nonce_differs_from_the_stored_one_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = SigningFixture::new()?;
        let idp = start_mock_idp(fixture.jwks_json.clone())?;
        let store = OidcLoginStateStore::new();
        let security = crate::security::SecurityStore::in_memory()?;

        // The IdP returns an otherwise-valid id token, but its `nonce` is NOT the
        // one this login generated — the replay-binding check must reject it.
        let result = run_login(&idp, &fixture, &store, &security, |_login_nonce| {
            "a-different-nonce-not-the-login-one-00000000".to_owned()
        })?;
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
    }
}
