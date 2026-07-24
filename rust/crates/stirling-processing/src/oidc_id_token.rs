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
//! Library functions only. The JWKS is fetched per verification (no caching —
//! a later refinement could add a bounded cache like [`crate::security_jwt`]'s).
//! There is no callback route, no session creation, and no `state`/`nonce`
//! *persistence* here — the caller supplies the `expected_nonce` it stored when
//! it built the authorization request.

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
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
/// Ceiling on an email claim, mirroring [`crate::security_jwt`].
const MAX_EMAIL_BYTES: usize = 320;
/// Generic ceiling for the optional human-readable string claims.
const MAX_CLAIM_BYTES: usize = 1_024;
/// Clock-skew leeway for `exp`, matching [`crate::security_jwt`]'s explicit
/// leeway convention (and `jsonwebtoken`'s own default).
const CLOCK_SKEW_SECONDS: u64 = 60;

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
    validate_token_shape(id_token)?;

    let header = decode_header(id_token).map_err(|_| OidcIdTokenError::InvalidToken)?;
    // The alg-confusion defense: reject anything that is not a public-key
    // signature algorithm BEFORE building a Validation or touching the key, so
    // an attacker-chosen `alg=HS256` (HMAC) can never be verified against a
    // public key. This is the first and primary gate.
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
        .ok_or(OidcIdTokenError::InvalidToken)?;
    let jwk = jwks.find(kid).ok_or(OidcIdTokenError::InvalidToken)?;
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
            issued_at: self.iat,
            expires_at: self.exp,
        })
    }
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
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde::Serialize;

    use super::{
        OidcIdTokenError, VerifiedOidcIdentity, algorithm_is_allowed, validate_jwks,
        verify_id_token_with_jwks,
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
}
