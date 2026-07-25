//! Strict Supabase JWT verification against a bounded, cached remote JWKS.
//!
//! Header and claim data remains untrusted until `jsonwebtoken::decode` has
//! verified the signature, issuer, expiry, audience policy, and required
//! registered claims with an explicitly allowed public-key algorithm.

use std::{
    collections::BTreeSet,
    io::Read as _,
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
use thiserror::Error;

const MAX_JWT_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: u64 = 256 * 1024;
const MAX_JWKS_KEYS: usize = 32;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_SUBJECT_BYTES: usize = 128;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_SESSION_ID_BYTES: usize = 256;
const MAX_ROLE_BYTES: usize = 64;
const MAX_PERMISSION_BYTES: usize = 128;
const MAX_PERMISSIONS: usize = 128;
const MAX_CLOCK_SKEW_SECONDS: u64 = 10 * 60;
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupabaseJwtConfig {
    pub issuer: String,
    pub expected_audience: Option<String>,
    pub clock_skew_seconds: u64,
    pub jwks_cache_seconds: u64,
}

impl SupabaseJwtConfig {
    /// Validates an issuer and builds a fail-closed verifier configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid/non-HTTPS remote issuer, empty audience,
    /// or excessive skew/cache values.
    pub fn validate(self) -> Result<Self, SupabaseJwtError> {
        let issuer = self.issuer.trim();
        if issuer.is_empty() || issuer.len() > MAX_ISSUER_BYTES {
            return Err(SupabaseJwtError::InvalidConfiguration);
        }
        let url = Url::parse(issuer).map_err(|_| SupabaseJwtError::InvalidConfiguration)?;
        if url.username() != ""
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !issuer_url_scheme_is_allowed(&url)
        {
            return Err(SupabaseJwtError::InvalidConfiguration);
        }
        if self
            .expected_audience
            .as_ref()
            .is_some_and(|audience| audience.trim().is_empty())
        {
            return Err(SupabaseJwtError::InvalidConfiguration);
        }
        let expected_audience = self
            .expected_audience
            .map(|audience| audience.trim().to_owned())
            .filter(|audience| !audience.is_empty());
        if expected_audience
            .as_ref()
            .is_some_and(|audience| audience.len() > MAX_ROLE_BYTES)
            || self.clock_skew_seconds > MAX_CLOCK_SKEW_SECONDS
            || self.jwks_cache_seconds == 0
            || self.jwks_cache_seconds > 24 * 60 * 60
        {
            return Err(SupabaseJwtError::InvalidConfiguration);
        }
        Ok(Self {
            issuer: issuer.trim_end_matches('/').to_owned(),
            expected_audience,
            clock_skew_seconds: self.clock_skew_seconds,
            jwks_cache_seconds: self.jwks_cache_seconds,
        })
    }

    fn jwks_url(&self) -> String {
        format!("{}/.well-known/jwks.json", self.issuer)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSupabaseIdentity {
    pub issuer: String,
    pub subject: String,
    pub username: String,
    pub email: Option<String>,
    pub authentication_type: String,
    pub role: String,
    pub session_id: String,
    pub permissions: BTreeSet<String>,
    pub anonymous: bool,
}

#[derive(Debug, Error)]
pub enum SupabaseJwtError {
    #[error("Supabase JWT configuration is invalid")]
    InvalidConfiguration,
    #[error("Supabase JWKS is unavailable")]
    JwksUnavailable,
    #[error("Supabase JWKS is invalid")]
    InvalidJwks,
    #[error("Supabase JWT is invalid")]
    InvalidToken,
    #[error("Supabase JWT verifier state is unavailable")]
    Poisoned,
}

pub struct SupabaseJwtVerifier {
    config: SupabaseJwtConfig,
    cache: Mutex<JwksCache>,
}

struct JwksCache {
    set: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

impl SupabaseJwtVerifier {
    /// Builds a verifier without fetching keys until its first verification.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration or HTTP client setup.
    pub fn new(config: SupabaseJwtConfig) -> Result<Self, SupabaseJwtError> {
        let config = config.validate()?;
        Ok(Self {
            config,
            cache: Mutex::new(JwksCache {
                set: None,
                fetched_at: None,
            }),
        })
    }

    /// Verifies a JWT and returns bounded identity claims. The unverified
    /// header is used only to select a cached public key and allowed algorithm.
    ///
    /// # Errors
    ///
    /// Returns a generic rejection for malformed, unsigned, expired,
    /// wrong-issuer/audience, unknown-key, or invalid-claim tokens.
    pub fn verify(&self, token: &str) -> Result<VerifiedSupabaseIdentity, SupabaseJwtError> {
        validate_token_shape(token)?;
        let header = decode_header(token).map_err(|_| SupabaseJwtError::InvalidToken)?;
        if !algorithm_is_allowed(header.alg)
            || header
                .typ
                .as_deref()
                .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("JWT"))
        {
            return Err(SupabaseJwtError::InvalidToken);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|kid| !kid.is_empty() && kid.len() <= MAX_KEY_ID_BYTES)
            .ok_or(SupabaseJwtError::InvalidToken)?;
        let jwk = self.key_for(kid)?;
        validate_jwk(&jwk, header.alg)?;
        let decoding_key =
            DecodingKey::from_jwk(&jwk).map_err(|_| SupabaseJwtError::InvalidToken)?;
        let mut validation = Validation::new(header.alg);
        validation.leeway = self.config.clock_skew_seconds;
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
        if let Some(audience) = self.config.expected_audience.as_deref() {
            validation.set_audience(&[audience]);
        } else {
            validation.validate_aud = false;
        }
        let claims = decode::<SupabaseClaims>(token, &decoding_key, &validation)
            .map_err(|_| SupabaseJwtError::InvalidToken)?
            .claims;
        claims.into_identity(&self.config)
    }

    fn key_for(&self, kid: &str) -> Result<Jwk, SupabaseJwtError> {
        let mut cache = self.lock_cache()?;
        let now = Instant::now();
        let expired = cache.fetched_at.is_none_or(|fetched_at| {
            now.duration_since(fetched_at) >= Duration::from_secs(self.config.jwks_cache_seconds)
        });
        let missing = cache.set.as_ref().and_then(|set| set.find(kid)).is_none();
        let refresh_allowed = cache
            .fetched_at
            .is_none_or(|fetched_at| now.duration_since(fetched_at) >= MIN_REFRESH_INTERVAL);
        if cache.set.is_none() || expired || (missing && refresh_allowed) {
            cache.set = Some(self.fetch_jwks()?);
            cache.fetched_at = Some(now);
        }
        cache
            .set
            .as_ref()
            .and_then(|set| set.find(kid))
            .cloned()
            .ok_or(SupabaseJwtError::InvalidToken)
    }

    fn fetch_jwks(&self) -> Result<JwkSet, SupabaseJwtError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .redirect(Policy::none())
            .user_agent("stirling-pdf-rust-jwks/1")
            .build()
            .map_err(|_| SupabaseJwtError::JwksUnavailable)?;
        let response = client
            .get(self.config.jwks_url())
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| SupabaseJwtError::JwksUnavailable)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES)
        {
            return Err(SupabaseJwtError::InvalidJwks);
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_JWKS_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SupabaseJwtError::JwksUnavailable)?;
        if bytes.len() as u64 > MAX_JWKS_BYTES {
            return Err(SupabaseJwtError::InvalidJwks);
        }
        let set: JwkSet =
            serde_json::from_slice(&bytes).map_err(|_| SupabaseJwtError::InvalidJwks)?;
        validate_jwks(&set)?;
        Ok(set)
    }

    fn lock_cache(&self) -> Result<MutexGuard<'_, JwksCache>, SupabaseJwtError> {
        self.cache.lock().map_err(|_| SupabaseJwtError::Poisoned)
    }

    #[cfg(test)]
    pub(crate) fn with_jwks(
        config: SupabaseJwtConfig,
        set: JwkSet,
    ) -> Result<Self, SupabaseJwtError> {
        validate_jwks(&set)?;
        let verifier = Self::new(config)?;
        *verifier.lock_cache()? = JwksCache {
            set: Some(set),
            fetched_at: Some(Instant::now()),
        };
        Ok(verifier)
    }
}

#[derive(Deserialize)]
struct SupabaseClaims {
    iss: String,
    aud: AudienceClaim,
    exp: u64,
    iat: u64,
    sub: String,
    role: String,
    aal: String,
    session_id: String,
    email: Option<String>,
    #[serde(default)]
    is_anonymous: bool,
    #[serde(default)]
    app_metadata: Option<AppMetadataClaims>,
    #[serde(default)]
    permissions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn values(&self) -> Vec<&str> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Deserialize)]
struct AppMetadataClaims {
    provider: Option<String>,
}

impl SupabaseClaims {
    fn into_identity(
        self,
        config: &SupabaseJwtConfig,
    ) -> Result<VerifiedSupabaseIdentity, SupabaseJwtError> {
        let now = u64::try_from(chrono::Utc::now().timestamp())
            .map_err(|_| SupabaseJwtError::InvalidToken)?;
        if self.iss != config.issuer
            || self.exp <= self.iat
            || self.iat > now.saturating_add(config.clock_skew_seconds)
            || !bounded_claim(&self.sub, MAX_SUBJECT_BYTES)
            || !looks_like_uuid(&self.sub)
            || !bounded_claim(&self.role, MAX_ROLE_BYTES)
            || !bounded_claim(&self.aal, MAX_ROLE_BYTES)
            || !bounded_claim(&self.session_id, MAX_SESSION_ID_BYTES)
        {
            return Err(SupabaseJwtError::InvalidToken);
        }
        let audiences = self.aud.values();
        if audiences.is_empty()
            || audiences
                .iter()
                .any(|audience| !bounded_claim(audience, MAX_ROLE_BYTES))
            || config
                .expected_audience
                .as_deref()
                .is_some_and(|expected| !audiences.contains(&expected))
        {
            return Err(SupabaseJwtError::InvalidToken);
        }
        let email = self
            .email
            .map(|email| email.trim().to_lowercase())
            .filter(|email| !email.is_empty());
        if email
            .as_deref()
            .is_some_and(|email| !valid_email_claim(email))
            || (!self.is_anonymous && email.is_none())
        {
            return Err(SupabaseJwtError::InvalidToken);
        }
        let provider = self
            .app_metadata
            .and_then(|metadata| metadata.provider)
            .map(|provider| provider.trim().to_lowercase())
            .filter(|provider| bounded_claim(provider, MAX_ROLE_BYTES));
        if !self.is_anonymous && provider.is_none() {
            return Err(SupabaseJwtError::InvalidToken);
        }
        if self.permissions.len() > MAX_PERMISSIONS {
            return Err(SupabaseJwtError::InvalidToken);
        }
        let permissions = self
            .permissions
            .into_iter()
            .map(|permission| permission.trim().to_owned())
            .collect::<BTreeSet<_>>();
        if permissions
            .iter()
            .any(|permission| !bounded_claim(permission, MAX_PERMISSION_BYTES))
        {
            return Err(SupabaseJwtError::InvalidToken);
        }
        let authentication_type = if self.is_anonymous {
            "anonymous"
        } else if provider.as_deref() == Some("email") {
            "supabase"
        } else {
            "oauth2"
        };
        let username = if self.is_anonymous {
            format!("anon_{}", self.sub)
        } else {
            email.clone().ok_or(SupabaseJwtError::InvalidToken)?
        };
        Ok(VerifiedSupabaseIdentity {
            issuer: self.iss,
            subject: self.sub,
            username,
            email,
            authentication_type: authentication_type.to_owned(),
            role: if self.is_anonymous {
                "ROLE_LIMITED_API_USER".to_owned()
            } else {
                "ROLE_USER".to_owned()
            },
            session_id: self.session_id,
            permissions,
            anonymous: self.is_anonymous,
        })
    }
}

/// Shared HTTPS-first URL-scheme policy for remote-issuer style configuration:
/// HTTPS is always allowed, and plain HTTP only against a loopback host (local
/// dev / self-hosted testing). Reused by [`crate::oidc_discovery`] so issuer and
/// discovered-endpoint validation follow the same security posture as Supabase
/// JWKS issuer validation rather than inventing a second policy.
pub(crate) fn issuer_url_scheme_is_allowed(url: &Url) -> bool {
    if url.scheme() == "https" {
        return url.host_str().is_some();
    }
    url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"))
}

fn validate_token_shape(token: &str) -> Result<(), SupabaseJwtError> {
    if token.is_empty()
        || token.len() > MAX_JWT_BYTES
        || !token.is_ascii()
        || token.bytes().filter(|byte| *byte == b'.').count() != 2
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(SupabaseJwtError::InvalidToken);
    }
    Ok(())
}

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

fn validate_jwk(jwk: &Jwk, algorithm: Algorithm) -> Result<(), SupabaseJwtError> {
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
        return Err(SupabaseJwtError::InvalidToken);
    }
    Ok(())
}

fn validate_jwks(set: &JwkSet) -> Result<(), SupabaseJwtError> {
    if set.keys.is_empty() || set.keys.len() > MAX_JWKS_KEYS {
        return Err(SupabaseJwtError::InvalidJwks);
    }
    let mut key_ids = BTreeSet::new();
    for key in &set.keys {
        let key_id = key
            .common
            .key_id
            .as_deref()
            .filter(|key_id| !key_id.is_empty() && key_id.len() <= MAX_KEY_ID_BYTES)
            .ok_or(SupabaseJwtError::InvalidJwks)?;
        if !key_ids.insert(key_id) || matches!(key.algorithm, AlgorithmParameters::OctetKey(_)) {
            return Err(SupabaseJwtError::InvalidJwks);
        }
    }
    Ok(())
}

fn bounded_claim(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_email_claim(email: &str) -> bool {
    bounded_claim(email, MAX_EMAIL_BYTES)
        && email
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'))
        && !email.starts_with("anon_")
}

fn looks_like_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde::Serialize;

    use super::{SupabaseJwtConfig, SupabaseJwtError, SupabaseJwtVerifier};

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        iat: u64,
        sub: &'a str,
        role: &'a str,
        aal: &'a str,
        session_id: &'a str,
        email: Option<&'a str>,
        is_anonymous: bool,
        app_metadata: serde_json::Value,
        permissions: Vec<&'a str>,
    }

    #[test]
    fn verifies_signature_issuer_audience_claims_and_permissions()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.token(false)?;
        let identity = fixture.verifier.verify(&token)?;
        assert_eq!(identity.subject, "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(identity.username, "user@example.test");
        assert_eq!(identity.authentication_type, "oauth2");
        assert_eq!(identity.role, "ROLE_USER");
        assert!(identity.permissions.contains("pdf.read"));
        Ok(())
    }

    #[test]
    fn rejects_tampering_wrong_audience_unknown_key_and_hmac_jwks()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut tampered = fixture.token(false)?;
        tampered.push('x');
        assert!(matches!(
            fixture.verifier.verify(&tampered),
            Err(SupabaseJwtError::InvalidToken)
        ));
        let wrong_audience = fixture.signed_token("other", false, Some("user@example.test"))?;
        assert!(matches!(
            fixture.verifier.verify(&wrong_audience),
            Err(SupabaseJwtError::InvalidToken)
        ));
        let unknown_key = fixture.signed_token_with_kid("unknown", "authenticated", false)?;
        assert!(matches!(
            fixture.verifier.verify(&unknown_key),
            Err(SupabaseJwtError::InvalidToken)
        ));
        let hmac: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "oct",
                "k": URL_SAFE_NO_PAD.encode([7_u8; 32]),
                "kid": "symmetric",
                "alg": "HS256"
            }]
        }))?;
        assert!(matches!(
            SupabaseJwtVerifier::with_jwks(test_config(), hmac),
            Err(SupabaseJwtError::InvalidJwks)
        ));
        Ok(())
    }

    #[test]
    fn requires_email_provider_for_full_users_and_bounds_anonymous_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let missing_email = fixture.signed_token("authenticated", false, None)?;
        assert!(matches!(
            fixture.verifier.verify(&missing_email),
            Err(SupabaseJwtError::InvalidToken)
        ));
        let token = fixture.token(true)?;
        let anonymous = fixture.verifier.verify(&token)?;
        assert!(anonymous.anonymous);
        assert!(anonymous.username.starts_with("anon_"));
        assert_eq!(anonymous.role, "ROLE_LIMITED_API_USER");
        Ok(())
    }

    struct Fixture {
        verifier: SupabaseJwtVerifier,
        encoding_key: EncodingKey,
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
                    "kid": "test-key",
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(modulus),
                    "e": URL_SAFE_NO_PAD.encode(exponent)
                }]
            }))?;
            Ok(Self {
                verifier: SupabaseJwtVerifier::with_jwks(test_config(), jwks)?,
                encoding_key,
            })
        }

        fn token(&self, anonymous: bool) -> Result<String, jsonwebtoken::errors::Error> {
            self.signed_token(
                "authenticated",
                anonymous,
                (!anonymous).then_some("user@example.test"),
            )
        }

        fn signed_token(
            &self,
            audience: &str,
            anonymous: bool,
            email: Option<&str>,
        ) -> Result<String, jsonwebtoken::errors::Error> {
            self.signed_token_with("test-key", audience, anonymous, email)
        }

        fn signed_token_with_kid(
            &self,
            kid: &str,
            audience: &str,
            anonymous: bool,
        ) -> Result<String, jsonwebtoken::errors::Error> {
            self.signed_token_with(kid, audience, anonymous, Some("user@example.test"))
        }

        fn signed_token_with(
            &self,
            kid: &str,
            audience: &str,
            anonymous: bool,
            email: Option<&str>,
        ) -> Result<String, jsonwebtoken::errors::Error> {
            let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default();
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(kid.to_owned());
            encode(
                &header,
                &TestClaims {
                    iss: "https://project.supabase.co/auth/v1",
                    aud: audience,
                    exp: now + 300,
                    iat: now,
                    sub: "123e4567-e89b-12d3-a456-426614174000",
                    role: "authenticated",
                    aal: "aal1",
                    session_id: "session-123",
                    email,
                    is_anonymous: anonymous,
                    app_metadata: serde_json::json!({ "provider": "github" }),
                    permissions: vec!["pdf.read", "pdf.write"],
                },
                &self.encoding_key,
            )
        }
    }

    fn test_config() -> SupabaseJwtConfig {
        SupabaseJwtConfig {
            issuer: "https://project.supabase.co/auth/v1".to_owned(),
            expected_audience: Some("authenticated".to_owned()),
            clock_skew_seconds: 120,
            jwks_cache_seconds: 300,
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
}
