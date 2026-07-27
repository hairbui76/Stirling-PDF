//! `OAuth2` resource-server primitives for the MCP boundary — the Rust port of
//! Java's `McpSecurityConfig` OAuth chain, `McpAudienceValidator`, and
//! `McpAuthenticationEntryPoint`.
//!
//! Java runs `/mcp` as a Spring `OAuth2` resource server whenever
//! `mcp.auth.mode` is anything other than exactly `apikey`: bearer JWTs are
//! validated against the issuer's JWKS (issuer + expiry + RFC 8707 audience),
//! the token's `scope` claim becomes the caller's granted tool scopes, a 401
//! carries the RFC 9728 `WWW-Authenticate` pointer at the protected-resource
//! metadata document, and that document itself is served under
//! `/.well-known/oauth-protected-resource`.
//!
//! This module owns the pure/verification half of that surface:
//!
//! - [`McpOAuthVerifier`]: bearer-JWT validation. It deliberately **reuses**
//!   the repo's hardened OIDC primitives instead of growing a second JWT
//!   stack: [`crate::oidc_id_token`]'s shape/alg-confusion pre-gate
//!   (`validated_header_and_kid`), its bounded [`OidcJwksCache`] with the
//!   kid-miss refresh cooldown, its SSRF-safe JWKS fetch, and
//!   [`crate::oidc_discovery`]'s validated issuer discovery (used only when
//!   `mcp.auth.jwksUri` is blank, mirroring Java's
//!   `NimbusJwtDecoder.withIssuerLocation`).
//! - [`www_authenticate_challenge`]: the 401 challenge header, byte-modeled on
//!   Java's `McpAuthenticationEntryPoint` (X-Forwarded-aware metadata URL,
//!   `error="invalid_token"`, sanitized `error_description` only when a token
//!   was actually presented and rejected).
//! - [`protected_resource_metadata`]: the RFC 9728 document, matching the
//!   claims Spring's `OAuth2ProtectedResourceMetadataFilter` plus Java's
//!   `buildResourceMetadata` customizer emit.
//!
//! The HTTP wiring (routes, per-tool scope gating, account binding) lives in
//! [`crate::mcp`]; the account lookup itself is
//! `SecurityStore::bind_mcp_oauth_user`.
//!
//! # Documented divergences from Java (see `rust/contracts/mcp.md`)
//!
//! - `exp` is **required** (Java's `JwtTimestampValidator` accepts a token
//!   with no `exp`); `nbf` is not honored. Both directions are fail-closed or
//!   neutral for real IdP-minted access tokens.
//! - The JWKS/discovery fetches go through the SSRF-safe client (https or
//!   loopback-http only, reserved-IP resolve-and-pin rejection); Java fetches
//!   any configured URL.
//! - The algorithm allowlist is the repo-wide public-key set (RSA/PSS/ECDSA/
//!   `EdDSA`); Spring's default is RS256-only.
//! - The JOSE `typ` header is checked: absent, `JWT`, or RFC 9068
//!   `at+jwt`/`application/at+jwt` (all case-insensitive) are accepted, any
//!   other value is rejected. Java's Spring decoder applies **no** `typ`
//!   verification at all, so exotic typs pass Java but fail closed here.
//! - The challenge/metadata URL scheme falls back to `http` when
//!   `X-Forwarded-Proto` is absent; Java falls back to the request's own
//!   scheme. This server only terminates plain HTTP (TLS lives on a fronting
//!   proxy that sets the forwarded headers), so the two are equivalent in
//!   practice.

use std::collections::BTreeSet;

use axum::http::{HeaderMap, header};
use jsonwebtoken::{DecodingKey, Validation, decode, jwk::JwkSet};
use serde_json::{Map, Value};

use crate::{
    oidc_discovery::OidcDiscoveryCache,
    oidc_id_token::{
        CLOCK_SKEW_SECONDS, JwtTypPolicy, OidcIdTokenError, OidcJwksCache, fetch_jwks,
        validate_jwk, validated_header_and_kid_for,
    },
    runtime_config::McpConfig,
};

/// RFC 9728 well-known path prefix, identical to Spring's
/// `OAuth2ProtectedResourceMetadataFilter.DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI`.
pub(crate) const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// The scopes this server advertises and enforces, matching Java.
const READ_SCOPE: &str = "mcp.tools.read";
const WRITE_SCOPE: &str = "mcp.tools.write";

/// A bearer JWT that passed signature, issuer, expiry, and RFC 8707 audience
/// validation. Only what the MCP boundary consumes is surfaced: the value of
/// the configured username claim (Java's `McpUserBindingFilter` input) and the
/// granted `scope` claim entries (Java's `SCOPE_` authorities).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpVerifiedToken {
    /// The configured `mcp.auth.usernameClaim` value, if present on the token.
    /// `None` maps to Java's 403 "Token is missing the ... claim" rejection.
    pub(crate) username_claim_value: Option<String>,
    /// The token's `scope` claim entries (space-split string or string array),
    /// exactly the set Java's `JwtGrantedAuthoritiesConverter` would grant.
    pub(crate) scopes: BTreeSet<String>,
}

/// Why a presented bearer token was rejected. `reason` feeds the sanitized
/// `error_description` of the challenge header and the server log, mirroring
/// Java's `McpAuthenticationEntryPoint.rejectionReason` ("code - description").
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpTokenRejection {
    pub(crate) reason: String,
}

impl McpTokenRejection {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Validates MCP bearer JWTs the way Java's `mcpJwtDecoder` +
/// `McpAudienceValidator` chain does. Built once per router (it owns the
/// bounded discovery/JWKS caches) and shared behind an `Arc`.
pub(crate) struct McpOAuthVerifier {
    issuer: String,
    /// Explicit `mcp.auth.jwksUri`; blank means "derive from the issuer's
    /// `OpenID` discovery document" (Java's `withIssuerLocation`).
    jwks_uri: String,
    /// RFC 8707 accepted audiences in config order: `mcp.auth.resourceId`
    /// first, then `mcp.auth.acceptedAudiences`, blanks skipped, first-wins
    /// dedupe — Java's `McpAudienceValidator` `LinkedHashSet`. Empty fails
    /// closed against every token.
    accepted_audiences: Vec<String>,
    /// `mcp.auth.usernameClaim`, defaulting blank to `sub` exactly as Java's
    /// `McpUserBindingFilter` constructor does.
    username_claim: String,
    discovery: OidcDiscoveryCache,
    jwks_cache: OidcJwksCache,
}

impl McpOAuthVerifier {
    pub(crate) fn from_config(config: &McpConfig) -> Self {
        let auth = &config.auth;
        let mut accepted_audiences = Vec::new();
        for audience in std::iter::once(auth.resource_id.as_str())
            .chain(auth.accepted_audiences.iter().map(String::as_str))
        {
            if !audience.trim().is_empty()
                && !accepted_audiences.iter().any(|known| known == audience)
            {
                accepted_audiences.push(audience.to_owned());
            }
        }
        let username_claim = if auth.username_claim.trim().is_empty() {
            "sub".to_owned()
        } else {
            auth.username_claim.clone()
        };
        Self {
            issuer: auth.issuer_uri.clone(),
            jwks_uri: auth.jwks_uri.clone(),
            accepted_audiences,
            username_claim,
            discovery: OidcDiscoveryCache::new(),
            jwks_cache: OidcJwksCache::new(),
        }
    }

    pub(crate) fn username_claim(&self) -> &str {
        &self.username_claim
    }

    /// Validates a presented bearer JWT. Performs blocking network I/O (JWKS
    /// fetch, possibly issuer discovery), so callers must run it on a blocking
    /// worker.
    ///
    /// # Errors
    ///
    /// Returns an [`McpTokenRejection`] whose reason names the failed stage;
    /// the audience messages are byte-identical to Java's
    /// `McpAudienceValidator`, and the unset-issuer reason carries Java's
    /// `mcp.auth.issuer-uri is not configured` fail-closed-decoder text.
    pub(crate) fn verify(&self, token: &str) -> Result<McpVerifiedToken, McpTokenRejection> {
        self.verify_with_fetch(token, fetch_jwks)
    }

    /// [`Self::verify`] with the JWKS fetch injected — the same test seam
    /// pattern as `verify_oidc_id_token_cached_with_fetch`.
    fn verify_with_fetch(
        &self,
        token: &str,
        fetch: impl Fn(&str) -> Result<JwkSet, OidcIdTokenError>,
    ) -> Result<McpVerifiedToken, McpTokenRejection> {
        if self.issuer.trim().is_empty() {
            // Java's fail-closed decoder: reject every token until configured.
            return Err(McpTokenRejection::new(
                "mcp.auth.issuer-uri is not configured",
            ));
        }
        // Shape + alg-confusion + kid pre-gate BEFORE any cache or network
        // interaction, exactly like the OIDC callback path — but with the
        // access-token `typ` policy: RFC 9068 access tokens (`typ: at+jwt`,
        // what conformant IdPs like Auth0 mint) must pass here, since Java's
        // Spring decoder applies no `typ` verification at all.
        let (header, kid) = validated_header_and_kid_for(token, JwtTypPolicy::AccessToken)
            .map_err(|_| {
                McpTokenRejection::new("Bearer token is malformed or uses a disallowed algorithm")
            })?;
        let jwks_uri = self.resolve_jwks_uri()?;
        let jwks =
            self.jwks_cache
                .jwks_for(&jwks_uri, &kid, fetch)
                .map_err(|error| match error {
                    OidcIdTokenError::InvalidJwks => McpTokenRejection::new("JWKS is invalid"),
                    _ => McpTokenRejection::new("JWKS is unavailable"),
                })?;
        let jwk = jwks
            .find(&kid)
            .ok_or_else(|| McpTokenRejection::new("Token signing key was not found in the JWKS"))?;
        validate_jwk(jwk, header.alg)
            .map_err(|_| McpTokenRejection::new("Token signing key was not found in the JWKS"))?;
        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|_| McpTokenRejection::new("Token signing key was not found in the JWKS"))?;

        let mut validation = Validation::new(header.alg);
        validation.leeway = CLOCK_SKEW_SECONDS;
        validation.set_issuer(&[self.issuer.as_str()]);
        // RFC 8707 audience is validated manually below so the rejection can
        // carry Java's exact McpAudienceValidator message.
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss"]);
        let claims = decode::<Map<String, Value>>(token, &decoding_key, &validation)
            .map_err(|_| McpTokenRejection::new("Token signature, issuer, or expiry is invalid"))?
            .claims;

        self.validate_audience(&claims)?;
        Ok(McpVerifiedToken {
            username_claim_value: claim_as_string(&claims, &self.username_claim),
            scopes: extract_scopes(&claims),
        })
    }

    /// The JWKS location: the explicit `mcp.auth.jwksUri` when set, otherwise
    /// the issuer's discovered `jwks_uri` (validated, SSRF-guarded, cached).
    fn resolve_jwks_uri(&self) -> Result<String, McpTokenRejection> {
        let configured = self.jwks_uri.trim();
        if !configured.is_empty() {
            return Ok(configured.to_owned());
        }
        self.discovery
            .discover(&self.issuer)
            .map(|metadata| metadata.jwks_uri)
            .map_err(|_| McpTokenRejection::new("OAuth issuer discovery failed"))
    }

    /// RFC 8707 audience binding with Java's exact `McpAudienceValidator`
    /// messages: fails closed when nothing is configured, otherwise requires
    /// the token's `aud` (string or array, Nimbus semantics) to contain one
    /// accepted audience.
    fn validate_audience(&self, claims: &Map<String, Value>) -> Result<(), McpTokenRejection> {
        if self.accepted_audiences.is_empty() {
            return Err(McpTokenRejection::new(
                "MCP audience binding is not configured; rejecting all tokens until \
                 mcp.auth.resource-id or mcp.auth.accepted-audiences is set.",
            ));
        }
        let matched = match claims.get("aud") {
            Some(Value::String(audience)) => self
                .accepted_audiences
                .iter()
                .any(|accepted| accepted == audience),
            Some(Value::Array(audiences)) => {
                audiences.iter().filter_map(Value::as_str).any(|audience| {
                    self.accepted_audiences
                        .iter()
                        .any(|accepted| accepted == audience)
                })
            }
            _ => false,
        };
        if matched {
            Ok(())
        } else {
            Err(McpTokenRejection::new(format!(
                "Token audience does not include this server's resource id or an accepted \
                 audience ({}).",
                self.accepted_audiences.join(", ")
            )))
        }
    }
}

/// The token's granted scopes exactly as Java's `JwtGrantedAuthoritiesConverter`
/// (claim name pinned to `scope`) reads them: a string claim is split on single
/// spaces, an array claim contributes its string entries, anything else grants
/// nothing.
fn extract_scopes(claims: &Map<String, Value>) -> BTreeSet<String> {
    match claims.get("scope") {
        Some(Value::String(scope)) => scope
            .split(' ')
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => BTreeSet::new(),
    }
}

/// A claim as a string, following Java `Jwt.getClaimAsString`'s conversion of
/// the scalar JSON types; structured values yield `None`.
fn claim_as_string(claims: &Map<String, Value>, name: &str) -> Option<String> {
    match claims.get(name)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Builds the 401 `WWW-Authenticate` challenge, porting Java's
/// `McpAuthenticationEntryPoint.commence` byte-for-byte where it authored the
/// format: `Bearer error="invalid_token"`, an `error_description` only when a
/// token was presented and rejected (`invalid_token - <reason>`, CR/LF/quotes
/// sanitized to spaces and trimmed), and the RFC 9728 `resource_metadata`
/// pointer derived from the client-most `X-Forwarded-*` values with
/// default-port elision.
pub(crate) fn www_authenticate_challenge(
    headers: &HeaderMap,
    metadata_path: &str,
    rejection_reason: Option<&str>,
) -> String {
    let metadata_url = external_base_url(headers) + metadata_path;
    let mut challenge = String::from("Bearer error=\"invalid_token\"");
    if let Some(reason) = rejection_reason {
        // Java prefixes the OAuth2 error code: "invalid_token - <description>".
        let combined = format!("invalid_token - {reason}");
        let sanitized = combined.replace(['\r', '\n', '"'], " ");
        challenge.push_str(", error_description=\"");
        challenge.push_str(sanitized.trim());
        challenge.push('"');
    }
    challenge.push_str(", resource_metadata=\"");
    challenge.push_str(&metadata_url);
    challenge.push('"');
    challenge
}

/// `scheme://host[:port]` for links this server hands back to the client:
/// client-most `X-Forwarded-Proto`/`X-Forwarded-Host`/`X-Forwarded-Port` when
/// present, else the request `Host`, with default ports elided — Java's
/// `McpAuthenticationEntryPoint` helpers. Quotes are stripped so a hostile
/// forwarded header cannot break out of a quoted header parameter.
fn external_base_url(headers: &HeaderMap) -> String {
    // Java falls back to request.getScheme(); this server only terminates
    // plain HTTP (TLS lives on a fronting proxy that sets X-Forwarded-Proto),
    // so a literal "http" fallback is the same value.
    let scheme = first_forwarded(headers, "x-forwarded-proto").unwrap_or_else(|| "http".to_owned());
    let scheme = sanitize_url_part(&scheme);
    let authority = forwarded_authority(headers, &scheme);
    format!("{scheme}://{}", sanitize_url_part(&authority))
}

/// host[:port] from forwarded headers when present, else the `Host` header.
fn forwarded_authority(headers: &HeaderMap, scheme: &str) -> String {
    if let Some(host) = first_forwarded(headers, "x-forwarded-host").filter(|host| !host.is_empty())
    {
        // X-Forwarded-Host may already carry a port.
        if authority_port(&host).is_some() {
            return host;
        }
        if let Some(port) = first_forwarded(headers, "x-forwarded-port")
            .filter(|port| !is_default_port(scheme, port))
        {
            return format!("{host}:{port}");
        }
        return host;
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("localhost")
        .trim()
        .to_owned();
    match authority_port(&host) {
        Some((name, port)) if is_default_port(scheme, port) => name.to_owned(),
        _ => host,
    }
}

/// Splits `host[:port]`, tolerating a bracketed IPv6 literal; `None` when no
/// explicit port is present.
fn authority_port(authority: &str) -> Option<(&str, &str)> {
    let (name, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let after = &rest[end + 1..];
        (&authority[..end + 2], after.strip_prefix(':')?)
    } else {
        let (name, port) = authority.rsplit_once(':')?;
        (name, port)
    };
    (!port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())).then_some((name, port))
}

fn is_default_port(scheme: &str, port: &str) -> bool {
    (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

/// First (client-most) value of a possibly comma-listed forwarded header,
/// trimmed; `None` when absent or blank.
fn first_forwarded(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let first = value.split(',').next().unwrap_or(value).trim();
    (!first.is_empty()).then(|| first.to_owned())
}

/// Strips characters that would corrupt a quoted header parameter or a URL
/// this server echoes back.
fn sanitize_url_part(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '"')
        .collect()
}

/// The RFC 9728 protected-resource metadata document, matching what Spring's
/// `OAuth2ProtectedResourceMetadataFilter` emits after Java's
/// `buildResourceMetadata` customizer runs:
///
/// - `resource`: `mcp.auth.resourceId` when set, otherwise the request URL
///   with the well-known segment removed (Spring's `resolveResourceIdentifier`
///   default, so `GET …/.well-known/oauth-protected-resource/mcp` derives
///   `…/mcp`);
/// - `bearer_methods_supported`: `["header"]` and
///   `tls_client_certificate_bound_access_tokens`: `true` (Spring's fixed
///   pre-customizer claims);
/// - `authorization_servers`: the configured issuer, when set;
/// - `scopes_supported`: the two tool scopes, only while scope enforcement is
///   on (advertising scopes the `IdP` cannot mint breaks spec-compliant
///   clients).
pub(crate) fn protected_resource_metadata(
    config: &McpConfig,
    headers: &HeaderMap,
    request_path: &str,
) -> Value {
    let mut document = Map::new();
    let resource_id = config.auth.resource_id.trim();
    let resource = if resource_id.is_empty() {
        let tail = request_path
            .strip_prefix(PROTECTED_RESOURCE_METADATA_PATH)
            .unwrap_or("");
        external_base_url(headers) + tail
    } else {
        resource_id.to_owned()
    };
    document.insert("resource".to_owned(), Value::String(resource));
    document.insert(
        "bearer_methods_supported".to_owned(),
        Value::Array(vec![Value::String("header".to_owned())]),
    );
    document.insert(
        "tls_client_certificate_bound_access_tokens".to_owned(),
        Value::Bool(true),
    );
    let issuer = config.auth.issuer_uri.trim();
    if !issuer.is_empty() {
        document.insert(
            "authorization_servers".to_owned(),
            Value::Array(vec![Value::String(issuer.to_owned())]),
        );
    }
    if config.scopes_enabled {
        document.insert(
            "scopes_supported".to_owned(),
            Value::Array(vec![
                Value::String(READ_SCOPE.to_owned()),
                Value::String(WRITE_SCOPE.to_owned()),
            ]),
        );
    }
    Value::Object(document)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::http::{HeaderMap, HeaderValue};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use crypto_bigint::{ByteOrder, Encoding as _};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode, jwk::JwkSet};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
    use serde::Serialize;
    use serde_json::json;

    use super::{
        McpOAuthVerifier, McpTokenRejection, McpVerifiedToken, PROTECTED_RESOURCE_METADATA_PATH,
        protected_resource_metadata, www_authenticate_challenge,
    };
    use crate::{
        oidc_id_token::OidcIdTokenError,
        runtime_config::{McpAuthConfig, McpConfig},
    };

    const ISSUER: &str = "https://mcp-issuer.example.test";
    const RESOURCE_ID: &str = "http://localhost:8080/mcp";
    const KID: &str = "mcp-oauth-test-key";

    #[derive(Serialize)]
    #[serde(untagged)]
    enum Aud<'a> {
        Single(&'a str),
        Multiple(Vec<&'a str>),
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        iss: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<Aud<'a>>,
        exp: u64,
        iat: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
    }

    fn now_secs() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default()
    }

    fn valid_claims() -> TestClaims<'static> {
        let now = now_secs();
        TestClaims {
            iss: ISSUER,
            sub: Some("mcp-user@example.test"),
            aud: Some(Aud::Single(RESOURCE_ID)),
            exp: now + 300,
            iat: now,
            scope: Some(json!("mcp.tools.read mcp.tools.write")),
            email: Some("mcp-user@example.test"),
        }
    }

    struct Fixture {
        jwks: JwkSet,
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
            let jwks: JwkSet = serde_json::from_value(json!({
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "kid": KID,
                    "alg": "RS256",
                    "n": URL_SAFE_NO_PAD.encode(&modulus),
                    "e": URL_SAFE_NO_PAD.encode(exponent)
                }]
            }))?;
            Ok(Self { jwks, encoding_key })
        }

        fn sign(&self, claims: &TestClaims) -> Result<String, jsonwebtoken::errors::Error> {
            self.sign_with_typ(claims, None)
        }

        fn sign_with_typ(
            &self,
            claims: &TestClaims,
            typ: Option<&str>,
        ) -> Result<String, jsonwebtoken::errors::Error> {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(KID.to_owned());
            if let Some(typ) = typ {
                header.typ = Some(typ.to_owned());
            }
            encode(&header, claims, &self.encoding_key)
        }

        fn verify(&self, token: &str) -> Result<McpVerifiedToken, McpTokenRejection> {
            default_verifier().verify_with_fetch(token, |_| Ok(self.jwks.clone()))
        }
    }

    fn default_verifier() -> McpOAuthVerifier {
        verifier_with(RESOURCE_ID, Vec::new())
    }

    fn verifier_with(resource_id: &str, accepted: Vec<String>) -> McpOAuthVerifier {
        McpOAuthVerifier::from_config(&test_config(resource_id, accepted))
    }

    fn test_config(resource_id: &str, accepted: Vec<String>) -> McpConfig {
        McpConfig {
            enabled: true,
            scopes_enabled: true,
            engine_capability_refresh_minutes: 5,
            allowed_operations: Vec::new(),
            blocked_operations: Vec::new(),
            max_request_bytes: 1024 * 1024,
            max_inline_response_bytes: 1024 * 1024,
            auth: McpAuthConfig {
                mode: "oauth".to_owned(),
                issuer_uri: ISSUER.to_owned(),
                jwks_uri: format!("{ISSUER}/jwks.json"),
                resource_id: resource_id.to_owned(),
                accepted_audiences: accepted,
                username_claim: "sub".to_owned(),
                require_existing_account: true,
            },
        }
    }

    fn minimal_unsigned_bytes(bytes: impl AsRef<[u8]>) -> Vec<u8> {
        let bytes = bytes.as_ref();
        let start = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len());
        bytes[start..].to_vec()
    }

    #[test]
    fn verifies_a_valid_token_and_extracts_username_and_scopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.sign(&valid_claims())?;
        let verified = fixture
            .verify(&token)
            .map_err(|rejection| rejection.reason)?;
        assert_eq!(
            verified.username_claim_value.as_deref(),
            Some("mcp-user@example.test")
        );
        assert_eq!(
            verified.scopes,
            BTreeSet::from(["mcp.tools.read".to_owned(), "mcp.tools.write".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn scope_array_and_custom_username_claim_are_honored() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.scope = Some(json!(["mcp.tools.read"]));
        let token = fixture.sign(&claims)?;
        let mut config = test_config(RESOURCE_ID, Vec::new());
        config.auth.username_claim = "email".to_owned();
        let custom_claim = McpOAuthVerifier::from_config(&config);
        let granted = custom_claim
            .verify_with_fetch(&token, |_| Ok(fixture.jwks.clone()))
            .map_err(|rejection| rejection.reason)?;
        assert_eq!(
            granted.username_claim_value.as_deref(),
            Some("mcp-user@example.test")
        );
        assert_eq!(
            granted.scopes,
            BTreeSet::from(["mcp.tools.read".to_owned()])
        );
        Ok(())
    }

    #[test]
    fn missing_scope_and_username_claims_yield_empty_grants()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.scope = None;
        claims.sub = None;
        let token = fixture.sign(&claims)?;
        let verified = fixture
            .verify(&token)
            .map_err(|rejection| rejection.reason)?;
        assert_eq!(verified.username_claim_value, None);
        assert!(verified.scopes.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_when_issuer_is_unconfigured_with_javas_fail_closed_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.sign(&valid_claims())?;
        let mut config = test_config(RESOURCE_ID, Vec::new());
        config.auth.issuer_uri = String::new();
        let verifier = McpOAuthVerifier::from_config(&config);
        let rejection = verifier
            .verify_with_fetch(&token, |_| Ok(fixture.jwks.clone()))
            .err()
            .ok_or("blank issuer must fail closed")?;
        assert_eq!(rejection.reason, "mcp.auth.issuer-uri is not configured");
        Ok(())
    }

    #[test]
    fn rejects_wrong_audience_with_javas_exact_message() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.aud = Some(Aud::Single("https://someone-else.example.test"));
        let token = fixture.sign(&claims)?;
        let rejection = fixture
            .verify(&token)
            .err()
            .ok_or("wrong audience must fail")?;
        assert_eq!(
            rejection.reason,
            format!(
                "Token audience does not include this server's resource id or an accepted \
                 audience ({RESOURCE_ID})."
            )
        );
        Ok(())
    }

    #[test]
    fn accepts_an_additional_audience_and_audience_arrays() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let mut claims = valid_claims();
        claims.aud = Some(Aud::Multiple(vec!["unrelated", "authenticated"]));
        let token = fixture.sign(&claims)?;
        let verifier = verifier_with(RESOURCE_ID, vec!["authenticated".to_owned()]);
        assert!(
            verifier
                .verify_with_fetch(&token, |_| Ok(fixture.jwks.clone()))
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn rejects_when_no_audience_is_configured_with_javas_exact_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.sign(&valid_claims())?;
        let verifier = verifier_with("", Vec::new());
        let rejection = verifier
            .verify_with_fetch(&token, |_| Ok(fixture.jwks.clone()))
            .err()
            .ok_or("unconfigured audience binding must fail closed")?;
        assert_eq!(
            rejection.reason,
            "MCP audience binding is not configured; rejecting all tokens until \
             mcp.auth.resource-id or mcp.auth.accepted-audiences is set."
        );
        Ok(())
    }

    #[test]
    fn rejects_expired_and_wrong_issuer_and_missing_exp_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize)]
        struct NoExpiry<'a> {
            iss: &'a str,
            sub: &'a str,
            aud: &'a str,
        }

        let fixture = Fixture::new()?;
        let mut expired = valid_claims();
        expired.exp = now_secs().saturating_sub(600);
        let token = fixture.sign(&expired)?;
        assert!(fixture.verify(&token).is_err());

        let mut wrong_issuer = valid_claims();
        wrong_issuer.iss = "https://impostor.example.test";
        let token = fixture.sign(&wrong_issuer)?;
        assert!(fixture.verify(&token).is_err());

        // No exp at all: Rust deliberately rejects (documented divergence).
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        let token = encode(
            &header,
            &NoExpiry {
                iss: ISSUER,
                sub: "x",
                aud: RESOURCE_ID,
            },
            &fixture.encoding_key,
        )?;
        assert!(fixture.verify(&token).is_err());
        Ok(())
    }

    #[test]
    fn accepts_rfc9068_at_jwt_access_tokens() -> Result<(), Box<dyn std::error::Error>> {
        // Conformant IdPs (e.g. Auth0) mint access tokens with header typ
        // "at+jwt" (RFC 9068). Java's Spring decoder applies no typ check at
        // all, so these MUST verify here too.
        let fixture = Fixture::new()?;
        for typ in ["at+jwt", "AT+JWT", "application/at+jwt", "JWT"] {
            let token = fixture.sign_with_typ(&valid_claims(), Some(typ))?;
            let verified = fixture
                .verify(&token)
                .map_err(|rejection| format!("typ {typ} must verify: {}", rejection.reason))?;
            assert_eq!(
                verified.username_claim_value.as_deref(),
                Some("mcp-user@example.test")
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_an_unknown_typ_before_any_fetch() -> Result<(), Box<dyn std::error::Error>> {
        // Anything beyond JWT / RFC 9068 at+jwt stays rejected at the pre-gate
        // (documented fail-closed divergence: Java checks no typ at all).
        let fixture = Fixture::new()?;
        let token = fixture.sign_with_typ(&valid_claims(), Some("JOSE"))?;
        let rejection = default_verifier()
            .verify_with_fetch(&token, |_| Err(OidcIdTokenError::JwksUnavailable))
            .err()
            .ok_or("unknown typ must be rejected")?;
        assert_eq!(
            rejection.reason,
            "Bearer token is malformed or uses a disallowed algorithm"
        );
        Ok(())
    }

    #[test]
    fn rejects_an_hs256_token_signed_with_public_material_before_any_fetch()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_owned());
        let forged = encode(
            &header,
            &valid_claims(),
            &EncodingKey::from_secret(b"public-material"),
        )?;
        let rejection = default_verifier()
            .verify_with_fetch(&forged, |_| {
                // A fetch here would mean the pre-gate failed to run first;
                // surface it as an unavailable JWKS so the assertion below
                // (on the malformed-token reason) still catches the ordering
                // regression without panicking.
                Err(OidcIdTokenError::JwksUnavailable)
            })
            .err()
            .ok_or("HS256 must be rejected")?;
        assert_eq!(
            rejection.reason,
            "Bearer token is malformed or uses a disallowed algorithm"
        );
        Ok(())
    }

    #[test]
    fn rejects_an_alg_none_token_before_any_fetch() -> Result<(), Box<dyn std::error::Error>> {
        // "alg":"none" cannot be minted through jsonwebtoken's encoder, so the
        // compact form is assembled by hand (with a non-empty bogus signature
        // so the rejection exercises the algorithm gate, not the shape check).
        let header = URL_SAFE_NO_PAD.encode(format!(
            "{{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"{KID}\"}}"
        ));
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_claims())?);
        let signature = URL_SAFE_NO_PAD.encode(b"forged");
        let token = format!("{header}.{claims}.{signature}");
        let rejection = default_verifier()
            .verify_with_fetch(&token, |_| Err(OidcIdTokenError::JwksUnavailable))
            .err()
            .ok_or("alg=none must be rejected")?;
        assert_eq!(
            rejection.reason,
            "Bearer token is malformed or uses a disallowed algorithm"
        );
        Ok(())
    }

    #[test]
    fn propagates_jwks_fetch_failures_as_unavailable() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let token = fixture.sign(&valid_claims())?;
        let rejection = default_verifier()
            .verify_with_fetch(&token, |_| Err(OidcIdTokenError::JwksUnavailable))
            .err()
            .ok_or("fetch failure must reject")?;
        assert_eq!(rejection.reason, "JWKS is unavailable");
        Ok(())
    }

    #[test]
    fn from_config_dedupes_audiences_and_defaults_the_username_claim() {
        let mut config = test_config(
            RESOURCE_ID,
            vec![
                RESOURCE_ID.to_owned(),
                "  ".to_owned(),
                "authenticated".to_owned(),
            ],
        );
        config.auth.username_claim = "   ".to_owned();
        let verifier = McpOAuthVerifier::from_config(&config);
        assert_eq!(
            verifier.accepted_audiences,
            vec![RESOURCE_ID.to_owned(), "authenticated".to_owned()]
        );
        assert_eq!(verifier.username_claim(), "sub");
    }

    #[test]
    fn challenge_header_matches_javas_entry_point_format() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("internal:8080"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("pdf.example.test"),
        );
        headers.insert("x-forwarded-port", HeaderValue::from_static("443"));
        let metadata_path = format!("{PROTECTED_RESOURCE_METADATA_PATH}/mcp");

        let tokenless = www_authenticate_challenge(&headers, &metadata_path, None);
        assert_eq!(
            tokenless,
            "Bearer error=\"invalid_token\", resource_metadata=\"https://pdf.example.test/.well-known/oauth-protected-resource/mcp\""
        );

        let rejected = www_authenticate_challenge(
            &headers,
            &metadata_path,
            Some("Token audience does not include \"this\"\r\nserver"),
        );
        assert_eq!(
            rejected,
            "Bearer error=\"invalid_token\", error_description=\"invalid_token - Token audience does not include  this   server\", resource_metadata=\"https://pdf.example.test/.well-known/oauth-protected-resource/mcp\""
        );
    }

    #[test]
    fn challenge_authority_handles_ports_and_fallbacks() {
        // Forwarded host carrying its own port wins over X-Forwarded-Port.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("proxy.example.test:8443"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert("x-forwarded-port", HeaderValue::from_static("9999"));
        assert!(
            www_authenticate_challenge(&headers, "/x", None)
                .contains("resource_metadata=\"https://proxy.example.test:8443/x\"")
        );

        // Non-default forwarded port is appended; default is elided.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-host",
            HeaderValue::from_static("proxy.example.test"),
        );
        headers.insert("x-forwarded-port", HeaderValue::from_static("8081"));
        assert!(
            www_authenticate_challenge(&headers, "/x", None)
                .contains("resource_metadata=\"http://proxy.example.test:8081/x\"")
        );

        // No forwarding: Host header with a default port elided.
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("stirling.example.test:80"));
        assert!(
            www_authenticate_challenge(&headers, "/x", None)
                .contains("resource_metadata=\"http://stirling.example.test/x\"")
        );

        // Bracketed IPv6 literals keep their non-default port.
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("[::1]:8080"));
        assert!(
            www_authenticate_challenge(&headers, "/x", None)
                .contains("resource_metadata=\"http://[::1]:8080/x\"")
        );
    }

    #[test]
    fn metadata_document_matches_java_claims() {
        let config = test_config(RESOURCE_ID, Vec::new());
        let headers = HeaderMap::new();
        let document = protected_resource_metadata(
            &config,
            &headers,
            &format!("{PROTECTED_RESOURCE_METADATA_PATH}/mcp"),
        );
        assert_eq!(document["resource"], RESOURCE_ID);
        assert_eq!(document["authorization_servers"], json!([ISSUER]));
        assert_eq!(
            document["scopes_supported"],
            json!(["mcp.tools.read", "mcp.tools.write"])
        );
        assert_eq!(document["bearer_methods_supported"], json!(["header"]));
        assert_eq!(
            document["tls_client_certificate_bound_access_tokens"],
            json!(true)
        );
    }

    #[test]
    fn metadata_document_derives_resource_and_omits_optional_claims() {
        let mut config = test_config("", Vec::new());
        config.scopes_enabled = false;
        config.auth.issuer_uri = String::new();
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("pdf.example.test:8080"));
        let document = protected_resource_metadata(
            &config,
            &headers,
            &format!("{PROTECTED_RESOURCE_METADATA_PATH}/mcp"),
        );
        // Spring's resolveResourceIdentifier default: the request URL with the
        // well-known segment removed.
        assert_eq!(document["resource"], "http://pdf.example.test:8080/mcp");
        assert!(document.get("authorization_servers").is_none());
        assert!(document.get("scopes_supported").is_none());
    }
}
