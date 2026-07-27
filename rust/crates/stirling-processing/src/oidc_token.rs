//! OIDC token exchange, pure-function groundwork: builds the
//! authorization-code-for-token request components and parses the token
//! endpoint's response. Continues the OIDC login arc from
//! [`crate::oidc_authorization`] (which builds the authorization redirect and
//! the PKCE `code_verifier`).
//!
//! Covers both client shapes: the public-client PKCE case (no `client_secret`)
//! and the confidential-client case, where the configured `client_secret` is
//! carried as an HTTP Basic `Authorization` header per RFC 6749 section 2.3.1 —
//! the `client_secret_basic` method Spring's `ClientRegistration` infers when
//! Java's `security.oauth2.clientSecret` is set. Note the Appendix B subtlety:
//! the client id and secret are each `application/x-www-form-urlencoded`
//! encoded **before** the `id:secret` pair is base64'd. PKCE is kept for
//! confidential clients too (RFC 9700 section 2.1.1 recommends PKCE for all
//! clients) — a deliberate divergence from Spring, which applies PKCE only to
//! public clients.
//!
//! This is construction + parsing ONLY (verified against the RFC 6749, RFC 7636,
//! and `OpenID` Connect Core 1.0 spec text directly, not assumed). It does NOT:
//! - make any network call — the live POST to the token endpoint is a separate,
//!   SSRF-gated slice, because `token_endpoint` (though it came from a validated
//!   discovery document) must get resolve-and-pin protection before it is
//!   fetched;
//! - verify the `id_token` — this extracts it as an opaque string only; its
//!   signature/issuer/audience/expiry/`nonce` validation is a later slice;
//! - create a session or wire any route.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use thiserror::Error;
use url::form_urlencoded;
use zeroize::Zeroizing;

/// The request body media type for the token endpoint (RFC 6749 section 4.1.3:
/// "The client makes a request to the token endpoint by sending the following
/// parameters using the `application/x-www-form-urlencoded` format").
const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// The components of an RFC 6749 section 4.1.3 (plus RFC 7636 section 4.5
/// `code_verifier`) access-token request, ready for a later live-fetch slice to
/// POST. Constructed here, not sent.
#[derive(Clone, Eq, PartialEq)]
pub struct OidcTokenRequest {
    /// The URL to POST to — the provider's `token_endpoint`, passed through
    /// unchanged (the request parameters go in the body, not the URL). A later
    /// slice validates and SSRF-checks this before fetching it.
    pub token_endpoint: String,
    /// The request body media type: `application/x-www-form-urlencoded`.
    pub content_type: &'static str,
    /// The `application/x-www-form-urlencoded` request body.
    pub form_body: String,
    /// The `Authorization` header value for a confidential client — the RFC
    /// 6749 section 2.3.1 `client_secret_basic` credentials — or [`None`] for a
    /// public client (no header sent). Zeroized on drop: the base64 payload is
    /// trivially reversible to the raw `client_secret`.
    pub authorization: Option<Zeroizing<String>>,
}

/// Manual so the derived output can never leak the `authorization` credentials
/// (base64 of the client secret) into logs or test failure dumps.
impl std::fmt::Debug for OidcTokenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OidcTokenRequest")
            .field("token_endpoint", &self.token_endpoint)
            .field("content_type", &self.content_type)
            .field("form_body", &self.form_body)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// A successfully-parsed OIDC token response for the public-client PKCE case
/// (`OpenID` Connect Core 1.0 section 3.1.3.3 / RFC 6749 section 5.1).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OidcTokenResponse {
    /// The ID token, extracted as an **opaque, unverified** string. `OpenID`
    /// Connect Core 1.0 section 3.1.3.3 requires it to be present; verifying
    /// its signature, issuer, audience, expiry, and `nonce` is a later slice.
    pub id_token: String,
    /// The `OAuth2` access token (RFC 6749 section 5.1: REQUIRED).
    pub access_token: String,
    /// The token type (RFC 6749 section 5.1: REQUIRED). `OpenID` Connect Core
    /// 1.0 section 3.1.3.3 says this "MUST be `Bearer`"; it is captured
    /// verbatim rather than rejected on mismatch, since providers vary in
    /// casing.
    pub token_type: String,
    /// Access-token lifetime in seconds, when present (RFC 6749 section 5.1:
    /// RECOMMENDED, not REQUIRED).
    pub expires_in: Option<u64>,
}

/// A parsed `OAuth2` token error response (RFC 6749 section 5.2).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OidcTokenErrorResponse {
    /// The single ASCII error code (RFC 6749 section 5.2: REQUIRED), e.g.
    /// `invalid_grant`, `invalid_client`, `invalid_request`.
    pub error: String,
    /// Human-readable text with additional information (OPTIONAL).
    pub error_description: Option<String>,
    /// A URI for a human-readable error page (OPTIONAL).
    pub error_uri: Option<String>,
}

#[derive(Debug, Error)]
pub enum OidcTokenError {
    /// The token endpoint returned a valid RFC 6749 section 5.2 error response.
    #[error("OIDC token endpoint returned error '{}'", .0.error)]
    Provider(OidcTokenErrorResponse),
    /// A success-shaped response missing the OIDC-required `id_token` (`OpenID`
    /// Connect Core 1.0 section 3.1.3.3).
    #[error("OIDC token response is missing the required id_token")]
    MissingIdToken,
    /// The response body is neither a valid success nor a valid error shape.
    #[error("OIDC token response is malformed")]
    Malformed,
}

/// Builds the PKCE authorization-code-for-token request components, for a
/// public client (`client_secret: None`) or a confidential one (`Some`).
/// Infallible: `token_endpoint` is passed through untouched (the parameters go
/// in the body, not the URL), so there is nothing to fail on.
///
/// The body is encoded with the `url` crate's `form_urlencoded::Serializer` —
/// the same machinery `reqwest::Url::query_pairs_mut()` (used by
/// [`crate::oidc_authorization`] for the authorization URL) is built on. It
/// percent-encodes each value per `application/x-www-form-urlencoded`, so a
/// `code` containing `+`/`/`/`=` (realistic for a base64url or opaque code) or
/// a `redirect_uri` carrying its own query string round-trips without
/// corrupting or colliding with the body's other parameters. The serializer
/// takes no URL and cannot fail, keeping this function infallible.
///
/// With a secret, the request additionally carries the RFC 6749 section 2.3.1
/// HTTP Basic `Authorization` header (see [`basic_client_authorization`]); the
/// form body is byte-identical in both cases. Keeping `client_id` in the body
/// alongside the header is permitted (section 2.3.1 constrains duplicating
/// *authentication* mechanisms; the bare `client_id` parameter is not one) and
/// keeps the two shapes diffable. The PKCE `code_verifier` is always sent —
/// RFC 9700's all-clients PKCE stance — even though Spring would drop PKCE for
/// a confidential client.
#[must_use]
pub fn build_oidc_token_request(
    token_endpoint: &str,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> OidcTokenRequest {
    let form_body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("code_verifier", code_verifier)
        .append_pair("client_id", client_id)
        .finish();

    OidcTokenRequest {
        token_endpoint: token_endpoint.to_owned(),
        content_type: FORM_URLENCODED_CONTENT_TYPE,
        form_body,
        authorization: client_secret
            .map(|client_secret| basic_client_authorization(client_id, client_secret)),
    }
}

/// The RFC 6749 section 2.3.1 `client_secret_basic` header value:
/// `Basic base64(urlencode(client_id) ":" urlencode(client_secret))`.
///
/// The Appendix B subtlety, easy to get wrong: the id and secret are each
/// `application/x-www-form-urlencoded` encoded (space becomes `+`, reserved
/// bytes percent-encoded — the same algorithm Java's `URLEncoder.encode` /
/// Spring's converter applies) **before** base64, so a `:` inside either value
/// can never be confused with the id/secret separator, and any octet sequence
/// round-trips.
fn basic_client_authorization(client_id: &str, client_secret: &str) -> Zeroizing<String> {
    let encoded_id: String = form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
    let encoded_secret: String =
        form_urlencoded::byte_serialize(client_secret.as_bytes()).collect();
    let credentials = Zeroizing::new(format!("{encoded_id}:{encoded_secret}"));
    Zeroizing::new(format!("Basic {}", STANDARD.encode(credentials.as_bytes())))
}

/// The union of the RFC 6749 section 5.1 success shape and the section 5.2 error
/// shape. Every field is optional so a body of either shape deserializes;
/// [`parse_oidc_token_response`] then decides which shape it actually is.
/// Unknown fields (e.g. `refresh_token`, `scope`) are ignored, not rejected.
#[derive(Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    error_uri: Option<String>,
}

/// Parses a token endpoint's `status` + JSON `body` into a typed success value
/// or a typed error. Makes no network call — the caller (a later slice) does
/// the fetch.
///
/// Decision order:
/// 1. A non-empty `error` field means an RFC 6749 section 5.2 error response;
///    it is returned as [`OidcTokenError::Provider`] regardless of `status`,
///    since providers return token errors under various 4xx (and occasionally
///    other) statuses.
/// 2. Otherwise a successful response must be HTTP 2xx (RFC 6749 section 5.1
///    specifies 200) and carry non-empty `access_token` and `token_type`; if
///    not, the body is neither a valid success nor a valid error →
///    [`OidcTokenError::Malformed`].
/// 3. On top of the `OAuth2` success shape, `OpenID` Connect Core 1.0 section
///    3.1.3.3 requires `id_token`; its absence is
///    [`OidcTokenError::MissingIdToken`].
///
/// # Errors
///
/// See the variants of [`OidcTokenError`]: a provider error, a missing
/// `id_token`, or a malformed/neither-shape body (including invalid JSON, or a
/// non-numeric `expires_in`, which per RFC 6749 section 5.1 must be a number).
pub fn parse_oidc_token_response(
    status: u16,
    body: &[u8],
) -> Result<OidcTokenResponse, OidcTokenError> {
    let raw: RawTokenResponse =
        serde_json::from_slice(body).map_err(|_| OidcTokenError::Malformed)?;

    if let Some(error) = raw.error.filter(|error| !error.is_empty()) {
        return Err(OidcTokenError::Provider(OidcTokenErrorResponse {
            error,
            error_description: raw.error_description,
            error_uri: raw.error_uri,
        }));
    }

    if !(200..300).contains(&status) {
        return Err(OidcTokenError::Malformed);
    }
    let (Some(access_token), Some(token_type)) = (
        raw.access_token.filter(|token| !token.is_empty()),
        raw.token_type.filter(|token_type| !token_type.is_empty()),
    ) else {
        return Err(OidcTokenError::Malformed);
    };
    let Some(id_token) = raw.id_token.filter(|token| !token.is_empty()) else {
        return Err(OidcTokenError::MissingIdToken);
    };

    Ok(OidcTokenResponse {
        id_token,
        access_token,
        token_type,
        expires_in: raw.expires_in,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        FORM_URLENCODED_CONTENT_TYPE, OidcTokenError, build_oidc_token_request,
        parse_oidc_token_response,
    };

    /// Parses an `application/x-www-form-urlencoded` body back into a map, using
    /// the same `reqwest::Url` parser that produced it — a round-trip check that
    /// no value was corrupted by the encoding.
    fn form_params(body: &str) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        Ok(reqwest::Url::parse(&format!("http://x/?{body}"))?
            .query_pairs()
            .into_owned()
            .collect())
    }

    #[test]
    fn builds_a_token_request_with_every_required_parameter_correctly_encoded()
    -> Result<(), Box<dyn std::error::Error>> {
        // A code with base64url/opaque special characters and a redirect_uri
        // carrying its own query string: exactly the inputs that corrupt a
        // naively-concatenated body (a `+`/`/`/`=` in the code, or the
        // redirect_uri's own `?`/`&`/`=`, would merge into or collide with the
        // body's other parameters).
        let request = build_oidc_token_request(
            "https://issuer.example.com/token",
            "my client id",
            None,
            "code+with/special=chars",
            "https://app.example.com/callback?a=1&b=2",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        );

        assert_eq!(request.token_endpoint, "https://issuer.example.com/token");
        assert_eq!(request.content_type, FORM_URLENCODED_CONTENT_TYPE);
        // Public client: no client authentication header.
        assert_eq!(request.authorization, None);

        let params = form_params(&request.form_body)?;
        assert_eq!(params["grant_type"], "authorization_code");
        assert_eq!(params["code"], "code+with/special=chars");
        assert_eq!(
            params["redirect_uri"],
            "https://app.example.com/callback?a=1&b=2"
        );
        assert_eq!(
            params["code_verifier"],
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert_eq!(params["client_id"], "my client id");
        // The redirect_uri's embedded query string must not have leaked out as
        // top-level body parameters.
        assert!(!params.contains_key("a"));
        assert!(!params.contains_key("b"));
        // And the raw body must actually be percent-encoded, not raw specials.
        assert!(
            request
                .form_body
                .contains("code=code%2Bwith%2Fspecial%3Dchars")
        );
        Ok(())
    }

    #[test]
    fn a_confidential_client_carries_the_exact_rfc6749_basic_header() {
        // A worked RFC 6749 section 2.3.1 + Appendix B example, with characters
        // in both id and secret that need form-urlencoding: each value is
        // encoded FIRST (space -> '+', reserved bytes -> %XX, so the embedded
        // ':' can't masquerade as the separator), THEN "id:secret" is base64'd.
        //   "client id:with/special" -> "client+id%3Awith%2Fspecial"
        //   "s3cr&t +/:="            -> "s3cr%26t+%2B%2F%3A%3D"
        //   base64("client+id%3Awith%2Fspecial:s3cr%26t+%2B%2F%3A%3D")
        let request = build_oidc_token_request(
            "https://issuer.example.com/token",
            "client id:with/special",
            Some("s3cr&t +/:="),
            "code-abc",
            "https://app.example.com/callback",
            "verifier",
        );
        assert_eq!(
            request.authorization.as_ref().map(|value| value.as_str()),
            Some("Basic Y2xpZW50K2lkJTNBd2l0aCUyRnNwZWNpYWw6czNjciUyNnQrJTJCJTJGJTNBJTNE"),
        );
    }

    #[test]
    fn with_and_without_a_secret_the_form_body_is_byte_identical() {
        // The secret moves ONLY into the Authorization header: the form body —
        // including the always-present PKCE code_verifier (RFC 9700 keeps PKCE
        // for confidential clients; Spring drops it, a deliberate divergence) —
        // must not change byte-for-byte, so a public-client request today is
        // exactly yesterday's request.
        let build = |secret: Option<&str>| {
            build_oidc_token_request(
                "https://issuer.example.com/token",
                "my-client",
                secret,
                "code-abc",
                "https://app.example.com/callback",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            )
        };
        let public = build(None);
        let confidential = build(Some("the-secret"));
        assert_eq!(
            public.form_body,
            "grant_type=authorization_code&code=code-abc\
             &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback\
             &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk\
             &client_id=my-client"
        );
        assert_eq!(public.form_body, confidential.form_body);
        assert_eq!(public.authorization, None);
        assert!(confidential.authorization.is_some());
    }

    #[test]
    fn the_debug_representation_never_leaks_the_client_credentials() {
        let request = build_oidc_token_request(
            "https://issuer.example.com/token",
            "my-client",
            Some("super-secret-value"),
            "code-abc",
            "https://app.example.com/callback",
            "verifier",
        );
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("super-secret-value"));
        // Not even the base64 form (trivially reversible) may appear.
        let encoded = request
            .authorization
            .as_ref()
            .map(|value| value.trim_start_matches("Basic ").to_owned())
            .unwrap_or_default();
        assert!(!debug.contains(&encoded));
    }

    #[test]
    fn parses_a_successful_token_response() -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{
            "access_token": "at-abc",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "header.payload.signature",
            "refresh_token": "rt-ignored",
            "scope": "openid profile"
        }"#;
        let response = parse_oidc_token_response(200, body)
            .map_err(|error| format!("expected success, got {error}"))?;
        assert_eq!(response.id_token, "header.payload.signature");
        assert_eq!(response.access_token, "at-abc");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        Ok(())
    }

    #[test]
    fn parses_a_successful_token_response_without_the_optional_expires_in()
    -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{"access_token":"at","token_type":"Bearer","id_token":"a.b.c"}"#;
        let response = parse_oidc_token_response(200, body)
            .map_err(|error| format!("expected success, got {error}"))?;
        assert_eq!(response.expires_in, None);
        assert_eq!(response.id_token, "a.b.c");
        Ok(())
    }

    #[test]
    fn rejects_a_success_response_missing_the_oidc_required_id_token() {
        // A perfectly valid OAuth2 success response — but OIDC (Core 1.0
        // section 3.1.3.3) REQUIRES id_token, so this must be rejected
        // specifically, not accepted or reported as generically malformed.
        let body = br#"{"access_token":"at","token_type":"Bearer","expires_in":3600}"#;
        let result = parse_oidc_token_response(200, body);
        assert!(
            matches!(result, Err(OidcTokenError::MissingIdToken)),
            "expected MissingIdToken, got {result:?}"
        );
    }

    #[test]
    fn rejects_a_success_response_with_an_empty_id_token() {
        let body = br#"{"access_token":"at","token_type":"Bearer","id_token":""}"#;
        assert!(matches!(
            parse_oidc_token_response(200, body),
            Err(OidcTokenError::MissingIdToken)
        ));
    }

    #[test]
    fn parses_an_oauth2_error_response() -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{
            "error": "invalid_grant",
            "error_description": "authorization code expired",
            "error_uri": "https://issuer.example.com/errors/invalid_grant"
        }"#;
        match parse_oidc_token_response(400, body) {
            Err(OidcTokenError::Provider(error)) => {
                assert_eq!(error.error, "invalid_grant");
                assert_eq!(
                    error.error_description.as_deref(),
                    Some("authorization code expired")
                );
                assert_eq!(
                    error.error_uri.as_deref(),
                    Some("https://issuer.example.com/errors/invalid_grant")
                );
            }
            other => return Err(format!("expected a provider error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn parses_an_error_response_with_only_the_required_error_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let body = br#"{"error":"invalid_client"}"#;
        match parse_oidc_token_response(401, body) {
            Err(OidcTokenError::Provider(error)) => {
                assert_eq!(error.error, "invalid_client");
                assert_eq!(error.error_description, None);
                assert_eq!(error.error_uri, None);
            }
            other => return Err(format!("expected a provider error, got {other:?}").into()),
        }
        Ok(())
    }

    #[test]
    fn rejects_a_non_json_body_as_malformed() {
        assert!(matches!(
            parse_oidc_token_response(200, b"not json at all"),
            Err(OidcTokenError::Malformed)
        ));
    }

    #[test]
    fn rejects_a_neither_success_nor_error_shape_as_malformed() {
        // Valid JSON, but carries neither an `error` code nor the required
        // success fields.
        let body = br#"{"something_else":"value"}"#;
        assert!(matches!(
            parse_oidc_token_response(200, body),
            Err(OidcTokenError::Malformed)
        ));
    }

    #[test]
    fn rejects_a_success_shape_with_a_non_2xx_status_as_malformed() {
        // Success fields but a 4xx status and no `error` code: neither a valid
        // success (RFC 6749 section 5.1 requires 200) nor a valid error.
        let body = br#"{"access_token":"at","token_type":"Bearer","id_token":"a.b.c"}"#;
        assert!(matches!(
            parse_oidc_token_response(400, body),
            Err(OidcTokenError::Malformed)
        ));
    }
}
