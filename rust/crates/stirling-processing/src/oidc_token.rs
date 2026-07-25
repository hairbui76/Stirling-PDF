//! OIDC token exchange, pure-function groundwork: builds the
//! authorization-code-for-token request components and parses the token
//! endpoint's response. Continues the OIDC login arc from
//! [`crate::oidc_authorization`] (which builds the authorization redirect and
//! the PKCE `code_verifier`).
//!
//! Targets the public-client PKCE case (no `client_secret`); confidential-client
//! authentication is a follow-up.
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

use serde::Deserialize;
use thiserror::Error;
use url::form_urlencoded;

/// The request body media type for the token endpoint (RFC 6749 section 4.1.3:
/// "The client makes a request to the token endpoint by sending the following
/// parameters using the `application/x-www-form-urlencoded` format").
const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// The components of an RFC 6749 section 4.1.3 (plus RFC 7636 section 4.5
/// `code_verifier`) access-token request, ready for a later live-fetch slice to
/// POST. Constructed here, not sent.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OidcTokenRequest {
    /// The URL to POST to — the provider's `token_endpoint`, passed through
    /// unchanged (the request parameters go in the body, not the URL). A later
    /// slice validates and SSRF-checks this before fetching it.
    pub token_endpoint: String,
    /// The request body media type: `application/x-www-form-urlencoded`.
    pub content_type: &'static str,
    /// The `application/x-www-form-urlencoded` request body.
    pub form_body: String,
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

/// Builds the public-client PKCE authorization-code-for-token request
/// components. Infallible: `token_endpoint` is passed through untouched (the
/// parameters go in the body, not the URL), so there is nothing to fail on.
///
/// The body is encoded with the `url` crate's `form_urlencoded::Serializer` —
/// the same machinery `reqwest::Url::query_pairs_mut()` (used by
/// [`crate::oidc_authorization`] for the authorization URL) is built on. It
/// percent-encodes each value per `application/x-www-form-urlencoded`, so a
/// `code` containing `+`/`/`/`=` (realistic for a base64url or opaque code) or
/// a `redirect_uri` carrying its own query string round-trips without
/// corrupting or colliding with the body's other parameters. The serializer
/// takes no URL and cannot fail, keeping this function infallible.
#[must_use]
pub fn build_oidc_token_request(
    token_endpoint: &str,
    client_id: &str,
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
    }
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
            "code+with/special=chars",
            "https://app.example.com/callback?a=1&b=2",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        );

        assert_eq!(request.token_endpoint, "https://issuer.example.com/token");
        assert_eq!(request.content_type, FORM_URLENCODED_CONTENT_TYPE);

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
