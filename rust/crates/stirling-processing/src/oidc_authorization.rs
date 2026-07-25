//! Builds the OIDC/OAuth2 authorization redirect: the second slice of the
//! generic OIDC login arc, continuing from [`crate::oidc_discovery`] (which
//! fetches and validates a provider's `.well-known/openid-configuration`).
//!
//! Given a discovered provider's metadata, a client ID, a redirect URI, and
//! requested scopes, this generates the random `state` (CSRF protection),
//! `nonce` (replay protection, later verified against the ID token's own
//! `nonce` claim), and PKCE `code_verifier`/`code_challenge` (RFC 7636,
//! mitigates authorization-code interception), then builds the full
//! authorization-endpoint redirect URL per `OpenID` Connect Core 1.0 section
//! 3.1.2.1's Authentication Request parameters.
//!
//! This is redirect-URL construction ONLY (verified against the RFC 7636 and
//! `OpenID` Connect Core 1.0 spec text directly, not assumed). It does not:
//! - persist `state`/`nonce`/`code_verifier` anywhere (no session, cookie, or
//!   other storage) — the caller must hold onto the returned
//!   [`OidcAuthorizationRequest`] until the callback arrives, by whatever
//!   mechanism a later ticket wires up;
//! - implement the callback route;
//! - exchange the eventual authorization code for tokens;
//! - create a session.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt as _;
use reqwest::Url;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::oidc_discovery::OidcProviderMetadata;

/// Random octets used for `state`, `nonce`, and the PKCE `code_verifier`.
///
/// Matches this codebase's established token-generation convention
/// (`security.rs`'s `random_secret`/`TOKEN_BYTES`: 32 random octets from
/// `rand::rng()`, base64url-no-pad encoded) *and* RFC 7636 section 4.1's own
/// recommendation for the code verifier specifically: "it is RECOMMENDED
/// that the output of a suitable random number generator be used to create a
/// 32-octet sequence. The octet sequence is then base64url-encoded" —
/// verified against the RFC text. 32 base64url-no-pad-encoded octets is
/// exactly 43 characters, which is also RFC 7636's minimum `code_verifier`
/// length (`code-verifier = 43*128unreserved`), so this single convention
/// satisfies both this codebase's norm and the spec's own recommendation at
/// once.
const RANDOM_TOKEN_BYTES: usize = 32;

/// `OpenID` Connect Core 1.0 section 3.1.2.1: "`OpenID` Connect requests MUST
/// contain the `openid` scope value. If the `openid` scope value is not
/// present, the behavior is entirely unspecified." — verified against the
/// spec text, not assumed. [`build_oidc_authorization_request`] always
/// includes this even if the caller's requested scopes omit it.
const OPENID_SCOPE: &str = "openid";

/// An authorization redirect ready to send the browser to, plus the
/// generated secrets the caller must persist (session, signed cookie, ...)
/// until the callback arrives — persistence itself is out of scope here and
/// left to a later ticket.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OidcAuthorizationRequest {
    /// The full `{authorization_endpoint}?...` URL to redirect the browser
    /// to.
    pub redirect_url: String,
    /// CSRF-protection value. Verify the callback's own `state` parameter
    /// matches this exactly before proceeding, and reject if it doesn't (or
    /// is missing).
    pub state: String,
    /// Replay-protection value. Verify it against the eventual ID token's
    /// own `nonce` claim during token validation.
    pub nonce: String,
    /// PKCE code verifier (RFC 7636). Send this — not `code_challenge` — as
    /// the `code_verifier` parameter in the later authorization-code-for-token
    /// exchange request.
    pub code_verifier: Zeroizing<String>,
}

#[derive(Debug, Error)]
pub enum OidcAuthorizationError {
    #[error("OIDC provider's authorization endpoint is not a valid URL")]
    InvalidAuthorizationEndpoint,
}

/// Builds an [`OidcAuthorizationRequest`] redirecting to `provider`'s
/// `authorization_endpoint`.
///
/// `scopes` need not include `"openid"` — it is always added if missing (see
/// [`OPENID_SCOPE`]'s doc comment). An explicitly included `"openid"` is not
/// duplicated. Every parameter value (`client_id`, `redirect_uri`, the
/// combined `scope` string, and the generated secrets) is encoded as a
/// single opaque query-parameter value via [`Url::query_pairs_mut`] — this
/// correctly percent-encodes any `?`/`&`/`=`/other reserved characters
/// embedded in `redirect_uri` (e.g. a redirect URI that itself carries a
/// query string) rather than letting them merge into, or collide with, the
/// authorization URL's own query string, and correctly appends to (rather
/// than clobbers) any query string `authorization_endpoint` already has.
///
/// # Errors
///
/// Returns [`OidcAuthorizationError::InvalidAuthorizationEndpoint`] if
/// `provider.authorization_endpoint` is not a well-formed URL. In practice
/// this should already have been rejected by
/// [`crate::oidc_discovery::discover_oidc_provider`], but that isn't
/// enforced by the type system here, since `OidcProviderMetadata`'s fields
/// are plain `String`s.
pub fn build_oidc_authorization_request(
    provider: &OidcProviderMetadata,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[&str],
) -> Result<OidcAuthorizationRequest, OidcAuthorizationError> {
    let state = random_url_safe_token();
    let nonce = random_url_safe_token();
    let code_verifier = Zeroizing::new(random_url_safe_token());
    let code_challenge = code_challenge_s256(&code_verifier);
    let scope = effective_scope(scopes);

    let mut url = Url::parse(&provider.authorization_endpoint)
        .map_err(|_| OidcAuthorizationError::InvalidAuthorizationEndpoint)?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &code_challenge)
        .append_pair("code_challenge_method", "S256");

    Ok(OidcAuthorizationRequest {
        redirect_url: url.to_string(),
        state,
        nonce,
        code_verifier,
    })
}

/// Builds the effective space-separated `scope` value: `scopes` with
/// [`OPENID_SCOPE`] present exactly once (prepended if the caller didn't
/// already include it, left as given otherwise).
fn effective_scope(scopes: &[&str]) -> String {
    if scopes.contains(&OPENID_SCOPE) {
        scopes.join(" ")
    } else {
        std::iter::once(OPENID_SCOPE)
            .chain(scopes.iter().copied())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// A cryptographically random, URL-safe token: [`RANDOM_TOKEN_BYTES`] random
/// octets from `rand::rng()`, base64url-no-pad encoded.
///
/// The resulting 43-character string satisfies RFC 7636 section 4.1's
/// `code_verifier` length and character-set requirements
/// (`code-verifier = 43*128unreserved`, `unreserved = ALPHA / DIGIT / "-" /
/// "." / "_" / "~"`): base64url's alphabet is a strict subset of
/// `unreserved` (alphanumerics plus `-`/`_`; it never emits `.`/`~`), so
/// every character this can produce is already RFC-7636-safe. `state` and
/// `nonce` aren't bound by that RFC, but reuse the same generation for the
/// same entropy and encoding.
///
/// `pub(crate)` so [`crate::oidc_login`] can mint the login-CSRF browser-binding
/// value with the identical entropy/encoding convention rather than duplicating
/// it.
pub(crate) fn random_url_safe_token() -> String {
    let mut bytes = [0_u8; RANDOM_TOKEN_BYTES];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// RFC 7636 section 4.2, `S256` method: `code_challenge =
/// BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` — verified against the
/// RFC text, including Appendix A's definition of `BASE64URL-ENCODE`
/// (standard base64url alphabet with trailing `=` padding stripped), which
/// is exactly [`URL_SAFE_NO_PAD`].
fn code_challenge_s256(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    use super::{OidcProviderMetadata, build_oidc_authorization_request};

    fn sample_provider() -> OidcProviderMetadata {
        OidcProviderMetadata {
            issuer: "https://issuer.example.com".to_owned(),
            authorization_endpoint: "https://issuer.example.com/authorize".to_owned(),
            token_endpoint: "https://issuer.example.com/token".to_owned(),
            jwks_uri: "https://issuer.example.com/jwks.json".to_owned(),
        }
    }

    fn query_params(
        redirect_url: &str,
    ) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        Ok(reqwest::Url::parse(redirect_url)?
            .query_pairs()
            .into_owned()
            .collect())
    }

    #[test]
    fn builds_a_redirect_url_with_every_required_parameter_correctly_encoded()
    -> Result<(), Box<dyn std::error::Error>> {
        // A redirect_uri with its own query string: this is exactly the case
        // that breaks if the outer query string is built by naive string
        // concatenation instead of proper per-parameter encoding — either
        // double-encoding, or letting the redirect_uri's own `?`/`&`/`=`
        // characters merge into (and collide with) the authorization URL's
        // own query string.
        let redirect_uri = "https://app.example.com/callback?tab=1&ref=abc";
        let request = build_oidc_authorization_request(
            &sample_provider(),
            "my client id", // deliberately contains a space, to exercise encoding too
            redirect_uri,
            &["profile", "email"],
        )?;

        assert!(
            request
                .redirect_url
                .starts_with("https://issuer.example.com/authorize?")
        );
        let params = query_params(&request.redirect_url)?;
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], "my client id");
        assert_eq!(params["redirect_uri"], redirect_uri);
        assert_eq!(params["scope"], "openid profile email");
        assert_eq!(params["state"], request.state);
        assert_eq!(params["nonce"], request.nonce);
        assert_eq!(params["code_challenge_method"], "S256");
        assert!(params.contains_key("code_challenge"));
        // Exactly one `redirect_uri` parameter — the redirect_uri's own
        // embedded query string must not have produced extra top-level
        // parameters (`tab`, `ref`) alongside it.
        assert!(!params.contains_key("tab"));
        assert!(!params.contains_key("ref"));
        Ok(())
    }

    #[test]
    fn appends_to_an_authorization_endpoint_that_already_has_a_query_string()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = sample_provider();
        provider.authorization_endpoint =
            "https://issuer.example.com/authorize?tenant=acme".to_owned();
        let request = build_oidc_authorization_request(
            &provider,
            "client",
            "https://app.example.com/callback",
            &[],
        )?;
        let params = query_params(&request.redirect_url)?;
        assert_eq!(params["tenant"], "acme");
        assert_eq!(params["response_type"], "code");
        Ok(())
    }

    #[test]
    fn adds_the_mandatory_openid_scope_even_when_not_requested()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = build_oidc_authorization_request(
            &sample_provider(),
            "client",
            "https://app.example.com/callback",
            &[],
        )?;
        let params = query_params(&request.redirect_url)?;
        assert_eq!(params["scope"], "openid");
        Ok(())
    }

    #[test]
    fn does_not_duplicate_an_explicitly_requested_openid_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = build_oidc_authorization_request(
            &sample_provider(),
            "client",
            "https://app.example.com/callback",
            &["openid", "profile"],
        )?;
        let params = query_params(&request.redirect_url)?;
        assert_eq!(params["scope"], "openid profile");
        Ok(())
    }

    #[test]
    fn rejects_a_malformed_authorization_endpoint() {
        let mut provider = sample_provider();
        provider.authorization_endpoint = "not a url".to_owned();
        let result = build_oidc_authorization_request(
            &provider,
            "client",
            "https://app.example.com/callback",
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn generates_different_state_nonce_and_verifier_across_calls()
    -> Result<(), Box<dyn std::error::Error>> {
        let provider = sample_provider();
        let first = build_oidc_authorization_request(
            &provider,
            "client",
            "https://app.example.com/callback",
            &[],
        )?;
        let second = build_oidc_authorization_request(
            &provider,
            "client",
            "https://app.example.com/callback",
            &[],
        )?;
        assert_ne!(first.state, second.state);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(*first.code_verifier, *second.code_verifier);
        // Sanity: the three values within one call aren't accidentally equal
        // to each other either.
        assert_ne!(first.state, first.nonce);
        assert_ne!(first.state, *first.code_verifier);
        assert_ne!(first.nonce, *first.code_verifier);
        Ok(())
    }

    #[test]
    fn code_verifier_state_and_nonce_meet_rfc7636_length_and_charset_requirements()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = build_oidc_authorization_request(
            &sample_provider(),
            "client",
            "https://app.example.com/callback",
            &[],
        )?;
        // RFC 7636 section 4.1: code-verifier = 43*128unreserved.
        for value in [
            request.code_verifier.as_str(),
            request.state.as_str(),
            request.nonce.as_str(),
        ] {
            assert!(
                (43..=128).contains(&value.len()),
                "{value} is not 43-128 characters"
            );
            assert!(
                value.bytes().all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'-' | b'.' | b'_' | b'~')),
                "{value} contains a character outside RFC 7636's unreserved set"
            );
        }
        Ok(())
    }

    #[test]
    fn code_challenge_matches_the_rfc7636_s256_derivation() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = build_oidc_authorization_request(
            &sample_provider(),
            "client",
            "https://app.example.com/callback",
            &[],
        )?;
        let expected_challenge =
            URL_SAFE_NO_PAD.encode(Sha256::digest(request.code_verifier.as_bytes()));
        let params = query_params(&request.redirect_url)?;
        assert_eq!(params["code_challenge"], expected_challenge);
        Ok(())
    }

    /// Cross-checks the S256 derivation against RFC 7636 Appendix B's own
    /// worked example, independent of this module's `code_verifier`
    /// generation — confirmed correct by computing it separately (Python's
    /// `hashlib`/`base64`) before being embedded here.
    #[test]
    fn s256_derivation_matches_rfc7636_appendix_b_worked_example() {
        let example_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let example_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(example_verifier.as_bytes())),
            example_challenge
        );
    }
}
