//! OIDC provider discovery: fetches and validates a generic `OpenID` Connect
//! issuer's `.well-known/openid-configuration` document.
//!
//! This is fetch-and-validate only — the first slice of generic OIDC support.
//! It answers exactly two questions: is this a well-formed, spec-compliant OIDC
//! provider, and what are its three key endpoints (`authorization_endpoint`,
//! `token_endpoint`, `jwks_uri`). Redirect-URL construction, state/nonce/PKCE
//! handling, the callback route, and the authorization-code-for-token exchange
//! are later, separate work and are deliberately not part of this module.
//!
//! Mirrors Java's `OAuth2Configuration.oidcClientRegistration()`, which uses
//! Spring's `ClientRegistrations.fromIssuerLocation(issuer)` to fetch and
//! validate the same discovery document.

use std::{io::Read as _, time::Duration};

use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
use thiserror::Error;

use crate::security_jwt::issuer_url_scheme_is_allowed;

const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_DISCOVERY_DOCUMENT_BYTES: u64 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The subset of an OIDC provider's discovery document this codebase currently
/// needs. Extra fields present in a real-world discovery document (e.g.
/// `userinfo_endpoint`, `response_types_supported`, ...) are ignored, not
/// rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

#[derive(Debug, Error)]
pub enum OidcDiscoveryError {
    #[error("OIDC issuer is invalid")]
    InvalidIssuer,
    #[error("OIDC discovery document is unavailable")]
    DiscoveryUnavailable,
    #[error("OIDC discovery document is invalid")]
    InvalidDiscoveryDocument,
    #[error("OIDC discovery document issuer does not match the configured issuer")]
    IssuerMismatch,
}

/// The raw JSON shape of `.well-known/openid-configuration`. Field names match
/// the OIDC Discovery 1.0 spec verbatim (already `snake_case`), so no renaming is
/// needed. A field missing from the document fails deserialization, which
/// [`discover_oidc_provider`] maps to [`OidcDiscoveryError::InvalidDiscoveryDocument`].
#[derive(Deserialize)]
struct RawOidcDiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// Fetches and validates `{issuer}/.well-known/openid-configuration`.
///
/// Validates that:
/// - `issuer` is a well-formed URL following the same HTTPS-first scheme
///   policy as Supabase JWKS issuer validation (HTTPS always allowed, plain
///   HTTP only against a loopback host), with no embedded credentials, query,
///   or fragment.
/// - the document's own `issuer` field is identical to the issuer URL used to
///   fetch it (required by OIDC Discovery 1.0 section 4.3, and a defence
///   against a misconfigured or spoofed provider).
/// - `authorization_endpoint`, `token_endpoint`, and `jwks_uri` are present and
///   are well-formed URLs under that same scheme policy.
///
/// # Errors
///
/// Returns [`OidcDiscoveryError::InvalidIssuer`] for a malformed or
/// disallowed-scheme issuer, [`OidcDiscoveryError::DiscoveryUnavailable`] when
/// the document can't be fetched, [`OidcDiscoveryError::InvalidDiscoveryDocument`]
/// for malformed JSON, a missing required field, or a disallowed-scheme
/// endpoint URL, and [`OidcDiscoveryError::IssuerMismatch`] when the document's
/// `issuer` disagrees with the requested issuer.
pub fn discover_oidc_provider(issuer: &str) -> Result<OidcProviderMetadata, OidcDiscoveryError> {
    let issuer = validated_issuer(issuer)?;
    let document = fetch_discovery_document(&issuer)?;
    if document.issuer != issuer {
        return Err(OidcDiscoveryError::IssuerMismatch);
    }
    validated_endpoint_url(&document.authorization_endpoint)?;
    validated_endpoint_url(&document.token_endpoint)?;
    validated_endpoint_url(&document.jwks_uri)?;
    Ok(OidcProviderMetadata {
        issuer: document.issuer,
        authorization_endpoint: document.authorization_endpoint,
        token_endpoint: document.token_endpoint,
        jwks_uri: document.jwks_uri,
    })
}

/// Validates the issuer and returns it normalized (trimmed of exactly one
/// trailing slash, matching `SupabaseJwtConfig::validate`), ready for building
/// the discovery URL and for the exact-match comparison against the document's
/// own `issuer` field.
fn validated_issuer(issuer: &str) -> Result<String, OidcDiscoveryError> {
    let issuer = issuer.trim();
    if issuer.is_empty() || issuer.len() > MAX_ISSUER_BYTES {
        return Err(OidcDiscoveryError::InvalidIssuer);
    }
    let url = Url::parse(issuer).map_err(|_| OidcDiscoveryError::InvalidIssuer)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !issuer_url_scheme_is_allowed(&url)
    {
        return Err(OidcDiscoveryError::InvalidIssuer);
    }
    Ok(issuer.trim_end_matches('/').to_owned())
}

/// Validates a discovered endpoint URL under the same scheme policy as the
/// issuer. Endpoint URLs aren't required to be credential/query/fragment-free
/// the way an OIDC issuer identifier is — only their scheme and host matter.
fn validated_endpoint_url(value: &str) -> Result<Url, OidcDiscoveryError> {
    let url = Url::parse(value).map_err(|_| OidcDiscoveryError::InvalidDiscoveryDocument)?;
    if issuer_url_scheme_is_allowed(&url) {
        Ok(url)
    } else {
        Err(OidcDiscoveryError::InvalidDiscoveryDocument)
    }
}

fn fetch_discovery_document(issuer: &str) -> Result<RawOidcDiscoveryDocument, OidcDiscoveryError> {
    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::none())
        .user_agent("stirling-pdf-rust-oidc-discovery/1")
        .build()
        .map_err(|_| OidcDiscoveryError::DiscoveryUnavailable)?;
    let response = client
        .get(format!("{issuer}/.well-known/openid-configuration"))
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|_| OidcDiscoveryError::DiscoveryUnavailable)?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DISCOVERY_DOCUMENT_BYTES)
    {
        return Err(OidcDiscoveryError::InvalidDiscoveryDocument);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_DISCOVERY_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OidcDiscoveryError::DiscoveryUnavailable)?;
    if bytes.len() as u64 > MAX_DISCOVERY_DOCUMENT_BYTES {
        return Err(OidcDiscoveryError::InvalidDiscoveryDocument);
    }
    serde_json::from_slice(&bytes).map_err(|_| OidcDiscoveryError::InvalidDiscoveryDocument)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::TcpListener,
        thread,
    };

    use super::{OidcDiscoveryError, discover_oidc_provider};

    /// Binds a loopback listener, builds `{"http://127.0.0.1:port", ...}` as
    /// the issuer, has `build_body` produce the discovery-document JSON to
    /// serve for it (so the body can embed the actual issuer URL, only known
    /// once the fixture is bound), serves exactly one request with that body,
    /// and returns `(issuer, discover_oidc_provider(&issuer))`.
    ///
    /// Mirrors the fixture-server pattern in `tessdata_admin.rs`'s
    /// `discovers_caches_and_atomically_downloads_remote_languages` test and
    /// `tests/timestamp_endpoint.rs`'s hand-rolled TSA server: a background
    /// `std::thread` over a real `TcpListener`, reading the raw request and
    /// writing a raw HTTP/1.1 response.
    fn discover_against_fixture(
        build_body: impl FnOnce(&str) -> String + Send + 'static,
    ) -> Result<
        (
            String,
            Result<super::OidcProviderMetadata, OidcDiscoveryError>,
        ),
        Box<dyn std::error::Error>,
    > {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let issuer = format!("http://{address}");
        let server = thread::spawn(move || -> Result<(), std::io::Error> {
            let body = build_body(&format!("http://{address}"));
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 2048];
            let read = stream.read(&mut request)?;
            let request = String::from_utf8_lossy(&request[..read]);
            if !request.starts_with("GET /.well-known/openid-configuration ") {
                return Err(std::io::Error::other(format!(
                    "unexpected fixture request: {request}"
                )));
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )?;
            stream.write_all(body.as_bytes())?;
            Ok(())
        });
        let result = discover_oidc_provider(&issuer);
        server.join().map_err(|_| "fixture server panicked")??;
        Ok((issuer, result))
    }

    fn well_formed_body(issuer: &str) -> String {
        format!(
            r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"{issuer}/jwks.json","userinfo_endpoint":"{issuer}/userinfo"}}"#
        )
    }

    #[test]
    fn parses_a_well_formed_discovery_document() -> Result<(), Box<dyn std::error::Error>> {
        let (issuer, result) = discover_against_fixture(well_formed_body)?;
        let metadata = result?;
        assert_eq!(metadata.issuer, issuer);
        assert_eq!(
            metadata.authorization_endpoint,
            format!("{issuer}/authorize")
        );
        assert_eq!(metadata.token_endpoint, format!("{issuer}/token"));
        assert_eq!(metadata.jwks_uri, format!("{issuer}/jwks.json"));
        Ok(())
    }

    #[test]
    fn rejects_a_discovery_document_whose_issuer_does_not_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"https://not-the-requested-issuer.example.com","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"{issuer}/jwks.json"}}"#
            )
        })?;
        assert!(matches!(result, Err(OidcDiscoveryError::IssuerMismatch)));
        Ok(())
    }

    #[test]
    fn rejects_a_discovery_document_missing_a_required_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            // `jwks_uri` is missing.
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_non_https_non_loopback_endpoint_url() -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            // `token_endpoint` is plain HTTP against a non-loopback host: not
            // allowed even though the issuer itself is (loopback) HTTP.
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"http://evil.example.com/token","jwks_uri":"{issuer}/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_non_https_non_loopback_issuer_without_contacting_it() {
        // No fixture server is started: a disallowed-scheme issuer must be
        // rejected before any network call is made.
        let result = discover_oidc_provider("http://evil.example.com");
        assert!(matches!(result, Err(OidcDiscoveryError::InvalidIssuer)));
    }

    #[test]
    fn rejects_an_issuer_with_embedded_credentials_or_a_query_or_fragment() {
        for issuer in [
            "https://user:pass@example.com",
            "https://example.com?query=1",
            "https://example.com#fragment",
        ] {
            let result = discover_oidc_provider(issuer);
            assert!(
                matches!(result, Err(OidcDiscoveryError::InvalidIssuer)),
                "expected {issuer} to be rejected, got {result:?}"
            );
        }
    }
}
