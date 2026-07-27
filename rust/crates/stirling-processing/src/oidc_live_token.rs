//! The first *live network call* of the generic OIDC login arc: the
//! authorization-code-for-token POST to a provider's `token_endpoint`. Continues
//! from [`crate::oidc_token`] (which builds the [`OidcTokenRequest`] and parses
//! the response) by actually sending it — behind an SSRF-safe, resolve-and-pin
//! fetch primitive.
//!
//! # Why this needs its own SSRF guard
//!
//! `token_endpoint` comes from the provider's discovery document, which is
//! untrusted input (`OpenID` Connect Core lets the provider choose it).
//! [`crate::oidc_discovery`] already rejects a `token_endpoint` whose **literal**
//! host is a private/reserved IP, but that check is literal-address-only: a
//! hostname that *resolves* to `169.254.169.254` / `10.0.0.x` (a DNS-based SSRF,
//! and its TOCTOU cousin DNS rebinding) sails straight through it — a gap
//! `oidc_discovery` documents and defers to exactly this slice.
//!
//! This module closes that gap for its own fetch path:
//! 1. resolve the target host to concrete IP address(es);
//! 2. vet **every** resolved address against `oidc_discovery`'s reserved-IP
//!    predicate ([`crate::oidc_discovery::ip_addr_is_reserved`], the single
//!    source of truth — reused, not reimplemented) and reject the whole request
//!    **before any TCP connection** if *any* of them is reserved (intentionally
//!    stricter than discovery's literal-only check);
//! 3. **pin** those exact vetted addresses onto the HTTP client via
//!    `reqwest`'s `resolve_to_addrs`, so the socket that actually connects
//!    cannot re-resolve the name to a different (unvetted) address between the
//!    check and the connect — the anti-rebinding step.
//!
//! It reuses `oidc_discovery`'s other fetch conventions too: no redirects,
//! connect/read timeouts, and a response-size cap enforced independently of the
//! advertised `Content-Length`.
//!
//! # Scheme gate (per-scheme address policy, not a skip)
//!
//! Both schemes vet the resolved addresses; they just apply the policy that
//! fits each. `https` — the scheme a real, spoofable production provider uses —
//! gets the full resolve-and-pin reserved-IP rejection, mirroring
//! [`crate::oidc_discovery`]'s own reserved-IP check exactly: if *any* resolved
//! address is private/reserved, the whole request is refused before connecting.
//! `http` is only admitted at all for the three loopback literals
//! (`localhost`/`127.0.0.1`/`::1`) that
//! [`crate::security_jwt::issuer_url_scheme_is_allowed`] permits — the
//! dev/self-hosted seam — so on that path *every* resolved address is required
//! to **be** loopback. That keeps the loopback mock the integration tests rely
//! on reachable while closing two holes an earlier revision left open: an
//! attacker-influenced `localhost` (via `/etc/hosts` or a poisoned resolver)
//! that resolves *off-box* to a non-loopback address, and the http-downgrade
//! asymmetry where the reserved-IP check was skipped entirely for `http`.
//!
//! # Two request shapes, one guard
//!
//! The same resolve-and-pin primitive backs both the token POST above and a
//! bodyless GET, exposed `pub(crate)` to the sibling [`crate::oidc_id_token`]
//! verifier for fetching a provider-controlled `jwks_uri` under the identical
//! SSRF protections (resolve-and-pin, per-scheme reserved rejection, no
//! redirects, connect/read timeouts, and a caller-supplied response-size cap
//! enforced independently of the advertised `Content-Length`).
//!
//! # Out of scope for *this* module
//!
//! This module still does not verify the `id_token` — its own response's
//! `id_token` remains an opaque string here; signature/issuer/audience/expiry/
//! `nonce` verification now lives in the sibling [`crate::oidc_id_token`], which
//! reuses this module's SSRF-safe GET to fetch the JWKS. Confidential-client
//! authentication is carried, not decided, here: when the built
//! [`OidcTokenRequest`] holds an `authorization` value (the RFC 6749 section
//! 2.3.1 Basic credentials, assembled in [`crate::oidc_token`]), it is attached
//! verbatim to the POST. No callback route, no session creation.

use std::{
    io::Read as _,
    net::{SocketAddr, ToSocketAddrs as _},
    time::Duration,
};

use reqwest::{
    Method, Url,
    blocking::Client,
    header::{AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy,
};
use thiserror::Error;

use crate::{
    oidc_discovery::ip_addr_is_reserved,
    oidc_token::{OidcTokenError, OidcTokenRequest, OidcTokenResponse, parse_oidc_token_response},
    security_jwt::issuer_url_scheme_is_allowed,
};

/// Matches `oidc_discovery`/`security_jwt`'s TCP-connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Matches `oidc_discovery`/`security_jwt`'s overall request timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Response-body cap, enforced independently of any advertised `Content-Length`.
/// A token response is a small JSON object; 64 KiB is generous headroom while
/// still bounding a hostile or runaway response.
const MAX_TOKEN_RESPONSE_BYTES: u64 = 64 * 1024;

/// The outcome of a live token exchange that failed before producing a typed
/// [`OidcTokenResponse`].
#[derive(Debug, Error)]
pub enum OidcLiveTokenError {
    /// The `token_endpoint` is not a well-formed URL, or its scheme/host is not
    /// allowed by [`issuer_url_scheme_is_allowed`]. Rejected before resolving or
    /// connecting.
    #[error("OIDC token endpoint URL is invalid")]
    InvalidEndpoint,
    /// The `token_endpoint` host resolved to a reserved/private address (or, for
    /// a multi-address name, at least one such address). Rejected before any TCP
    /// connection — this is the SSRF/DNS-rebinding guard firing.
    #[error("OIDC token endpoint resolves to a blocked address")]
    BlockedAddress,
    /// The token endpoint could not be reached, timed out, or returned an
    /// over-large / unreadable response.
    #[error("OIDC token endpoint is unavailable")]
    Unavailable,
    /// The endpoint responded, but the body was a provider error, was missing
    /// the required `id_token`, or was otherwise not a valid token response —
    /// see [`OidcTokenError`].
    #[error(transparent)]
    Token(#[from] OidcTokenError),
}

/// Exchanges an already-built [`OidcTokenRequest`] (from
/// [`crate::oidc_token::build_oidc_token_request`]) for a typed
/// [`OidcTokenResponse`], posting to its `token_endpoint` through the SSRF-safe
/// resolve-and-pin fetch primitive and feeding the `(status, body)` into
/// [`parse_oidc_token_response`].
///
/// # Errors
///
/// Returns [`OidcLiveTokenError::InvalidEndpoint`] for a malformed or
/// disallowed-scheme `token_endpoint`, [`OidcLiveTokenError::BlockedAddress`]
/// when the host resolves (wholly or partly) into a reserved/private range,
/// [`OidcLiveTokenError::Unavailable`] when the endpoint can't be reached or its
/// response can't be read within the size cap, and
/// [`OidcLiveTokenError::Token`] (wrapping an [`OidcTokenError`]) for a provider
/// error response, a missing `id_token`, or an otherwise malformed body.
pub fn exchange_oidc_token(
    request: &OidcTokenRequest,
) -> Result<OidcTokenResponse, OidcLiveTokenError> {
    exchange_oidc_token_with_resolver(request, resolve_host)
}

/// [`exchange_oidc_token`] with the host-resolution step injected, so tests can
/// drive the resolve-and-pin logic deterministically (a hostname resolving to a
/// chosen private/public address, or to a loopback mock) without depending on
/// real DNS. Production always uses [`resolve_host`].
fn exchange_oidc_token_with_resolver(
    request: &OidcTokenRequest,
    resolve: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
) -> Result<OidcTokenResponse, OidcLiveTokenError> {
    let (status, body) = ssrf_safe_fetch(
        Method::POST,
        &request.token_endpoint,
        Some(&FetchBody {
            content_type: request.content_type,
            body: &request.form_body,
            // Confidential-client Basic credentials, when configured; absent
            // for a public client, byte-identical to the pre-secret request.
            authorization: request
                .authorization
                .as_ref()
                .map(|authorization| authorization.as_str()),
        }),
        MAX_TOKEN_RESPONSE_BYTES,
        resolve,
    )?;
    Ok(parse_oidc_token_response(status, &body)?)
}

/// SSRF-safe GET of a bounded resource (in practice a provider's JWKS document),
/// reusing the exact same resolve-and-pin fetch primitive as the token POST.
///
/// Exposed `pub(crate)` so [`crate::oidc_id_token`] can fetch a
/// provider-controlled `jwks_uri` under the identical protections rather than
/// standing up a second, subtly-different network path. `max_response_bytes`
/// bounds the response body independently of any advertised `Content-Length`.
/// Production DNS resolution ([`resolve_host`]) is used; tests drive the
/// resolve-and-pin logic through [`ssrf_safe_get_with_resolver`].
///
/// # Errors
///
/// Returns [`OidcLiveTokenError::InvalidEndpoint`] for a malformed or
/// disallowed-scheme URL, [`OidcLiveTokenError::BlockedAddress`] when the host
/// resolves (wholly or partly) into a reserved range on the `https` path — or to
/// any non-loopback address on the `http` path — and
/// [`OidcLiveTokenError::Unavailable`] when the endpoint can't be reached or its
/// response can't be read within `max_response_bytes`.
pub(crate) fn ssrf_safe_get(
    endpoint: &str,
    max_response_bytes: u64,
) -> Result<(u16, Vec<u8>), OidcLiveTokenError> {
    ssrf_safe_fetch(
        Method::GET,
        endpoint,
        None,
        max_response_bytes,
        resolve_host,
    )
}

/// A request body (media type + bytes, plus the optional client-authentication
/// `Authorization` header value) for the POST path; [`None`] on the GET path,
/// where no body, `Content-Type`, or `Authorization` header is sent.
struct FetchBody<'a> {
    content_type: &'a str,
    body: &'a str,
    authorization: Option<&'a str>,
}

/// [`ssrf_safe_get`] with the host-resolution step injected, so the GET path can
/// be driven deterministically in tests (a `jwks_uri` resolving to a chosen
/// private/public address, or to a loopback mock) without real DNS — the GET
/// counterpart of [`exchange_oidc_token_with_resolver`].
#[cfg(test)]
fn ssrf_safe_get_with_resolver(
    endpoint: &str,
    max_response_bytes: u64,
    resolve: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
) -> Result<(u16, Vec<u8>), OidcLiveTokenError> {
    ssrf_safe_fetch(Method::GET, endpoint, None, max_response_bytes, resolve)
}

/// Production host resolution: the platform resolver (`getaddrinfo`) via
/// [`ToSocketAddrs`](std::net::ToSocketAddrs). An IP-literal host round-trips
/// through this unchanged.
fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(Iterator::collect)
}

/// The SSRF-safe fetch primitive shared by the token POST and the JWKS GET:
/// validate the URL's scheme/host, resolve and vet the host, pin the vetted
/// addresses, then send `method` — attaching `request_body`'s `Content-Type`
/// header and bytes only when it is [`Some`] (the POST path) — and return the
/// response `(status, bytes)` with the body read under `max_response_bytes`.
///
/// Keeping this one function means the resolve-and-vet SSRF logic is written
/// exactly once; the only per-caller differences (method, whether a body is
/// sent, and the response-size cap) are parameters.
fn ssrf_safe_fetch(
    method: Method,
    endpoint: &str,
    request_body: Option<&FetchBody<'_>>,
    max_response_bytes: u64,
    resolve: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
) -> Result<(u16, Vec<u8>), OidcLiveTokenError> {
    let url = Url::parse(endpoint).map_err(|_| OidcLiveTokenError::InvalidEndpoint)?;
    if !issuer_url_scheme_is_allowed(&url) {
        return Err(OidcLiveTokenError::InvalidEndpoint);
    }
    let host = url.host_str().ok_or(OidcLiveTokenError::InvalidEndpoint)?;
    let port = url
        .port_or_known_default()
        .ok_or(OidcLiveTokenError::InvalidEndpoint)?;

    // Resolve + vet BEFORE building the client or connecting. This is the step
    // that closes discovery's DNS-name hole for this fetch path.
    let pinned = resolve_and_vet(host, port, url.scheme(), resolve)?;

    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(Policy::none())
        .user_agent("stirling-pdf-rust-oidc/1")
        // Pin the exact vetted addresses so the socket cannot re-resolve `host`
        // to a different address between the check above and the connect below
        // (anti DNS-rebinding / TOCTOU). reqwest keys this override on the host
        // name; an IP-literal host bypasses resolution entirely and connects to
        // that literal directly, which the vet above has already screened.
        .resolve_to_addrs(host, &pinned)
        .build()
        .map_err(|_| OidcLiveTokenError::Unavailable)?;

    let mut builder = client.request(method, url);
    if let Some(&FetchBody {
        content_type,
        body,
        authorization,
    }) = request_body
    {
        builder = builder
            .header(CONTENT_TYPE, content_type)
            .body(body.to_owned());
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization);
        }
    }
    let response = builder
        .send()
        .map_err(|_| OidcLiveTokenError::Unavailable)?;

    // Do NOT `error_for_status`: RFC 6749 section 5.2 token errors arrive as
    // 4xx with a JSON error body the caller must see. GET callers screen the
    // status themselves.
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes)
    {
        return Err(OidcLiveTokenError::Unavailable);
    }
    let mut bytes = Vec::new();
    response
        .take(max_response_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OidcLiveTokenError::Unavailable)?;
    if bytes.len() as u64 > max_response_bytes {
        return Err(OidcLiveTokenError::Unavailable);
    }
    Ok((status, bytes))
}

/// Resolves `host` to concrete addresses and vets them against a per-scheme
/// SSRF policy, returning the exact addresses to pin (never empty) or an error.
///
/// Each scheme applies the policy that fits it (see the module docs), and
/// neither *skips* the check:
///
/// - **`https`** (the scheme a real, spoofable provider uses): reject if *any*
///   resolved address is in a private/reserved range, using the single shared
///   [`ip_addr_is_reserved`] predicate — the resolve-and-pin rejection that
///   mirrors discovery's own reserved-IP check.
/// - **`http`** (only ever admitted for the loopback literals
///   [`issuer_url_scheme_is_allowed`] permits — the dev/self-hosted seam):
///   reject unless *every* resolved address is loopback. Loopback stays
///   reachable for the mock, but an `http` host that resolves *off-box* to a
///   non-loopback address (an attacker-influenced `localhost`, or an
///   http-downgrade to some other host) is refused rather than silently
///   reached. This is the hardening that closed the earlier http-path skip.
fn resolve_and_vet(
    host: &str,
    port: u16,
    scheme: &str,
    resolve: impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
) -> Result<Vec<SocketAddr>, OidcLiveTokenError> {
    let addrs = resolve(host, port).map_err(|_| OidcLiveTokenError::Unavailable)?;
    if addrs.is_empty() {
        return Err(OidcLiveTokenError::Unavailable);
    }
    let blocked = if scheme == "https" {
        addrs.iter().any(|addr| ip_addr_is_reserved(addr.ip()))
    } else {
        // http: the only scheme besides https the gate admits, and only for a
        // loopback literal. Require loopback on every resolved address.
        addrs.iter().any(|addr| !addr.ip().is_loopback())
    };
    if blocked {
        return Err(OidcLiveTokenError::BlockedAddress);
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };

    use super::{
        OidcLiveTokenError, exchange_oidc_token_with_resolver, resolve_and_vet,
        ssrf_safe_get_with_resolver,
    };
    use crate::oidc_token::{OidcTokenError, OidcTokenRequest};

    const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
    /// Generous cap for the GET-path tests (a real JWKS is a small JSON object).
    const JWKS_TEST_CAP: u64 = 256 * 1024;

    fn http_response(status_line: &str, json: &str) -> String {
        format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            json.len()
        )
    }

    /// Serves exactly one HTTP request on `listener`, returning the raw request
    /// text it received (so a test can assert the method and form body). Uses a
    /// short read timeout and reads until it quiesces so the POST body — which
    /// can arrive in a segment after the headers — is captured in full. Mirrors
    /// the one-shot loopback fixture pattern in `oidc_discovery`'s tests.
    fn serve_once(
        listener: TcpListener,
        response: String,
    ) -> JoinHandle<Result<String, std::io::Error>> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_millis(250)))?;
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                match stream.read(&mut buffer) {
                    Ok(read) if read > 0 => request.extend_from_slice(&buffer[..read]),
                    // EOF (`Ok(0)`) or a read timeout (`Err`, WouldBlock/TimedOut)
                    // both mean the request is fully buffered; stop and respond.
                    _ => break,
                }
            }
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
            Ok(String::from_utf8_lossy(&request).into_owned())
        })
    }

    fn token_request(token_endpoint: String) -> OidcTokenRequest {
        OidcTokenRequest {
            token_endpoint,
            content_type: FORM_CONTENT_TYPE,
            form_body: "grant_type=authorization_code&code=abc&code_verifier=xyz".to_owned(),
            authorization: None,
        }
    }

    fn v4(octets: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
            port,
        )
    }

    // ---- happy path (c) ----------------------------------------------------

    #[test]
    fn exchanges_a_code_for_a_typed_token_response_against_a_loopback_mock()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let body = r#"{"access_token":"at-abc","token_type":"Bearer","expires_in":3600,"id_token":"h.p.s","refresh_token":"ignored"}"#;
        let server = serve_once(listener, http_response("200 OK", body));

        // Host is `localhost` (a name, so reqwest consults the pinned override);
        // the injected resolver points it at the loopback mock. The scheme is
        // http, allowed by the loopback seam, so the reserved-IP check is not
        // applied to the (reserved) loopback address.
        let request = token_request(format!("http://localhost:{}/token", address.port()));
        let resolve = move |_host: &str, _port: u16| Ok(vec![address]);
        let response = exchange_oidc_token_with_resolver(&request, resolve)?;

        let received = server.join().map_err(|_| "fixture server panicked")??;
        assert!(
            received.starts_with("POST /token "),
            "expected a POST to /token, got: {received}"
        );
        assert!(
            received.contains("grant_type=authorization_code"),
            "form body did not reach the endpoint: {received}"
        );
        assert_eq!(response.id_token, "h.p.s");
        assert_eq!(response.access_token, "at-abc");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, Some(3600));
        Ok(())
    }

    // ---- confidential-client Basic credentials reach the wire --------------

    #[test]
    fn a_confidential_request_sends_its_basic_authorization_header()
    -> Result<(), Box<dyn std::error::Error>> {
        use zeroize::Zeroizing;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let body = r#"{"access_token":"at","token_type":"Bearer","id_token":"a.b.c"}"#;
        let server = serve_once(listener, http_response("200 OK", body));

        let mut request = token_request(format!("http://localhost:{}/token", address.port()));
        request.authorization = Some(Zeroizing::new(
            "Basic bXktY2xpZW50OnRoZS1zZWNyZXQ=".to_owned(),
        ));
        let resolve = move |_: &str, _: u16| Ok(vec![address]);
        exchange_oidc_token_with_resolver(&request, resolve)?;

        let received = server.join().map_err(|_| "fixture server panicked")??;
        assert!(
            received.lines().any(|line| line
                .trim_end()
                .eq_ignore_ascii_case("authorization: Basic bXktY2xpZW50OnRoZS1zZWNyZXQ=")),
            "the Basic credentials never reached the endpoint: {received}"
        );
        Ok(())
    }

    #[test]
    fn a_public_request_sends_no_authorization_header() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let body = r#"{"access_token":"at","token_type":"Bearer","id_token":"a.b.c"}"#;
        let server = serve_once(listener, http_response("200 OK", body));

        let request = token_request(format!("http://localhost:{}/token", address.port()));
        let resolve = move |_: &str, _: u16| Ok(vec![address]);
        exchange_oidc_token_with_resolver(&request, resolve)?;

        let received = server.join().map_err(|_| "fixture server panicked")??;
        assert!(
            !received.to_ascii_lowercase().contains("authorization:"),
            "a public client must not send client credentials: {received}"
        );
        Ok(())
    }

    // ---- provider error (d) ------------------------------------------------

    #[test]
    fn surfaces_an_oauth2_provider_error_from_the_token_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let body = r#"{"error":"invalid_grant","error_description":"authorization code expired"}"#;
        let server = serve_once(listener, http_response("400 Bad Request", body));

        let request = token_request(format!("http://localhost:{}/token", address.port()));
        let resolve = move |_: &str, _: u16| Ok(vec![address]);
        let result = exchange_oidc_token_with_resolver(&request, resolve);
        let _ = server.join().map_err(|_| "fixture server panicked")??;

        match result {
            Err(OidcLiveTokenError::Token(OidcTokenError::Provider(error))) => {
                assert_eq!(error.error, "invalid_grant");
                assert_eq!(
                    error.error_description.as_deref(),
                    Some("authorization code expired")
                );
            }
            other => return Err(format!("expected a provider error, got {other:?}").into()),
        }
        Ok(())
    }

    // ---- resolve_to_addrs is actually wired (e) ----------------------------

    #[test]
    fn pins_the_vetted_address_so_the_connection_ignores_system_dns()
    -> Result<(), Box<dyn std::error::Error>> {
        // Bind the mock on 127.0.0.2 — a loopback address the system resolver
        // never returns for "localhost" (which maps to 127.0.0.1 / ::1). The
        // request targets http://localhost:PORT, so it can only reach this mock
        // if resolve_to_addrs actually pinned the vetted 127.0.0.2 address.
        // Without that wiring, reqwest would resolve "localhost" to 127.0.0.1,
        // where nothing is listening, and the exchange would fail.
        let listener = TcpListener::bind("127.0.0.2:0")?;
        let address = listener.local_addr()?;
        let body = r#"{"access_token":"at","token_type":"Bearer","id_token":"a.b.c"}"#;
        let server = serve_once(listener, http_response("200 OK", body));

        let request = token_request(format!("http://localhost:{}/token", address.port()));
        let resolve = move |_: &str, _: u16| Ok(vec![address]);
        let response = exchange_oidc_token_with_resolver(&request, resolve)?;

        let received = server.join().map_err(|_| "fixture server panicked")??;
        assert!(
            received.starts_with("POST /token "),
            "request never reached the pinned 127.0.0.2 mock: {received}"
        );
        assert_eq!(response.id_token, "a.b.c");
        Ok(())
    }

    // ---- reserved-IP rejection before connect (a) --------------------------

    #[test]
    fn rejects_a_host_that_resolves_to_a_reserved_address_without_connecting() {
        // 10.0.0.1 (RFC 1918) and 169.254.169.254 (link-local cloud metadata)
        // are the canonical DNS-based SSRF targets. Neither is reachable in the
        // test environment, so if a connection were attempted it would stall
        // near the 3s connect timeout; the assertion that the rejection is
        // near-instant proves it happened before any connect.
        for octets in [[10_u8, 0, 0, 1], [169, 254, 169, 254]] {
            let request = token_request("https://provider.example.com/token".to_owned());
            let resolve = move |_: &str, port: u16| Ok(vec![v4(octets, port)]);
            let started = Instant::now();
            let result = exchange_oidc_token_with_resolver(&request, resolve);
            let elapsed = started.elapsed();
            assert!(
                matches!(result, Err(OidcLiveTokenError::BlockedAddress)),
                "expected {octets:?} to be blocked, got {result:?}"
            );
            assert!(
                elapsed < Duration::from_secs(1),
                "rejection of {octets:?} took {elapsed:?}; a connection was likely attempted"
            );
        }
    }

    #[test]
    fn rejects_when_any_of_several_resolved_addresses_is_reserved() {
        // A name that resolves to a public AND a private address (a classic
        // multi-record DNS bypass) must be rejected on the private one.
        let request = token_request("https://provider.example.com/token".to_owned());
        let resolve =
            |_: &str, port: u16| Ok(vec![v4([8, 8, 8, 8], port), v4([10, 0, 0, 1], port)]);
        assert!(matches!(
            exchange_oidc_token_with_resolver(&request, resolve),
            Err(OidcLiveTokenError::BlockedAddress)
        ));
    }

    #[test]
    fn rejects_a_host_that_resolves_to_an_ipv4_mapped_ipv6_private_address()
    -> Result<(), Box<dyn std::error::Error>> {
        // A name resolving to the IPv4-mapped IPv6 form of a private address
        // (`::ffff:10.0.0.1`) must be rejected: `resolve_and_vet` feeds the
        // resolved `IpAddr` straight into `oidc_discovery`'s shared reserved
        // predicate, which unwraps embedded IPv4 forms — so the embedded-notation
        // SSRF that discovery's literal check already covers is closed on the
        // resolved-address path too, not just for bare IPv4 records.
        let mapped: IpAddr = "::ffff:10.0.0.1".parse()?;
        let result = resolve_and_vet(
            "provider.example.com",
            443,
            "https",
            move |_: &str, port: u16| Ok(vec![SocketAddr::new(mapped, port)]),
        );
        assert!(matches!(result, Err(OidcLiveTokenError::BlockedAddress)));
        Ok(())
    }

    // ---- public-resolved path reaches the fetch (b) ------------------------

    #[test]
    fn a_public_resolution_passes_the_ssrf_gate_and_yields_the_addresses_to_pin()
    -> Result<(), Box<dyn std::error::Error>> {
        // 93.184.216.34 is a public address, in none of the reserved ranges.
        // resolve_and_vet returning it (rather than an error) is exactly the
        // boundary "the fetch is reached": these are the addresses the client
        // would then pin and connect to.
        let public = v4([93, 184, 216, 34], 443);
        let vetted = resolve_and_vet("provider.example.com", 443, "https", |_: &str, _: u16| {
            Ok(vec![public])
        })?;
        assert_eq!(vetted, vec![public]);
        Ok(())
    }

    #[test]
    fn the_ssrf_gate_blocks_https_to_loopback_but_the_http_seam_still_allows_it()
    -> Result<(), Box<dyn std::error::Error>> {
        // Proves the scheme gate is not a weakening: over https, even a loopback
        // address is blocked (a real provider is https, so the resolve-and-pin
        // path stays strict) ...
        let loopback = v4([127, 0, 0, 1], 443);
        assert!(matches!(
            resolve_and_vet("provider.example.com", 443, "https", |_: &str, _: u16| Ok(
                vec![loopback]
            )),
            Err(OidcLiveTokenError::BlockedAddress)
        ));
        // ... while over http (only reachable for a loopback literal via the
        // scheme allow-list) the reserved check is intentionally not applied, so
        // the loopback mock the integration tests use stays reachable.
        let allowed = resolve_and_vet("localhost", 8080, "http", |_: &str, _: u16| {
            Ok(vec![loopback])
        })?;
        assert_eq!(allowed, vec![loopback]);
        Ok(())
    }

    // ---- http-loopback hardening (#39): off-box localhost is rejected -------

    #[test]
    fn rejects_an_http_host_that_resolves_off_box_to_a_non_loopback_address() {
        // The hardening: an earlier revision SKIPPED the reserved-IP check for
        // http entirely, so an http://localhost whose name resolves off-box
        // (poisoned /etc/hosts or resolver) to a non-loopback address reached
        // it. Now the http path requires EVERY resolved address to be loopback,
        // so both a public and a private (but non-loopback) resolution of
        // "localhost" over http are refused. Neither address is reachable in the
        // test environment, so the rejection is also verified to be immediate
        // (before any connect) via resolve_and_vet directly.
        for octets in [[93_u8, 184, 216, 34], [10, 0, 0, 1]] {
            let result = resolve_and_vet("localhost", 80, "http", move |_: &str, port: u16| {
                Ok(vec![v4(octets, port)])
            });
            assert!(
                matches!(result, Err(OidcLiveTokenError::BlockedAddress)),
                "expected http://localhost resolving to {octets:?} to be blocked, got {result:?}"
            );
        }
    }

    #[test]
    fn still_allows_an_http_host_that_resolves_to_a_non_127_0_0_1_loopback_address()
    -> Result<(), Box<dyn std::error::Error>> {
        // The seam must stay open for the whole 127.0.0.0/8 loopback block, not
        // just 127.0.0.1 — the pinned-address test binds its mock on 127.0.0.2.
        let loopback = v4([127, 0, 0, 2], 8080);
        let allowed = resolve_and_vet("localhost", 8080, "http", move |_: &str, _: u16| {
            Ok(vec![loopback])
        })?;
        assert_eq!(allowed, vec![loopback]);
        Ok(())
    }

    // ---- the generalized SSRF-safe GET (JWKS fetch path) -------------------

    #[test]
    fn the_jwks_get_reads_a_bounded_body_from_a_loopback_mock()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let jwks = r#"{"keys":[{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB"}]}"#;
        let server = serve_once(listener, http_response("200 OK", jwks));

        // Same loopback seam the token POST uses: http://localhost pinned at the
        // mock via the injected resolver.
        let (status, body) = ssrf_safe_get_with_resolver(
            &format!("http://localhost:{}/jwks.json", address.port()),
            JWKS_TEST_CAP,
            move |_: &str, _: u16| Ok(vec![address]),
        )?;

        let received = server.join().map_err(|_| "fixture server panicked")??;
        assert!(
            received.starts_with("GET /jwks.json "),
            "expected a GET to /jwks.json, got: {received}"
        );
        assert_eq!(status, 200);
        assert_eq!(body, jwks.as_bytes());
        Ok(())
    }

    #[test]
    fn the_jwks_get_rejects_a_jwks_uri_that_resolves_to_a_private_address() {
        // The provider-controlled jwks_uri gets the same resolve-and-pin SSRF
        // rejection as the token endpoint: a name resolving into a private range
        // is refused before any connection, so the verifier can never be steered
        // to fetch "keys" from internal infrastructure.
        let resolve = |_: &str, port: u16| Ok(vec![v4([10, 0, 0, 1], port)]);
        let started = Instant::now();
        let result = ssrf_safe_get_with_resolver(
            "https://provider.example.com/jwks.json",
            JWKS_TEST_CAP,
            resolve,
        );
        assert!(
            matches!(result, Err(OidcLiveTokenError::BlockedAddress)),
            "expected a private-resolved jwks_uri to be blocked, got {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "rejection was not immediate; a connection was likely attempted"
        );
    }

    #[test]
    fn the_jwks_get_enforces_the_response_size_cap() -> Result<(), Box<dyn std::error::Error>> {
        // A hostile or runaway JWKS endpoint returning a body larger than the
        // cap is refused rather than buffered unbounded. The mock omits
        // Content-Length (Connection: close, read-to-EOF), so this exercises the
        // streaming .take(cap + 1) guard, not just the advertised-length check.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let oversized = "x".repeat(64);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{oversized}"
        );
        let server = serve_once(listener, response);

        let result = ssrf_safe_get_with_resolver(
            &format!("http://localhost:{}/jwks.json", address.port()),
            32, // cap below the 64-byte body
            move |_: &str, _: u16| Ok(vec![address]),
        );
        let _ = server.join().map_err(|_| "fixture server panicked")?;
        assert!(
            matches!(result, Err(OidcLiveTokenError::Unavailable)),
            "expected an over-cap body to be rejected, got {result:?}"
        );
        Ok(())
    }

    // ---- endpoint validation happens before resolving ----------------------

    #[test]
    fn rejects_a_disallowed_scheme_endpoint_before_resolving() {
        // http to a non-loopback host is not allowed (matches discovery's
        // scheme policy). It must be rejected without invoking the resolver at
        // all — the resolver here panics if called, and the test would fail if
        // the rejection happened any later than the scheme check.
        let request = token_request("http://provider.example.com/token".to_owned());
        let resolve = |_: &str, _: u16| -> std::io::Result<Vec<SocketAddr>> {
            panic!("resolver must not be called for a disallowed-scheme endpoint")
        };
        assert!(matches!(
            exchange_oidc_token_with_resolver(&request, resolve),
            Err(OidcLiveTokenError::InvalidEndpoint)
        ));
    }

    #[test]
    fn rejects_a_malformed_endpoint_before_resolving() {
        let request = token_request("not a url".to_owned());
        let resolve = |_: &str, _: u16| -> std::io::Result<Vec<SocketAddr>> {
            panic!("resolver must not be called for a malformed endpoint")
        };
        assert!(matches!(
            exchange_oidc_token_with_resolver(&request, resolve),
            Err(OidcLiveTokenError::InvalidEndpoint)
        ));
    }
}
