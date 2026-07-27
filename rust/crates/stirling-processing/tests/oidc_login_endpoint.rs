//! Reviewed-secured-router integration tests for the generic-OIDC login routes
//! (`POST /api/v1/auth/oidc/authorize` + `GET /api/v1/auth/oidc/callback`).
//!
//! These drive the whole login handshake through the HTTP boundary against a
//! loopback mock `IdP` (discovery + token + JWKS + a self-signed id token). The
//! mock mirrors the fixture in `src/oidc_login.rs`, but here every step goes
//! over the router: `POST /authorize` yields the authorization URL + `state`
//! (and sets the login-CSRF browser-binding cookie), the mock's id token echoes
//! the URL's `nonce`, `GET /callback` — riding that cookie back, as the
//! initiating browser would — completes the login and answers the BROWSER with
//! a `302` to the SPA (`{origin}{path}#access_token=…`, mirroring Java's
//! `CustomOAuth2AuthenticationSuccessHandler`); the fragment token is then
//! exercised against `GET /auth/me`. Failures are `302`s to
//! `{path}?errorOAuth=oauth2AuthenticationError` (Java's failure handler),
//! one fixed location for every rejection cause.

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crypto_bigint::{ByteOrder, Encoding as _};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey as _, traits::PublicKeyParts as _};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
};
use tempfile::{TempDir, tempdir};
use tower::ServiceExt as _;

const CLIENT_ID: &str = "oidc-login-test-client";
const SUBJECT: &str = "oidc-endpoint-subject-1";
const KID: &str = "oidc-endpoint-test-key";
const PREFERRED_USERNAME: &str = "oidc-endpoint-user";
const REDIRECT_URI: &str = "http://127.0.0.1/login/oauth2/code/oidc";

// ---- RSA signing fixture (mirrors oidc_login's test fixture) ----------------

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

fn id_token_claims(issuer: &str, nonce: &str) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": issuer,
        "sub": SUBJECT,
        "aud": CLIENT_ID,
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "preferred_username": PREFERRED_USERNAME,
        "email": "oidc-endpoint-user@example.test",
        "sid": "provider-session-endpoint"
    })
}

// ---- mock IdP (discovery + token + jwks on one loopback listener) -----------

struct MockIdp {
    issuer: String,
    id_token_slot: Arc<Mutex<String>>,
    _handle: JoinHandle<()>,
}

impl MockIdp {
    fn set_id_token(&self, id_token: String) {
        if let Ok(mut slot) = self.id_token_slot.lock() {
            *slot = id_token;
        }
    }
}

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
            "access_token": "at-oidc-endpoint",
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

// ---- app + request helpers --------------------------------------------------

/// Builds a reviewed-secured app whose settings point OIDC login at `issuer`
/// (`None` ⇒ omit the whole `oauth2` block, leaving the feature unconfigured).
/// The returned [`TempDir`] guard owns the security database directory and must
/// outlive the app.
fn build_app(issuer: Option<&str>) -> Result<(TempDir, Router), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let config_directory = directory.path().join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings_path = config_directory.join("settings.yml");
    let oauth2_block = match issuer {
        Some(issuer) => format!(
            "  oauth2:\n    issuer: {issuer}\n    clientId: {CLIENT_ID}\n    redirectUri: {REDIRECT_URI}\n    scopes:\n      - openid\n      - profile\n      - email\n"
        ),
        None => String::new(),
    };
    fs::write(
        &settings_path,
        format!(
            "security:\n  initialLogin:\n    username: admin@example.test\n    password: test-only-password\n{oauth2_block}"
        ),
    )?;
    let runtime_config =
        RuntimeConfig::from_files(settings_path, config_directory.join("missing.yml"));
    let app =
        app_with_reviewed_security(1024 * 1024, TimestampSettings::default(), runtime_config)?;
    Ok((directory, app))
}

async fn oidc_authorize(
    app: &Router,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(Request::post("/api/v1/auth/oidc/authorize").body(Body::empty())?)
        .await?)
}

async fn oidc_callback(
    app: &Router,
    query: &str,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(Request::get(format!("/api/v1/auth/oidc/callback?{query}")).body(Body::empty())?)
        .await?)
}

/// Like [`oidc_callback`], but rides the browser-binding cookie the authorize
/// response set — the genuine same-browser callback of the login-CSRF defense.
async fn oidc_callback_with_cookie(
    app: &Router,
    query: &str,
    cookie: &str,
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/auth/oidc/callback?{query}"))
                .header(header::COOKIE, cookie)
                .body(Body::empty())?,
        )
        .await?)
}

/// Extracts the `name=value` pair of the browser-binding cookie set by the
/// authorize response, ready to be sent back verbatim as a `Cookie` header.
fn binding_cookie_pair(response: &axum::response::Response) -> Option<String> {
    let set_cookie = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    Some(set_cookie.split(';').next()?.trim().to_owned())
}

async fn response_json(
    response: axum::response::Response,
) -> Result<Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 1024 * 1024).await?,
    )?)
}

fn query_param(url: &str, key: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.into_owned())
}

/// The generic browser failure `Location` every genuine callback rejection
/// collapses to (Java's failure handler with this port's fixed error value).
const FAILURE_LOCATION: &str = "/auth/callback?errorOAuth=oauth2AuthenticationError";

/// The `Set-Cookie` clearing the SPA redirect-path cookie, sent on every
/// browser redirect (success and failure) with Java's exact attributes.
const CLEARED_REDIRECT_COOKIE: &str = "stirling_redirect_path=; Path=/; Max-Age=0; SameSite=Lax";

fn location_header(response: &axum::response::Response) -> Option<String> {
    Some(
        response
            .headers()
            .get(header::LOCATION)?
            .to_str()
            .ok()?
            .to_owned(),
    )
}

/// Asserts the response is the browser redirect shape both callback outcomes
/// share — `302 Found` plus the redirect-cookie clearing `Set-Cookie` — and
/// returns its `Location`.
fn assert_browser_redirect(
    response: &axum::response::Response,
) -> Result<String, Box<dyn std::error::Error>> {
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok()),
        Some(CLEARED_REDIRECT_COOKIE),
        "every callback redirect must clear the SPA redirect-path cookie"
    );
    location_header(response).ok_or_else(|| "a 302 callback response carried no Location".into())
}

/// Extracts `access_token` from a success redirect's `#fragment`, the exact
/// contract `AuthCallback.tsx` consumes (`URLSearchParams` over the hash).
fn fragment_access_token(location: &str) -> Option<String> {
    let (_, fragment) = location.split_once('#')?;
    fragment
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "access_token")
        .map(|(_, value)| value.to_owned())
}

/// Runs `POST /authorize`, then mints an id token for the returned `nonce`
/// (via `nonce_for_token`) and calls `GET /callback` with the issued `state`,
/// riding ONE `Cookie` header (as a browser would) that carries the
/// browser-binding cookie the authorize response set plus any `extra_cookies`
/// (`name=value` pairs, e.g. the SPA's redirect-path cookie). Returns the
/// issued `state`, the binding cookie pair, and the raw callback response so
/// callers assert status/headers themselves.
async fn drive_login_with_cookies(
    app: &Router,
    idp: &MockIdp,
    fixture: &SigningFixture,
    nonce_for_token: impl Fn(&str) -> String,
    extra_cookies: &[&str],
) -> Result<(String, String, axum::response::Response), Box<dyn std::error::Error>> {
    let authorize = oidc_authorize(app).await?;
    assert_eq!(authorize.status(), StatusCode::OK);
    let binding_cookie = binding_cookie_pair(&authorize)
        .ok_or("authorize response set no browser-binding cookie")?;
    let authorize = response_json(authorize).await?;
    let authorization_url = authorize["authorizationUrl"]
        .as_str()
        .ok_or("missing authorizationUrl")?
        .to_owned();
    let state = authorize["state"]
        .as_str()
        .ok_or("missing state")?
        .to_owned();
    // The state echoed in the redirect URL is exactly the JSON `state`.
    assert_eq!(
        query_param(&authorization_url, "state").as_deref(),
        Some(state.as_str())
    );
    let nonce = query_param(&authorization_url, "nonce").ok_or("missing nonce in url")?;
    idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &nonce_for_token(&nonce)))?);
    let mut cookie_header = binding_cookie.clone();
    for cookie in extra_cookies {
        cookie_header.push_str("; ");
        cookie_header.push_str(cookie);
    }
    let callback = oidc_callback_with_cookie(
        app,
        &format!("code=auth-code-endpoint&state={state}"),
        &cookie_header,
    )
    .await?;
    Ok((state, binding_cookie, callback))
}

/// [`drive_login_with_cookies`] with only the binding cookie — the plain
/// same-browser login.
async fn drive_login(
    app: &Router,
    idp: &MockIdp,
    fixture: &SigningFixture,
    nonce_for_token: impl Fn(&str) -> String,
) -> Result<(String, String, axum::response::Response), Box<dyn std::error::Error>> {
    drive_login_with_cookies(app, idp, fixture, nonce_for_token, &[]).await
}

// ---- happy path end-to-end --------------------------------------------------

#[tokio::test]
async fn oidc_login_issues_a_working_session_end_to_end() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    let (_state, _cookie, callback) = drive_login(&app, &idp, &fixture, str::to_owned).await?;

    // The callback answers the BROWSER: a 302 to the SPA callback route with
    // the access token in the URL FRAGMENT — `{path}#access_token=…`, exactly
    // what `AuthCallback.tsx` parses. With no redirect cookie and no
    // forwarded/referer/host context the Location stays context-relative.
    let location = assert_browser_redirect(&callback)?;
    let access_token =
        fragment_access_token(&location).ok_or("missing access_token in redirect fragment")?;
    assert_eq!(
        location,
        format!("/auth/callback#access_token={access_token}")
    );
    assert!(access_token.starts_with("spdf_at_"));

    // The fragment token is a real session: it authenticates a follow-up
    // request exactly like a password login's access token.
    let me = app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(me.status(), StatusCode::OK);
    assert_eq!(
        response_json(me).await?["user"]["username"],
        PREFERRED_USERNAME
    );
    Ok(())
}

// ---- context-aware success redirect (cookie path + forwarded origin) --------

#[tokio::test]
async fn oidc_success_redirect_honors_redirect_cookie_and_forwarded_origin()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    // The browser rides BOTH cookies back (binding + the SPA's redirect path,
    // written with encodeURIComponent) through a TLS-terminating proxy.
    let authorize = oidc_authorize(&app).await?;
    assert_eq!(authorize.status(), StatusCode::OK);
    let binding_cookie = binding_cookie_pair(&authorize)
        .ok_or("authorize response set no browser-binding cookie")?;
    let authorize = response_json(authorize).await?;
    let authorization_url = authorize["authorizationUrl"]
        .as_str()
        .ok_or("missing authorizationUrl")?;
    let state = authorize["state"].as_str().ok_or("missing state")?;
    let nonce = query_param(authorization_url, "nonce").ok_or("missing nonce in url")?;
    idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &nonce))?);

    let callback = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/auth/oidc/callback?code=auth-code-endpoint&state={state}"
            ))
            .header(
                header::COOKIE,
                format!("{binding_cookie}; stirling_redirect_path=%2Fafter-login"),
            )
            .header("x-forwarded-host", "app.example.test")
            .header("x-forwarded-proto", "https")
            .header(header::HOST, "127.0.0.1:8080")
            .body(Body::empty())?,
        )
        .await?;

    let location = assert_browser_redirect(&callback)?;
    let access_token =
        fragment_access_token(&location).ok_or("missing access_token in redirect fragment")?;
    // Origin from X-Forwarded-* (beating Host), path from the decoded cookie:
    // exactly Java's `buildContextAwareRedirectUrl` composition.
    assert_eq!(
        location,
        format!("https://app.example.test/after-login#access_token={access_token}")
    );
    Ok(())
}

// ---- hostile redirect cookie falls back to the default path -----------------

#[tokio::test]
async fn oidc_redirect_cookie_cannot_escape_the_path() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    for hostile in [
        "https%3A%2F%2Fevil.example", // absolute URL
        "%2F%2Fevil.example",         // protocol-relative
        "relative%2Fpath",            // not an absolute path
    ] {
        let (_state, _cookie, callback) = drive_login_with_cookies(
            &app,
            &idp,
            &fixture,
            str::to_owned,
            &[&format!("stirling_redirect_path={hostile}")],
        )
        .await?;
        let location = assert_browser_redirect(&callback)?;
        let access_token =
            fragment_access_token(&location).ok_or("missing access_token in redirect fragment")?;
        assert_eq!(
            location,
            format!("/auth/callback#access_token={access_token}"),
            "hostile cookie {hostile:?} must fall back to the default path"
        );
    }
    Ok(())
}

// ---- header injection via the redirect cookie is impossible -----------------

#[tokio::test]
async fn oidc_redirect_cookie_cannot_inject_headers_or_control_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    // Decoded cookie values that start with `/` (so they pass the path filter)
    // but smuggle CR/LF or other control bytes: the composed Location cannot
    // be a header value, so the redirect must fall back to the bare default
    // path — dropping the token rather than risking response splitting. No
    // header other than the expected ones may appear.
    for hostile in [
        "%2Fx%0D%0AX-Evil%3A%201", // /x\r\nX-Evil: 1 — classic response splitting
        "%2Fx%0Ainjected",         // bare \n
        "%2Fx%00null",             // NUL byte
    ] {
        let (_state, _cookie, callback) = drive_login_with_cookies(
            &app,
            &idp,
            &fixture,
            str::to_owned,
            &[&format!("stirling_redirect_path={hostile}")],
        )
        .await?;
        let location = assert_browser_redirect(&callback)?;
        assert_eq!(
            location, "/auth/callback",
            "control bytes in cookie {hostile:?} must collapse to the bare default path"
        );
        assert!(
            callback.headers().get("x-evil").is_none(),
            "no header may be injected through the redirect cookie"
        );
    }
    Ok(())
}

// ---- CSRF: a state that was never issued (route-level rejection) ------------

#[tokio::test]
async fn oidc_callback_rejects_a_state_that_was_never_issued()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    // A real login is in flight (state stored server-side)...
    let authorize = oidc_authorize(&app).await?;
    assert_eq!(authorize.status(), StatusCode::OK);
    let nonce = query_param(
        response_json(authorize).await?["authorizationUrl"]
            .as_str()
            .ok_or("missing authorizationUrl")?,
        "nonce",
    )
    .ok_or("missing nonce")?;
    // ...but the id token is ready, so only the state gates the forged callback.
    idp.set_id_token(fixture.sign(&id_token_claims(&idp.issuer, &nonce))?);

    let forged = oidc_callback(&app, "code=auth-code-endpoint&state=attacker-forged-state").await?;
    // A never-issued state must be rejected at the route — as the browser
    // failure redirect (Java's failure handler), never a session.
    assert_eq!(
        assert_browser_redirect(&forged)?,
        FAILURE_LOCATION,
        "a never-issued state must land on the generic error location"
    );
    Ok(())
}

// ---- single-use: a replayed callback is rejected the second time ------------

#[tokio::test]
async fn oidc_callback_state_is_single_use_a_replay_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    let (state, cookie, first) = drive_login(&app, &idp, &fixture, str::to_owned).await?;
    assert_eq!(first.status(), StatusCode::FOUND);
    assert!(
        location_header(&first).is_some_and(|location| location.contains("#access_token=")),
        "the first callback must succeed"
    );

    // Replay the exact same state+code WITH the same browser-binding cookie.
    // The id token is still available and the binding matches, so if the store
    // used get-not-remove this would succeed — the single-use guard is the
    // only thing rejecting it, proven here at the route level.
    let replay = oidc_callback_with_cookie(
        &app,
        &format!("code=auth-code-endpoint&state={state}"),
        &cookie,
    )
    .await?;
    assert_eq!(
        assert_browser_redirect(&replay)?,
        FAILURE_LOCATION,
        "a replayed state must be rejected the second time"
    );
    Ok(())
}

// ---- nonce mismatch collapses to the same generic 401 -----------------------

#[tokio::test]
async fn oidc_callback_rejects_a_mismatched_nonce_as_generic_auth_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    // The id token is otherwise valid but carries the wrong nonce; the callback
    // must reject it, and with the SAME redirect a bad state produces (no leak
    // of whether it was a CSRF-state miss or a verification failure).
    let (_state, _cookie, callback) = drive_login(&app, &idp, &fixture, |_nonce| {
        "a-different-nonce-not-the-login-one".to_owned()
    })
    .await?;
    assert_eq!(assert_browser_redirect(&callback)?, FAILURE_LOCATION);
    Ok(())
}

// ---- missing query params → the same generic error redirect -----------------

#[tokio::test]
async fn oidc_callback_missing_code_or_state_redirects_to_the_error_location()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    // Java's OAuth2LoginAuthenticationFilter treats a request that is not a
    // valid authorization response as an authentication failure, and the
    // failure handler redirects the browser — indistinguishably from any
    // other rejection. Same here.
    for query in [
        "",
        "code=only-a-code",
        "state=only-a-state",
        "code=&state=abc",
    ] {
        let response = oidc_callback(&app, query).await?;
        assert_eq!(
            assert_browser_redirect(&response)?,
            FAILURE_LOCATION,
            "missing/empty code or state should redirect for query {query:?}"
        );
    }
    Ok(())
}

// ---- disabled when unconfigured ---------------------------------------------

#[tokio::test]
async fn oidc_routes_are_absent_when_no_provider_is_configured()
-> Result<(), Box<dyn std::error::Error>> {
    let (_guard, app) = build_app(None)?;

    let authorize = oidc_authorize(&app).await?;
    assert_eq!(
        authorize.status(),
        StatusCode::NOT_FOUND,
        "authorize must not exist when OIDC login is unconfigured"
    );
    let callback = oidc_callback(&app, "code=abc&state=def").await?;
    assert_eq!(
        callback.status(),
        StatusCode::NOT_FOUND,
        "callback must not exist when OIDC login is unconfigured"
    );

    // The rest of the auth surface still works (password login unaffected).
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"username":"admin@example.test","password":"test-only-password"}"#,
                ))?,
        )
        .await?;
    assert_eq!(login.status(), StatusCode::OK);
    Ok(())
}
