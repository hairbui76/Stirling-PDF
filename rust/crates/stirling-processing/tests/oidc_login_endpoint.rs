//! Reviewed-secured-router integration tests for the generic-OIDC login routes
//! (`POST /api/v1/auth/oidc/authorize` + `GET /api/v1/auth/oidc/callback`).
//!
//! These drive the whole login handshake through the HTTP boundary against a
//! loopback mock `IdP` (discovery + token + JWKS + a self-signed id token). The
//! mock mirrors the fixture in `src/oidc_login.rs`, but here every step goes
//! over the router: `POST /authorize` yields the authorization URL + `state`
//! (and sets the login-CSRF browser-binding cookie), the mock's id token echoes
//! the URL's `nonce`, `GET /callback` — riding that cookie back, as the
//! initiating browser would — completes the login, and the returned access
//! token is exercised against `GET /auth/me`.

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

/// Runs `POST /authorize`, then mints an id token for the returned `nonce`
/// (via `nonce_for_token`) and calls `GET /callback` with the issued `state`,
/// forwarding the browser-binding cookie the authorize response set (as the
/// initiating browser would). Returns the issued `state`, that cookie pair,
/// and the raw callback response so callers assert status/body themselves.
async fn drive_login(
    app: &Router,
    idp: &MockIdp,
    fixture: &SigningFixture,
    nonce_for_token: impl Fn(&str) -> String,
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
    let callback = oidc_callback_with_cookie(
        app,
        &format!("code=auth-code-endpoint&state={state}"),
        &binding_cookie,
    )
    .await?;
    Ok((state, binding_cookie, callback))
}

// ---- happy path end-to-end --------------------------------------------------

#[tokio::test]
async fn oidc_login_issues_a_working_session_end_to_end() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    let (_state, _cookie, callback) = drive_login(&app, &idp, &fixture, str::to_owned).await?;
    assert_eq!(callback.status(), StatusCode::OK);
    let session = response_json(callback).await?;

    // The callback returns the SAME shape as the password login handler:
    // { user: {...}, session: { access_token, refresh_token, ... } }.
    assert_eq!(session["user"]["username"], PREFERRED_USERNAME);
    assert_eq!(session["user"]["authenticationType"], "oauth2");
    let access_token = session["session"]["access_token"]
        .as_str()
        .ok_or("missing access token")?;
    assert!(access_token.starts_with("spdf_at_"));
    assert!(
        session["session"]["refresh_token"]
            .as_str()
            .is_some_and(|token| token.starts_with("spdf_rt_"))
    );

    // The issued session actually authenticates a subsequent request.
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
    assert_eq!(
        forged.status(),
        StatusCode::UNAUTHORIZED,
        "a never-issued state must be rejected at the route"
    );
    // No session was minted for the forged callback.
    let forged = response_json(forged).await?;
    assert!(forged.get("session").is_none());
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
    assert_eq!(first.status(), StatusCode::OK);

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
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "a replayed state must be rejected the second time"
    );
    assert!(response_json(replay).await?.get("session").is_none());
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
    // must reject it, and with the SAME 401 a bad state produces (no leak of
    // whether it was a CSRF-state miss or a verification failure).
    let (_state, _cookie, callback) = drive_login(&app, &idp, &fixture, |_nonce| {
        "a-different-nonce-not-the-login-one".to_owned()
    })
    .await?;
    assert_eq!(callback.status(), StatusCode::UNAUTHORIZED);
    assert!(response_json(callback).await?.get("session").is_none());
    Ok(())
}

// ---- missing query params → 400 ---------------------------------------------

#[tokio::test]
async fn oidc_callback_missing_code_or_state_is_a_bad_request()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = SigningFixture::new()?;
    let idp = start_mock_idp(fixture.jwks_json.clone())?;
    let (_guard, app) = build_app(Some(&idp.issuer))?;

    for query in [
        "",
        "code=only-a-code",
        "state=only-a-state",
        "code=&state=abc",
    ] {
        let response = oidc_callback(&app, query).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "missing/empty code or state should be 400 for query {query:?}"
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
