//! Deterministic, network-free plumbing for the proprietary external-API-call
//! integration step.
//!
//! This is slice 1 of the port: the pieces that build and validate a request
//! before a byte ever leaves the process. It mirrors, 1:1, the Java oracles
//! under `app/proprietary/.../integration/api/`:
//!
//! - [`ExternalApiPaths`] — resolve a step-supplied relative path under the
//!   connection's operator-set base URL. This is the SSRF anchor: a step author
//!   supplies only a *relative* path, never a host.
//!   (oracle `ExternalApiPaths.java`)
//! - [`Placeholders`] — `{{dotted.path}}` substitution against a JSON context,
//!   with per-position escaping. (oracle `Placeholders.java`)
//! - [`ApiConnectionSettings`] — parse/validate an operator's connection config.
//!   (oracle `ApiConnectionSettings.java`)
//! - [`ExternalApiHeaders`] — RFC-7230 header-name/value grammar and the
//!   reserved-header set. (oracle `ExternalApiHeaders.java`)
//! - [`MultipartBody`] — build a `multipart/form-data` body in memory.
//!   (oracle `MultipartBody.java`)
//!
//! Every `IllegalArgumentException` in Java becomes an [`ExternalApiError`]; the
//! message strings are reproduced **verbatim** because the Java tests (and this
//! module's ported tests) assert on message substrings, and the operator sees
//! them while editing a connection.
//!
//! All four slices are landed: slice 1 (this request-construction plumbing),
//! slice 2 (`DocumentContext` + `buildBody`), slice 3 (the SSRF-safe outbound
//! caller with `TOKEN_LOGIN` parsing/validation and the login-once token cache
//! — oracles `ExternalApiCaller`, `ApiTokenCache`, `ApiTokenLogin`,
//! `ApiIntegrationValidator`), and slice 4 (verdict/report/replace handling,
//! `ResultUrls`/`ResultFiles`, and the `integration_http` route wiring).
#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    io::{Cursor, Read as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use lopdf::Document;
use rand::RngExt as _;
use regex::Regex;
use reqwest::{Method, blocking::Client, header::CONTENT_TYPE, redirect::Policy};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use url::Url;
use zip::ZipArchive;

use crate::{
    oidc_discovery::ip_addr_is_reserved,
    purview::{AssignmentMethod, PdfSensitivityLabels},
};

// ---------------------------------------------------------------------------
// Error type — every Java IllegalArgumentException maps here. Display carries
// the verbatim message so callers/tests can match on substrings.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub(crate) struct ExternalApiError(String);

fn invalid(message: impl Into<String>) -> ExternalApiError {
    ExternalApiError(message.into())
}

// ---------------------------------------------------------------------------
// (a) ExternalApiPaths — the SSRF anchor. (oracle ExternalApiPaths.java)
// ---------------------------------------------------------------------------

/// Resolves a step-supplied relative path under a connection's base URL.
///
/// `URI.resolve`/`Url::join` are deliberately **not** used: joining the
/// protocol-relative `//evil.example` against `https://api.example.com/v1`
/// silently changes host. Instead the path is screened, appended textually,
/// re-parsed (which normalises `.`/`..` segments), and the result is re-checked
/// against the base — so a miss in the screen is still caught by the check.
pub(crate) struct ExternalApiPaths;

impl ExternalApiPaths {
    /// `base` is the connection's base URL, already validated as http(s) with a
    /// host. `path` is a relative path, optionally with a query string; blank
    /// means the base itself.
    pub(crate) fn resolve(base: &Url, path: &str) -> Result<Url, ExternalApiError> {
        if path.trim().is_empty() {
            return Ok(base.clone());
        }
        let candidate = path.trim();
        Self::screen(candidate)?;

        let candidate = if candidate.starts_with('/') {
            candidate.to_owned()
        } else {
            format!("/{candidate}")
        };

        // Textual append against the base *string* (never `Url::join`). The base
        // has no trailing slash in practice (`ApiConnectionSettings` strips it);
        // `trim_end_matches('/')` also collapses the `url` crate's root-only
        // path so a host-only base like `https://api.example.com` matches Java's
        // trailing-slash-free `URI.toString()`.
        let combined = format!("{}{}", base.as_str().trim_end_matches('/'), candidate);
        let resolved = Url::parse(&combined)
            .map_err(|_| invalid(format!("api step 'path' is not a valid URL path: {path}")))?;

        Self::require_same_origin(base, &resolved, path)?;
        Self::require_under_base_path(base, &resolved, path)?;
        Ok(resolved)
    }

    /// Reject the shapes that could retarget the request before it is assembled.
    fn screen(path: &str) -> Result<(), ExternalApiError> {
        if path.contains("://") || path.starts_with("//") {
            return Err(invalid(format!(
                "api step 'path' must be relative to the connection's base URL, not an absolute or \
                 protocol-relative URL: {path}"
            )));
        }
        for c in path.chars() {
            // Control characters and spaces can split the request line; a
            // backslash is normalised to '/' by some servers and would sidestep
            // the traversal check below.
            if c <= '\u{20}' || c == '\u{7F}' || c == '\\' {
                return Err(invalid(format!(
                    "api step 'path' contains an illegal character: {path}"
                )));
            }
        }
        if path.contains('#') {
            return Err(invalid(format!(
                "api step 'path' must not contain a fragment: {path}"
            )));
        }
        // Percent-encoded dots would survive normalisation and be decoded by the
        // target, so a traversal must not be smuggled past us in encoded form.
        // Only dots are rejected: an encoded slash/backslash is legitimate data
        // inside a single segment (Placeholders encodes substituted values).
        if path.to_ascii_lowercase().contains("%2e") {
            return Err(invalid(format!(
                "api step 'path' must not percent-encode dots: {path}"
            )));
        }
        Ok(())
    }

    fn require_same_origin(
        base: &Url,
        resolved: &Url,
        original: &str,
    ) -> Result<(), ExternalApiError> {
        let same_origin = base.scheme().eq_ignore_ascii_case(resolved.scheme())
            && hosts_equal(base.host_str(), resolved.host_str())
            && base.port_or_known_default() == resolved.port_or_known_default()
            && resolved.username().is_empty()
            && resolved.password().is_none();
        if same_origin {
            return Ok(());
        }
        Err(invalid(format!(
            "api step 'path' would change the target host; it must stay under the connection's \
             base URL: {original}"
        )))
    }

    fn require_under_base_path(
        base: &Url,
        resolved: &Url,
        original: &str,
    ) -> Result<(), ExternalApiError> {
        // The base URL has its trailing slash stripped at parse time, so a base
        // path of "/v1" must match "/v1" exactly or be followed by a separator —
        // never "/v1betray".
        let base_path = base.path().trim_end_matches('/');
        let resolved_path = resolved.path();
        let under = base_path.is_empty()
            || resolved_path == base_path
            || resolved_path.starts_with(&format!("{base_path}/"));
        if under {
            return Ok(());
        }
        Err(invalid(format!(
            "api step 'path' escapes the connection's base path: {original}"
        )))
    }
}

fn hosts_equal(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        (None, None) => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// (b) Placeholders — {{dotted.path}} substitution. (oracle Placeholders.java)
// ---------------------------------------------------------------------------

/// How a resolved value is escaped for the position it lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Escaping {
    /// Verbatim: form fields and header values, which are validated separately.
    None,
    /// Percent-encoded: a path segment, where a stray slash would change the
    /// target. RFC-3986 unreserved characters pass through; dots are left raw.
    UrlPath,
}

/// The `{{ dotted.path }}` grammar. Compiled once. `(?-u)` makes `\w`/`\s`
/// ASCII, matching Java `Pattern`'s default (non-Unicode) classes.
fn placeholder_regex() -> Option<&'static Regex> {
    static PLACEHOLDER: OnceLock<Option<Regex>> = OnceLock::new();
    PLACEHOLDER
        .get_or_init(|| Regex::new(r"(?-u)\{\{\s*([\w.]+)\s*\}\}").ok())
        .as_ref()
}

pub(crate) struct Placeholders;

impl Placeholders {
    /// Substitute `{{...}}` references in `template` against `context`.
    ///
    /// `None` (Java `null`) passes through as `None`; an empty template passes
    /// through unchanged. A reference that names something the context does not
    /// hold is a hard error, so a typo surfaces instead of silently sending an
    /// empty value.
    pub(crate) fn resolve(
        template: Option<&str>,
        context: &Value,
        escaping: Escaping,
    ) -> Result<Option<String>, ExternalApiError> {
        let Some(template) = template else {
            return Ok(None);
        };
        if template.is_empty() {
            return Ok(Some(String::new()));
        }
        // The pattern is a valid compile-time constant, so `None` is unreachable;
        // fall back to leaving the template untouched rather than panicking.
        let Some(regex) = placeholder_regex() else {
            return Ok(Some(template.to_owned()));
        };

        let mut out = String::new();
        let mut last = 0;
        for captures in regex.captures_iter(template) {
            let (Some(whole), Some(reference)) = (captures.get(0), captures.get(1)) else {
                continue;
            };
            let path = reference.as_str();
            out.push_str(&template[last..whole.start()]);
            match Self::lookup(context, path) {
                Some(value) => out.push_str(&Self::render(value, escaping)),
                None => {
                    return Err(invalid(
                        String::from("unknown placeholder '{{")
                            + path
                            + "}}'; available: document.*, classification.*, sensitivityLabel.*, \
                               run.*",
                    ));
                }
            }
            last = whole.end();
        }
        out.push_str(&template[last..]);
        Ok(Some(out))
    }

    /// Resolve every string in a JSON tree, leaving structure and non-strings
    /// alone. Only JSON strings are substituted, always with [`Escaping::None`].
    pub(crate) fn resolve_tree(node: Value, context: &Value) -> Result<Value, ExternalApiError> {
        match node {
            Value::Object(map) => {
                let mut out = Map::new();
                for (name, child) in map {
                    out.insert(name, Self::resolve_tree(child, context)?);
                }
                Ok(Value::Object(out))
            }
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(Self::resolve_tree(item, context)?);
                }
                Ok(Value::Array(out))
            }
            Value::String(text) => {
                let resolved = Self::resolve(Some(&text), context, Escaping::None)?;
                Ok(Value::String(resolved.unwrap_or_default()))
            }
            other => Ok(other),
        }
    }

    /// Whether the text references anything at all, so callers can skip
    /// resolving.
    pub(crate) fn has_placeholder(text: Option<&str>) -> bool {
        match (text, placeholder_regex()) {
            (Some(text), Some(regex)) => regex.is_match(text),
            _ => false,
        }
    }

    /// Dotted lookup. A present JSON `null` returns `Some(Null)` (rendered as
    /// empty), while a missing key or a non-object mid-path returns `None`
    /// (an error at the call site).
    fn lookup<'a>(context: &'a Value, path: &str) -> Option<&'a Value> {
        let mut segments: Vec<&str> = path.split('.').collect();
        // Java `String.split(regex)` (limit 0) drops trailing empty strings.
        while segments.last() == Some(&"") {
            segments.pop();
        }
        let mut node = context;
        for segment in segments {
            if !node.is_object() {
                return None;
            }
            node = node.get(segment)?;
        }
        Some(node)
    }

    /// A null renders empty rather than the literal "null": absent metadata is a
    /// normal state, and "null" in a vendor's field would read as a value. An
    /// object/array renders as its compact JSON.
    fn render(value: &Value, escaping: Escaping) -> String {
        let text = match value {
            Value::Null => String::new(),
            Value::String(s) => s.clone(),
            // Number/Bool → their scalar string; Object/Array → compact JSON.
            other => other.to_string(),
        };
        match escaping {
            Escaping::None => text,
            Escaping::UrlPath => url_encode_path_segment(&text),
        }
    }
}

/// Encode for a path segment (RFC-3986 unreserved pass through). Dots are left
/// raw on purpose: `%2E%2E` survives normalisation and would be decoded by the
/// target, so an encoded traversal would arrive intact and unexamined. Left
/// raw, `..` normalises here and is caught by the under-the-base check.
fn url_encode_path_segment(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        let c = byte as char;
        let unreserved = c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~');
        if unreserved {
            out.push(c);
        } else {
            out.push('%');
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0F)] as char);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// (d) ExternalApiHeaders — RFC-7230 grammar + reserved set.
//     (oracle ExternalApiHeaders.java)
// ---------------------------------------------------------------------------

const RESERVED_HEADERS: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "expect",
];

/// RFC-7230 `token` special characters (beyond alphanumerics).
const HEADER_TOKEN_SPECIALS: &str = "!#$%&'*+-.^_`|~";

pub(crate) struct ExternalApiHeaders;

impl ExternalApiHeaders {
    /// RFC-7230 `token`: the only characters legal in a header name.
    pub(crate) fn is_valid_name(name: &str) -> bool {
        !name.is_empty() && name.chars().all(Self::is_token_char)
    }

    /// Visible ASCII, space and horizontal tab. Excludes CR/LF and NUL, which
    /// would inject.
    pub(crate) fn is_valid_value(value: &str) -> bool {
        value
            .chars()
            .all(|c| ('\u{20}'..='\u{7E}').contains(&c) || c == '\t')
    }

    pub(crate) fn is_reserved(name: &str) -> bool {
        RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str())
    }

    fn is_token_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || HEADER_TOKEN_SPECIALS.contains(c)
    }
}

// ---------------------------------------------------------------------------
// (c) ApiConnectionSettings — connection config. (oracle ApiConnectionSettings.java)
// ---------------------------------------------------------------------------

/// How an API connection authenticates. Enum names match Java's, which is what
/// [`ApiConnectionSettings`]'s credential-free `Display`/`Debug` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiAuthType {
    None,
    Bearer,
    Basic,
    Header,
    TokenLogin,
}

impl fmt::Display for ApiAuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ApiAuthType::None => "NONE",
            ApiAuthType::Bearer => "BEARER",
            ApiAuthType::Basic => "BASIC",
            ApiAuthType::Header => "HEADER",
            ApiAuthType::TokenLogin => "TOKEN_LOGIN",
        })
    }
}

/// How a `TOKEN_LOGIN` connection turns credentials into a short-lived token.
/// (oracle `ApiTokenLogin`.)
///
/// The two axes that vary between vendors are *where* the token comes back
/// (`token_response_header` **or** `token_response_json_path` — exactly one) and
/// *how* it is then presented (`token_header_name` + optional prefix). Parsed and
/// validated by [`ApiTokenLogin::from_options`] (slice 3).
///
/// `login_body` / `login_headers` carry the credentials, so [`fmt::Debug`] never
/// prints them (mirrors Java `toString`).
#[derive(Clone)]
pub(crate) struct ApiTokenLogin {
    login_path: String,
    /// The JSON object sent to `login_path`; may embed the password.
    login_body: Value,
    /// Headers sent on the login call; may embed a client secret.
    login_headers: BTreeMap<String, String>,
    /// Exactly one of these two is `Some` (enforced at parse time).
    token_response_header: Option<String>,
    token_response_json_path: Option<String>,
    /// The header the token is presented under on authenticated calls.
    token_header_name: String,
    /// Already carries its trailing space when non-empty (Java stores it so),
    /// so the sent value is simply `token_prefix + token`.
    token_prefix: String,
    token_ttl_seconds: i32,
}

impl fmt::Debug for ApiTokenLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiTokenLogin[loginPath={}, tokenTtlSeconds={}]",
            self.login_path, self.token_ttl_seconds
        )
    }
}

const BASE_URL_OPTION: &str = "baseUrl";
const AUTH_TYPE_OPTION: &str = "authType";
const HEADER_NAME_OPTION: &str = "headerName";
const HEADER_PREFIX_OPTION: &str = "headerPrefix";
const TOKEN_OPTION: &str = "token";
const USERNAME_OPTION: &str = "username";
const PASSWORD_OPTION: &str = "password";
const HEADERS_OPTION: &str = "headers";
const RESULT_URL_HOSTS_OPTION: &str = "resultUrlHosts";
const TIMEOUT_SECONDS_OPTION: &str = "timeoutSeconds";

const DEFAULT_TIMEOUT_SECONDS: i32 = 60;
const MAX_TIMEOUT_SECONDS: i32 = 600;

/// A resolved API connection: where to call, and how to authenticate.
///
/// `base_url` is the security anchor: it is operator-set and is the only thing
/// that decides which host is contacted. A pipeline step supplies a *relative
/// path* only, resolved under this base by [`ExternalApiPaths`].
#[derive(Clone)]
pub(crate) struct ApiConnectionSettings {
    pub(crate) base_url: String,
    pub(crate) auth_type: ApiAuthType,
    pub(crate) header_name: Option<String>,
    pub(crate) header_prefix: Option<String>,
    pub(crate) token: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) token_login: Option<ApiTokenLogin>,
    pub(crate) result_url_hosts: BTreeSet<String>,
    pub(crate) timeout_seconds: i32,
}

impl ApiConnectionSettings {
    /// Ports Java `ApiConnectionSettings.from(Map<String,Object>)`.
    ///
    /// Named `from_options` (not `from`) to avoid clashing with the `From`
    /// trait; the constructor is fallible, so `From` cannot express it.
    ///
    /// The Java oracle takes `Map<String,Object>`, so non-string option values
    /// are stringified via `Object.toString()` (e.g. a numeric `timeoutSeconds`
    /// or header value). [`java_to_string`] reproduces that for JSON scalars.
    pub(crate) fn from_options(
        options: &BTreeMap<String, Value>,
    ) -> Result<Self, ExternalApiError> {
        let base_url = trimmed(options.get(BASE_URL_OPTION))
            .ok_or_else(|| invalid("api config requires a 'baseUrl' option"))?;
        let uri = parse_http_url(&base_url)?;
        if uri.query().is_some() || uri.fragment().is_some() {
            return Err(invalid(
                "api config 'baseUrl' must not carry a query string or fragment",
            ));
        }

        let auth_type = parse_auth_type(trimmed(options.get(AUTH_TYPE_OPTION)).as_deref())?;
        let header_name = trimmed(options.get(HEADER_NAME_OPTION));
        // Many APIs want a scheme before the token ("Authorization: Token abc").
        let header_prefix = trimmed(options.get(HEADER_PREFIX_OPTION));
        let token = trimmed(options.get(TOKEN_OPTION));
        let username = trimmed(options.get(USERNAME_OPTION));
        let password = trimmed(options.get(PASSWORD_OPTION));

        match auth_type {
            ApiAuthType::Bearer => {
                require(
                    token.as_deref(),
                    "api config authType 'BEARER' requires a 'token'",
                )?;
            }
            ApiAuthType::Header => {
                require(
                    token.as_deref(),
                    "api config authType 'HEADER' requires a 'token'",
                )?;
                require(
                    header_name.as_deref(),
                    "api config authType 'HEADER' requires a 'headerName'",
                )?;
                if let Some(name) = header_name.as_deref()
                    && !ExternalApiHeaders::is_valid_name(name)
                {
                    return Err(invalid(format!(
                        "api config 'headerName' is not a valid HTTP header name: {name}"
                    )));
                }
            }
            ApiAuthType::Basic => {
                require(
                    username.as_deref(),
                    "api config authType 'BASIC' requires a 'username'",
                )?;
                require(
                    password.as_deref(),
                    "api config authType 'BASIC' requires a 'password'",
                )?;
            }
            // The TOKEN_LOGIN sub-config is validated by ApiTokenLogin::from_options
            // below (matching Java's `/* validated by ApiTokenLogin.from below */`).
            ApiAuthType::TokenLogin | ApiAuthType::None => {}
        }

        // Evaluated in Java's constructor-argument order so error precedence
        // matches: headers, then token-login, then result hosts, then timeout.
        let headers = parse_headers(options.get(HEADERS_OPTION))?;
        let token_login = if auth_type == ApiAuthType::TokenLogin {
            Some(ApiTokenLogin::from_options(options)?)
        } else {
            None
        };
        let result_url_hosts = parse_result_url_hosts(options.get(RESULT_URL_HOSTS_OPTION))?;
        let timeout_seconds = parse_timeout(options.get(TIMEOUT_SECONDS_OPTION))?;

        Ok(Self {
            base_url: strip_trailing_slash(&base_url),
            auth_type,
            header_name,
            header_prefix,
            token,
            username,
            password,
            headers,
            token_login,
            result_url_hosts,
            timeout_seconds,
        })
    }

    /// The configured base as a URL; callers resolve step paths under it.
    pub(crate) fn base_uri(&self) -> Result<Url, ExternalApiError> {
        Url::parse(&self.base_url).map_err(|_| invalid("api config 'baseUrl' is not a valid URL"))
    }
}

/// Never prints the credentials, so an accidental log line cannot leak them.
impl fmt::Display for ApiConnectionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiConnectionSettings[baseUrl={}, authType={}, timeoutSeconds={}]",
            self.base_url, self.auth_type, self.timeout_seconds
        )
    }
}

impl fmt::Debug for ApiConnectionSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

fn parse_http_url(value: &str) -> Result<Url, ExternalApiError> {
    // Parity guard. Java validates with java.net.URI (strict RFC 3986), which
    // rejects several malformed bases outright. The WHATWG `url` crate is far
    // more forgiving — it silently repairs them — and because `baseUrl` is the
    // SSRF anchor of this feature, that repair can invent a host the operator
    // never wrote. Two classes must fail closed exactly as the oracle does.
    //
    // 1. A backslash is illegal anywhere in a URI, so java.net.URI throws a
    //    URISyntaxException before it ever inspects the scheme or host. The
    //    `url` crate instead reads '\' as '/', e.g.
    //    `https://api.example.com\@evil.example/x` parses (host api.example.com,
    //    "@evil.example" buried in the path) and `https:/\/\evil.example`
    //    collapses to host evil.example — a backslash placed earlier in the
    //    authority could just as easily pivot the host. Reject any backslash
    //    first, matching Java's ordering and its "is not a valid URL" message.
    if value.contains('\\') {
        return Err(invalid("api config 'baseUrl' is not a valid URL"));
    }
    let uri = Url::parse(value).map_err(|_| invalid("api config 'baseUrl' is not a valid URL"))?;
    // The `url` crate already lower-cases the scheme.
    if uri.scheme() != "http" && uri.scheme() != "https" {
        return Err(invalid(
            "api config 'baseUrl' must be an http(s) URL, e.g. https://api.example.com",
        ));
    }
    // 2. The authority must be introduced by exactly "//" followed by a host
    //    character. java.net.URI treats a missing "//" (`https:example.com`), a
    //    single slash (`https:/example.com`), extra leading slashes
    //    (`https:///evil.example/x`) or an empty authority as a host-less URI —
    //    opaque or empty-authority — and reports a null host. The `url` crate
    //    collapses the slashes and promotes the first path segment to the host,
    //    so those forms must be rejected here to keep the oracle's verdict and
    //    its "must include a host" message.
    let after_scheme = value.split_once(':').map_or("", |(_, rest)| rest);
    let host_region = after_scheme
        .strip_prefix("//")
        .ok_or_else(|| invalid("api config 'baseUrl' must include a host"))?;
    // First authority char being a path/query/fragment delimiter (or absent)
    // means the authority is empty — host-less to java.net.URI.
    if host_region
        .chars()
        .next()
        .is_none_or(|c| matches!(c, '/' | '?' | '#'))
    {
        return Err(invalid("api config 'baseUrl' must include a host"));
    }
    match uri.host_str() {
        Some(host) if !host.is_empty() => Ok(uri),
        _ => Err(invalid("api config 'baseUrl' must include a host")),
    }
}

fn parse_auth_type(value: Option<&str>) -> Result<ApiAuthType, ExternalApiError> {
    let Some(value) = value else {
        return Ok(ApiAuthType::None);
    };
    match value.to_ascii_uppercase().as_str() {
        "NONE" => Ok(ApiAuthType::None),
        "BEARER" => Ok(ApiAuthType::Bearer),
        "BASIC" => Ok(ApiAuthType::Basic),
        "HEADER" => Ok(ApiAuthType::Header),
        "TOKEN_LOGIN" => Ok(ApiAuthType::TokenLogin),
        // Parity trap: the Java message lists only NONE/BEARER/BASIC/HEADER —
        // TOKEN_LOGIN is a valid value but is omitted from the error. Verbatim.
        _ => Err(invalid(format!(
            "api config 'authType' must be one of NONE, BEARER, BASIC, HEADER; got {value}"
        ))),
    }
}

/// Static headers sent on every call. Rejects anything auth-bearing to keep one
/// auth path.
fn parse_headers(value: Option<&Value>) -> Result<BTreeMap<String, String>, ExternalApiError> {
    let raw = match value {
        None | Some(Value::Null) => return Ok(BTreeMap::new()),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(invalid("api config 'headers' must be an object")),
    };
    let mut headers = BTreeMap::new();
    for (key, entry) in raw {
        let Some(name) = trimmed_str(key) else {
            continue;
        };
        if !ExternalApiHeaders::is_valid_name(&name) {
            return Err(invalid(format!(
                "api config 'headers' has an invalid header name: {name}"
            )));
        }
        if ExternalApiHeaders::is_reserved(&name) {
            return Err(invalid(format!(
                "api config 'headers' must not set '{name}'; use 'authType' and 'token' instead"
            )));
        }
        let header_value = match entry {
            Value::Null => None,
            other => Some(java_to_string(other)),
        };
        match header_value {
            Some(header_value) if ExternalApiHeaders::is_valid_value(&header_value) => {
                headers.insert(name, header_value);
            }
            _ => {
                return Err(invalid(format!(
                    "api config 'headers' has an invalid value for '{name}'"
                )));
            }
        }
    }
    Ok(headers)
}

/// Hosts a result may be fetched from, beyond the connection's own. Declared by
/// the operator because trusting the host named in the API's response is an SSRF.
fn parse_result_url_hosts(value: Option<&Value>) -> Result<BTreeSet<String>, ExternalApiError> {
    let list = match value {
        None | Some(Value::Null) => return Ok(BTreeSet::new()),
        Some(Value::Array(list)) => list,
        Some(_) => {
            return Err(invalid(
                "api config 'resultUrlHosts' must be a list of hostnames",
            ));
        }
    };
    let mut out = BTreeSet::new();
    for entry in list {
        let Some(host) = trimmed(Some(entry)) else {
            continue;
        };
        if host.contains('/') || host.contains(':') || host.contains('*') {
            // A URL, port or wildcard reads as broader than it is; subdomains are
            // already covered by the endsWith('.' + host) rule at match time.
            return Err(invalid(format!(
                "api config 'resultUrlHosts' takes bare hostnames, e.g. cdn.vendor.com; got {host}"
            )));
        }
        out.insert(host.to_lowercase());
    }
    Ok(out)
}

fn parse_timeout(value: Option<&Value>) -> Result<i32, ExternalApiError> {
    let text = match value {
        None | Some(Value::Null) => return Ok(DEFAULT_TIMEOUT_SECONDS),
        Some(other) => java_to_string(other),
    };
    // Java `Integer.parseInt(value.toString().trim())`.
    let seconds: i32 = text
        .trim()
        .parse()
        .map_err(|_| invalid("api config 'timeoutSeconds' must be a number"))?;
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&seconds) {
        return Err(invalid(format!(
            "api config 'timeoutSeconds' must be between 1 and {MAX_TIMEOUT_SECONDS}"
        )));
    }
    Ok(seconds)
}

fn require(present: Option<&str>, message: &str) -> Result<(), ExternalApiError> {
    match present {
        Some(_) => Ok(()),
        None => Err(invalid(message)),
    }
}

fn strip_trailing_slash(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

/// Java `Object.toString()` for a JSON scalar: a string yields its raw content
/// (no quotes); everything else (number/bool/null/array/object) yields its JSON
/// serialization, which for scalars matches `Integer.toString`/`Boolean.toString`.
fn java_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Java `trimmed(Object)`: `null` → `None`; otherwise `toString().trim()`, with
/// an empty result collapsing to `None`.
fn trimmed(value: Option<&Value>) -> Option<String> {
    match value {
        None | Some(Value::Null) => None,
        Some(other) => trimmed_str(&java_to_string(other)),
    }
}

fn trimmed_str(value: &str) -> Option<String> {
    let text = value.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

// ---------------------------------------------------------------------------
// (e) MultipartBody — build a multipart/form-data body. (oracle MultipartBody.java)
// ---------------------------------------------------------------------------

/// Builds a `multipart/form-data` body in memory. The boundary is
/// `StirlingBoundary` + base64url(16 random bytes), minted per request, so a
/// field value can never end its own part.
pub(crate) struct MultipartBody {
    boundary: String,
    out: Vec<u8>,
}

impl MultipartBody {
    pub(crate) fn new() -> Self {
        let mut random = [0_u8; 16];
        rand::rng().fill(&mut random);
        Self {
            boundary: format!("StirlingBoundary{}", URL_SAFE_NO_PAD.encode(random)),
            out: Vec::new(),
        }
    }

    pub(crate) fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Only the *name* is guarded (a quote/CR/LF/backslash could forge part
    /// headers). The value is body — quotes, newlines and backslashes are
    /// ordinary data here and are written verbatim (checking it like a header
    /// rejected every JSON value).
    pub(crate) fn add_field(
        &mut self,
        name: &str,
        value: &str,
    ) -> Result<&mut Self, ExternalApiError> {
        Self::require_safe(name, "field name")?;
        let header = format!(
            "--{}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n",
            self.boundary
        );
        self.out.extend_from_slice(header.as_bytes());
        self.out.extend_from_slice(value.as_bytes());
        self.out.extend_from_slice(b"\r\n");
        Ok(self)
    }

    pub(crate) fn add_file(
        &mut self,
        name: &str,
        filename: &str,
        content_type: &str,
        content: &[u8],
    ) -> Result<&mut Self, ExternalApiError> {
        Self::require_safe(name, "file field name")?;
        Self::require_safe(filename, "filename")?;
        let header = format!(
            "--{}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n\
             Content-Type: {content_type}\r\n\r\n",
            self.boundary
        );
        self.out.extend_from_slice(header.as_bytes());
        self.out.extend_from_slice(content);
        self.out.extend_from_slice(b"\r\n");
        Ok(self)
    }

    pub(crate) fn add_fields(
        &mut self,
        fields: &BTreeMap<String, String>,
    ) -> Result<&mut Self, ExternalApiError> {
        for (name, value) in fields {
            self.add_field(name, value)?;
        }
        Ok(self)
    }

    /// The bytes that go on the wire, including the closing boundary. Does not
    /// consume the builder, so `content_type()` is still callable afterwards.
    pub(crate) fn build(&self) -> Vec<u8> {
        let mut bytes = self.out.clone();
        bytes.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        bytes
    }

    /// A quote, CR, LF or backslash in a part header (field name or filename)
    /// would close the quoted string and forge headers of its own. Values are
    /// not checked: they are body, delimited by a per-request random boundary.
    fn require_safe(value: &str, what: &str) -> Result<(), ExternalApiError> {
        if value.contains('"')
            || value.contains('\r')
            || value.contains('\n')
            || value.contains('\\')
        {
            return Err(invalid(format!(
                "api step {what} contains an illegal character: {value}"
            )));
        }
        Ok(())
    }
}

impl Default for MultipartBody {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// (f) DocumentContext — the `{{...}}` namespace: everything Stirling already
//     knows about the document and the run, as one JSON object.
//     (oracle DocumentContext.java)
// ---------------------------------------------------------------------------

/// The Info-dictionary custom-metadata key the classifier writes its verdict
/// under. Verbatim from Java `PdfMetadataService.CLASSIFICATION_KEY`.
const CLASSIFICATION_KEY: &[u8] = b"StirlingPDFClassification";

/// Lower-case hex, matching Java `HexFormat.of().formatHex(...)`.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// The run facts a step already holds: which policy sent the document, the run
/// id, and when. Java reads `policyName`/`runId` from request headers and stamps
/// `Instant.now().toString()`; here the timestamp is supplied so the context is
/// deterministic and testable. All three are recorded even when absent (as JSON
/// `null`), so `{{run.policyName}}` resolves to empty rather than erroring.
pub(crate) struct RunFacts<'a> {
    pub(crate) policy_name: Option<&'a str>,
    pub(crate) run_id: Option<&'a str>,
    pub(crate) timestamp: &'a str,
}

/// Builds the placeholder namespace. (oracle `DocumentContext`)
pub(crate) struct DocumentContext;

impl DocumentContext {
    /// Everything known about the document and run, as one JSON object.
    ///
    /// Base facts are always present: `filename`, `extension`, `contentType`,
    /// `sizeBytes`, `sha256`, `base64`. PDF facts (`pageCount`, `encrypted`, the
    /// Info metadata, `classification.*`, `sensitivityLabel.*`) are best-effort —
    /// a non-PDF or an unparseable one simply omits them, never fails.
    ///
    /// A parsed PDF sets every Info field (`title`…`modified`) even when the
    /// value is absent, as JSON `null` — matching Java's unconditional
    /// `document.put(...)`. So `{{document.title}}` on a parsed PDF resolves to
    /// empty, while on a non-PDF the key is missing and the placeholder errors.
    pub(crate) fn build(
        file_bytes: &[u8],
        filename: Option<&str>,
        content_type: Option<&str>,
        run: &RunFacts<'_>,
    ) -> Value {
        let mut document = Map::new();
        document.insert("filename".to_owned(), opt_string(filename));
        document.insert(
            "extension".to_owned(),
            opt_string(extension_of(filename).as_deref()),
        );
        document.insert("contentType".to_owned(), opt_string(content_type));
        document.insert("sizeBytes".to_owned(), Value::from(file_bytes.len()));
        document.insert("sha256".to_owned(), Value::String(sha256_hex(file_bytes)));
        // The bytes themselves, for steps that carry the document inside a JSON
        // body (an attachment field, a signing payload) rather than as multipart.
        document.insert(
            "base64".to_owned(),
            Value::String(STANDARD.encode(file_bytes)),
        );

        // PDF facts and the two top-level namespaces are best-effort.
        let mut classification: Option<Value> = None;
        let mut sensitivity_label: Option<Value> = None;
        if looks_like_pdf(file_bytes) {
            add_pdf_facts(
                &mut document,
                &mut classification,
                &mut sensitivity_label,
                file_bytes,
            );
        }

        let mut root = Map::new();
        root.insert("document".to_owned(), Value::Object(document));
        if let Some(classification) = classification {
            root.insert("classification".to_owned(), classification);
        }
        if let Some(sensitivity_label) = sensitivity_label {
            root.insert("sensitivityLabel".to_owned(), sensitivity_label);
        }

        let mut run_node = Map::new();
        run_node.insert("policyName".to_owned(), opt_string(run.policy_name));
        run_node.insert("runId".to_owned(), opt_string(run.run_id));
        run_node.insert(
            "timestamp".to_owned(),
            Value::String(run.timestamp.to_owned()),
        );
        root.insert("run".to_owned(), Value::Object(run_node));

        Value::Object(root)
    }
}

/// PDF-only facts. A document we cannot parse still gets the base facts; a parse
/// failure here is swallowed, matching Java's `catch (IOException | RuntimeException)`.
fn add_pdf_facts(
    document: &mut Map<String, Value>,
    classification: &mut Option<Value>,
    sensitivity_label: &mut Option<Value>,
    content: &[u8],
) {
    let Ok(pdf) = Document::load_mem(content) else {
        // An encrypted or malformed PDF is a normal thing to send to an external
        // API; the extra facts are a convenience, not a precondition.
        return;
    };

    document.insert("pageCount".to_owned(), Value::from(pdf.get_pages().len()));
    document.insert(
        "encrypted".to_owned(),
        Value::Bool(pdf.encryption_state.is_some()),
    );

    // Reuse the pdf_json Info extraction (title…producer + ISO created/modified),
    // which mirrors PDFBox's `PDDocumentInformation` getters and date formatting.
    let info = crate::pdf_json::extract_metadata(&pdf);
    document.insert("title".to_owned(), opt_string(info.title.as_deref()));
    document.insert("author".to_owned(), opt_string(info.author.as_deref()));
    document.insert("subject".to_owned(), opt_string(info.subject.as_deref()));
    document.insert("keywords".to_owned(), opt_string(info.keywords.as_deref()));
    document.insert("creator".to_owned(), opt_string(info.creator.as_deref()));
    document.insert("producer".to_owned(), opt_string(info.producer.as_deref()));
    document.insert(
        "created".to_owned(),
        opt_string(info.creation_date.as_deref()),
    );
    document.insert(
        "modified".to_owned(),
        opt_string(info.modification_date.as_deref()),
    );

    add_classification(classification, &pdf);
    add_sensitivity_label(sensitivity_label, &pdf);
}

/// The classifier policy's verdict, so a call-out can act on it without
/// re-classifying. JSON when it parses, otherwise the raw text (written by
/// another tool, still recognisable to the receiver).
fn add_classification(out: &mut Option<Value>, pdf: &Document) {
    let Some(raw) = crate::pdf_metadata::document_info_text(pdf, CLASSIFICATION_KEY)
        .filter(|value| !value.trim().is_empty())
    else {
        return;
    };
    *out = Some(match serde_json::from_str::<Value>(&raw) {
        Ok(parsed) => parsed,
        Err(_) => Value::String(raw),
    });
}

/// The Purview label already on the document, if any (the first found).
fn add_sensitivity_label(out: &mut Option<Value>, pdf: &Document) {
    let labels = PdfSensitivityLabels::read_all(pdf);
    let Some(label) = labels.into_iter().next() else {
        return;
    };
    let mut node = Map::new();
    node.insert(
        "labelId".to_owned(),
        Value::String(label.label_id().to_owned()),
    );
    node.insert("name".to_owned(), opt_string(label.name()));
    node.insert(
        "siteId".to_owned(),
        Value::String(label.site_id().to_owned()),
    );
    node.insert(
        "method".to_owned(),
        match label.method() {
            // Java writes the enum *name* (STANDARD / PRIVILEGED), not the
            // mixed-case wire form.
            Some(method) => Value::String(assignment_method_name(method).to_owned()),
            None => Value::Null,
        },
    );
    node.insert("protected".to_owned(), Value::Bool(label.is_protected()));
    *out = Some(Value::Object(node));
}

/// The enum name Java's `AssignmentMethod.name()` yields.
fn assignment_method_name(method: AssignmentMethod) -> &'static str {
    match method {
        AssignmentMethod::Standard => "STANDARD",
        AssignmentMethod::Privileged => "PRIVILEGED",
    }
}

/// A present value renders as a JSON string; an absent one as JSON `null`, so a
/// documented-but-empty field resolves to empty rather than being missing.
fn opt_string(value: Option<&str>) -> Value {
    match value {
        Some(text) => Value::String(text.to_owned()),
        None => Value::Null,
    }
}

/// Cheap magic-byte check so a non-PDF never pays for a parse attempt. Matches
/// Java's `length > 4 && bytes 0..4 == "%PDF"`.
fn looks_like_pdf(content: &[u8]) -> bool {
    content.len() > 4 && &content[0..4] == b"%PDF"
}

/// Lower-case SHA-256 hex of the exact bytes the API will receive — the field
/// external systems most often key on (dedupe, chain-of-custody).
fn sha256_hex(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX_LOWER[usize::from(byte >> 4)] as char);
        out.push(HEX_LOWER[usize::from(byte & 0x0F)] as char);
    }
    out
}

/// The lower-cased extension, or `None` when the name has no dot or ends in one.
/// Java `extensionOf`: `lastIndexOf('.')`, reject `< 0` or trailing dot.
fn extension_of(filename: Option<&str>) -> Option<String> {
    let filename = filename?;
    let dot = filename.rfind('.')?;
    if dot == filename.len() - 1 {
        return None;
    }
    Some(filename[dot + 1..].to_lowercase())
}

// ---------------------------------------------------------------------------
// (g) buildBody — assemble the outbound body from the resolved fields, context
//     and file. (oracle ExternalApiCallController.buildBody / templatedBody)
// ---------------------------------------------------------------------------

/// A JSON media type, matching Java's `MediaType.APPLICATION_JSON_VALUE`.
const APPLICATION_JSON: &str = "application/json";

/// Field (multipart) and property (json) the auto-populated context rides under.
/// Verbatim from Java `ExternalApiCallController.CONTEXT_FIELD`.
const CONTEXT_FIELD: &str = "stirlingContext";

pub(crate) const BODY_MULTIPART: &str = "multipart";
pub(crate) const BODY_JSON: &str = "json";
pub(crate) const BODY_BINARY: &str = "binary";

/// The assembled outbound body: the content type to send and the raw bytes.
/// (Java's `ExternalApiCaller.Body`.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundBody {
    pub(crate) content_type: String,
    pub(crate) bytes: Vec<u8>,
}

/// The inputs [`build_body`] needs, gathered so the entry point stays a single
/// argument. `fields` are already placeholder-resolved by the caller; `filename`
/// / `content_type` are the safe/resolved forms the caller settled on.
pub(crate) struct BodyRequest<'a> {
    /// Already normalised to `multipart` | `json` | `binary`.
    pub(crate) body_mode: &'a str,
    /// A JSON template that, when set (non-blank), takes precedence over
    /// `body_mode` and carries an arbitrary vendor payload.
    pub(crate) body_template: Option<&'a str>,
    pub(crate) include_file: bool,
    pub(crate) include_context: bool,
    pub(crate) file_field_name: &'a str,
    pub(crate) filename: &'a str,
    pub(crate) content_type: &'a str,
    pub(crate) content: &'a [u8],
    pub(crate) fields: &'a BTreeMap<String, String>,
}

/// Assemble the outbound body. (oracle `ExternalApiCallController.buildBody`)
///
/// - `multipart` — the file plus form fields (what most upload APIs expect);
///   `includeFile=false` sends the fields only (a notify-style call-out).
/// - `json` — a JSON object of the fields, with the context optionally merged in
///   and the file base64'd under `content`.
/// - `binary` — the raw bytes as the body; fields have nowhere to go, so they are
///   refused rather than dropped, and `includeFile=false` would send nothing.
///
/// A non-blank `bodyTemplate` overrides all three: the template is resolved
/// against a deep copy of the context that also carries the file.
pub(crate) fn build_body(
    request: &BodyRequest<'_>,
    context: &Value,
) -> Result<OutboundBody, ExternalApiError> {
    if let Some(template) = request
        .body_template
        .filter(|template| !template.trim().is_empty())
    {
        return templated_body(
            template,
            context,
            request.filename,
            request.content_type,
            request.content,
        );
    }

    match request.body_mode {
        BODY_BINARY => {
            if !request.fields.is_empty() {
                return Err(invalid(
                    "bodyMode 'binary' sends only the document, so 'fields' cannot be sent; use \
                     'headers' instead, or bodyMode 'multipart'.",
                ));
            }
            if !request.include_file {
                return Err(invalid(
                    "bodyMode 'binary' with includeFile=false would send an empty body",
                ));
            }
            Ok(OutboundBody {
                content_type: request.content_type.to_owned(),
                bytes: request.content.to_vec(),
            })
        }
        BODY_JSON => {
            let mut json = Map::new();
            for (name, value) in request.fields {
                json.insert(name.clone(), Value::String(value.clone()));
            }
            if request.include_context
                && let Value::Object(map) = context
            {
                // Java `json.setAll(context)`: later inserts win over an earlier
                // field of the same name.
                for (name, value) in map {
                    json.insert(name.clone(), value.clone());
                }
            }
            if request.include_file {
                json.insert(
                    "filename".to_owned(),
                    Value::String(request.filename.to_owned()),
                );
                json.insert(
                    "contentType".to_owned(),
                    Value::String(request.content_type.to_owned()),
                );
                json.insert(
                    "content".to_owned(),
                    Value::String(STANDARD.encode(request.content)),
                );
            }
            let bytes = serde_json::to_vec(&Value::Object(json))
                .map_err(|_| invalid("api step failed to serialize the JSON body"))?;
            Ok(OutboundBody {
                content_type: APPLICATION_JSON.to_owned(),
                bytes,
            })
        }
        // multipart (default).
        _ => {
            let mut all = request.fields.clone();
            if request.include_context {
                let serialized = serde_json::to_string(context)
                    .map_err(|_| invalid("api step failed to serialize the context"))?;
                all.insert(CONTEXT_FIELD.to_owned(), serialized);
            }
            let mut body = MultipartBody::new();
            body.add_fields(&all)?;
            if request.include_file {
                body.add_file(
                    request.file_field_name,
                    request.filename,
                    request.content_type,
                    request.content,
                )?;
            }
            Ok(OutboundBody {
                content_type: body.content_type(),
                bytes: body.build(),
            })
        }
    }
}

/// A caller-shaped JSON body: the template is resolved against the context so an
/// arbitrary vendor payload can be expressed as config. `{{document.base64}}`
/// carries the file itself. (oracle `ExternalApiCallController.templatedBody`)
///
/// The file is injected into a *deep copy* of the context — `stirlingContext`
/// must not silently grow by a whole document.
// `content` (the bytes) and `context` (the namespace) are the oracle's own
// parameter names; kept for a faithful port despite the similar-names lint.
#[allow(clippy::similar_names)]
fn templated_body(
    body_template: &str,
    context: &Value,
    filename: &str,
    content_type: &str,
    content: &[u8],
) -> Result<OutboundBody, ExternalApiError> {
    let template: Value = serde_json::from_str(body_template)
        .map_err(|_| invalid("api step 'bodyTemplate' must be valid JSON"))?;

    let mut with_file = context.clone();
    if let Some(Value::Object(document)) = with_file.get_mut("document") {
        document.insert("base64".to_owned(), Value::String(STANDARD.encode(content)));
        document.insert(
            "safeFilename".to_owned(),
            Value::String(filename.to_owned()),
        );
        document.insert(
            "resolvedContentType".to_owned(),
            Value::String(content_type.to_owned()),
        );
    }

    let resolved = Placeholders::resolve_tree(template, &with_file)?;
    let bytes = serde_json::to_vec(&resolved)
        .map_err(|_| invalid("api step failed to serialize the templated body"))?;
    Ok(OutboundBody {
        content_type: APPLICATION_JSON.to_owned(),
        bytes,
    })
}

// ===========================================================================
// (h) Slice 3 — the SSRF-safe outbound caller, per-authType credential headers,
//     and the TOKEN_LOGIN login-once token cache. Mirrors the Java oracles
//     `ExternalApiCaller`, `ApiTokenCache`, `ApiTokenLogin`, `ApiIntegrationValidator`
//     (the base-host gate) and `ResultUrls` (the result-fetch host allowlist).
// ===========================================================================

// ---- ApiTokenLogin: parse + token extraction (oracle ApiTokenLogin) --------

const LOGIN_PATH_OPTION: &str = "loginPath";
const LOGIN_BODY_OPTION: &str = "loginBody";
const LOGIN_HEADERS_OPTION: &str = "loginHeaders";
const TOKEN_RESPONSE_HEADER_OPTION: &str = "tokenResponseHeader";
const TOKEN_RESPONSE_JSON_PATH_OPTION: &str = "tokenResponseJsonPath";
const TOKEN_HEADER_NAME_OPTION: &str = "tokenHeaderName";
const TOKEN_PREFIX_OPTION: &str = "tokenPrefix";
const TOKEN_TTL_SECONDS_OPTION: &str = "tokenTtlSeconds";

/// Conservative default (oracle `ApiTokenLogin.DEFAULT_TOKEN_TTL_SECONDS`):
/// cache for 25 min against a token good for ~30, so a slow call finishes on a
/// token still valid when it started.
const DEFAULT_TOKEN_TTL_SECONDS: i32 = 1500;
const MAX_TOKEN_TTL_SECONDS: i32 = 86400;

impl ApiTokenLogin {
    /// Ports Java `ApiTokenLogin.from(Map<String,Object>)`. Validation order (and
    /// so error precedence) matches the oracle: loginPath, exactly-one-of the two
    /// token-location options, tokenHeaderName presence + grammar, the response
    /// header's grammar, then loginBody / loginHeaders / TTL.
    fn from_options(options: &BTreeMap<String, Value>) -> Result<Self, ExternalApiError> {
        let login_path = trimmed(options.get(LOGIN_PATH_OPTION)).ok_or_else(|| {
            invalid("api config authType 'TOKEN_LOGIN' requires a 'loginPath', e.g. /auth/login")
        })?;

        let response_header = trimmed(options.get(TOKEN_RESPONSE_HEADER_OPTION));
        let response_json_path = trimmed(options.get(TOKEN_RESPONSE_JSON_PATH_OPTION));
        // Exactly one: both-absent and both-present are equally rejected.
        if response_header.is_none() == response_json_path.is_none() {
            return Err(invalid(
                "api config authType 'TOKEN_LOGIN' needs exactly one of 'tokenResponseHeader' \
                 (e.g. X-Auth-Token) or 'tokenResponseJsonPath' (e.g. access_token) to say where \
                 the token comes back",
            ));
        }

        let token_header_name =
            trimmed(options.get(TOKEN_HEADER_NAME_OPTION)).ok_or_else(|| {
                invalid(
                    "api config authType 'TOKEN_LOGIN' requires a 'tokenHeaderName' saying which \
                 header carries the token back, e.g. X-Auth-Token or Authorization",
                )
            })?;
        if !ExternalApiHeaders::is_valid_name(&token_header_name) {
            return Err(invalid(format!(
                "api config 'tokenHeaderName' is not a valid HTTP header name: {token_header_name}"
            )));
        }
        if let Some(header) = response_header.as_deref()
            && !ExternalApiHeaders::is_valid_name(header)
        {
            return Err(invalid(format!(
                "api config 'tokenResponseHeader' is not a valid HTTP header name: {header}"
            )));
        }

        let login_body = nested_object(options.get(LOGIN_BODY_OPTION), LOGIN_BODY_OPTION)?;
        let login_headers = parse_login_headers(options.get(LOGIN_HEADERS_OPTION))?;
        // Stored already carrying its trailing space, so the sent value is just
        // `prefix + token` (oracle stores it the same way).
        let token_prefix = trimmed(options.get(TOKEN_PREFIX_OPTION))
            .map(|prefix| format!("{prefix} "))
            .unwrap_or_default();
        let token_ttl_seconds = parse_token_ttl(options.get(TOKEN_TTL_SECONDS_OPTION))?;

        Ok(Self {
            login_path,
            login_body,
            login_headers,
            token_response_header: response_header,
            token_response_json_path: response_json_path,
            token_header_name,
            token_prefix,
            token_ttl_seconds,
        })
    }

    /// Pull the token out of a login response — from the configured response
    /// header, or by walking the configured dotted JSON path. Credential-free
    /// failure messages (they name the config field, never the response body).
    fn extract_token(&self, response: &ApiResponse) -> Result<String, ExternalApiError> {
        if let Some(header_name) = &self.token_response_header {
            return match response.header(header_name) {
                Some(value) if !value.trim().is_empty() => Ok(value.to_owned()),
                _ => Err(invalid(format!(
                    "Login succeeded but returned no '{header_name}' response header"
                ))),
            };
        }
        // Exactly one of the two is set; this is the JSON-path branch.
        let Some(path) = self.token_response_json_path.as_deref() else {
            return Err(invalid(
                "Login succeeded but no token location was configured",
            ));
        };
        let body = response.body_as_json();
        let mut node = body.as_ref();
        for segment in json_path_segments(path) {
            node = node.and_then(|value| value.get(segment));
        }
        match node.and_then(scalar_token) {
            Some(token) => Ok(token),
            None => Err(invalid(format!(
                "Login succeeded but its body had no token at '{path}'"
            ))),
        }
    }

    /// The header to send on an authenticated call: `(tokenHeaderName, prefix + token)`.
    fn auth_header(&self, token: &str) -> (String, String) {
        (
            self.token_header_name.clone(),
            format!("{}{token}", self.token_prefix),
        )
    }
}

/// Java `nestedObject`: `null` → empty object; a non-object → error; else the
/// object itself. Kept as a JSON [`Value`] so the login body serialises verbatim.
fn nested_object(value: Option<&Value>, option: &str) -> Result<Value, ExternalApiError> {
    match value {
        None | Some(Value::Null) => Ok(Value::Object(Map::new())),
        Some(Value::Object(map)) => Ok(Value::Object(map.clone())),
        Some(_) => Err(invalid(format!("api config '{option}' must be an object"))),
    }
}

/// The login call's headers. Unlike the connection's static `headers`, these are
/// **not** screened against the reserved set (a login legitimately sets
/// `X-Client-Secret`, and some flows post to `Authorization`): only name grammar
/// and value grammar are enforced. (oracle `ApiTokenLogin.loginHeaders`)
fn parse_login_headers(
    value: Option<&Value>,
) -> Result<BTreeMap<String, String>, ExternalApiError> {
    let raw = match value {
        None | Some(Value::Null) => return Ok(BTreeMap::new()),
        Some(Value::Object(map)) => map,
        Some(_) => return Err(invalid("api config 'loginHeaders' must be an object")),
    };
    let mut out = BTreeMap::new();
    for (name, entry) in raw {
        if !ExternalApiHeaders::is_valid_name(name) {
            return Err(invalid(format!(
                "api config 'loginHeaders' has an invalid header name: {name}"
            )));
        }
        let header_value = match entry {
            Value::Null => None,
            other => Some(java_to_string(other)),
        };
        match header_value {
            Some(value) if ExternalApiHeaders::is_valid_value(&value) => {
                out.insert(name.clone(), value);
            }
            _ => {
                return Err(invalid(format!(
                    "api config 'loginHeaders' has an invalid value for '{name}'"
                )));
            }
        }
    }
    Ok(out)
}

fn parse_token_ttl(value: Option<&Value>) -> Result<i32, ExternalApiError> {
    let text = match value {
        None | Some(Value::Null) => return Ok(DEFAULT_TOKEN_TTL_SECONDS),
        Some(other) => java_to_string(other),
    };
    let seconds: i32 = text
        .trim()
        .parse()
        .map_err(|_| invalid("api config 'tokenTtlSeconds' must be a number"))?;
    if !(1..=MAX_TOKEN_TTL_SECONDS).contains(&seconds) {
        return Err(invalid(format!(
            "api config 'tokenTtlSeconds' must be between 1 and {MAX_TOKEN_TTL_SECONDS}"
        )));
    }
    Ok(seconds)
}

/// Java `String.split("\\.")` with the default limit drops trailing empties.
fn json_path_segments(path: &str) -> Vec<&str> {
    let mut segments: Vec<&str> = path.split('.').collect();
    while segments.last() == Some(&"") {
        segments.pop();
    }
    segments
}

/// A JSON *value* node (Jackson `isValueNode()` && not blank): a non-blank
/// string, or a number/boolean rendered as text. An object/array/null is not a
/// token.
fn scalar_token(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        _ => None,
    }
}

// ---- ApiResponse (oracle ExternalApiCaller.Response) -----------------------

/// What the external API sent back. Header lookup is case-insensitive; the body
/// is the bytes read under the response-size cap.
#[derive(Debug, Clone)]
pub(crate) struct ApiResponse {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) body: Vec<u8>,
    headers: Vec<(String, String)>,
}

impl ApiResponse {
    /// A response header by name, case-insensitively; `None` when absent.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub(crate) fn is_json(&self) -> bool {
        self.content_type
            .as_deref()
            .is_some_and(|content_type| content_type.to_ascii_lowercase().contains("json"))
    }

    pub(crate) fn body_as_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn body_as_json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

// ---- SSRF gate: resolve, vet, pin (oracle ApiIntegrationValidator / S3Clients) ----

/// Cap on a response read into memory (oracle `ExternalApiCaller.MAX_RESPONSE_BYTES`):
/// 64 MiB. Enforced as a bounded read — the advertised `Content-Length` is
/// rejected up front, and the body itself is never buffered past the cap.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
/// Per-connection TCP-connect timeout (oracle `ExternalApiCaller.CONNECT_TIMEOUT`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded so many connections cannot grow the token cache without limit
/// (oracle `ApiTokenCache.MAX_ENTRIES`).
const MAX_TOKEN_CACHE_ENTRIES: usize = 500;

const BASE_HOST_SETTING: &str = "API connection base URL";
const RESULT_URL_SETTING: &str = "API result URL";
const PRIVATE_OPT_IN_HINT: &str =
    "set policies.allowPrivateApiEndpoints=true to opt in (e.g. for an on-prem integration).";

/// AWS/GCP/Azure, Oracle and IBM metadata addresses (oracle
/// `ApiIntegrationValidator.CLOUD_METADATA_IPS`).
///
/// The Java oracle compares these as textual `String.startsWith` prefixes, which
/// cannot match the IPv6 entry once `InetAddress.getHostAddress()` expands it to
/// `fd00:ec2:0:0:0:0:0:254`. Here they are parsed `IpAddr`s compared for equality
/// (after unwrapping an IPv4-mapped form), so `fd00:ec2::254` is actually
/// blocked — a deliberate, strictly-safer divergence from the oracle.
const CLOUD_METADATA_IPS: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 253)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 250)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
];

/// A hostname resolved to the exact addresses to connect to, pinned so DNS
/// cannot be re-pointed between the vet and the connect (anti-rebinding/TOCTOU).
struct PinnedHost {
    host: String,
    addrs: Vec<SocketAddr>,
}

/// A resolver injection seam: production uses [`resolve_host`]; tests drive the
/// gate deterministically without real DNS.
type HostResolver<'a> = &'a dyn Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>;

/// Production host resolution via the platform resolver. An IP-literal host
/// round-trips through this unchanged.
fn resolve_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(Iterator::collect)
}

/// Strip an IPv4-mapped-IPv6 wrapper so the compare sees the bare IPv4 address
/// (mirrors the oracle's `normalise`, minus the zone id which `IpAddr` never
/// carries here). Used for the deny message's display; the *detection* in
/// [`is_cloud_metadata`] additionally unwraps every other embedding form.
fn normalise_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Every IPv4 address `address` embeds through a standardized IPv4-in-IPv6
/// notation, in the SAME set of forms
/// [`oidc_discovery::ip_addr_is_reserved`] unwraps: IPv4-mapped,
/// IPv4-compatible, NAT64 well-known + local-use, 6to4, Teredo (server and
/// obfuscated client), and ISATAP. See `oidc_discovery` for the per-form RFC
/// citations and byte layouts — those extractors are private to that module and
/// this track must not widen another module's surface, so the layouts are
/// reproduced here. Keeping the two in lockstep is what makes the cloud-metadata
/// deny as comprehensive as the reserved-range check: e.g. `169.254.169.254`
/// encoded as the NAT64 AAAA `64:ff9b::a9fe:a9fe` must be caught even when the
/// operator has opted into private endpoints (which skips the reserved check).
fn embedded_ipv4_forms(address: Ipv6Addr) -> Vec<Ipv4Addr> {
    let octets = address.octets();
    let mut forms = Vec::new();

    // IPv4-mapped (`::ffff:a.b.c.d`, RFC 4291) — stdlib recognises this one.
    if let Some(v4) = address.to_ipv4_mapped() {
        forms.push(v4);
    }
    // IPv4-compatible (`::a.b.c.d`, RFC 4291 2.5.5.1): high 96 bits all zero.
    if octets[..12] == [0; 12] {
        forms.push(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    // NAT64 Well-Known Prefix (`64:ff9b::/96`, RFC 6052): IPv4 in the low 32 bits.
    if octets[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
        forms.push(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }
    // NAT64 Local-Use Prefix (`64:ff9b:1::/48`, RFC 8215): IPv4 straddles the
    // reserved "u" octet at index 8 (high bits at 6-7, low bits at 9-10).
    if octets[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01] {
        forms.push(Ipv4Addr::new(octets[6], octets[7], octets[9], octets[10]));
    }
    // 6to4 (`2002::/16`, RFC 3056): IPv4 in octets 2-5.
    if octets[..2] == [0x20, 0x02] {
        forms.push(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }
    // Teredo (`2001::/32`, RFC 4380): plain server IPv4 in octets 4-7 and the
    // bitwise-inverted ("obfuscated") client IPv4 in octets 12-15.
    if octets[..4] == [0x20, 0x01, 0x00, 0x00] {
        forms.push(Ipv4Addr::new(octets[4], octets[5], octets[6], octets[7]));
        forms.push(Ipv4Addr::new(
            !octets[12],
            !octets[13],
            !octets[14],
            !octets[15],
        ));
    }
    // ISATAP (RFC 5214): the `5e-fe` marker at octets 10-11, IPv4 in octets
    // 12-15; the 64-bit network prefix (octets 0-7) is unconstrained.
    if octets[10..12] == [0x5e, 0xfe] {
        forms.push(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    forms
}

/// True when `ip` is — or embeds, through any standardized IPv4-in-IPv6
/// notation ([`embedded_ipv4_forms`]) — one of the [`CLOUD_METADATA_IPS`]. This
/// deny is meant to be unconditional (it runs even under the private opt-in), so
/// it cannot rely on the reserved-range check to catch the embedded forms.
fn is_cloud_metadata(ip: IpAddr) -> bool {
    // Direct hit: a bare IPv4 metadata address, the IPv6 metadata literal, or an
    // IPv4-mapped wrapper thereof.
    if CLOUD_METADATA_IPS.contains(&normalise_ip(ip)) {
        return true;
    }
    // Otherwise, any other embedding of a metadata IPv4 is equally a hit.
    match ip {
        IpAddr::V6(v6) => embedded_ipv4_forms(v6)
            .into_iter()
            .any(|v4| CLOUD_METADATA_IPS.contains(&IpAddr::V4(v4))),
        IpAddr::V4(_) => false,
    }
}

/// The base-host gate run at dispatch time (oracle
/// `ApiIntegrationValidator.requirePublicHost`): the cloud-metadata deny is
/// UNCONDITIONAL and runs first; the private/reserved rejection is then skipped
/// only when the operator has opted into private endpoints.
fn require_public_host(
    base: &Url,
    allow_private: bool,
    resolve: HostResolver<'_>,
) -> Result<PinnedHost, ExternalApiError> {
    resolve_and_pin(base, allow_private, BASE_HOST_SETTING, true, resolve)
}

/// Resolve `url`'s host, vet every resolved address, and return them pinned.
///
/// `deny_metadata` gates the unconditional cloud-metadata block. It is `true`
/// for BOTH the base host and result URLs so a metadata IP (in any embedding
/// form — see [`is_cloud_metadata`]) is rejected even under the private opt-in,
/// which skips the reserved-range rejection. The base host mirrors the Java
/// `ApiIntegrationValidator` metadata deny; applying it to result URLs is
/// deliberately stricter than the `ResultUrls` oracle (which relies on the
/// reserved-range rejection alone, leaving metadata reachable under the opt-in).
/// The reserved-range rejection is always gated by `allow_private`. Every vetted
/// address is pinned so the socket cannot re-resolve to a different address after
/// the check.
fn resolve_and_pin(
    url: &Url,
    allow_private: bool,
    setting_name: &str,
    deny_metadata: bool,
    resolve: HostResolver<'_>,
) -> Result<PinnedHost, ExternalApiError> {
    let host = match url.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => {
            return Err(invalid(format!(
                "{setting_name} must include a host: {url}"
            )));
        }
    };
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid(format!("{setting_name} must include a host: {url}")))?;

    let addrs = resolve(host, port)
        .map_err(|_| invalid(format!("Unable to resolve {setting_name} host '{host}'")))?;
    if addrs.is_empty() {
        return Err(invalid(format!(
            "Unable to resolve {setting_name} host '{host}'"
        )));
    }

    if deny_metadata && let Some(addr) = addrs.iter().find(|addr| is_cloud_metadata(addr.ip())) {
        return Err(invalid(format!(
            "{setting_name} host '{host}' resolves to the cloud metadata service ({}), which is \
             never a valid integration target.",
            normalise_ip(addr.ip())
        )));
    }

    if !allow_private && let Some(addr) = addrs.iter().find(|addr| ip_addr_is_reserved(addr.ip())) {
        return Err(invalid(format!(
            "{setting_name} host '{host}' resolves to private/link-local address {}; \
             {PRIVATE_OPT_IN_HINT}",
            addr.ip()
        )));
    }

    Ok(PinnedHost {
        host: host.to_owned(),
        addrs,
    })
}

// ---- The low-level pinned send (oracle ExternalApiCaller.send) --------------

/// One outbound request's parameters, gathered so [`send`] stays a two-argument
/// function rather than a positional pile.
struct SendParts<'a> {
    method: &'a str,
    url: &'a Url,
    /// Set only for body-bearing verbs; `None` on a GET.
    content_type: Option<&'a str>,
    body: Option<&'a [u8]>,
    headers: &'a [(String, String)],
    timeout_seconds: i32,
    max_response_bytes: u64,
}

/// Send one request to the pinned host and read the response under the cap.
///
/// The client follows NO redirects (a 3xx could re-target a host the base URL
/// never authorised, undoing the gate) and pins the vetted addresses. Every error
/// message is credential-free: it names only the scheme/host/path, never the
/// token, the basic-auth pair, or a query string an operator may have put in the
/// path.
fn send(pinned: &PinnedHost, parts: &SendParts<'_>) -> Result<ApiResponse, ExternalApiError> {
    let method = Method::from_bytes(parts.method.as_bytes())
        .map_err(|_| invalid("api step has an unsupported HTTP method"))?;
    let timeout = Duration::from_secs(u64::try_from(parts.timeout_seconds).unwrap_or(60));

    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        .redirect(Policy::none())
        // Pin the vetted addresses; reqwest keys this on the host name, and an
        // IP-literal host bypasses resolution and connects to the literal (already
        // vetted) directly.
        .resolve_to_addrs(&pinned.host, &pinned.addrs)
        .build()
        .map_err(|_| invalid(format!("Failed to call {}", safe_target(parts.url))))?;

    let mut request = client.request(method, parts.url.clone());
    if let Some(content_type) = parts.content_type {
        request = request.header(CONTENT_TYPE, content_type);
    }
    for (name, value) in parts.headers {
        request = request.header(name, value);
    }
    if let Some(body) = parts.body {
        request = request.body(body.to_vec());
    }
    let response = request
        .send()
        .map_err(|_| invalid(format!("Failed to call {}", safe_target(parts.url))))?;

    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let headers = collect_headers(response.headers());
    // Reject an over-large body before reading it, then read under a hard cap so
    // a response omitting Content-Length cannot buffer past the limit either.
    if response
        .content_length()
        .is_some_and(|length| length > parts.max_response_bytes)
    {
        return Err(oversized(parts.url, parts.max_response_bytes));
    }
    let mut body = Vec::new();
    response
        .take(parts.max_response_bytes + 1)
        .read_to_end(&mut body)
        .map_err(|_| invalid(format!("Failed to call {}", safe_target(parts.url))))?;
    if body.len() as u64 > parts.max_response_bytes {
        return Err(oversized(parts.url, parts.max_response_bytes));
    }
    Ok(ApiResponse {
        status,
        content_type,
        body,
        headers,
    })
}

fn oversized(url: &Url, cap: u64) -> ExternalApiError {
    invalid(format!(
        "Response from {} exceeds the {cap} byte limit",
        safe_target(url)
    ))
}

/// Response headers as owned pairs, joining duplicate names with `, ` (oracle
/// `String.join(", ", values)`).
fn collect_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in headers {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if let Some(existing) = out
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name.as_str()))
        {
            existing.1.push_str(", ");
            existing.1.push_str(value);
        } else {
            out.push((name.as_str().to_owned(), value.to_owned()));
        }
    }
    out
}

/// Scheme, host and path only (oracle `safeTarget`): a query string could carry a
/// token an operator put there, and user-info is never echoed.
fn safe_target(url: &Url) -> String {
    let mut out = String::new();
    out.push_str(url.scheme());
    out.push_str("://");
    if let Some(host) = url.host_str() {
        out.push_str(host);
    }
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(url.path());
    out
}

// ---- Token cache (oracle ApiTokenCache) ------------------------------------

struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Login-once cache of `TOKEN_LOGIN` tokens, keyed on the connection's login
/// identity (credentials included) so editing a password stops reusing the token
/// bought with the old one. Each entry expires on its connection's stated TTL;
/// reading never extends it.
struct TokenCache {
    entries: HashMap<String, CachedToken>,
}

impl TokenCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// A live token for `key`, dropping it if it has expired (reading does not
    /// extend the vendor's clock).
    fn get(&mut self, key: &str) -> Option<String> {
        match self.entries.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => Some(entry.token.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }

    fn put(&mut self, key: String, token: String, ttl_seconds: i32) {
        self.purge_expired();
        if self.entries.len() >= MAX_TOKEN_CACHE_ENTRIES && !self.entries.contains_key(&key) {
            // Bounded like Caffeine's maximumSize: evict the soonest-to-expire.
            if let Some(evict) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(existing, _)| existing.clone())
            {
                self.entries.remove(&evict);
            }
        }
        let ttl = Duration::from_secs(u64::try_from(ttl_seconds).unwrap_or(1).max(1));
        self.entries.insert(
            key,
            CachedToken {
                token,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    fn invalidate(&mut self, key: &str) {
        self.entries.remove(key);
    }

    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.expires_at > now);
    }
}

/// Identity of a connection's login for cache purposes, INCLUDING the credentials
/// (login body + headers), hashed so the plaintext secret is never kept as a map
/// key. (oracle `ApiConnectionSettings.tokenCacheKey` + the TTL suffix)
fn token_cache_key(settings: &ApiConnectionSettings, login: &ApiTokenLogin) -> String {
    let body = serde_json::to_string(&login.login_body).unwrap_or_default();
    let headers = serde_json::to_string(&login.login_headers).unwrap_or_default();
    let material = format!(
        "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}\u{0}{body}\u{0}{headers}",
        settings.base_url,
        login.login_path,
        login.token_header_name,
        login.token_prefix,
        login.token_response_header.as_deref().unwrap_or_default(),
        login
            .token_response_json_path
            .as_deref()
            .unwrap_or_default(),
        login.token_ttl_seconds,
    );
    sha256_hex(material.as_bytes())
}

// ---- ExternalApiCaller (oracle ExternalApiCaller) --------------------------

/// Performs the outbound call for an `API` connection, and caches `TOKEN_LOGIN`
/// tokens. `allow_private_endpoints` mirrors the operator property
/// `policies.allowPrivateApiEndpoints` the base-host gate consults.
pub(crate) struct ExternalApiCaller {
    allow_private_endpoints: bool,
    tokens: Mutex<TokenCache>,
}

impl ExternalApiCaller {
    pub(crate) fn new(allow_private_endpoints: bool) -> Self {
        Self {
            allow_private_endpoints,
            tokens: Mutex::new(TokenCache::new()),
        }
    }

    /// POST a document to `path` under the base URL as multipart/form-data.
    #[allow(clippy::too_many_arguments)] // Faithful to the oracle's postFile signature.
    pub(crate) fn post_file(
        &self,
        settings: &ApiConnectionSettings,
        path: &str,
        file_field_name: &str,
        filename: &str,
        file_content_type: &str,
        content: &[u8],
        fields: &BTreeMap<String, String>,
    ) -> Result<ApiResponse, ExternalApiError> {
        self.post_file_with_resolver(
            settings,
            path,
            file_field_name,
            filename,
            file_content_type,
            content,
            fields,
            &resolve_host,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn post_file_with_resolver(
        &self,
        settings: &ApiConnectionSettings,
        path: &str,
        file_field_name: &str,
        filename: &str,
        file_content_type: &str,
        content: &[u8],
        fields: &BTreeMap<String, String>,
        resolve: HostResolver<'_>,
    ) -> Result<ApiResponse, ExternalApiError> {
        let mut multipart = MultipartBody::new();
        multipart.add_fields(fields)?;
        multipart.add_file(file_field_name, filename, file_content_type, content)?;
        let body = OutboundBody {
            content_type: multipart.content_type(),
            bytes: multipart.build(),
        };
        self.dispatch_with_resolver(settings, "POST", path, &body, &BTreeMap::new(), resolve)
    }

    /// Send `body` to `path` under the base URL with `method` (POST/PUT/PATCH).
    pub(crate) fn dispatch(
        &self,
        settings: &ApiConnectionSettings,
        method: &str,
        path: &str,
        body: &OutboundBody,
        extra_headers: &BTreeMap<String, String>,
    ) -> Result<ApiResponse, ExternalApiError> {
        self.dispatch_with_resolver(settings, method, path, body, extra_headers, &resolve_host)
    }

    fn dispatch_with_resolver(
        &self,
        settings: &ApiConnectionSettings,
        method: &str,
        path: &str,
        body: &OutboundBody,
        extra_headers: &BTreeMap<String, String>,
        resolve: HostResolver<'_>,
    ) -> Result<ApiResponse, ExternalApiError> {
        let base = settings.base_uri()?;
        // Resolve the step path first (an invalid path errors before the host is
        // dialled), then re-vet the host at dispatch time and pin it.
        let target = ExternalApiPaths::resolve(&base, path)?;
        let pinned = require_public_host(&base, self.allow_private_endpoints, resolve)?;

        let response = self.attempt(settings, method, &target, body, extra_headers, &pinned)?;
        if response.status == 401 && settings.auth_type == ApiAuthType::TokenLogin {
            // The cached token was rejected — expired early or revoked. One fresh
            // login and one retry; a second 401 means the credentials are wrong.
            self.invalidate_token(settings);
            return self.attempt(settings, method, &target, body, extra_headers, &pinned);
        }
        Ok(response)
    }

    /// GET `path` under the base URL (credentials applied; no 401 re-auth retry —
    /// that is `dispatch`'s alone, mirroring the oracle).
    pub(crate) fn get(
        &self,
        settings: &ApiConnectionSettings,
        path: &str,
    ) -> Result<ApiResponse, ExternalApiError> {
        self.get_with_resolver(settings, path, &resolve_host)
    }

    fn get_with_resolver(
        &self,
        settings: &ApiConnectionSettings,
        path: &str,
        resolve: HostResolver<'_>,
    ) -> Result<ApiResponse, ExternalApiError> {
        let base = settings.base_uri()?;
        let target = ExternalApiPaths::resolve(&base, path)?;
        let pinned = require_public_host(&base, self.allow_private_endpoints, resolve)?;
        let headers = self.request_headers(settings, &pinned)?;
        send(
            &pinned,
            &SendParts {
                method: "GET",
                url: &target,
                content_type: None,
                body: None,
                headers: &headers,
                timeout_seconds: settings.timeout_seconds,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
        )
    }

    /// GET a validated result URL. No credentials are sent — a result URL usually
    /// lives on a third-party host (a presigned link), and forwarding the token
    /// there would leak it. The only way to obtain a [`ValidatedResultUrl`] is
    /// [`ResultUrls::validate`], which is where the host allowlist lives.
    // A method (not an associated fn) to mirror the oracle's instance API and
    // keep call sites reading `caller.get_result(...)`; it needs no cache state.
    #[allow(clippy::unused_self)]
    pub(crate) fn get_result(
        &self,
        settings: &ApiConnectionSettings,
        target: &ValidatedResultUrl,
    ) -> Result<ApiResponse, ExternalApiError> {
        send(
            &target.pinned,
            &SendParts {
                method: "GET",
                url: &target.url,
                content_type: None,
                body: None,
                headers: &[],
                timeout_seconds: settings.timeout_seconds,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
        )
    }

    fn attempt(
        &self,
        settings: &ApiConnectionSettings,
        method: &str,
        target: &Url,
        body: &OutboundBody,
        extra_headers: &BTreeMap<String, String>,
        pinned: &PinnedHost,
    ) -> Result<ApiResponse, ExternalApiError> {
        let mut headers = self.request_headers(settings, pinned)?;
        // Step headers last so a step can add to a connection default; reserved
        // names (incl. the auth header) were rejected before we got here.
        for (name, value) in extra_headers {
            headers.push((name.clone(), value.clone()));
        }
        send(
            pinned,
            &SendParts {
                method,
                url: target,
                content_type: Some(&body.content_type),
                body: Some(&body.bytes),
                headers: &headers,
                timeout_seconds: settings.timeout_seconds,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
        )
    }

    /// The connection's static headers plus the credential header for its
    /// `authType` (oracle `applyHeaders`).
    fn request_headers(
        &self,
        settings: &ApiConnectionSettings,
        pinned: &PinnedHost,
    ) -> Result<Vec<(String, String)>, ExternalApiError> {
        let mut out: Vec<(String, String)> = settings
            .headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        match settings.auth_type {
            ApiAuthType::None => {}
            ApiAuthType::Bearer => {
                let token = settings.token.as_deref().unwrap_or_default();
                out.push(("Authorization".to_owned(), format!("Bearer {token}")));
            }
            ApiAuthType::Header => {
                let name = settings.header_name.clone().unwrap_or_default();
                let token = settings.token.as_deref().unwrap_or_default();
                let value = match settings.header_prefix.as_deref() {
                    Some(prefix) => format!("{prefix} {token}"),
                    None => token.to_owned(),
                };
                out.push((name, value));
            }
            ApiAuthType::Basic => {
                let user = settings.username.as_deref().unwrap_or_default();
                let pass = settings.password.as_deref().unwrap_or_default();
                let encoded = STANDARD.encode(format!("{user}:{pass}"));
                out.push(("Authorization".to_owned(), format!("Basic {encoded}")));
            }
            ApiAuthType::TokenLogin => {
                out.push(self.auth_header(settings, pinned)?);
            }
        }
        Ok(out)
    }

    fn auth_header(
        &self,
        settings: &ApiConnectionSettings,
        pinned: &PinnedHost,
    ) -> Result<(String, String), ExternalApiError> {
        let login = settings.token_login.as_ref().ok_or_else(|| {
            invalid("api config authType 'TOKEN_LOGIN' requires a token-login sub-config")
        })?;
        let token = self.token(settings, login, pinned)?;
        Ok(login.auth_header(&token))
    }

    fn token(
        &self,
        settings: &ApiConnectionSettings,
        login: &ApiTokenLogin,
        pinned: &PinnedHost,
    ) -> Result<String, ExternalApiError> {
        let key = token_cache_key(settings, login);
        if let Some(token) = self.cache_get(&key)? {
            return Ok(token);
        }
        let token = Self::login(settings, login, pinned)?;
        self.cache_put(key, &token, login.token_ttl_seconds)?;
        Ok(token)
    }

    fn login(
        settings: &ApiConnectionSettings,
        login: &ApiTokenLogin,
        pinned: &PinnedHost,
    ) -> Result<String, ExternalApiError> {
        let base = settings.base_uri()?;
        let target = ExternalApiPaths::resolve(&base, &login.login_path)?;
        let body = serde_json::to_vec(&login.login_body)
            .map_err(|_| invalid("api step failed to serialize the login body"))?;
        let headers: Vec<(String, String)> = login
            .login_headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let response = send(
            pinned,
            &SendParts {
                method: "POST",
                url: &target,
                content_type: Some(APPLICATION_JSON),
                body: Some(&body),
                headers: &headers,
                timeout_seconds: settings.timeout_seconds,
                max_response_bytes: MAX_RESPONSE_BYTES,
            },
        )?;
        if !response.is_success() {
            // Deliberately does not echo the body: a login failure can repeat the
            // credentials back, and this message reaches the run log.
            let host = base.host_str().unwrap_or_default();
            return Err(invalid(format!(
                "Login to {host}{} returned HTTP {}",
                login.login_path, response.status
            )));
        }
        login.extract_token(&response)
    }

    fn cache_get(&self, key: &str) -> Result<Option<String>, ExternalApiError> {
        let mut cache = self
            .tokens
            .lock()
            .map_err(|_| invalid("api token cache is unavailable"))?;
        Ok(cache.get(key))
    }

    fn cache_put(&self, key: String, token: &str, ttl: i32) -> Result<(), ExternalApiError> {
        let mut cache = self
            .tokens
            .lock()
            .map_err(|_| invalid("api token cache is unavailable"))?;
        cache.put(key, token.to_owned(), ttl);
        Ok(())
    }

    fn invalidate_token(&self, settings: &ApiConnectionSettings) {
        if let Some(login) = settings.token_login.as_ref()
            && let Ok(mut cache) = self.tokens.lock()
        {
            cache.invalidate(&token_cache_key(settings, login));
        }
    }
}

// ---- ResultUrls: the result-fetch host allowlist (oracle ResultUrls) -------

/// A result URL that has passed [`ResultUrls::validate`] — the only way to obtain
/// one, so [`ExternalApiCaller::get_result`] cannot be called with something
/// unchecked. Carries the pinned addresses vetted during validation.
pub(crate) struct ValidatedResultUrl {
    url: Url,
    pinned: PinnedHost,
}

pub(crate) struct ResultUrls;

impl ResultUrls {
    /// Validate a result URL the API asked us to fetch. Unlike a step `path`
    /// (operator-written), this URL is chosen by the remote service at run time,
    /// so it is checked against an operator-declared host allowlist and then
    /// resolved/vetted like any other target.
    pub(crate) fn validate(
        settings: &ApiConnectionSettings,
        url: &str,
        allow_private: bool,
    ) -> Result<ValidatedResultUrl, ExternalApiError> {
        Self::validate_with_resolver(settings, url, allow_private, &resolve_host)
    }

    fn validate_with_resolver(
        settings: &ApiConnectionSettings,
        url_str: &str,
        allow_private: bool,
        resolve: HostResolver<'_>,
    ) -> Result<ValidatedResultUrl, ExternalApiError> {
        let url = Url::parse(url_str.trim()).map_err(|_| {
            invalid(format!(
                "The API returned a result URL that is not a valid URL: {url_str}"
            ))
        })?;
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            // file:, gopher:, jar: and friends turn a URL fetch into a local read.
            return Err(invalid(format!(
                "The API returned a result URL that is not http(s): {url_str}"
            )));
        }
        let host = match url.host_str() {
            Some(host) if !host.is_empty() => host.to_owned(),
            _ => {
                return Err(invalid(format!(
                    "The API returned a result URL with no host: {url_str}"
                )));
            }
        };
        if !url.username().is_empty() || url.password().is_some() {
            // Credentials in a URL are the classic way to make one host look like
            // another.
            return Err(invalid(
                "The API returned a result URL carrying credentials, which is not accepted",
            ));
        }
        if !Self::is_allowed_host(settings, &host) {
            return Err(invalid(format!(
                "The API returned a result URL on '{host}', which this connection does not allow. \
                 Add it to the connection's 'resultUrlHosts' if results are meant to come from \
                 there."
            )));
        }
        // Even an allowlisted name must not resolve somewhere internal. The
        // cloud-metadata deny is applied here too (`deny_metadata = true`): it
        // must hold even when the operator opted into private endpoints, which
        // skips the reserved-range rejection the metadata IPs would otherwise
        // fall under. (This is stricter than the Java `ResultUrls` oracle, whose
        // reserved-only path leaves metadata reachable under the opt-in.)
        let pinned = resolve_and_pin(&url, allow_private, RESULT_URL_SETTING, true, resolve)?;
        Ok(ValidatedResultUrl { url, pinned })
    }

    /// The connection's own host is implicitly allowed; anything else must be
    /// declared. A subdomain of a declared host matches, but a bare suffix does
    /// not (`evilvendor.com` is not admitted by `vendor.com`).
    pub(crate) fn is_allowed_host(settings: &ApiConnectionSettings, host: &str) -> bool {
        let candidate = host.to_lowercase();
        if let Ok(base) = settings.base_uri()
            && base
                .host_str()
                .is_some_and(|base_host| base_host.eq_ignore_ascii_case(&candidate))
        {
            return true;
        }
        settings.result_url_hosts.iter().any(|entry| {
            let allowed = entry.to_lowercase();
            candidate == allowed || candidate.ends_with(&format!(".{allowed}"))
        })
    }
}

// ===========================================================================
// (i) Slice 4 — controller orchestration, response handling, and result
//     parsing. Mirrors the Java oracles `ExternalApiCallController` (the
//     `call` flow: verdict gate, report mode, replace mode), `ResultFiles`
//     (naming + archive selection), and reuses slice-3 `ResultUrls`/`getResult`
//     for the SSRF-vetted result fetch. The axum route + policy-step wiring
//     live in `integration_http.rs` and `policy_config.rs`.
// ===========================================================================

/// `ExternalApiCallController.MODE_REPORT` — the document continues untouched and
/// the API's answer rides in the report header.
const MODE_REPORT: &str = "report";
/// `ExternalApiCallController.MODE_REPLACE` — the response body becomes the document.
const MODE_REPLACE: &str = "replace";

/// The report travels as an HTTP header (Jetty caps a response header at 8 KB),
/// so a larger body is summarised rather than risking a header the container
/// refuses to write. (oracle `ExternalApiCallController.MAX_REPORT_BODY_CHARS`)
const MAX_REPORT_BODY_CHARS: usize = 4096;

/// `MediaType.APPLICATION_OCTET_STREAM_VALUE` — the fallback content type for an
/// upload/response that names none.
const APPLICATION_OCTET_STREAM: &str = "application/octet-stream";

/// `ExternalApiCallController.safeFileName` fallback when the upload names none.
const DEFAULT_FILENAME: &str = "document";

// ---- ResultFiles: name + archive selection (oracle ResultFiles.java) -------

/// Standard ZIP local-file-header magic, matching Java
/// `ZipExtractionUtils.ZIP_MAGIC`. A response is treated as an archive iff its
/// first four bytes are exactly this.
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// Recursion bound for nested archives (oracle `ZipExtractionUtils.MAX_UNZIP_DEPTH`);
/// a deeper nesting is left as a file rather than recursed into.
const MAX_UNZIP_DEPTH: usize = 10;

/// Adversarial bounds the Java oracle leaves to `ZipSecurity`'s hardened stream:
/// a cap on how many entries and how many decompressed bytes an archive may yield,
/// so a zip bomb cannot exhaust memory. The byte cap reuses the response cap.
const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = MAX_RESPONSE_BYTES;

/// Works out which bytes, and under which name, a response contributes to the
/// pipeline. (oracle `ResultFiles`)
pub(crate) struct ResultFiles;

impl ResultFiles {
    /// The filename to give the returned bytes: the server's `Content-Disposition`
    /// first, then the request base name with an extension derived from
    /// `Content-Type`, and only then the request name unchanged.
    /// (oracle `ResultFiles.nameFor`)
    pub(crate) fn name_for(response: &ApiResponse, request_filename: &str) -> String {
        if let Some(from_server) = response
            .header("content-disposition")
            .and_then(filename_from_disposition)
        {
            return from_server;
        }
        match extension_for(response.content_type.as_deref()) {
            None => request_filename.to_owned(),
            Some(extension) => format!("{}.{extension}", base_name(request_filename)),
        }
    }

    /// Whether the chosen name is itself an archive, so its content type is not the
    /// entry's. (oracle `ResultFiles.isArchiveName`)
    pub(crate) fn is_archive_name(filename: &str) -> bool {
        filename.to_ascii_lowercase().ends_with(".zip")
    }

    /// Whether the bytes start with the ZIP magic. (oracle `ResultFiles.isArchive`
    /// via `ZipExtractionUtils.isZip`)
    pub(crate) fn is_archive(bytes: &[u8]) -> bool {
        is_zip_bytes(bytes)
    }

    /// Pick the file a step asked for out of an archive: a `*`-glob against an
    /// entry name, or a 0-based index. An empty match or a multi-match is an error
    /// naming what was there — a silent pick of the wrong file is worse than a
    /// failed step. (oracle `ResultFiles.selectFromArchive`)
    pub(crate) fn select_from_archive(
        bytes: &[u8],
        select: &str,
    ) -> Result<(String, Vec<u8>), ExternalApiError> {
        let entries = extract_zip(bytes)?;
        if entries.is_empty() {
            return Err(invalid("The API returned an empty archive"));
        }
        if let Some(index) = as_index(select) {
            let len = entries.len();
            let Some(position) = usize::try_from(index)
                .ok()
                .filter(|position| *position < len)
            else {
                return Err(invalid(format!(
                    "'responseSelect' asked for entry {index} but the archive has {len}: {}",
                    names_list(entries.iter().map(|(name, _)| name.as_str()))
                )));
            };
            return entries
                .into_iter()
                .nth(position)
                .ok_or_else(|| invalid("archive entry index out of range"));
        }
        let matched: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, (name, _))| matches_glob(name, select))
            .map(|(index, _)| index)
            .collect();
        if matched.is_empty() {
            return Err(invalid(format!(
                "'responseSelect' matched nothing in the archive; it holds {}",
                names_list(entries.iter().map(|(name, _)| name.as_str()))
            )));
        }
        if matched.len() > 1 {
            // Taking the first would be a coin toss the operator did not ask for.
            return Err(invalid(format!(
                "'responseSelect' matched {} entries ({}); narrow it, or use an index",
                matched.len(),
                names_list(matched.iter().map(|&index| entries[index].0.as_str()))
            )));
        }
        let index = matched[0];
        entries
            .into_iter()
            .nth(index)
            .ok_or_else(|| invalid("archive entry index out of range"))
    }
}

/// The ZIP magic-byte test, shared by [`ResultFiles::is_archive`] and the nested
/// extraction check.
fn is_zip_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= ZIP_MAGIC.len() && bytes[..ZIP_MAGIC.len()] == ZIP_MAGIC
}

/// A running budget so extraction cannot be turned into an unbounded memory
/// allocation by a hostile archive.
struct ExtractBudget {
    entries: usize,
    bytes: u64,
}

/// Flatten a ZIP into `(name, bytes)` pairs, one per file entry, recursing into
/// nested archives up to [`MAX_UNZIP_DEPTH`]. (oracle `ZipExtractionUtils.extractZip`)
///
/// Everything is held in memory, so there is no filesystem to zip-slip into — the
/// entry name is used only as data, never as a path. Entry count and decompressed
/// size are bounded to defuse a zip bomb.
fn extract_zip(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ExternalApiError> {
    let mut out = Vec::new();
    let mut budget = ExtractBudget {
        entries: 0,
        bytes: 0,
    };
    extract_zip_into(bytes, 0, &mut budget, &mut out)?;
    Ok(out)
}

fn extract_zip_into(
    bytes: &[u8],
    depth: usize,
    budget: &mut ExtractBudget,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), ExternalApiError> {
    let read_error = || invalid("The API returned an archive that could not be read");
    let mut archive = ZipArchive::new(Cursor::new(bytes)).map_err(|_| read_error())?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|_| read_error())?;
        if entry.is_dir() {
            continue;
        }
        budget.entries += 1;
        if budget.entries > MAX_ARCHIVE_ENTRIES {
            return Err(invalid("The API returned an archive with too many entries"));
        }
        if budget.bytes.saturating_add(entry.size()) > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err(invalid(
                "The API returned an archive that expands beyond the allowed size",
            ));
        }
        let name = entry.name().to_owned();
        // Read under a hard cap so a lying declared size cannot buffer past the
        // budget either.
        let remaining = MAX_ARCHIVE_UNCOMPRESSED_BYTES.saturating_sub(budget.bytes);
        let mut data = Vec::new();
        entry
            .by_ref()
            .take(remaining + 1)
            .read_to_end(&mut data)
            .map_err(|_| invalid("The API returned an archive entry that could not be read"))?;
        if data.len() as u64 > remaining {
            return Err(invalid(
                "The API returned an archive that expands beyond the allowed size",
            ));
        }
        budget.bytes += data.len() as u64;
        drop(entry);
        if is_zip_bytes(&data) && depth < MAX_UNZIP_DEPTH {
            // A nested archive is replaced by its own entries (matching the oracle),
            // never added as a `.zip` itself.
            extract_zip_into(&data, depth + 1, budget, out)?;
        } else {
            out.push((name, data));
        }
    }
    Ok(())
}

/// `[a, b, c]`, matching Java `List.toString()` used in the selection errors.
fn names_list<'a>(names: impl Iterator<Item = &'a str>) -> String {
    format!("[{}]", names.collect::<Vec<_>>().join(", "))
}

/// A `*`-only glob against the whole (lower-cased) entry name. (oracle
/// `ResultFiles.matchesGlob`)
fn matches_glob(filename: &str, glob: &str) -> bool {
    let name = filename.to_ascii_lowercase();
    let pattern = glob.trim().to_ascii_lowercase();
    let regex_src = format!(
        "^{}$",
        pattern
            .split('*')
            .map(regex::escape)
            .collect::<Vec<_>>()
            .join(".*")
    );
    match Regex::new(&regex_src) {
        Ok(regex) => regex.is_match(&name),
        Err(_) => false,
    }
}

/// `select` as a 0-based index, or `None` when it is not an integer (Java parses
/// with `Integer.valueOf`, so an out-of-`i32`-range value is treated as a glob).
fn as_index(select: &str) -> Option<i32> {
    select.trim().parse::<i32>().ok()
}

/// `attachment; filename="signed.pdf"` or its RFC 5987 `filename*` form. The name
/// comes from the remote server, so any path it brings is stripped — it is treated
/// as data, never as a location. (oracle `ResultFiles.filenameFromDisposition`)
fn filename_from_disposition(disposition: &str) -> Option<String> {
    for part in disposition.split(';') {
        let token = part.trim();
        let mut value = if starts_with_ci(token, "filename=") {
            token["filename=".len()..].trim().to_owned()
        } else if starts_with_ci(token, "filename*=") {
            let raw = token["filename*=".len()..].trim();
            match raw.rfind('\'') {
                Some(tick) => raw[tick + 1..].to_owned(),
                None => raw.to_owned(),
            }
        } else {
            continue;
        };
        if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
            value = value[1..value.len() - 1].to_owned();
        }
        if let Some(simple) = simple_file_name(&value) {
            return Some(simple);
        }
    }
    None
}

/// Case-insensitive ASCII prefix test that never panics on a multi-byte boundary.
fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.is_char_boundary(prefix.len())
        && text
            .get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Strip any path a server-supplied name carries (defusing traversal) and trim;
/// a blank result is `None`. (oracle `Filenames.toSimpleFileName`)
fn simple_file_name(value: &str) -> Option<String> {
    let last = value.rsplit(['/', '\\']).next().unwrap_or(value).trim();
    (!last.is_empty()).then(|| last.to_owned())
}

/// The extension for a content type, or `None` to keep the server's filename.
/// (oracle `ResultFiles.EXTENSION_BY_TYPE` / `extensionFor`)
fn extension_for(content_type: Option<&str>) -> Option<&'static str> {
    let content_type = content_type?;
    let base = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    Some(match base.as_str() {
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/json" => "json",
        "text/plain" => "txt",
        "text/html" => "html",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/tiff" => "tiff",
        "application/msword" => "doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => "docx",
        "application/vnd.ms-excel" => "xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => "xlsx",
        _ => return None,
    })
}

/// The base name (everything before the last dot), or the whole name when it has
/// no dot or only a leading one. (oracle `ResultFiles.baseName`)
fn base_name(filename: &str) -> &str {
    match filename.rfind('.') {
        Some(dot) if dot > 0 => &filename[..dot],
        _ => filename,
    }
}

// ---- The controller `call` orchestration (oracle ExternalApiCallController) -

/// One external-API-call step, resolved down to the values the orchestration
/// needs. The raw `method` / `body_mode` / `response_mode` are normalised inside
/// [`ExternalApiCaller::call`] so their rejection messages match the oracle;
/// `fields` / `headers` are the raw JSON-object strings (parsed there), and `run`
/// carries the policy/run facts the context is stamped with.
pub(crate) struct ExternalApiCallRequest<'a> {
    pub(crate) file_content: &'a [u8],
    pub(crate) original_filename: Option<&'a str>,
    pub(crate) file_content_type: Option<&'a str>,
    pub(crate) path: Option<&'a str>,
    pub(crate) method: Option<&'a str>,
    pub(crate) body_mode: Option<&'a str>,
    pub(crate) file_field_name: &'a str,
    pub(crate) response_mode: Option<&'a str>,
    pub(crate) result_url_path: Option<&'a str>,
    pub(crate) result_url_header: Option<&'a str>,
    pub(crate) response_select: Option<&'a str>,
    pub(crate) require_true: Option<&'a str>,
    pub(crate) fields: Option<&'a str>,
    pub(crate) body_template: Option<&'a str>,
    pub(crate) headers: Option<&'a str>,
    pub(crate) include_context: bool,
    pub(crate) include_file: bool,
    pub(crate) run: RunFacts<'a>,
}

/// The document (and optional report header) a completed step hands back to the
/// pipeline. `report` is set only in `report` mode; in `replace` mode the `body`
/// is the new document.
pub(crate) struct ExternalApiCallResult {
    pub(crate) content_type: String,
    pub(crate) filename: String,
    pub(crate) body: Vec<u8>,
    pub(crate) report: Option<String>,
}

impl ExternalApiCaller {
    /// Run one external-API-call step end to end: build the context and body,
    /// dispatch under the SSRF-safe caller, gate on the verdict, then either
    /// replace the document with the response or pass it through with the answer in
    /// the report header. (oracle `ExternalApiCallController.call`)
    // `content` (the bytes) and `context` (the namespace) are the oracle's own names.
    #[allow(clippy::similar_names)]
    pub(crate) fn call(
        &self,
        settings: &ApiConnectionSettings,
        request: &ExternalApiCallRequest<'_>,
    ) -> Result<ExternalApiCallResult, ExternalApiError> {
        let mode = normalise(
            request.response_mode,
            MODE_REPORT,
            &[MODE_REPORT, MODE_REPLACE],
        )?;
        let body_mode = normalise(
            request.body_mode,
            BODY_MULTIPART,
            &[BODY_MULTIPART, BODY_JSON, BODY_BINARY],
        )?;
        let verb = parse_method(request.method)?;

        let filename = safe_file_name(request.original_filename);
        let content_type = request
            .file_content_type
            .unwrap_or(APPLICATION_OCTET_STREAM);
        let content = request.file_content;

        let context = DocumentContext::build(
            content,
            request.original_filename,
            request.file_content_type,
            &request.run,
        );

        // Argument-evaluation order matches the oracle so error precedence does:
        // path first, then the body (which resolves `fields`), then the headers.
        let resolved_path = Placeholders::resolve(request.path, &context, Escaping::UrlPath)?;
        let fields = resolve_all(&parse_json_object(request.fields, "fields")?, &context)?;
        let body = build_body(
            &BodyRequest {
                body_mode: &body_mode,
                body_template: request.body_template,
                include_file: request.include_file,
                include_context: request.include_context,
                file_field_name: request.file_field_name,
                filename: &filename,
                content_type,
                content,
                fields: &fields,
            },
            &context,
        )?;
        let headers = validated_headers(resolve_all(
            &parse_json_object(request.headers, "headers")?,
            &context,
        )?)?;

        let response = self.dispatch(
            settings,
            &verb,
            resolved_path.as_deref().unwrap_or(""),
            &body,
            &headers,
        )?;

        if !response.is_success() {
            // Fail the step: a policy that silently continued past a rejected
            // call-out would deliver documents the external system believes it
            // never approved.
            return Err(invalid(format!(
                "External API returned HTTP {}{}",
                response.status,
                summarise(&response)
            )));
        }

        enforce_verdict(&response, request.require_true)?;

        if mode == MODE_REPLACE {
            self.replace_document(
                settings,
                &response,
                &filename,
                request.result_url_path,
                request.result_url_header,
                request.response_select,
            )
        } else {
            report_only(content, &filename, content_type, &response)
        }
    }

    /// Turn the response into the document that continues down the pipeline: the
    /// body inline, a URL to fetch it from, or an archive to pick from. Anything
    /// else fails the step rather than putting a non-document into the pipeline.
    /// (oracle `ExternalApiCallController.replaceDocument`)
    fn replace_document(
        &self,
        settings: &ApiConnectionSettings,
        response: &ApiResponse,
        request_filename: &str,
        result_url_path: Option<&str>,
        result_url_header: Option<&str>,
        response_select: Option<&str>,
    ) -> Result<ExternalApiCallResult, ExternalApiError> {
        let url = result_url(response, result_url_path, result_url_header)?;
        let followed = url.is_some();
        // When the API pointed at a URL, ResultUrls decides whether it may be
        // fetched (operator-declared host allowlist + SSRF vet); the fetch itself
        // forwards NO credentials.
        let fetched = match url {
            Some(url) => {
                let target = ResultUrls::validate(settings, &url, self.allow_private_endpoints)?;
                let payload = self.get_result(settings, &target)?;
                if !payload.is_success() {
                    return Err(invalid(format!(
                        "Fetching the API's result URL returned HTTP {}",
                        payload.status
                    )));
                }
                Some(payload)
            }
            None => None,
        };
        let payload = fetched.as_ref().unwrap_or(response);

        if payload.body.is_empty() {
            return Err(invalid(
                "External API returned an empty body, so there is no document to replace with; use \
                 responseMode=report to keep the original.",
            ));
        }
        if payload.is_json() && !followed {
            return Err(invalid(
                "External API returned JSON, which cannot replace the document. Use \
                 responseMode=report to keep the original and record the answer, or set \
                 resultUrlPath if the JSON points at the document.",
            ));
        }

        let mut filename = ResultFiles::name_for(payload, request_filename);
        let document = if ResultFiles::is_archive(&payload.body) {
            let Some(select) = response_select
                .map(str::trim)
                .filter(|select| !select.is_empty())
            else {
                // Handing a .zip to a step that expects a PDF fails later and more
                // obscurely.
                return Err(invalid(
                    "External API returned an archive; set 'responseSelect' (e.g. *.pdf, or an \
                     index) to say which entry becomes the document.",
                ));
            };
            let (member_name, member_bytes) =
                ResultFiles::select_from_archive(&payload.body, select)?;
            filename = member_name;
            member_bytes
        } else {
            if response_select
                .map(str::trim)
                .is_some_and(|select| !select.is_empty())
            {
                return Err(invalid(
                    "'responseSelect' was set but the API returned a single file, not an archive",
                ));
            }
            payload.body.clone()
        };

        // Faithful to the oracle: when a member was selected the archive's own
        // content type still drives this, since `payload.contentType()` is the ZIP's.
        let content_type =
            if payload.content_type.is_none() || ResultFiles::is_archive_name(&filename) {
                APPLICATION_OCTET_STREAM.to_owned()
            } else {
                payload
                    .content_type
                    .as_deref()
                    .unwrap_or_default()
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            };
        Ok(ExternalApiCallResult {
            content_type,
            filename,
            body: document,
            report: None,
        })
    }
}

/// Normalise an optional enumerated value: blank/absent falls back, otherwise it
/// is trimmed/lower-cased and must be one of `allowed`. (oracle
/// `ExternalApiCallController.normalise`)
fn normalise(
    value: Option<&str>,
    fallback: &str,
    allowed: &[&str],
) -> Result<String, ExternalApiError> {
    let out = match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => value.to_lowercase(),
        None => fallback.to_owned(),
    };
    if !allowed.contains(&out.as_str()) {
        return Err(invalid(format!(
            "must be one of {}; got {}",
            allowed.join(", "),
            value.unwrap_or_default()
        )));
    }
    Ok(out)
}

/// Only the body-bearing verbs; GET/DELETE would silently drop the document.
/// `None` defaults to POST (Spring's `defaultValue`). (oracle `parseMethod`)
fn parse_method(method: Option<&str>) -> Result<String, ExternalApiError> {
    let verb = match method {
        None => "POST".to_owned(),
        Some(method) => method.trim().to_uppercase(),
    };
    if !["POST", "PUT", "PATCH"].contains(&verb.as_str()) {
        return Err(invalid(format!(
            "'method' must be POST, PUT or PATCH; got {}",
            method.unwrap_or_default()
        )));
    }
    Ok(verb)
}

/// A JSON object of string values (`fields` / `headers`); a JSON `null` value
/// becomes empty, any other non-string its JSON form. Blank/absent yields an empty
/// map. (oracle `ExternalApiCallController.parseJsonObject`)
fn parse_json_object(
    json: Option<&str>,
    what: &str,
) -> Result<BTreeMap<String, String>, ExternalApiError> {
    let Some(json) = json.map(str::trim).filter(|json| !json.is_empty()) else {
        return Ok(BTreeMap::new());
    };
    let parsed: Value = serde_json::from_str(json)
        .map_err(|_| invalid(format!("api step '{what}' must be a JSON object")))?;
    let Value::Object(map) = parsed else {
        return Err(invalid(format!("api step '{what}' must be a JSON object")));
    };
    let mut out = BTreeMap::new();
    for (key, value) in map {
        let text = match value {
            Value::Null => String::new(),
            other => java_to_string(&other),
        };
        out.insert(key, text);
    }
    Ok(out)
}

/// Resolve every value's placeholders against the context. (oracle `resolveAll`)
fn resolve_all(
    values: &BTreeMap<String, String>,
    context: &Value,
) -> Result<BTreeMap<String, String>, ExternalApiError> {
    let mut out = BTreeMap::new();
    for (key, value) in values {
        let resolved =
            Placeholders::resolve(Some(value), context, Escaping::None)?.unwrap_or_default();
        out.insert(key.clone(), resolved);
    }
    Ok(out)
}

/// Per-step headers, held to the same rules as a connection's static headers: a
/// valid RFC-7230 name, not a reserved one, and a value with no injectable
/// characters (a resolved placeholder could carry a newline out of metadata).
/// (oracle `ExternalApiCallController.validatedHeaders`)
fn validated_headers(
    headers: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, ExternalApiError> {
    for (name, value) in &headers {
        if !ExternalApiHeaders::is_valid_name(name) {
            return Err(invalid(format!(
                "api step 'headers' has an invalid header name: {name}"
            )));
        }
        if ExternalApiHeaders::is_reserved(name) {
            return Err(invalid(format!(
                "api step 'headers' must not set '{name}'; it is set by the connection or the client"
            )));
        }
        if !ExternalApiHeaders::is_valid_value(value) {
            return Err(invalid(format!(
                "api step 'headers' has an invalid value for '{name}'"
            )));
        }
    }
    Ok(headers)
}

/// The result URL the API pointed at, from a header or a dotted body path; `None`
/// when neither is set. (oracle `ExternalApiCallController.resultUrl`)
fn result_url(
    response: &ApiResponse,
    result_url_path: Option<&str>,
    result_url_header: Option<&str>,
) -> Result<Option<String>, ExternalApiError> {
    if let Some(header) = result_url_header.filter(|header| !header.trim().is_empty()) {
        return match response.header(header.trim()) {
            Some(value) if !value.trim().is_empty() => Ok(Some(value.to_owned())),
            _ => Err(invalid(format!(
                "'resultUrlHeader' names '{header}' but the response had no such header"
            ))),
        };
    }
    let Some(path) = result_url_path.filter(|path| !path.trim().is_empty()) else {
        return Ok(None);
    };
    let body = response.body_as_json();
    match body.as_ref().and_then(|root| navigate(root, path.trim())) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::Number(number)) => Ok(Some(number.to_string())),
        Some(Value::Bool(flag)) => Ok(Some(flag.to_string())),
        _ => Err(invalid(format!(
            "'resultUrlPath' found no URL at '{path}' in the response"
        ))),
    }
}

/// Gate the run on a boolean verdict in the API's JSON answer. `requireTrue` names
/// a field (dotted for a nested one) that must be JSON `true`, or the step fails so
/// the document is parked rather than delivered. Fail-closed: a missing field, a
/// non-boolean, a `false`, or a non-JSON body all stop the run — this is what makes
/// a scanner's "not clean" actually stop the pipeline.
/// (oracle `ExternalApiCallController.enforceVerdict`)
///
/// DIVERGENCE (deliberate, strictly safer): the oracle uses Jackson's
/// `node.asBoolean(false)`, which — confirmed against `jackson-databind` 3.1.2 —
/// coerces a **non-zero integer** verdict to `true` (`IntNode._asBoolean`). Here
/// only a genuine JSON boolean `true` passes; a numeric/string/`null` verdict fails
/// closed, exactly as this slice's contract requires ("must be JSON `true`; non-bool
/// stops the run"). This can only ever *refuse* a verdict the oracle would have
/// admitted, never the reverse, so it cannot let an unapproved document through.
fn enforce_verdict(
    response: &ApiResponse,
    require_true: Option<&str>,
) -> Result<(), ExternalApiError> {
    let Some(require_true) = require_true
        .map(str::trim)
        .filter(|require| !require.is_empty())
    else {
        return Ok(());
    };
    let approved = response.is_json()
        && response
            .body_as_json()
            .as_ref()
            .and_then(|root| navigate(root, require_true))
            .is_some_and(|node| matches!(node, Value::Bool(true)));
    if !approved {
        return Err(invalid(format!(
            "External API verdict '{require_true}' was not true{}; the document was not approved, so \
             the run was stopped.",
            summarise(response)
        )));
    }
    Ok(())
}

/// The document passes through; the API's answer rides in the report header.
/// (oracle `ExternalApiCallController.reportOnly`)
fn report_only(
    content: &[u8],
    filename: &str,
    content_type: &str,
    response: &ApiResponse,
) -> Result<ExternalApiCallResult, ExternalApiError> {
    Ok(ExternalApiCallResult {
        content_type: content_type.to_owned(),
        filename: filename.to_owned(),
        body: content.to_vec(),
        report: Some(build_report(response)?),
    })
}

/// A JSON object describing the call, small enough to survive as a header: the
/// parsed body when it is JSON and short enough, else a truncated rendering; the
/// byte count otherwise. (oracle `ExternalApiCallController.buildReport`)
fn build_report(response: &ApiResponse) -> Result<String, ExternalApiError> {
    let mut report = Map::new();
    report.insert("status".to_owned(), Value::from(response.status));
    report.insert(
        "contentType".to_owned(),
        response
            .content_type
            .clone()
            .map_or(Value::Null, Value::String),
    );
    if response.is_json() {
        let text = response.body_as_text();
        match serde_json::from_str::<Value>(&text) {
            Ok(parsed) => {
                let rendered = serde_json::to_string(&parsed).unwrap_or_default();
                if rendered.chars().count() <= MAX_REPORT_BODY_CHARS {
                    report.insert("body".to_owned(), parsed);
                } else {
                    report.insert("bodyTruncated".to_owned(), Value::Bool(true));
                    report.insert(
                        "body".to_owned(),
                        Value::String(char_prefix(&rendered, MAX_REPORT_BODY_CHARS)),
                    );
                }
            }
            Err(error) => {
                // Content-Type said JSON but the body is not; keep the step alive
                // and say so.
                report.insert(
                    "bodyParseError".to_owned(),
                    Value::String(error.to_string()),
                );
                report.insert("body".to_owned(), Value::String(truncate(&text)));
            }
        }
    } else {
        report.insert("bodyBytes".to_owned(), Value::from(response.body.len()));
    }
    serde_json::to_string(&Value::Object(report))
        .map_err(|_| invalid("api step failed to build the report header"))
}

/// `: <one-line truncated body>`, or empty when the body is blank. (oracle
/// `ExternalApiCallController.summarise`)
fn summarise(response: &ApiResponse) -> String {
    let text = truncate(&response.body_as_text());
    if text.is_empty() {
        String::new()
    } else {
        format!(": {text}")
    }
}

/// Collapse whitespace to single spaces, trim, and cap at
/// [`MAX_REPORT_BODY_CHARS`] with an ellipsis. (oracle `truncate`)
fn truncate(text: &str) -> String {
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= MAX_REPORT_BODY_CHARS {
        one_line
    } else {
        format!("{}…", char_prefix(&one_line, MAX_REPORT_BODY_CHARS))
    }
}

/// The first `max` characters of `text` (char-safe, never splitting a code point).
fn char_prefix(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// The upload's safe basename, or `document`. (oracle `safeFileName`)
fn safe_file_name(original: Option<&str>) -> String {
    original
        .and_then(simple_file_name)
        .unwrap_or_else(|| DEFAULT_FILENAME.to_owned())
}

/// Walk a dotted path through a JSON tree, returning the node it names or `None`
/// (a missing key or a non-object mid-path). Trailing empty segments are dropped,
/// matching Java `String.split` (limit 0).
fn navigate<'a>(root: &'a Value, dotted: &str) -> Option<&'a Value> {
    let mut segments: Vec<&str> = dotted.split('.').collect();
    while segments.last() == Some(&"") {
        segments.pop();
    }
    let mut node = root;
    for segment in segments {
        node = node.get(segment)?;
    }
    Some(node)
}

// ===========================================================================
// Tests — 1:1 translations of the JUnit oracles under
// app/proprietary/.../integration/api/ (plus focused coverage for the parts
// with no dedicated JUnit suite: ApiConnectionSettings + ExternalApiHeaders).
// ===========================================================================

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use url::Url;

    use super::{
        ApiAuthType, ApiConnectionSettings, Escaping, ExternalApiError, ExternalApiHeaders,
        ExternalApiPaths, MultipartBody, Placeholders,
    };

    /// Assert a result is an error whose message contains `needle` (the
    /// message-substring check the oracle tests use). No `unwrap` / `expect`
    /// (both denied in this crate).
    fn assert_err_contains<T>(result: Result<T, ExternalApiError>, needle: &str) {
        match result {
            Ok(_) => panic!("expected an error containing {needle:?}, got Ok"),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains(needle),
                    "message {message:?} did not contain {needle:?}"
                );
            }
        }
    }

    // -------------------------------------------------------------------
    // ExternalApiPathsTest
    // -------------------------------------------------------------------

    const BASE_STR: &str = "https://api.example.com/v1";

    #[test]
    fn resolve_appends_a_relative_path() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        assert_eq!(
            ExternalApiPaths::resolve(&base, "/scan")?,
            Url::parse("https://api.example.com/v1/scan")?
        );
        Ok(())
    }

    #[test]
    fn resolve_adds_the_leading_slash_when_omitted() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        assert_eq!(
            ExternalApiPaths::resolve(&base, "scan")?,
            Url::parse("https://api.example.com/v1/scan")?
        );
        Ok(())
    }

    #[test]
    fn resolve_blank_path_is_the_base_itself() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        // "" is the Rust analogue of Java's `null` (both are "blank").
        assert_eq!(ExternalApiPaths::resolve(&base, "  ")?, base);
        assert_eq!(ExternalApiPaths::resolve(&base, "")?, base);
        Ok(())
    }

    #[test]
    fn resolve_keeps_a_query_string() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        assert_eq!(
            ExternalApiPaths::resolve(&base, "/scan?mode=strict")?,
            Url::parse("https://api.example.com/v1/scan?mode=strict")?
        );
        Ok(())
    }

    #[test]
    fn resolve_allows_a_traversal_that_stays_under_the_base()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        // "/v1/a/../b" normalises to "/v1/b", still under the base.
        assert_eq!(
            ExternalApiPaths::resolve(&base, "/a/../b")?,
            Url::parse("https://api.example.com/v1/b")?
        );
        Ok(())
    }

    #[test]
    fn resolve_base_with_no_path_accepts_any_path() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://api.example.com")?;
        assert_eq!(
            ExternalApiPaths::resolve(&base, "/scan")?,
            Url::parse("https://api.example.com/scan")?
        );
        Ok(())
    }

    #[test]
    fn resolve_keeps_an_encoded_slash_from_a_substituted_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        // A filename containing '/' arrives as %2F: data inside one segment.
        assert_eq!(
            ExternalApiPaths::resolve(&base, "/docs/my%2Ffile.pdf")?,
            Url::parse("https://api.example.com/v1/docs/my%2Ffile.pdf")?
        );
        Ok(())
    }

    #[test]
    fn resolve_protocol_relative_url_cannot_change_host() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = Url::parse(BASE_STR)?;
        assert_err_contains(
            ExternalApiPaths::resolve(&base, "//evil.example/x"),
            "must be relative",
        );
        Ok(())
    }

    #[test]
    fn resolve_absolute_url_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        for path in [
            "https://evil.example/x",
            "http://evil.example/x",
            "HTTPS://evil.example/x",
            "file:///etc/passwd",
        ] {
            assert!(ExternalApiPaths::resolve(&base, path).is_err());
        }
        Ok(())
    }

    #[test]
    fn resolve_traversal_above_the_base_path_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = Url::parse(BASE_STR)?;
        assert_err_contains(ExternalApiPaths::resolve(&base, "/../admin"), "escapes");
        Ok(())
    }

    #[test]
    fn resolve_percent_encoded_traversal_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        assert_err_contains(
            ExternalApiPaths::resolve(&base, "/%2e%2e/admin"),
            "percent-encode",
        );
        Ok(())
    }

    #[test]
    fn resolve_request_splitting_characters_are_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = Url::parse(BASE_STR)?;
        for path in [
            "/scan\r\nX-Injected: 1",
            "/scan\nfoo",
            "/sc an",
            "/scan\\..\\x",
        ] {
            assert_err_contains(ExternalApiPaths::resolve(&base, path), "illegal character");
        }
        Ok(())
    }

    #[test]
    fn resolve_sibling_path_sharing_a_prefix_is_rejected() -> Result<(), Box<dyn std::error::Error>>
    {
        let base = Url::parse(BASE_STR)?;
        // "/v1betray" shares a textual prefix with "/v1" but is a different tree.
        assert_err_contains(
            ExternalApiPaths::resolve(&base, "/../v1betray/x"),
            "escapes",
        );
        Ok(())
    }

    #[test]
    fn resolve_fragment_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse(BASE_STR)?;
        assert_err_contains(ExternalApiPaths::resolve(&base, "/scan#frag"), "fragment");
        Ok(())
    }

    // -------------------------------------------------------------------
    // PlaceholdersTest
    // -------------------------------------------------------------------

    fn context() -> Value {
        json!({
            "document": {
                "filename": "invoice.pdf",
                "sha256": "abc123",
                "pageCount": 3,
                "title": null
            },
            "sensitivityLabel": { "name": "Confidential" },
            "run": { "policyName": "Outbound review" }
        })
    }

    fn context_with(key: &str, extra: Value) -> Value {
        let mut root = context();
        if let Value::Object(map) = &mut root {
            map.insert(key.to_owned(), extra);
        }
        root
    }

    #[test]
    fn placeholder_substitutes_a_dotted_path() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Placeholders::resolve(Some("{{document.filename}}"), &context(), Escaping::None)?,
            Some("invoice.pdf".to_owned())
        );
        Ok(())
    }

    #[test]
    fn placeholder_substitutes_several_with_surrounding_text()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Placeholders::resolve(
                Some(
                    "{{document.filename}} ({{document.pageCount}}p) is {{sensitivityLabel.name}}"
                ),
                &context(),
                Escaping::None
            )?,
            Some("invoice.pdf (3p) is Confidential".to_owned())
        );
        Ok(())
    }

    #[test]
    fn placeholder_tolerates_whitespace_inside_braces() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Placeholders::resolve(Some("{{ document.sha256 }}"), &context(), Escaping::None)?,
            Some("abc123".to_owned())
        );
        Ok(())
    }

    #[test]
    fn placeholder_null_value_renders_empty_not_the_word_null()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Placeholders::resolve(Some("[{{document.title}}]"), &context(), Escaping::None)?,
            Some("[]".to_owned())
        );
        Ok(())
    }

    #[test]
    fn placeholder_text_with_no_placeholder_is_untouched() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            Placeholders::resolve(Some("/scan"), &context(), Escaping::None)?,
            Some("/scan".to_owned())
        );
        // `None` is the Rust analogue of Java's `null` template → passes through.
        assert_eq!(
            Placeholders::resolve(None, &context(), Escaping::None)?,
            None
        );
        Ok(())
    }

    #[test]
    fn placeholder_unknown_path_is_an_error() {
        assert_err_contains(
            Placeholders::resolve(Some("{{document.nope}}"), &context(), Escaping::None),
            "unknown placeholder",
        );
        assert!(
            Placeholders::resolve(Some("{{nope.at.all}}"), &context(), Escaping::None).is_err()
        );
    }

    #[test]
    fn placeholder_an_object_renders_as_json() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            Placeholders::resolve(Some("{{sensitivityLabel}}"), &context(), Escaping::None)?,
            Some(r#"{"name":"Confidential"}"#.to_owned())
        );
        Ok(())
    }

    #[test]
    fn placeholder_path_escaping_encodes_separators_but_not_dots()
    -> Result<(), Box<dyn std::error::Error>> {
        let context = context_with("x", json!({ "weird": "a/b c.pdf" }));
        assert_eq!(
            Placeholders::resolve(Some("{{x.weird}}"), &context, Escaping::UrlPath)?,
            Some("a%2Fb%20c.pdf".to_owned())
        );
        Ok(())
    }

    #[test]
    fn placeholder_a_traversal_in_a_value_is_neutralised() -> Result<(), Box<dyn std::error::Error>>
    {
        let context = context_with("x", json!({ "nasty": "../../admin" }));
        let Some(resolved) =
            Placeholders::resolve(Some("/docs/{{x.nasty}}"), &context, Escaping::UrlPath)?
        else {
            panic!("expected Some");
        };
        assert_eq!(resolved, "/docs/..%2F..%2Fadmin");

        let base = Url::parse("https://api.example.com/v1")?;
        assert_eq!(
            ExternalApiPaths::resolve(&base, &resolved)?,
            Url::parse("https://api.example.com/v1/docs/..%2F..%2Fadmin")?
        );
        Ok(())
    }

    #[test]
    fn placeholder_a_traversal_in_the_template_itself_is_still_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://api.example.com/v1")?;
        assert_err_contains(ExternalApiPaths::resolve(&base, "/docs/../../x"), "escapes");
        Ok(())
    }

    #[test]
    fn placeholder_detects_whether_text_references_anything() {
        assert!(Placeholders::has_placeholder(Some("{{a.b}}")));
        assert!(!Placeholders::has_placeholder(Some("plain")));
        assert!(!Placeholders::has_placeholder(None));
    }

    // -------------------------------------------------------------------
    // PlaceholdersTemplateTest
    // -------------------------------------------------------------------

    fn template_context() -> Value {
        let base64 = STANDARD.encode("%PDF-1.7");
        json!({
            "document": {
                "filename": "contract.pdf",
                "base64": base64,
                "pageCount": 4
            },
            "run": { "policyName": "Signature run" },
            "sensitivityLabel": { "name": "Confidential" }
        })
    }

    #[test]
    fn template_builds_consignos_workflow_payload() -> Result<(), Box<dyn std::error::Error>> {
        let template = r#"
            {
              "name": "{{document.filename}}",
              "status": 1,
              "documents": [
                {"name": "{{document.filename}}", "data": "{{document.base64}}"}
              ],
              "actions": [
                {
                  "mode": "remote",
                  "ref": "1",
                  "signer": {"type": "certifio", "email": "notary@example.test", "lang": "en"}
                }
              ]
            }
        "#;
        let body =
            Placeholders::resolve_tree(serde_json::from_str(template)?, &template_context())?;

        assert_eq!(
            body.pointer("/name").and_then(Value::as_str),
            Some("contract.pdf")
        );
        // Numbers keep their type; only strings are substituted.
        assert!(body.pointer("/status").is_some_and(Value::is_number));
        assert_eq!(body.pointer("/status").and_then(Value::as_i64), Some(1));
        assert_eq!(
            body.pointer("/documents/0/name").and_then(Value::as_str),
            Some("contract.pdf")
        );
        let Some(data) = body.pointer("/documents/0/data").and_then(Value::as_str) else {
            panic!("expected documents[0].data string");
        };
        assert_eq!(String::from_utf8(STANDARD.decode(data)?)?, "%PDF-1.7");
        assert_eq!(
            body.pointer("/actions/0/signer/type")
                .and_then(Value::as_str),
            Some("certifio")
        );
        assert_eq!(
            body.pointer("/actions/0/ref").and_then(Value::as_str),
            Some("1")
        );
        Ok(())
    }

    #[test]
    fn template_resolves_inside_nested_objects_and_arrays() -> Result<(), Box<dyn std::error::Error>>
    {
        let template = r#"{"a":{"b":[{"c":"{{document.filename}}"},"{{run.policyName}}"]}}"#;
        let body =
            Placeholders::resolve_tree(serde_json::from_str(template)?, &template_context())?;
        assert_eq!(
            body.pointer("/a/b/0/c").and_then(Value::as_str),
            Some("contract.pdf")
        );
        assert_eq!(
            body.pointer("/a/b/1").and_then(Value::as_str),
            Some("Signature run")
        );
        Ok(())
    }

    #[test]
    fn template_leaves_non_strings_alone() -> Result<(), Box<dyn std::error::Error>> {
        let template = r#"{"n":3,"b":true,"z":null,"arr":[1,2]}"#;
        let body =
            Placeholders::resolve_tree(serde_json::from_str(template)?, &template_context())?;
        assert_eq!(body.pointer("/n").and_then(Value::as_i64), Some(3));
        assert_eq!(body.pointer("/b").and_then(Value::as_bool), Some(true));
        assert!(body.pointer("/z").is_some_and(Value::is_null));
        assert_eq!(body.pointer("/arr/1").and_then(Value::as_i64), Some(2));
        Ok(())
    }

    #[test]
    fn template_substitutes_within_surrounding_text() -> Result<(), Box<dyn std::error::Error>> {
        let template = r#"{"subject":"{{run.policyName}}: {{document.filename}}"}"#;
        let body =
            Placeholders::resolve_tree(serde_json::from_str(template)?, &template_context())?;
        assert_eq!(
            body.pointer("/subject").and_then(Value::as_str),
            Some("Signature run: contract.pdf")
        );
        Ok(())
    }

    #[test]
    fn template_a_typo_is_an_error_not_a_silently_empty_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = r#"{"x":"{{document.flename}}"}"#;
        assert_err_contains(
            Placeholders::resolve_tree(serde_json::from_str(template)?, &template_context()),
            "unknown placeholder",
        );
        Ok(())
    }

    // -------------------------------------------------------------------
    // MultipartBodyTest
    // -------------------------------------------------------------------

    fn render_body(body: &MultipartBody) -> String {
        String::from_utf8_lossy(&body.build()).into_owned()
    }

    #[test]
    fn multipart_carries_a_json_value_through_untouched() -> Result<(), Box<dyn std::error::Error>>
    {
        // Regression: values were once checked like headers, which rejected every
        // JSON value — including the auto-populated context.
        let json = r#"{"document":{"title":"Q3 \"final\""},"n":2}"#;
        let mut body = MultipartBody::new();
        body.add_field("stirlingContext", json)?;
        assert!(render_body(&body).contains(json));
        Ok(())
    }

    #[test]
    fn multipart_carries_a_value_with_newlines_and_backslashes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut body = MultipartBody::new();
        body.add_field("notes", "line one\nline two\\end")?;
        assert!(render_body(&body).contains("line one\nline two\\end"));
        Ok(())
    }

    #[test]
    fn multipart_writes_the_document_under_its_field_name_and_filename()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut body = MultipartBody::new();
        let mut fields = BTreeMap::new();
        fields.insert("policy".to_owned(), "strict".to_owned());
        body.add_fields(&fields)?;
        body.add_file("file", "claim.pdf", "application/pdf", b"%PDF-1.7")?;

        let rendered = render_body(&body);
        assert!(rendered.contains("name=\"policy\""));
        assert!(rendered.contains("strict"));
        assert!(rendered.contains("name=\"file\"; filename=\"claim.pdf\""));
        assert!(rendered.contains("Content-Type: application/pdf"));
        assert!(rendered.contains("%PDF-1.7"));
        assert!(
            body.content_type()
                .starts_with("multipart/form-data; boundary=StirlingBoundary")
        );
        Ok(())
    }

    #[test]
    fn multipart_refuses_a_field_name_that_could_forge_its_own_headers() {
        for name in ["na\"me", "na\rme", "na\nme", "na\\me"] {
            let mut body = MultipartBody::new();
            assert_err_contains(body.add_field(name, "v"), "illegal character");
        }
    }

    #[test]
    fn multipart_refuses_a_filename_that_could_forge_its_own_headers() {
        for filename in ["a\".pdf", "a\r.pdf", "a\n.pdf"] {
            let mut body = MultipartBody::new();
            assert_err_contains(
                body.add_file("file", filename, "application/pdf", &[1]),
                "illegal character",
            );
        }
    }

    #[test]
    fn multipart_each_body_gets_its_own_boundary() {
        assert_ne!(
            MultipartBody::new().content_type(),
            MultipartBody::new().content_type()
        );
    }

    // -------------------------------------------------------------------
    // ApiConnectionSettings — no dedicated JUnit suite exists; these exercise
    // the behaviours the Java oracle (ApiConnectionSettings.java) specifies.
    // -------------------------------------------------------------------

    fn options(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    #[test]
    fn settings_base_url_is_required() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&BTreeMap::new()),
            "requires a 'baseUrl'",
        );
    }

    #[test]
    fn settings_base_url_must_be_http() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[(
                "baseUrl",
                json!("ftp://files.example.com/x"),
            )])),
            "must be an http(s) URL",
        );
    }

    #[test]
    fn settings_base_url_rejects_query_and_fragment() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[(
                "baseUrl",
                json!("https://api.example.com/v1?x=1"),
            )])),
            "must not carry a query string or fragment",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[(
                "baseUrl",
                json!("https://api.example.com/v1#frag"),
            )])),
            "must not carry a query string or fragment",
        );
    }

    #[test]
    fn settings_base_url_rejects_forms_the_oracle_refuses() {
        // Java validates with java.net.URI (strict RFC 3986); these malformed
        // bases are host-less or illegal to the oracle. The WHATWG `url` crate
        // would otherwise repair them and invent a host — a base URL is the SSRF
        // anchor, so it must fail closed identically. Verdicts verified
        // case-by-case against java.net.URI (see parse_http_url).

        // A backslash is illegal anywhere in a URI -> URISyntaxException. The
        // `url` crate reads it as '/' and would keep or pivot the host.
        for base in [
            "https:/\\/\\evil.example",
            "https://api.example.com\\@evil.example/x",
        ] {
            assert_err_contains(
                ApiConnectionSettings::from_options(&options(&[("baseUrl", json!(base))])),
                "is not a valid URL",
            );
        }

        // Missing / single / extra authority slashes -> null host in
        // java.net.URI. The `url` crate collapses them and promotes the first
        // path segment to the host.
        for base in [
            "https:///scan",
            "https:///evil.example/x",
            "https:/evil.example",
            "https:evil.example",
        ] {
            assert_err_contains(
                ApiConnectionSettings::from_options(&options(&[("baseUrl", json!(base))])),
                "must include a host",
            );
        }

        // Degenerate empty authority -> the `url` crate errors at parse (empty
        // host); still a rejection, matching the oracle's refusal.
        for base in ["https://", "https:///"] {
            assert!(
                ApiConnectionSettings::from_options(&options(&[("baseUrl", json!(base))])).is_err()
            );
        }
    }

    #[test]
    fn settings_strips_trailing_slash_and_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let settings = ApiConnectionSettings::from_options(&options(&[(
            "baseUrl",
            json!("https://api.example.com/v1/"),
        )]))?;
        assert_eq!(settings.base_url, "https://api.example.com/v1");
        assert_eq!(settings.auth_type, ApiAuthType::None);
        assert_eq!(settings.timeout_seconds, 60);
        assert!(settings.token_login.is_none());
        Ok(())
    }

    #[test]
    fn settings_invalid_auth_type_message_omits_token_login() {
        // Parity trap: TOKEN_LOGIN is a valid value but the error omits it.
        match ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("authType", json!("WEIRD")),
        ])) {
            Ok(_) => panic!("expected an error"),
            Err(error) => {
                let message = error.to_string();
                assert!(message.contains("must be one of NONE, BEARER, BASIC, HEADER"));
                assert!(message.contains("got WEIRD"));
                assert!(!message.contains("TOKEN_LOGIN"));
            }
        }
    }

    #[test]
    fn settings_bearer_requires_a_token_case_insensitive() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("authType", json!("bearer")),
            ])),
            "authType 'BEARER' requires a 'token'",
        );
    }

    #[test]
    fn settings_bearer_with_token_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("authType", json!("BEARER")),
            ("token", json!("sk-secret")),
        ]))?;
        assert_eq!(settings.auth_type, ApiAuthType::Bearer);
        assert_eq!(settings.token.as_deref(), Some("sk-secret"));
        Ok(())
    }

    #[test]
    fn settings_header_auth_validates_token_then_name() -> Result<(), Box<dyn std::error::Error>> {
        let base = || ("baseUrl", json!("https://api.example.com"));
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[base(), ("authType", json!("HEADER"))])),
            "authType 'HEADER' requires a 'token'",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                base(),
                ("authType", json!("HEADER")),
                ("token", json!("t")),
            ])),
            "authType 'HEADER' requires a 'headerName'",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                base(),
                ("authType", json!("HEADER")),
                ("token", json!("t")),
                ("headerName", json!("bad name")),
            ])),
            "is not a valid HTTP header name",
        );

        let settings = ApiConnectionSettings::from_options(&options(&[
            base(),
            ("authType", json!("HEADER")),
            ("token", json!("pd-secret")),
            ("headerName", json!("Authorization")),
            ("headerPrefix", json!("API-Key")),
        ]))?;
        assert_eq!(settings.auth_type, ApiAuthType::Header);
        assert_eq!(settings.header_name.as_deref(), Some("Authorization"));
        assert_eq!(settings.header_prefix.as_deref(), Some("API-Key"));
        assert_eq!(settings.token.as_deref(), Some("pd-secret"));
        Ok(())
    }

    #[test]
    fn settings_basic_requires_username_and_password() -> Result<(), Box<dyn std::error::Error>> {
        let base = || ("baseUrl", json!("https://api.example.com"));
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[base(), ("authType", json!("BASIC"))])),
            "authType 'BASIC' requires a 'username'",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                base(),
                ("authType", json!("BASIC")),
                ("username", json!("alice")),
            ])),
            "authType 'BASIC' requires a 'password'",
        );

        let settings = ApiConnectionSettings::from_options(&options(&[
            base(),
            ("authType", json!("BASIC")),
            ("username", json!("alice")),
            ("password", json!("s3cret")),
        ]))?;
        assert_eq!(settings.auth_type, ApiAuthType::Basic);
        assert_eq!(settings.username.as_deref(), Some("alice"));
        assert_eq!(settings.password.as_deref(), Some("s3cret"));
        Ok(())
    }

    #[test]
    fn settings_headers_reject_reserved_names() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("headers", json!({ "Authorization": "Bearer x" })),
            ])),
            "use 'authType' and 'token' instead",
        );
    }

    #[test]
    fn settings_headers_reject_invalid_name_and_value() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("headers", json!({ "bad name": "x" })),
            ])),
            "invalid header name",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("headers", json!({ "X-Trace": "a\r\nb" })),
            ])),
            "invalid value for 'X-Trace'",
        );
    }

    #[test]
    fn settings_headers_must_be_an_object() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("headers", json!("not-an-object")),
            ])),
            "must be an object",
        );
    }

    #[test]
    fn settings_headers_stringify_a_numeric_value() -> Result<(), Box<dyn std::error::Error>> {
        // Parity trap (Object.toString): a numeric header value is stringified.
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("headers", json!({ "X-Count": 123 })),
        ]))?;
        assert_eq!(
            settings.headers.get("X-Count").map(String::as_str),
            Some("123")
        );
        Ok(())
    }

    #[test]
    fn settings_result_url_hosts_are_bare_and_lowercased() -> Result<(), Box<dyn std::error::Error>>
    {
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("resultUrlHosts", json!(["CDN.Vendor.com", "other.example"])),
        ]))?;
        assert!(settings.result_url_hosts.contains("cdn.vendor.com"));
        assert!(settings.result_url_hosts.contains("other.example"));
        Ok(())
    }

    #[test]
    fn settings_result_url_hosts_reject_non_bare_entries() {
        for host in [
            json!(["cdn.vendor.com/path"]),
            json!(["host:8080"]),
            json!(["*.evil.com"]),
        ] {
            assert_err_contains(
                ApiConnectionSettings::from_options(&options(&[
                    ("baseUrl", json!("https://api.example.com")),
                    ("resultUrlHosts", host),
                ])),
                "takes bare hostnames",
            );
        }
    }

    #[test]
    fn settings_result_url_hosts_must_be_a_list() {
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("resultUrlHosts", json!("cdn.vendor.com")),
            ])),
            "must be a list of hostnames",
        );
    }

    #[test]
    fn settings_timeout_parses_ranges_and_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let base = || ("baseUrl", json!("https://api.example.com"));
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                base(),
                ("timeoutSeconds", json!("abc")),
            ])),
            "must be a number",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[base(), ("timeoutSeconds", json!(0))])),
            "must be between 1 and 600",
        );
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                base(),
                ("timeoutSeconds", json!(601)),
            ])),
            "must be between 1 and 600",
        );

        // Numeric and string forms both parse (Object.toString parity).
        let numeric = ApiConnectionSettings::from_options(&options(&[
            base(),
            ("timeoutSeconds", json!(30)),
        ]))?;
        assert_eq!(numeric.timeout_seconds, 30);
        let string = ApiConnectionSettings::from_options(&options(&[
            base(),
            ("timeoutSeconds", json!("45")),
        ]))?;
        assert_eq!(string.timeout_seconds, 45);
        let default = ApiConnectionSettings::from_options(&options(&[base()]))?;
        assert_eq!(default.timeout_seconds, 60);
        Ok(())
    }

    #[test]
    fn settings_token_login_validates_its_sub_config() -> Result<(), Box<dyn std::error::Error>> {
        // Slice 3: TOKEN_LOGIN no longer defers — the sub-config is validated
        // (loginPath is required), matching Java `ApiTokenLogin.from`.
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("authType", json!("TOKEN_LOGIN")),
            ])),
            "requires a 'loginPath'",
        );

        // A fully-specified TOKEN_LOGIN parses and records the sub-config.
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("authType", json!("TOKEN_LOGIN")),
            ("loginPath", json!("/auth/login")),
            ("tokenResponseHeader", json!("X-Auth-Token")),
            ("tokenHeaderName", json!("X-Auth-Token")),
        ]))?;
        assert_eq!(settings.auth_type, ApiAuthType::TokenLogin);
        assert!(settings.token_login.is_some());
        Ok(())
    }

    #[test]
    fn settings_display_and_debug_are_credential_free() -> Result<(), Box<dyn std::error::Error>> {
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("authType", json!("BASIC")),
            ("username", json!("alice")),
            ("password", json!("s3cret")),
        ]))?;
        let display = settings.to_string();
        let debug = format!("{settings:?}");
        assert_eq!(display, debug);
        assert!(display.contains("baseUrl=https://api.example.com"));
        assert!(display.contains("authType=BASIC"));
        assert!(display.contains("timeoutSeconds=60"));
        assert!(!display.contains("alice"));
        assert!(!display.contains("s3cret"));
        Ok(())
    }

    #[test]
    fn settings_base_uri_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let settings = ApiConnectionSettings::from_options(&options(&[(
            "baseUrl",
            json!("https://api.example.com/v1"),
        )]))?;
        assert_eq!(
            settings.base_uri()?,
            Url::parse("https://api.example.com/v1")?
        );
        Ok(())
    }

    // -------------------------------------------------------------------
    // ExternalApiHeaders — grammar + reserved set. (ExternalApiHeaders.java)
    // -------------------------------------------------------------------

    #[test]
    fn header_name_grammar() {
        assert!(ExternalApiHeaders::is_valid_name("X-Api-Key"));
        assert!(ExternalApiHeaders::is_valid_name("Content-Type"));
        // A reserved name is still a *valid* name (reservation is separate).
        assert!(ExternalApiHeaders::is_valid_name("authorization"));
        assert!(!ExternalApiHeaders::is_valid_name(""));
        assert!(!ExternalApiHeaders::is_valid_name("bad name"));
        assert!(!ExternalApiHeaders::is_valid_name("a:b"));
    }

    #[test]
    fn header_value_grammar() {
        assert!(ExternalApiHeaders::is_valid_value("application/json"));
        assert!(ExternalApiHeaders::is_valid_value("a\tb"));
        assert!(!ExternalApiHeaders::is_valid_value("a\rb"));
        assert!(!ExternalApiHeaders::is_valid_value("a\nb"));
        assert!(!ExternalApiHeaders::is_valid_value("a\u{0}b"));
        assert!(!ExternalApiHeaders::is_valid_value("café"));
    }

    #[test]
    fn header_reserved_set_is_case_insensitive() {
        assert!(ExternalApiHeaders::is_reserved("Authorization"));
        assert!(ExternalApiHeaders::is_reserved("authorization"));
        assert!(ExternalApiHeaders::is_reserved("HOST"));
        assert!(ExternalApiHeaders::is_reserved("Content-Length"));
        assert!(!ExternalApiHeaders::is_reserved("X-Api-Key"));
    }

    // -------------------------------------------------------------------
    // Independent adversarial coverage (tester). Each expected verdict is the
    // Java oracle's, verified against the controller/service under
    // app/proprietary/.../integration/api/. These probe the edges the 1:1
    // ports leave implicit — case folding, exact-match branches, opaque body
    // bytes, and credential non-leakage.
    // -------------------------------------------------------------------

    #[test]
    fn adversarial_mixed_case_percent_encoded_dot_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        // Java lowercases before the "%2e" test, so an UPPER/mixed encoding of a
        // dot is caught just the same — a traversal cannot be smuggled in as %2E.
        let base = Url::parse(BASE_STR)?;
        for path in ["/%2E%2E/admin", "/dir/%2E/x", "/%2eADMIN"] {
            assert_err_contains(ExternalApiPaths::resolve(&base, path), "percent-encode");
        }
        Ok(())
    }

    #[test]
    fn adversarial_path_normalizing_to_exactly_the_base_path_is_allowed()
    -> Result<(), Box<dyn std::error::Error>> {
        // Exercises requireUnderBasePath's middle branch (resolvedPath == basePath):
        // "/v1/../v1" normalises to exactly "/v1", which is the base itself, not an
        // escape — so it must be accepted, not rejected.
        let base = Url::parse(BASE_STR)?;
        assert_eq!(
            ExternalApiPaths::resolve(&base, "/../v1")?,
            Url::parse("https://api.example.com/v1")?
        );
        Ok(())
    }

    #[test]
    fn adversarial_placeholder_descending_into_a_string_is_unknown() {
        // "{{a.b.c}}" where a.b is a string: the lookup hits a non-object mid-path
        // and must surface as an unknown-placeholder error, never a silent empty.
        assert_err_contains(
            Placeholders::resolve(
                Some("{{document.filename.deep}}"),
                &context(),
                Escaping::None,
            ),
            "unknown placeholder",
        );
    }

    #[test]
    fn adversarial_timeout_accepts_the_max_boundary_number_and_string()
    -> Result<(), Box<dyn std::error::Error>> {
        // 600 is inclusive; both the JSON-number and the stringified form parse to it.
        let base = || ("baseUrl", json!("https://api.example.com"));
        let numeric = ApiConnectionSettings::from_options(&options(&[
            base(),
            ("timeoutSeconds", json!(600)),
        ]))?;
        assert_eq!(numeric.timeout_seconds, 600);
        let string = ApiConnectionSettings::from_options(&options(&[
            base(),
            ("timeoutSeconds", json!("600")),
        ]))?;
        assert_eq!(string.timeout_seconds, 600);
        Ok(())
    }

    #[test]
    fn adversarial_header_value_rejects_a_bare_newline() {
        // A lone LF (no CR) still injects: the value grammar excludes it.
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("headers", json!({ "X-Trace": "a\nb" })),
            ])),
            "invalid value for 'X-Trace'",
        );
    }

    #[test]
    fn adversarial_reserved_header_is_rejected_regardless_of_case() {
        // Reservation folds case, so a shouty "AUTHorization" cannot slip past.
        assert_err_contains(
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("headers", json!({ "AUTHorization": "Bearer x" })),
            ])),
            "use 'authType' and 'token' instead",
        );
    }

    #[test]
    fn adversarial_result_url_hosts_reject_wildcard_port_and_scheme_forms() {
        // The three exact shapes the operator might reach for that read broader
        // than a bare host: a wildcard, a host:port, and a full URL.
        for host in [
            json!(["*.vendor.com"]),
            json!(["vendor.com:443"]),
            json!(["http://vendor.com"]),
        ] {
            assert_err_contains(
                ApiConnectionSettings::from_options(&options(&[
                    ("baseUrl", json!("https://api.example.com")),
                    ("resultUrlHosts", host),
                ])),
                "takes bare hostnames",
            );
        }
    }

    #[test]
    fn adversarial_base_url_with_userinfo_is_accepted_like_the_oracle()
    -> Result<(), Box<dyn std::error::Error>> {
        // java.net.URI reports a host for a userinfo authority, so parseHttpUrl
        // accepts it (the host, not the userinfo, is what anchors the request).
        // The `url` crate must agree — the credential-in-URL is not rejected here.
        let settings = ApiConnectionSettings::from_options(&options(&[(
            "baseUrl",
            json!("https://user:pass@api.example.com/v1"),
        )]))?;
        assert_eq!(settings.base_url, "https://user:pass@api.example.com/v1");
        Ok(())
    }

    #[test]
    fn adversarial_debug_and_display_never_leak_a_bearer_token()
    -> Result<(), Box<dyn std::error::Error>> {
        // The BASIC credential-free check has a sibling here for the token secret:
        // neither Display nor Debug may echo it into a log line.
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("authType", json!("BEARER")),
            ("token", json!("sk-super-secret-token")),
        ]))?;
        for rendered in [settings.to_string(), format!("{settings:?}")] {
            assert!(!rendered.contains("sk-super-secret-token"));
        }
        Ok(())
    }

    #[test]
    fn adversarial_config_parse_accepts_the_validator_test_base_urls()
    -> Result<(), Box<dyn std::error::Error>> {
        // Cross-check against ApiIntegrationValidatorTest: the private/metadata
        // rejection is the validator's job (a later slice), but the config-parse
        // step must first accept these as well-formed http(s) hosts.
        for base in [
            "https://1.1.1.1/v1",
            "http://10.0.0.5/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.10.0.20:8080/api",
            "http://169.254.169.253/",
        ] {
            let settings =
                ApiConnectionSettings::from_options(&options(&[("baseUrl", json!(base))]))?;
            assert!(settings.base_url.starts_with("http"));
        }
        Ok(())
    }

    #[test]
    fn adversarial_multipart_filename_with_an_encoded_slash_survives()
    -> Result<(), Box<dyn std::error::Error>> {
        // %2F carries none of the forbidden part-header characters, so an encoded
        // slash in a filename is data and must reach the wire byte-for-byte.
        let mut body = MultipartBody::new();
        body.add_file("file", "report%2F2024.pdf", "application/pdf", b"%PDF-1.7")?;
        assert!(render_body(&body).contains("filename=\"report%2F2024.pdf\""));
        Ok(())
    }

    #[test]
    fn adversarial_multipart_value_embedding_a_boundary_stays_opaque()
    -> Result<(), Box<dyn std::error::Error>> {
        // The real boundary carries 16 random bytes an attacker cannot predict, so
        // a value that embeds a whole forged part is just bytes: it can neither end
        // its own part nor forge a new one.
        let mut body = MultipartBody::new();
        let evil = "\r\n--StirlingBoundaryFORGED\r\nContent-Disposition: form-data; \
                    name=\"injected\"\r\n\r\nowned\r\n--StirlingBoundaryFORGED--";
        body.add_field("legit", evil)?;

        let content_type = body.content_type();
        let real_boundary = content_type
            .rsplit_once("boundary=")
            .map(|(_, boundary)| boundary.to_owned())
            .ok_or("content-type carried no boundary")?;
        assert_ne!(real_boundary, "StirlingBoundaryFORGED");

        let rendered = render_body(&body);
        // The value survives byte-for-byte…
        assert!(rendered.contains(evil));
        // …and the only real delimiters are the field's opener and the closer, so
        // the forged boundary did not split the body into an extra part.
        let real_delim = format!("--{real_boundary}");
        assert_eq!(rendered.matches(&real_delim).count(), 2);
        Ok(())
    }
}

// ===========================================================================
// Slice-2 tests — DocumentContext + buildBody.
//
// 1:1 translations of `DocumentContextTest.java` and the body-shape assertions
// in `ExternalApiCallControllerLiveTest.java` (`sendsTheDocumentAndWhatWeKnow…`,
// `sendsAVendorShapedJsonBody…`, `notifyStyleCallOut…`), plus DEV-level edge
// coverage for the branches those oracles leave implicit. The live-test HTTP
// receiver is replaced by asserting directly on the assembled body bytes — this
// slice has no network, so the wire *is* the [`OutboundBody`].
// ===========================================================================

#[cfg(test)]
// `content` (bytes) and `context` (namespace) co-occur throughout these ports —
// the oracle's own names; the similar-names lint is a false positive here.
#[allow(clippy::similar_names)]
mod slice2_tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use lopdf::{Dictionary, Document, Object, dictionary};
    use serde_json::Value;

    use super::{
        BODY_BINARY, BODY_JSON, BODY_MULTIPART, BodyRequest, DocumentContext, Escaping,
        ExternalApiError, Placeholders, RunFacts, build_body,
    };
    use crate::purview::{AssignmentMethod, PdfSensitivityLabels, SensitivityLabel};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TENANT: &str = "cb46c030-1825-4e81-a295-151c039dbf02";
    const LABEL_GUID: &str = "2096f6a2-d2f7-48be-b329-b73aaa526e5d";
    const TIMESTAMP: &str = "2026-07-25T12:00:00Z";

    /// No `unwrap`/`expect` (both denied in this crate): assert an error whose
    /// message contains `needle`, the message-substring check the oracles use.
    fn assert_err_contains<T>(result: Result<T, ExternalApiError>, needle: &str) {
        match result {
            Ok(_) => panic!("expected an error containing {needle:?}, got Ok"),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains(needle),
                    "message {message:?} did not contain {needle:?}"
                );
            }
        }
    }

    /// A two-page PDF shell, the Rust analogue of the oracle's `pdfBytes(...)`
    /// (which adds two `PDPage`s). Callers add Info entries / a label, then
    /// [`serialize`] to the bytes `DocumentContext::build` re-parses.
    fn two_page_pdf() -> Document {
        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let page = |document: &mut Document| {
            document.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
            })
        };
        let page_one = page(&mut document);
        let page_two = page(&mut document);
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_one), Object::Reference(page_two)],
                "Count" => 2,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);
        document
    }

    fn serialize(document: &mut Document) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    fn set_info(document: &mut Document, pairs: &[(&str, &str)]) {
        let mut info = Dictionary::new();
        for (key, value) in pairs {
            info.set(*key, Object::string_literal(*value));
        }
        let info_id = document.add_object(info);
        document.trailer.set("Info", info_id);
    }

    fn pdf_with_info(pairs: &[(&str, &str)]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut document = two_page_pdf();
        if !pairs.is_empty() {
            set_info(&mut document, pairs);
        }
        serialize(&mut document)
    }

    fn confidential_label(
        method: Option<AssignmentMethod>,
    ) -> Result<SensitivityLabel, Box<dyn std::error::Error>> {
        Ok(SensitivityLabel::new(
            LABEL_GUID.to_owned(),
            Some("Confidential".to_owned()),
            TENANT.to_owned(),
            method,
            None,
            None,
        )?)
    }

    /// A labelled, classified, titled PDF — the live test's `pdf()` fixture, so
    /// the context has something real to carry across every namespace.
    fn rich_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut document = two_page_pdf();
        set_info(
            &mut document,
            &[
                ("Title", "Q3 Claim"),
                (
                    "StirlingPDFClassification",
                    "{\"label\":\"invoice\",\"confidence\":0.91}",
                ),
            ],
        );
        // Writes label keys into the existing Info dict (and the XMP surface),
        // leaving Title / classification untouched.
        PdfSensitivityLabels::apply(
            &mut document,
            &confidential_label(Some(AssignmentMethod::Privileged))?,
        )?;
        serialize(&mut document)
    }

    fn run() -> RunFacts<'static> {
        RunFacts {
            policy_name: Some("Outbound review"),
            run_id: Some("run-42"),
            timestamp: TIMESTAMP,
        }
    }

    fn str_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
        value.pointer(pointer).and_then(Value::as_str)
    }

    // -------------------------------------------------------------------
    // DocumentContextTest
    // -------------------------------------------------------------------

    #[test]
    fn describes_the_pdf_and_the_run() -> TestResult {
        let content = pdf_with_info(&[("Title", "Q3 Invoice"), ("Author", "Anthony")])?;
        let context = DocumentContext::build(
            &content,
            Some("invoice.pdf"),
            Some("application/pdf"),
            &run(),
        );

        assert_eq!(str_at(&context, "/document/filename"), Some("invoice.pdf"));
        assert_eq!(str_at(&context, "/document/extension"), Some("pdf"));
        assert_eq!(
            str_at(&context, "/document/contentType"),
            Some("application/pdf")
        );
        assert_eq!(
            context
                .pointer("/document/sizeBytes")
                .and_then(Value::as_u64),
            Some(content.len() as u64)
        );
        assert_eq!(
            context
                .pointer("/document/pageCount")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            context
                .pointer("/document/encrypted")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(str_at(&context, "/document/title"), Some("Q3 Invoice"));
        assert_eq!(str_at(&context, "/document/author"), Some("Anthony"));
        assert_eq!(str_at(&context, "/run/policyName"), Some("Outbound review"));
        assert_eq!(str_at(&context, "/run/runId"), Some("run-42"));
        assert_eq!(str_at(&context, "/run/timestamp"), Some(TIMESTAMP));
        Ok(())
    }

    #[test]
    fn hashes_the_content_the_api_will_receive() -> TestResult {
        let content = pdf_with_info(&[])?;
        let sha = DocumentContext::build(&content, Some("a.pdf"), None, &run())
            .pointer("/document/sha256")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or("sha256 present")?;

        assert_eq!(sha.len(), 64);
        assert!(
            sha.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        // Same bytes, same hash regardless of filename: dedupe / chain-of-custody.
        assert_eq!(
            str_at(
                &DocumentContext::build(&content, Some("renamed.pdf"), None, &run()),
                "/document/sha256"
            ),
            Some(sha.as_str())
        );
        Ok(())
    }

    #[test]
    fn carries_the_bytes_as_base64_for_body_payloads() -> TestResult {
        let content = pdf_with_info(&[])?;
        let base64 = DocumentContext::build(&content, Some("a.pdf"), None, &run())
            .pointer("/document/base64")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or("base64 present")?;
        assert_eq!(STANDARD.decode(base64)?, content);
        Ok(())
    }

    #[test]
    fn surfaces_an_existing_purview_label() -> TestResult {
        let mut document = two_page_pdf();
        PdfSensitivityLabels::apply(
            &mut document,
            &confidential_label(Some(AssignmentMethod::Privileged))?,
        )?;
        let content = serialize(&mut document)?;

        let context = DocumentContext::build(
            &content,
            Some("secret.pdf"),
            Some("application/pdf"),
            &run(),
        );
        assert_eq!(
            str_at(&context, "/sensitivityLabel/name"),
            Some("Confidential")
        );
        assert_eq!(str_at(&context, "/sensitivityLabel/siteId"), Some(TENANT));
        assert_eq!(
            str_at(&context, "/sensitivityLabel/method"),
            Some("PRIVILEGED")
        );
        assert_eq!(
            context
                .pointer("/sensitivityLabel/protected")
                .and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            str_at(&context, "/sensitivityLabel/labelId"),
            Some(LABEL_GUID)
        );
        Ok(())
    }

    #[test]
    fn surfaces_the_classifier_verdict_as_json() -> TestResult {
        let content = pdf_with_info(&[(
            "StirlingPDFClassification",
            "{\"label\":\"invoice\",\"confidence\":0.91}",
        )])?;
        let context = DocumentContext::build(&content, Some("a.pdf"), None, &run());

        // Nested, not a JSON string, so {{classification.label}} resolves.
        assert_eq!(str_at(&context, "/classification/label"), Some("invoice"));
        assert_eq!(
            context
                .pointer("/classification/confidence")
                .and_then(Value::as_f64),
            Some(0.91)
        );
        Ok(())
    }

    #[test]
    fn omits_what_is_absent_rather_than_inventing_it() -> TestResult {
        let content = pdf_with_info(&[])?;
        let context = DocumentContext::build(
            &content,
            Some("a.pdf"),
            None,
            &RunFacts {
                policy_name: None,
                run_id: None,
                timestamp: TIMESTAMP,
            },
        );

        assert!(context.pointer("/sensitivityLabel").is_none());
        assert!(context.pointer("/classification").is_none());
        // policyName is present-but-null, so {{run.policyName}} resolves to empty.
        assert!(
            context
                .pointer("/run/policyName")
                .is_some_and(Value::is_null)
        );
        Ok(())
    }

    #[test]
    fn a_non_pdf_still_gets_the_basics() {
        let content = b"just text";
        let context =
            DocumentContext::build(content, Some("notes.txt"), Some("text/plain"), &run());

        assert_eq!(str_at(&context, "/document/filename"), Some("notes.txt"));
        assert_eq!(str_at(&context, "/document/extension"), Some("txt"));
        assert_eq!(
            context
                .pointer("/document/sizeBytes")
                .and_then(Value::as_u64),
            Some(content.len() as u64)
        );
        assert_eq!(str_at(&context, "/document/sha256").map(str::len), Some(64));
        // No PDF facts, and no panic either.
        assert!(context.pointer("/document/pageCount").is_none());
    }

    #[test]
    fn unparseable_bytes_claiming_to_be_a_pdf_do_not_fail_the_step() {
        let content = b"%PDF-1.7 but truncated";
        let context =
            DocumentContext::build(content, Some("broken.pdf"), Some("application/pdf"), &run());

        assert_eq!(str_at(&context, "/document/sha256").map(str::len), Some(64));
        assert!(context.pointer("/document/pageCount").is_none());
    }

    // -------------------------------------------------------------------
    // DEV edge coverage the DocumentContextTest oracle leaves implicit.
    // -------------------------------------------------------------------

    #[test]
    fn parsed_pdf_sets_absent_info_fields_as_present_null() -> TestResult {
        // A parsed PDF with no Title still carries a null "title" key, so
        // {{document.title}} resolves to empty rather than erroring — the exact
        // difference from a non-PDF, where the key is missing.
        let content = pdf_with_info(&[])?;
        let context = DocumentContext::build(&content, Some("a.pdf"), None, &run());
        assert!(
            context
                .pointer("/document/title")
                .is_some_and(Value::is_null)
        );
        assert!(
            context
                .pointer("/document/author")
                .is_some_and(Value::is_null)
        );

        assert_eq!(
            Placeholders::resolve(Some("[{{document.title}}]"), &context, Escaping::None)?,
            Some("[]".to_owned())
        );
        // A non-PDF omits the key entirely, so the same placeholder errors.
        let non_pdf = DocumentContext::build(b"plain", Some("a.txt"), None, &run());
        assert_err_contains(
            Placeholders::resolve(Some("{{document.title}}"), &non_pdf, Escaping::None),
            "unknown placeholder",
        );
        Ok(())
    }

    #[test]
    fn classification_that_is_not_json_passes_through_as_text() -> TestResult {
        let content = pdf_with_info(&[("StirlingPDFClassification", "top secret")])?;
        let context = DocumentContext::build(&content, Some("a.pdf"), None, &run());
        assert_eq!(str_at(&context, "/classification"), Some("top secret"));
        Ok(())
    }

    #[test]
    fn blank_classification_is_omitted() -> TestResult {
        let content = pdf_with_info(&[("StirlingPDFClassification", "   ")])?;
        let context = DocumentContext::build(&content, Some("a.pdf"), None, &run());
        assert!(context.pointer("/classification").is_none());
        Ok(())
    }

    #[test]
    fn label_without_a_method_renders_method_as_null() -> TestResult {
        let mut document = two_page_pdf();
        PdfSensitivityLabels::apply(&mut document, &confidential_label(None)?)?;
        let content = serialize(&mut document)?;
        let context = DocumentContext::build(&content, Some("a.pdf"), None, &run());
        assert!(
            context
                .pointer("/sensitivityLabel/method")
                .is_some_and(Value::is_null)
        );
        Ok(())
    }

    #[test]
    fn extension_is_absent_for_a_dotless_or_trailing_dot_name() {
        for name in ["README", "archive."] {
            let context = DocumentContext::build(b"x", Some(name), None, &run());
            assert!(
                context
                    .pointer("/document/extension")
                    .is_some_and(Value::is_null),
                "expected null extension for {name:?}"
            );
        }
        // A null filename yields a null extension too, without panicking.
        let context = DocumentContext::build(b"x", None, None, &run());
        assert!(
            context
                .pointer("/document/filename")
                .is_some_and(Value::is_null)
        );
        assert!(
            context
                .pointer("/document/extension")
                .is_some_and(Value::is_null)
        );
    }

    // -------------------------------------------------------------------
    // buildBody — the body-shape assertions from ExternalApiCallControllerLiveTest.
    // -------------------------------------------------------------------

    fn resolved_fields(
        context: &Value,
        pairs: &[(&str, &str)],
    ) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
        let mut fields = BTreeMap::new();
        for (name, template) in pairs {
            let resolved = Placeholders::resolve(Some(template), context, Escaping::None)?
                .ok_or("expected a resolved field")?;
            fields.insert((*name).to_owned(), resolved);
        }
        Ok(fields)
    }

    #[test]
    fn multipart_sends_the_document_and_what_we_know_about_it() -> TestResult {
        let content = rich_pdf()?;
        let context =
            DocumentContext::build(&content, Some("claim.pdf"), Some("application/pdf"), &run());
        let fields = resolved_fields(
            &context,
            &[
                ("label", "{{sensitivityLabel.name}}"),
                ("class", "{{classification.label}}"),
                ("pages", "{{document.pageCount}}"),
            ],
        )?;

        let body = build_body(
            &BodyRequest {
                body_mode: BODY_MULTIPART,
                body_template: None,
                include_file: true,
                include_context: true,
                file_field_name: "file",
                filename: "claim.pdf",
                content_type: "application/pdf",
                content: &content,
                fields: &fields,
            },
            &context,
        )?;

        assert!(body.content_type.starts_with("multipart/form-data"));
        let rendered = String::from_utf8_lossy(&body.bytes);
        // Fields the vendor asked for, filled from what Stirling already knew.
        assert!(rendered.contains("name=\"label\""));
        assert!(rendered.contains("Confidential"));
        assert!(rendered.contains("name=\"class\""));
        assert!(rendered.contains("invoice"));
        assert!(rendered.contains("name=\"pages\""));
        // {{document.pageCount}} is a JSON number, rendered as "2".
        assert_eq!(fields.get("pages").map(String::as_str), Some("2"));
        // The document itself, under the field name the vendor expects.
        assert!(rendered.contains("name=\"file\"; filename=\"claim.pdf\""));
        assert!(rendered.contains("%PDF"));
        // The context, including which policy and run sent it.
        assert!(rendered.contains("stirlingContext"));
        assert!(rendered.contains("Outbound review"));
        assert!(rendered.contains("run-42"));
        Ok(())
    }

    #[test]
    fn json_body_carries_a_vendor_shaped_document_via_template() -> TestResult {
        let content = rich_pdf()?;
        let context =
            DocumentContext::build(&content, Some("claim.pdf"), Some("application/pdf"), &run());

        // ConsignO's submit shape: the PDF base64'd into documents[0].data.
        let body = build_body(
            &BodyRequest {
                // bodyMode is json, but the template takes precedence.
                body_mode: BODY_JSON,
                body_template: Some(
                    "{\"name\":\"{{document.filename}}\",\"status\":1,\
                     \"documents\":[{\"name\":\"{{document.filename}}\",\"data\":\"{{document.base64}}\"}],\
                     \"actions\":[{\"mode\":\"remote\",\"signer\":{\"type\":\"certifio\"}}]}",
                ),
                include_file: true,
                include_context: true,
                file_field_name: "file",
                filename: "claim.pdf",
                content_type: "application/pdf",
                content: &content,
                fields: &BTreeMap::new(),
            },
            &context,
        )?;

        assert_eq!(body.content_type, "application/json");
        let sent: Value = serde_json::from_slice(&body.bytes)?;
        assert_eq!(str_at(&sent, "/name"), Some("claim.pdf"));
        // Numbers keep their type; only strings are substituted.
        assert!(sent.pointer("/status").is_some_and(Value::is_number));
        assert_eq!(str_at(&sent, "/actions/0/signer/type"), Some("certifio"));
        let data = str_at(&sent, "/documents/0/data").ok_or("documents[0].data string")?;
        assert!(STANDARD.decode(data)?.starts_with(b"%PDF"));
        Ok(())
    }

    #[test]
    fn json_notify_style_sends_the_facts_without_the_document() -> TestResult {
        let content = rich_pdf()?;
        let context = DocumentContext::build(
            &content,
            Some("claim.pdf"),
            Some("application/pdf"),
            &RunFacts {
                policy_name: Some("Outbound review"),
                run_id: Some("run-7"),
                timestamp: TIMESTAMP,
            },
        );

        let body = build_body(
            &BodyRequest {
                body_mode: BODY_JSON,
                body_template: None,
                include_file: false,
                include_context: true,
                file_field_name: "file",
                filename: "claim.pdf",
                content_type: "application/pdf",
                content: &content,
                fields: &BTreeMap::new(),
            },
            &context,
        )?;

        assert_eq!(body.content_type, "application/json");
        let sent: Value = serde_json::from_slice(&body.bytes)?;
        assert_eq!(str_at(&sent, "/document/filename"), Some("claim.pdf"));
        assert_eq!(str_at(&sent, "/run/policyName"), Some("Outbound review"));
        // No document: the point of a notification is the facts, not the bytes.
        assert!(sent.pointer("/content").is_none());
        // The raw PDF header never appears (document.base64 is "JVBERg…", not "%PDF").
        assert!(!String::from_utf8_lossy(&body.bytes).contains("%PDF"));
        Ok(())
    }

    #[test]
    fn json_body_includes_fields_context_and_the_base64_file() -> TestResult {
        let content = pdf_with_info(&[])?;
        let context =
            DocumentContext::build(&content, Some("a.pdf"), Some("application/pdf"), &run());
        let mut fields = BTreeMap::new();
        fields.insert("policy".to_owned(), "strict".to_owned());

        let body = build_body(
            &BodyRequest {
                body_mode: BODY_JSON,
                body_template: None,
                include_file: true,
                include_context: true,
                file_field_name: "file",
                filename: "a.pdf",
                content_type: "application/pdf",
                content: &content,
                fields: &fields,
            },
            &context,
        )?;

        let sent: Value = serde_json::from_slice(&body.bytes)?;
        assert_eq!(str_at(&sent, "/policy"), Some("strict"));
        assert_eq!(str_at(&sent, "/document/filename"), Some("a.pdf"));
        assert_eq!(str_at(&sent, "/filename"), Some("a.pdf"));
        assert_eq!(str_at(&sent, "/contentType"), Some("application/pdf"));
        let encoded = str_at(&sent, "/content").ok_or("content string")?;
        assert_eq!(STANDARD.decode(encoded)?, content);
        Ok(())
    }

    #[test]
    fn multipart_fields_only_when_the_file_is_excluded() -> TestResult {
        let content = pdf_with_info(&[])?;
        let context =
            DocumentContext::build(&content, Some("a.pdf"), Some("application/pdf"), &run());
        let mut fields = BTreeMap::new();
        fields.insert("event".to_owned(), "reviewed".to_owned());

        let body = build_body(
            &BodyRequest {
                body_mode: BODY_MULTIPART,
                body_template: None,
                include_file: false,
                include_context: false,
                file_field_name: "file",
                filename: "a.pdf",
                content_type: "application/pdf",
                content: &content,
                fields: &fields,
            },
            &context,
        )?;

        assert!(body.content_type.starts_with("multipart/form-data"));
        let rendered = String::from_utf8_lossy(&body.bytes);
        assert!(rendered.contains("name=\"event\""));
        assert!(rendered.contains("reviewed"));
        // Fields-only: no file part, so the document bytes never appear.
        assert!(!rendered.contains("filename=\"a.pdf\""));
        assert!(!rendered.contains("%PDF"));
        Ok(())
    }

    #[test]
    fn binary_sends_the_raw_bytes_under_the_resolved_content_type() -> TestResult {
        let content = b"%PDF-1.7 raw";
        let context =
            DocumentContext::build(content, Some("a.pdf"), Some("application/pdf"), &run());

        let body = build_body(
            &BodyRequest {
                body_mode: BODY_BINARY,
                body_template: None,
                include_file: true,
                include_context: false,
                file_field_name: "file",
                filename: "a.pdf",
                content_type: "application/pdf",
                content,
                fields: &BTreeMap::new(),
            },
            &context,
        )?;

        assert_eq!(body.content_type, "application/pdf");
        assert_eq!(body.bytes, content);
        Ok(())
    }

    #[test]
    fn binary_refuses_fields_and_an_empty_body() {
        let context = DocumentContext::build(b"x", Some("a.bin"), None, &run());
        let mut fields = BTreeMap::new();
        fields.insert("policy".to_owned(), "strict".to_owned());

        assert_err_contains(
            build_body(
                &BodyRequest {
                    body_mode: BODY_BINARY,
                    body_template: None,
                    include_file: true,
                    include_context: false,
                    file_field_name: "file",
                    filename: "a.bin",
                    content_type: "application/octet-stream",
                    content: b"x",
                    fields: &fields,
                },
                &context,
            ),
            "'fields' cannot be sent",
        );

        assert_err_contains(
            build_body(
                &BodyRequest {
                    body_mode: BODY_BINARY,
                    body_template: None,
                    include_file: false,
                    include_context: false,
                    file_field_name: "file",
                    filename: "a.bin",
                    content_type: "application/octet-stream",
                    content: b"x",
                    fields: &BTreeMap::new(),
                },
                &context,
            ),
            "would send an empty body",
        );
    }

    #[test]
    fn body_template_must_be_valid_json() {
        let context = DocumentContext::build(b"%PDF-x", Some("a.pdf"), None, &run());
        assert_err_contains(
            build_body(
                &BodyRequest {
                    body_mode: BODY_JSON,
                    body_template: Some("{ not json"),
                    include_file: true,
                    include_context: false,
                    file_field_name: "file",
                    filename: "a.pdf",
                    content_type: "application/pdf",
                    content: b"%PDF-x",
                    fields: &BTreeMap::new(),
                },
                &context,
            ),
            "must be valid JSON",
        );
    }

    #[test]
    fn body_template_deep_copies_the_context_and_injects_the_file() -> TestResult {
        let content = pdf_with_info(&[])?;
        let context =
            DocumentContext::build(&content, Some("orig.pdf"), Some("application/pdf"), &run());

        let body = build_body(
            &BodyRequest {
                body_mode: BODY_JSON,
                body_template: Some(
                    "{\"safe\":\"{{document.safeFilename}}\",\"ct\":\"{{document.resolvedContentType}}\"}",
                ),
                include_file: true,
                include_context: false,
                file_field_name: "file",
                filename: "safe.pdf",
                content_type: "application/pdf",
                content: &content,
                fields: &BTreeMap::new(),
            },
            &context,
        )?;

        // The injected fields resolve against the copy…
        let sent: Value = serde_json::from_slice(&body.bytes)?;
        assert_eq!(str_at(&sent, "/safe"), Some("safe.pdf"));
        assert_eq!(str_at(&sent, "/ct"), Some("application/pdf"));
        // …but the original context was not mutated (deep copy), so its document
        // still lacks the injected keys.
        assert!(context.pointer("/document/safeFilename").is_none());
        assert!(context.pointer("/document/resolvedContentType").is_none());
        Ok(())
    }
}

// ===========================================================================
// Slice 3 tests — the SSRF-safe caller, credential headers, and TOKEN_LOGIN
// cache, driven against a real loopback mock HTTP server through real reqwest
// (the model proven in mcp.rs / oidc_live_token.rs). No external network. No
// `unwrap`/`expect` (both denied in this crate): errors surface via `?`,
// `let … else { panic! }`, or `assert_err_contains`.
// ===========================================================================
#[cfg(test)]
mod slice3_tests {
    use std::{
        collections::BTreeMap,
        io::{Cursor, Read as _, Write as _},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use regex::Regex;
    use serde_json::{Value, json};
    use url::Url;

    use super::{
        ApiConnectionSettings, ApiResponse, ApiTokenLogin, ExternalApiCallRequest,
        ExternalApiCallResult, ExternalApiCaller, ExternalApiError, OutboundBody, ResultFiles,
        ResultUrls, RunFacts, SendParts, is_cloud_metadata, require_public_host, resolve_host,
        send, token_cache_key,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    /// The request headers a capturing mock recorded (kept simple for clippy).
    type CapturedHeaders = Arc<Mutex<Vec<(String, String)>>>;

    /// No `unwrap`/`expect`: assert an error whose message contains `needle`.
    fn assert_err_contains<T>(result: Result<T, ExternalApiError>, needle: &str) {
        match result {
            Ok(_) => panic!("expected an error containing {needle:?}, got Ok"),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains(needle),
                    "message {message:?} did not contain {needle:?}"
                );
            }
        }
    }

    fn options(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    fn settings_with(
        base_url: &str,
        extra: &[(&str, Value)],
    ) -> Result<ApiConnectionSettings, ExternalApiError> {
        let mut pairs: Vec<(&str, Value)> = vec![("baseUrl", json!(base_url))];
        pairs.extend_from_slice(extra);
        ApiConnectionSettings::from_options(&options(&pairs))
    }

    fn json_body() -> OutboundBody {
        OutboundBody {
            content_type: "application/json".to_owned(),
            bytes: b"{}".to_vec(),
        }
    }

    fn addr(literal: &str, port: u16) -> SocketAddr {
        let ip = literal
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        SocketAddr::new(ip, port)
    }

    fn loopback_resolver() -> impl Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>> {
        |_host: &str, port: u16| Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)])
    }

    // ---------------------------------------------------------------------
    // A minimal, routable loopback HTTP/1.1 mock. Serves connections until
    // dropped; each is handed to the test's handler closure.
    // ---------------------------------------------------------------------

    struct MockRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl MockRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }

        fn body_text(&self) -> String {
            String::from_utf8_lossy(&self.body).into_owned()
        }
    }

    struct MockResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        omit_content_length: bool,
    }

    impl MockResponse {
        fn json(status: u16, body: &str) -> Self {
            Self {
                status,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: body.as_bytes().to_vec(),
                omit_content_length: false,
            }
        }

        fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_owned(), value.to_owned()));
            self
        }
    }

    type Handler = Arc<dyn Fn(&MockRequest) -> MockResponse + Send + Sync>;

    struct MockServer {
        base_url: String,
        shutdown: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl MockServer {
        fn start(handler: Handler) -> std::io::Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            listener.set_nonblocking(true)?;
            let address = listener.local_addr()?;
            let shutdown = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&shutdown);
            let handle = thread::spawn(move || serve_loop(&listener, &flag, &handler));
            Ok(Self {
                base_url: format!("http://{address}"),
                shutdown,
                handle: Some(handle),
            })
        }

        fn port(&self) -> Option<u16> {
            self.base_url
                .rsplit(':')
                .next()
                .and_then(|port| port.parse().ok())
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve_loop(listener: &TcpListener, shutdown: &AtomicBool, handler: &Handler) {
        while !shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = handle_connection(stream, handler);
                }
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, handler: &Handler) -> std::io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut buffer = Vec::new();
        let mut header_end: Option<usize> = None;
        let mut content_length = 0_usize;
        loop {
            if header_end.is_none()
                && let Some(position) = find_subsequence(&buffer, b"\r\n\r\n")
            {
                header_end = Some(position + 4);
                let head = String::from_utf8_lossy(&buffer[..position]);
                content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
            }
            if let Some(start) = header_end
                && buffer.len() >= start + content_length
            {
                break;
            }
            let mut chunk = [0_u8; 4096];
            match stream.read(&mut chunk) {
                Ok(read) if read > 0 => buffer.extend_from_slice(&chunk[..read]),
                _ => break,
            }
        }
        let request = parse_request(&buffer, header_end.unwrap_or(buffer.len()), content_length);
        let response = handler(&request);
        write_response(&mut stream, &response)
    }

    fn parse_request(buffer: &[u8], header_end: usize, content_length: usize) -> MockRequest {
        let head = String::from_utf8_lossy(&buffer[..header_end.min(buffer.len())]);
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or_default();
        let method = request_line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_owned();
        let path = request_line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_owned(), value.trim().to_owned()))
            })
            .collect();
        let body_start = header_end.min(buffer.len());
        let body_end = (body_start + content_length).min(buffer.len());
        MockRequest {
            method,
            path,
            headers,
            body: buffer[body_start..body_end].to_vec(),
        }
    }

    fn write_response(stream: &mut TcpStream, response: &MockResponse) -> std::io::Result<()> {
        let reason = match response.status {
            200 => "OK",
            201 => "Created",
            302 => "Found",
            401 => "Unauthorized",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Status",
        };
        let mut head = format!("HTTP/1.1 {} {reason}\r\n", response.status);
        for (name, value) in &response.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        if !response.omit_content_length {
            head.push_str("Content-Length: ");
            head.push_str(&response.body.len().to_string());
            head.push_str("\r\n");
        }
        head.push_str("Connection: close\r\n\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(&response.body)?;
        stream.flush()
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    // ---- credential-header wire tests (oracle ExternalApiCallerAuthHeaderTest) ----

    fn header_capturing_server() -> std::io::Result<(MockServer, CapturedHeaders)> {
        let seen: CapturedHeaders = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let handler: Handler = Arc::new(move |request: &MockRequest| {
            if let Ok(mut guard) = sink.lock() {
                *guard = request.headers.clone();
            }
            MockResponse::json(200, "{\"ok\":true}")
        });
        Ok((MockServer::start(handler)?, seen))
    }

    fn header_value(seen: &CapturedHeaders, name: &str) -> Option<String> {
        let Ok(guard) = seen.lock() else {
            return None;
        };
        guard
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }

    fn send_ingest(
        caller: &ExternalApiCaller,
        settings: &ApiConnectionSettings,
    ) -> Result<ApiResponse, ExternalApiError> {
        caller.dispatch(settings, "POST", "/ingest", &json_body(), &BTreeMap::new())
    }

    #[test]
    fn bearer_auth_puts_a_bearer_header_on_the_wire() -> TestResult {
        let (server, seen) = header_capturing_server()?;
        let caller = ExternalApiCaller::new(true); // loopback is reserved; opt in
        // A stray headerPrefix must not touch BEARER (mirrors the oracle).
        let settings = settings_with(
            &server.base_url,
            &[
                ("authType", json!("BEARER")),
                ("headerPrefix", json!("API-Key")),
                ("token", json!("sk-secret")),
            ],
        )?;
        assert!(send_ingest(&caller, &settings)?.is_success());
        assert_eq!(
            header_value(&seen, "authorization").as_deref(),
            Some("Bearer sk-secret")
        );
        Ok(())
    }

    #[test]
    fn header_auth_with_prefix_sends_scheme_and_token() -> TestResult {
        let (server, seen) = header_capturing_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &server.base_url,
            &[
                ("authType", json!("HEADER")),
                ("headerName", json!("Authorization")),
                ("headerPrefix", json!("API-Key")),
                ("token", json!("pd-secret")),
            ],
        )?;
        assert!(send_ingest(&caller, &settings)?.is_success());
        assert_eq!(
            header_value(&seen, "authorization").as_deref(),
            Some("API-Key pd-secret")
        );
        Ok(())
    }

    #[test]
    fn header_auth_without_prefix_sends_the_bare_token() -> TestResult {
        let (server, seen) = header_capturing_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &server.base_url,
            &[
                ("authType", json!("HEADER")),
                ("headerName", json!("x-api-key")),
                ("token", json!("sk-ant-secret")),
            ],
        )?;
        assert!(send_ingest(&caller, &settings)?.is_success());
        // No scheme invented; and no Authorization header conjured.
        assert_eq!(
            header_value(&seen, "x-api-key").as_deref(),
            Some("sk-ant-secret")
        );
        assert_eq!(header_value(&seen, "authorization"), None);
        Ok(())
    }

    #[test]
    fn basic_auth_sends_base64_of_user_colon_pass() -> TestResult {
        let (server, seen) = header_capturing_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &server.base_url,
            &[
                ("authType", json!("BASIC")),
                ("username", json!("alice")),
                ("password", json!("s3cret")),
            ],
        )?;
        assert!(send_ingest(&caller, &settings)?.is_success());
        let expected = format!("Basic {}", STANDARD.encode("alice:s3cret"));
        assert_eq!(
            header_value(&seen, "authorization").as_deref(),
            Some(expected.as_str())
        );
        Ok(())
    }

    #[test]
    fn none_auth_sends_no_credentials_but_keeps_static_headers() -> TestResult {
        let (server, seen) = header_capturing_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &server.base_url,
            &[("headers", json!({"X-Custom": "custom-value"}))],
        )?;
        assert!(send_ingest(&caller, &settings)?.is_success());
        assert_eq!(header_value(&seen, "authorization"), None);
        assert_eq!(
            header_value(&seen, "x-custom").as_deref(),
            Some("custom-value")
        );
        Ok(())
    }

    // ---- redirect and response-size bounds (oracle ExternalApiCaller) -------

    #[test]
    fn a_redirect_is_not_followed() -> TestResult {
        let handler: Handler = Arc::new(|_request: &MockRequest| {
            MockResponse::json(302, "{}").with_header("Location", "http://evil.example/steal")
        });
        let server = MockServer::start(handler)?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let response = caller.dispatch(&settings, "POST", "/go", &json_body(), &BTreeMap::new())?;
        // The 3xx is surfaced, not chased to the attacker's host.
        assert_eq!(response.status, 302);
        assert_eq!(
            response.header("location"),
            Some("http://evil.example/steal")
        );
        Ok(())
    }

    #[test]
    fn an_oversized_response_is_rejected_via_its_content_length() -> TestResult {
        let handler: Handler =
            Arc::new(|_request: &MockRequest| MockResponse::json(200, "0123456789ABCDEF"));
        let server = MockServer::start(handler)?;
        let pinned = require_public_host(&Url::parse(&server.base_url)?, true, &resolve_host)?;
        let target = Url::parse(&format!("{}/big", server.base_url))?;
        // A tiny cap stands in for MAX_RESPONSE_BYTES; the advertised length is
        // rejected before the body is read.
        let result = send(
            &pinned,
            &SendParts {
                method: "GET",
                url: &target,
                content_type: None,
                body: None,
                headers: &[],
                timeout_seconds: 5,
                max_response_bytes: 8,
            },
        );
        assert_err_contains(result, "exceeds the 8 byte limit");
        Ok(())
    }

    #[test]
    fn an_oversized_response_without_content_length_is_capped_during_read() -> TestResult {
        let handler: Handler = Arc::new(|_request: &MockRequest| MockResponse {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: b"0123456789ABCDEF".to_vec(),
            omit_content_length: true,
        });
        let server = MockServer::start(handler)?;
        let pinned = require_public_host(&Url::parse(&server.base_url)?, true, &resolve_host)?;
        let target = Url::parse(&format!("{}/big", server.base_url))?;
        // No Content-Length: the bounded read (take cap+1) still refuses to buffer
        // past the cap.
        let result = send(
            &pinned,
            &SendParts {
                method: "GET",
                url: &target,
                content_type: None,
                body: None,
                headers: &[],
                timeout_seconds: 5,
                max_response_bytes: 8,
            },
        );
        assert_err_contains(result, "exceeds the 8 byte limit");
        Ok(())
    }

    // ---- the SSRF base-host gate (oracle ApiIntegrationValidator) -----------

    #[test]
    fn gate_accepts_an_ordinary_public_host() -> TestResult {
        let base = Url::parse("https://api.example.com/v1")?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("1.1.1.1", 443)])
        };
        let pinned = require_public_host(&base, false, &resolve)?;
        assert_eq!(pinned.addrs, vec![addr("1.1.1.1", 443)]);
        Ok(())
    }

    #[test]
    fn gate_rejects_a_private_host_by_default() -> TestResult {
        let base = Url::parse("http://internal.example/x")?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("10.0.0.5", 80)])
        };
        assert_err_contains(
            require_public_host(&base, false, &resolve),
            "private/link-local",
        );
        assert_err_contains(
            require_public_host(&base, false, &resolve),
            "allowPrivateApiEndpoints",
        );
        Ok(())
    }

    #[test]
    fn gate_allows_a_private_host_when_opted_in() -> TestResult {
        let base = Url::parse("http://10.10.0.20:8080/api")?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("10.10.0.20", 8080)])
        };
        let pinned = require_public_host(&base, true, &resolve)?;
        assert_eq!(pinned.host, "10.10.0.20");
        Ok(())
    }

    #[test]
    fn gate_blocks_cloud_metadata_even_with_the_private_opt_in() -> TestResult {
        for literal in ["169.254.169.254", "169.254.169.253", "169.254.169.250"] {
            let base = Url::parse("http://metadata.example/latest/meta-data/")?;
            let resolve = move |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
                Ok(vec![addr(literal, 80)])
            };
            // The opt-in allows RFC1918, but the metadata endpoint stays blocked.
            assert_err_contains(
                require_public_host(&base, true, &resolve),
                "metadata service",
            );
        }
        Ok(())
    }

    #[test]
    fn gate_blocks_the_ipv6_metadata_address_the_oracle_string_compare_missed() -> TestResult {
        // Java's `String.startsWith` cannot match fd00:ec2::254 once expanded to
        // its full form; the parsed-IpAddr compare here blocks it, opt-in or not.
        let base = Url::parse("http://metadata6.example/latest")?;
        let metadata6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
            80,
        );
        let resolve = move |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![metadata6])
        };
        assert_err_contains(
            require_public_host(&base, true, &resolve),
            "metadata service",
        );
        Ok(())
    }

    #[test]
    fn gate_reports_metadata_before_the_generic_private_message() -> TestResult {
        // 169.254/16 is also link-local, but the unconditional metadata deny wins
        // (and runs before the opt-in), so the message names the metadata service.
        let base = Url::parse("http://metadata.example/x")?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("169.254.169.254", 80)])
        };
        assert_err_contains(
            require_public_host(&base, false, &resolve),
            "metadata service",
        );
        Ok(())
    }

    /// Every standardized IPv4-in-IPv6 embedding of `v4`, in the same forms
    /// [`super::embedded_ipv4_forms`] unwraps. This is the inverse of that
    /// helper, so a metadata IPv4 hidden in any of them must be detected.
    fn ipv6_embeddings_of(v4: Ipv4Addr) -> Vec<(&'static str, Ipv6Addr)> {
        let [a, b, c, d] = v4.octets();
        let hi = u16::from_be_bytes([a, b]);
        let lo = u16::from_be_bytes([c, d]);
        // Teredo stores the client IPv4 bitwise-inverted.
        let cli_hi = u16::from_be_bytes([!a, !b]);
        let cli_lo = u16::from_be_bytes([!c, !d]);
        vec![
            ("ipv4-mapped", v4.to_ipv6_mapped()),
            ("ipv4-compatible", Ipv6Addr::new(0, 0, 0, 0, 0, 0, hi, lo)),
            (
                "nat64-well-known",
                Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, hi, lo),
            ),
            (
                "nat64-local-use",
                // 64:ff9b:1::/48 with the IPv4 straddling the reserved "u" octet.
                Ipv6Addr::from([
                    0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, a, b, 0x00, c, d, 0, 0, 0, 0, 0,
                ]),
            ),
            ("6to4", Ipv6Addr::new(0x2002, hi, lo, 0, 0, 0, 0, 0)),
            (
                "teredo-server",
                Ipv6Addr::new(0x2001, 0, hi, lo, 0, 0, 0, 0),
            ),
            (
                "teredo-client",
                Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, cli_hi, cli_lo),
            ),
            (
                // Arbitrary public /64 prefix; only the 5e-fe marker + IPv4 matter.
                "isatap",
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0x5efe, hi, lo),
            ),
        ]
    }

    #[test]
    fn metadata_deny_unwraps_every_ipv4_in_ipv6_embedding_form() {
        // The finding: the deny previously unwrapped only the IPv4-MAPPED form, so
        // a metadata IP encoded as e.g. a NAT64 AAAA slipped through. Each metadata
        // address must now be caught in EVERY standardized embedding form.
        for v4 in [
            Ipv4Addr::new(169, 254, 169, 254),
            Ipv4Addr::new(169, 254, 169, 253),
            Ipv4Addr::new(169, 254, 169, 250),
        ] {
            assert!(is_cloud_metadata(IpAddr::V4(v4)), "bare {v4}");
            for (form, v6) in ipv6_embeddings_of(v4) {
                assert!(
                    is_cloud_metadata(IpAddr::V6(v6)),
                    "metadata {v4} embedded as {form} ({v6}) escaped the deny",
                );
            }
        }
    }

    #[test]
    fn metadata_deny_does_not_over_block_a_public_ipv4_embedded_in_ipv6() {
        // The unwrapping must be precise: a PUBLIC IPv4 in the same embeddings is
        // not the metadata service, so the deny must not fire on it.
        let public = Ipv4Addr::new(1, 1, 1, 1);
        assert!(!is_cloud_metadata(IpAddr::V4(public)));
        for (form, v6) in ipv6_embeddings_of(public) {
            assert!(
                !is_cloud_metadata(IpAddr::V6(v6)),
                "public {public} embedded as {form} ({v6}) was wrongly flagged as metadata",
            );
        }
    }

    #[test]
    fn gate_blocks_a_nat64_embedded_metadata_ip_under_the_private_opt_in() -> TestResult {
        // The exact finding scenario on an IPv6-only + DNS64/NAT64 host: the AAAA
        // 64:ff9b::a9fe:a9fe encodes 169.254.169.254. Under the private opt-in the
        // reserved-range vet is skipped, so only the (now comprehensive) metadata
        // deny stands between the caller and the metadata service.
        let base = Url::parse("http://metadata-nat64.example/latest/meta-data/")?;
        let nat64 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe)),
            80,
        );
        let resolve =
            move |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> { Ok(vec![nat64]) };
        assert_err_contains(
            require_public_host(&base, true, &resolve),
            "metadata service",
        );
        Ok(())
    }

    #[test]
    fn gate_rejects_an_unresolvable_host() -> TestResult {
        let base = Url::parse("https://nope.example/x")?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Err(std::io::Error::other("nxdomain"))
        };
        assert_err_contains(
            require_public_host(&base, false, &resolve),
            "Unable to resolve",
        );
        Ok(())
    }

    #[test]
    fn gate_rejects_when_only_one_of_several_addresses_is_private() -> TestResult {
        // A multi-address name is rejected if ANY resolved address is reserved.
        let base = Url::parse("https://dual.example/x")?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("1.1.1.1", 443), addr("10.0.0.5", 443)])
        };
        assert_err_contains(
            require_public_host(&base, false, &resolve),
            "private/link-local",
        );
        Ok(())
    }

    #[test]
    fn dispatch_pins_the_vetted_address_so_a_named_host_reaches_it() -> TestResult {
        // Proves resolve_to_addrs is actually wired: the base host is a NAME (not a
        // loopback literal), vetted to 127.0.0.1 and pinned, so reqwest connects
        // there rather than re-resolving.
        let (server, seen) = header_capturing_server()?;
        let Some(port) = server.port() else {
            panic!("mock server had no port");
        };
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &format!("http://api.internal.test:{port}"),
            &[("authType", json!("BEARER")), ("token", json!("tok"))],
        )?;
        let resolve = loopback_resolver();
        let response = caller.dispatch_with_resolver(
            &settings,
            "POST",
            "/ingest",
            &json_body(),
            &BTreeMap::new(),
            &resolve,
        )?;
        assert!(response.is_success());
        assert_eq!(
            header_value(&seen, "authorization").as_deref(),
            Some("Bearer tok")
        );
        Ok(())
    }

    // ---- TOKEN_LOGIN end-to-end (oracle ExternalApiCallerTokenLoginTest) ----

    struct ConsignoState {
        logins: usize,
        issued_token: String,
        reject_token: bool,
        last_call_token: Option<String>,
        workflow_body: Option<String>,
    }

    impl ConsignoState {
        fn shared(token: &str) -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(Self {
                logins: 0,
                issued_token: token.to_owned(),
                reject_token: false,
                last_call_token: None,
                workflow_body: None,
            }))
        }
    }

    fn consigno_server(state: Arc<Mutex<ConsignoState>>) -> std::io::Result<MockServer> {
        let handler: Handler = Arc::new(move |request: &MockRequest| {
            let path = request.path.split('?').next().unwrap_or_default();
            match path {
                "/api/v1/auth/login" => {
                    let body = request.body_text();
                    let client_id = request.header("X-Client-Id").map(str::to_owned);
                    let client_secret = request.header("X-Client-Secret").map(str::to_owned);
                    let Ok(mut guard) = state.lock() else {
                        return MockResponse::json(500, "{}");
                    };
                    guard.logins += 1; // count every attempt, like the oracle
                    if client_id.as_deref() != Some("client-abc")
                        || client_secret.as_deref() != Some("client-xyz")
                        || !body.contains("\"password\":\"s3cr3t\"")
                        || !body.contains("\"tenantId\":\"acme\"")
                    {
                        return MockResponse::json(401, "{}");
                    }
                    let token = guard.issued_token.clone();
                    MockResponse::json(200, "{\"msg\":\"ok\"}").with_header("X-Auth-Token", &token)
                }
                "/api/v1/documents" => {
                    let token = request.header("X-Auth-Token").map(str::to_owned);
                    let Ok(mut guard) = state.lock() else {
                        return MockResponse::json(500, "{}");
                    };
                    guard.last_call_token = token.clone();
                    if guard.reject_token || token.as_deref() != Some(guard.issued_token.as_str()) {
                        return MockResponse::json(401, "{\"msg\":\"expired\"}");
                    }
                    MockResponse::json(
                        201,
                        "{\"response\":{\"metadata\":{\"documentId\":\"doc-9\"}}}",
                    )
                }
                "/api/v1/workflows" => {
                    let token = request.header("X-Auth-Token").map(str::to_owned);
                    let body = request.body_text();
                    let Ok(mut guard) = state.lock() else {
                        return MockResponse::json(500, "{}");
                    };
                    if token.as_deref() != Some(guard.issued_token.as_str()) {
                        return MockResponse::json(401, "{\"msg\":\"expired\"}");
                    }
                    guard.workflow_body = Some(body);
                    MockResponse::json(201, "{\"response\":{\"id\":\"wf-7\",\"status\":1}}")
                }
                _ => MockResponse::json(404, "{}"),
            }
        });
        MockServer::start(handler)
    }

    fn consigno_settings(base_url: &str) -> Result<ApiConnectionSettings, ExternalApiError> {
        ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!(base_url)),
            ("authType", json!("TOKEN_LOGIN")),
            ("loginPath", json!("/auth/login")),
            (
                "loginBody",
                json!({"username": "api@acme.test", "password": "s3cr3t", "tenantId": "acme"}),
            ),
            (
                "loginHeaders",
                json!({"X-Client-Id": "client-abc", "X-Client-Secret": "client-xyz"}),
            ),
            ("tokenResponseHeader", json!("X-Auth-Token")),
            ("tokenHeaderName", json!("X-Auth-Token")),
        ]))
    }

    fn upload(
        caller: &ExternalApiCaller,
        settings: &ApiConnectionSettings,
    ) -> Result<ApiResponse, ExternalApiError> {
        caller.post_file(
            settings,
            "/documents",
            "file",
            "contract.pdf",
            "application/pdf",
            b"%PDF-1.7",
            &BTreeMap::new(),
        )
    }

    #[test]
    fn logs_in_and_sends_the_token_from_the_response_header() -> TestResult {
        let state = ConsignoState::shared("token-1");
        let server = consigno_server(Arc::clone(&state))?;
        let caller = ExternalApiCaller::new(true);
        let settings = consigno_settings(&format!("{}/api/v1", server.base_url))?;

        let response = upload(&caller, &settings)?;
        assert_eq!(response.status, 201);
        assert!(response.body_as_text().contains("doc-9"));

        let Ok(guard) = state.lock() else {
            panic!("state poisoned");
        };
        assert_eq!(guard.logins, 1);
        assert_eq!(guard.last_call_token.as_deref(), Some("token-1"));
        Ok(())
    }

    #[test]
    fn reuses_the_token_across_calls_rather_than_logging_in_per_document() -> TestResult {
        let state = ConsignoState::shared("token-1");
        let server = consigno_server(Arc::clone(&state))?;
        let caller = ExternalApiCaller::new(true);

        // Fresh settings each call (as a stateless per-document step would build),
        // so token reuse must come from the cache, not from a shared settings object.
        for _ in 0..3 {
            let settings = consigno_settings(&format!("{}/api/v1", server.base_url))?;
            assert_eq!(upload(&caller, &settings)?.status, 201);
        }

        let Ok(guard) = state.lock() else {
            panic!("state poisoned");
        };
        // A three-document policy must not perform three logins.
        assert_eq!(guard.logins, 1);
        Ok(())
    }

    #[test]
    fn re_authenticates_once_when_the_token_is_rejected() -> TestResult {
        let state = ConsignoState::shared("token-1");
        let server = consigno_server(Arc::clone(&state))?;
        let caller = ExternalApiCaller::new(true);
        let settings = consigno_settings(&format!("{}/api/v1", server.base_url))?;

        assert_eq!(upload(&caller, &settings)?.status, 201);
        // The vendor expires the token early and issues a new one.
        {
            let Ok(mut guard) = state.lock() else {
                panic!("state poisoned");
            };
            guard.issued_token = "token-2".to_owned();
        }
        assert_eq!(upload(&caller, &settings)?.status, 201);

        let Ok(guard) = state.lock() else {
            panic!("state poisoned");
        };
        assert_eq!(guard.logins, 2);
        assert_eq!(guard.last_call_token.as_deref(), Some("token-2"));
        Ok(())
    }

    #[test]
    fn a_persistent_401_surfaces_rather_than_looping_forever() -> TestResult {
        let state = ConsignoState::shared("token-1");
        {
            let Ok(mut guard) = state.lock() else {
                panic!("state poisoned");
            };
            guard.reject_token = true;
        }
        let server = consigno_server(Arc::clone(&state))?;
        let caller = ExternalApiCaller::new(true);
        let settings = consigno_settings(&format!("{}/api/v1", server.base_url))?;

        let response = upload(&caller, &settings)?;
        assert_eq!(response.status, 401);

        let Ok(guard) = state.lock() else {
            panic!("state poisoned");
        };
        // The initial login plus exactly one re-auth, then give up.
        assert_eq!(guard.logins, 2);
        Ok(())
    }

    #[test]
    fn bad_credentials_fail_the_step_without_echoing_them() -> TestResult {
        let state = ConsignoState::shared("token-1");
        let server = consigno_server(Arc::clone(&state))?;
        let caller = ExternalApiCaller::new(true);
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!(format!("{}/api/v1", server.base_url))),
            ("authType", json!("TOKEN_LOGIN")),
            ("loginPath", json!("/auth/login")),
            (
                "loginBody",
                json!({"username": "api@acme.test", "password": "wrong"}),
            ),
            (
                "loginHeaders",
                json!({"X-Client-Id": "client-abc", "X-Client-Secret": "nope"}),
            ),
            ("tokenResponseHeader", json!("X-Auth-Token")),
            ("tokenHeaderName", json!("X-Auth-Token")),
        ]))?;

        match upload(&caller, &settings) {
            Ok(_) => panic!("expected the bad-credential login to fail the step"),
            Err(error) => {
                let message = error.to_string();
                assert!(message.contains("returned HTTP 401"), "message: {message}");
                // The password must never ride out onward in the run log.
                assert!(
                    !message.contains("wrong"),
                    "message leaked a credential: {message}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn submits_a_consigno_workflow_end_to_end_with_the_document_inline() -> TestResult {
        let state = ConsignoState::shared("token-1");
        let server = consigno_server(Arc::clone(&state))?;
        let caller = ExternalApiCaller::new(true);
        let settings = consigno_settings(&format!("{}/api/v1", server.base_url))?;

        let pdf = b"%PDF-1.7 contract";
        let workflow = json!({
            "name": "contract.pdf",
            "status": 1,
            "documents": [{"name": "contract.pdf", "data": STANDARD.encode(pdf)}],
            "actions": [{"mode": "remote", "signer": {"type": "certifio"}}],
        });
        let body = OutboundBody {
            content_type: "application/json".to_owned(),
            bytes: serde_json::to_vec(&workflow)?,
        };
        let response = caller.dispatch(&settings, "POST", "/workflows", &body, &BTreeMap::new())?;
        assert_eq!(response.status, 201);
        let returned: Value = serde_json::from_slice(&response.body)?;
        assert_eq!(
            returned.pointer("/response/id").and_then(Value::as_str),
            Some("wf-7")
        );

        let Ok(guard) = state.lock() else {
            panic!("state poisoned");
        };
        assert_eq!(guard.logins, 1);
        let received: Value = serde_json::from_str(guard.workflow_body.as_deref().unwrap_or("{}"))?;
        let arrived = received
            .pointer("/documents/0/data")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(STANDARD.decode(arrived).unwrap_or_default(), pdf);
        Ok(())
    }

    // ---- TOKEN_LOGIN with the token in a JSON body path (OAuth2 shape) ------

    #[test]
    fn token_login_reads_a_json_path_and_presents_it_with_a_prefix() -> TestResult {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let handler: Handler = Arc::new(move |request: &MockRequest| match request.path.as_str() {
            "/oauth/token" => {
                MockResponse::json(200, "{\"access_token\":\"jwt-xyz\",\"expires_in\":3600}")
            }
            "/resource" => {
                if let Ok(mut guard) = sink.lock() {
                    *guard = request.headers.clone();
                }
                let authorized = request.header("Authorization") == Some("Bearer jwt-xyz");
                if authorized {
                    MockResponse::json(200, "{\"ok\":true}")
                } else {
                    MockResponse::json(401, "{}")
                }
            }
            _ => MockResponse::json(404, "{}"),
        });
        let server = MockServer::start(handler)?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &server.base_url,
            &[
                ("authType", json!("TOKEN_LOGIN")),
                ("loginPath", json!("/oauth/token")),
                ("tokenResponseJsonPath", json!("access_token")),
                ("tokenHeaderName", json!("Authorization")),
                ("tokenPrefix", json!("Bearer")),
            ],
        )?;
        let response = caller.dispatch(
            &settings,
            "POST",
            "/resource",
            &json_body(),
            &BTreeMap::new(),
        )?;
        assert_eq!(response.status, 200);
        assert_eq!(
            header_value(&seen, "authorization").as_deref(),
            Some("Bearer jwt-xyz")
        );
        Ok(())
    }

    // ---- ApiTokenLogin: parsing + token extraction (oracle ApiTokenLogin) ---

    fn login_from(pairs: &[(&str, Value)]) -> Result<ApiTokenLogin, ExternalApiError> {
        ApiTokenLogin::from_options(&options(pairs))
    }

    fn response_of(status: u16, headers: &[(&str, &str)], body: &str) -> ApiResponse {
        ApiResponse {
            status,
            content_type: headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
                .map(|(_, value)| (*value).to_owned()),
            body: body.as_bytes().to_vec(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn header_login() -> Result<ApiTokenLogin, ExternalApiError> {
        login_from(&[
            ("loginPath", json!("/auth/login")),
            ("tokenResponseHeader", json!("X-Auth-Token")),
            ("tokenHeaderName", json!("X-Auth-Token")),
        ])
    }

    #[test]
    fn token_login_requires_a_login_path() {
        assert_err_contains(
            login_from(&[
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
            ]),
            "requires a 'loginPath'",
        );
    }

    #[test]
    fn token_login_needs_exactly_one_token_location() {
        // Neither.
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenHeaderName", json!("X-Auth-Token")),
            ]),
            "exactly one of",
        );
        // Both.
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenResponseJsonPath", json!("access_token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
            ]),
            "exactly one of",
        );
    }

    #[test]
    fn token_login_requires_and_validates_the_token_header_name() {
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
            ]),
            "requires a 'tokenHeaderName'",
        );
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("bad name")),
            ]),
            "'tokenHeaderName' is not a valid HTTP header name",
        );
    }

    #[test]
    fn token_login_validates_the_response_header_grammar() {
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("bad header")),
                ("tokenHeaderName", json!("X-Auth-Token")),
            ]),
            "'tokenResponseHeader' is not a valid HTTP header name",
        );
    }

    #[test]
    fn token_login_login_body_must_be_an_object() {
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
                ("loginBody", json!("not-an-object")),
            ]),
            "'loginBody' must be an object",
        );
    }

    #[test]
    fn token_login_rejects_bad_login_header_name_and_value() {
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
                ("loginHeaders", json!({"bad name": "v"})),
            ]),
            "'loginHeaders' has an invalid header name",
        );
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
                ("loginHeaders", json!({"X-Client-Secret": "line\nbreak"})),
            ]),
            "'loginHeaders' has an invalid value for 'X-Client-Secret'",
        );
    }

    #[test]
    fn token_login_ttl_must_be_a_number_in_range() {
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
                ("tokenTtlSeconds", json!("soon")),
            ]),
            "'tokenTtlSeconds' must be a number",
        );
        assert_err_contains(
            login_from(&[
                ("loginPath", json!("/auth/login")),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
                ("tokenTtlSeconds", json!(0)),
            ]),
            "'tokenTtlSeconds' must be between 1 and 86400",
        );
    }

    #[test]
    fn extract_token_from_a_response_header() -> TestResult {
        let login = header_login()?;
        let response = response_of(200, &[("X-Auth-Token", "tok-99")], "{}");
        assert_eq!(login.extract_token(&response)?, "tok-99");
        Ok(())
    }

    #[test]
    fn extract_token_missing_header_is_an_error() -> TestResult {
        let login = header_login()?;
        let response = response_of(200, &[("Content-Type", "application/json")], "{}");
        assert_err_contains(
            login.extract_token(&response),
            "returned no 'X-Auth-Token' response header",
        );
        Ok(())
    }

    #[test]
    fn extract_token_walks_a_nested_json_path() -> TestResult {
        let login = login_from(&[
            ("loginPath", json!("/auth/login")),
            ("tokenResponseJsonPath", json!("data.token")),
            ("tokenHeaderName", json!("Authorization")),
        ])?;
        let response = response_of(
            200,
            &[("Content-Type", "application/json")],
            "{\"data\":{\"token\":\"nested-tok\"}}",
        );
        assert_eq!(login.extract_token(&response)?, "nested-tok");
        Ok(())
    }

    #[test]
    fn extract_token_missing_json_value_is_an_error() -> TestResult {
        let login = login_from(&[
            ("loginPath", json!("/auth/login")),
            ("tokenResponseJsonPath", json!("access_token")),
            ("tokenHeaderName", json!("Authorization")),
        ])?;
        // Present but an object (not a scalar) → no token.
        let response = response_of(
            200,
            &[("Content-Type", "application/json")],
            "{\"access_token\":{\"nested\":1}}",
        );
        assert_err_contains(login.extract_token(&response), "no token at 'access_token'");
        Ok(())
    }

    #[test]
    fn auth_header_applies_the_prefix_then_the_bare_form() -> TestResult {
        let prefixed = login_from(&[
            ("loginPath", json!("/oauth/token")),
            ("tokenResponseJsonPath", json!("access_token")),
            ("tokenHeaderName", json!("Authorization")),
            ("tokenPrefix", json!("Bearer")),
        ])?;
        assert_eq!(
            prefixed.auth_header("t"),
            ("Authorization".to_owned(), "Bearer t".to_owned())
        );

        let bare = header_login()?;
        assert_eq!(
            bare.auth_header("t"),
            ("X-Auth-Token".to_owned(), "t".to_owned())
        );
        Ok(())
    }

    #[test]
    fn token_cache_key_changes_with_the_credentials_but_is_stable_per_config() -> TestResult {
        let build = |password: &str| -> Result<ApiConnectionSettings, ExternalApiError> {
            ApiConnectionSettings::from_options(&options(&[
                ("baseUrl", json!("https://api.example.com")),
                ("authType", json!("TOKEN_LOGIN")),
                ("loginPath", json!("/auth/login")),
                ("loginBody", json!({"username": "u", "password": password})),
                ("tokenResponseHeader", json!("X-Auth-Token")),
                ("tokenHeaderName", json!("X-Auth-Token")),
            ]))
        };
        let one = build("one")?;
        let one_again = build("one")?;
        let two = build("two")?;
        let (Some(login_one), Some(login_one_again), Some(login_two)) = (
            one.token_login.as_ref(),
            one_again.token_login.as_ref(),
            two.token_login.as_ref(),
        ) else {
            panic!("token-login sub-config missing");
        };

        // Same config → same key (so a per-document step reuses the cached token).
        assert_eq!(
            token_cache_key(&one, login_one),
            token_cache_key(&one_again, login_one_again)
        );
        // Editing the password → different key (evicts the token bought with the old one).
        assert_ne!(
            token_cache_key(&one, login_one),
            token_cache_key(&two, login_two)
        );
        Ok(())
    }

    // ---- ResultUrls: the result-fetch host allowlist (oracle ResultUrls) ----

    fn vendor_connection(
        result_hosts: Option<Value>,
    ) -> Result<ApiConnectionSettings, ExternalApiError> {
        let mut pairs = vec![("baseUrl", json!("https://api.vendor.example/v1"))];
        if let Some(hosts) = result_hosts {
            pairs.push(("resultUrlHosts", hosts));
        }
        ApiConnectionSettings::from_options(&options(&pairs))
    }

    #[test]
    fn result_host_allowlist_matches_own_declared_and_subdomains() -> TestResult {
        let own = vendor_connection(None)?;
        assert!(ResultUrls::is_allowed_host(&own, "api.vendor.example"));

        let declared = vendor_connection(Some(json!(["cdn.vendor.example"])))?;
        assert!(ResultUrls::is_allowed_host(&declared, "cdn.vendor.example"));

        let parent = vendor_connection(Some(json!(["vendor.example"])))?;
        assert!(ResultUrls::is_allowed_host(
            &parent,
            "files.eu.vendor.example"
        ));

        let mixed_case = vendor_connection(Some(json!(["CDN.Vendor.Example"])))?;
        assert!(ResultUrls::is_allowed_host(
            &mixed_case,
            "cdn.vendor.example"
        ));

        // A bare suffix must NOT match: evilvendor.example is not vendor.example.
        assert!(!ResultUrls::is_allowed_host(&parent, "evilvendor.example"));
        Ok(())
    }

    #[test]
    fn result_url_refuses_undeclared_hosts_and_dangerous_shapes() -> TestResult {
        let settings = vendor_connection(Some(json!(["cdn.vendor.example"])))?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("1.1.1.1", 443)])
        };

        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "https://evil.example/x.pdf",
                false,
                &resolve,
            ),
            "does not allow",
        );
        assert_err_contains(
            ResultUrls::validate_with_resolver(&settings, "file:///etc/passwd", false, &resolve),
            "is not http(s)",
        );
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "https://user:pw@cdn.vendor.example/x.pdf",
                false,
                &resolve,
            ),
            "credentials",
        );
        assert_err_contains(
            ResultUrls::validate_with_resolver(&settings, "not a url", false, &resolve),
            "is not a valid URL",
        );
        Ok(())
    }

    #[test]
    fn result_url_refuses_internal_addresses_even_when_declared() -> TestResult {
        let settings = vendor_connection(Some(json!(["169.254.169.254", "localhost"])))?;
        let metadata = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("169.254.169.254", 80)])
        };
        // The metadata deny now runs for result URLs too (and before the
        // reserved-range rejection), so the message names the metadata service.
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "http://169.254.169.254/latest/meta-data/iam/",
                false,
                &metadata,
            ),
            "metadata service",
        );

        let loopback = |_host: &str, port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)])
        };
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "http://localhost:8080/admin",
                false,
                &loopback,
            ),
            "private/link-local",
        );
        Ok(())
    }

    #[test]
    fn get_result_fetches_a_validated_url_without_forwarding_credentials() -> TestResult {
        let (server, seen) = header_capturing_server()?;
        let caller = ExternalApiCaller::new(true);
        // A BEARER connection whose token must NOT leak to the result host.
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.vendor.example/v1")),
            ("authType", json!("BEARER")),
            ("token", json!("do-not-leak")),
            ("resultUrlHosts", json!(["127.0.0.1"])),
        ]))?;
        // The result URL's port is the mock's; the resolver pins it to loopback.
        let url = format!("{}/files/signed.pdf", server.base_url);
        let resolve = loopback_resolver();
        let validated = ResultUrls::validate_with_resolver(&settings, &url, true, &resolve)?;

        let response = caller.get_result(&settings, &validated)?;
        assert!(response.is_success());
        // The connection's credentials were deliberately not sent to the CDN host.
        assert_eq!(header_value(&seen, "authorization"), None);
        Ok(())
    }

    // ======================================================================
    // Slice 4 — the controller `call` orchestration, driven end-to-end
    // against the loopback mock. A 1:1 port of `ExternalApiCallControllerLiveTest`
    // (the receiver is the point: assertions are about what actually left on the
    // wire), plus focused unit coverage for ResultUrls / ResultFiles / the verdict
    // gate. No `unwrap`/`expect`.
    // ======================================================================

    const TIMESTAMP: &str = "2026-07-25T12:00:00Z";

    /// A labelled, classified, titled two-page PDF — the oracle's `pdf()` fixture,
    /// so the context has something real to carry across every namespace.
    fn rich_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use lopdf::{Dictionary, Document, Object, dictionary};

        use crate::purview::{AssignmentMethod, PdfSensitivityLabels, SensitivityLabel};

        let mut document = Document::with_version("1.7");
        let pages_id = document.new_object_id();
        let page = |document: &mut Document| {
            document.add_object(dictionary! {
                "Type" => "Page",
                "Parent" => pages_id,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
            })
        };
        let page_one = page(&mut document);
        let page_two = page(&mut document);
        document.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(page_one), Object::Reference(page_two)],
                "Count" => 2,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        document.trailer.set("Root", catalog_id);

        let mut info = Dictionary::new();
        info.set("Title", Object::string_literal("Q3 Claim"));
        info.set(
            "StirlingPDFClassification",
            Object::string_literal("{\"label\":\"invoice\",\"confidence\":0.91}"),
        );
        let info_id = document.add_object(info);
        document.trailer.set("Info", info_id);

        let label = SensitivityLabel::new(
            "2096f6a2-d2f7-48be-b329-b73aaa526e5d".to_owned(),
            Some("Confidential".to_owned()),
            "cb46c030-1825-4e81-a295-151c039dbf02".to_owned(),
            Some(AssignmentMethod::Privileged),
            None,
            None,
        )?;
        PdfSensitivityLabels::apply(&mut document, &label)?;

        let mut bytes = Vec::new();
        document.save_to(&mut bytes)?;
        Ok(bytes)
    }

    /// The oracle's `zip()`: an archive holding an audit trail and the signed PDF.
    fn zip_bundle() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use zip::{ZipWriter, write::SimpleFileOptions};
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default();
        zip.start_file("audit-trail.txt", options)?;
        zip.write_all(b"who signed what")?;
        zip.start_file("signed.pdf", options)?;
        zip.write_all(b"%PDF-1.7 signed")?;
        Ok(zip.finish()?.into_inner())
    }

    /// What the receiver saw for the most recent (non-result-fetch) request.
    struct CapturedReq {
        method: String,
        content_type: Option<String>,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    }

    impl CapturedReq {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }

        fn body_text(&self) -> String {
            String::from_utf8_lossy(&self.body).into_owned()
        }
    }

    type Slot = Arc<Mutex<Option<CapturedReq>>>;

    fn capture_into(slot: &Slot, request: &MockRequest) {
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(CapturedReq {
                method: request.method.clone(),
                content_type: request.header("content-type").map(str::to_owned),
                body: request.body.clone(),
                headers: request.headers.clone(),
            });
        }
    }

    fn take_captured(slot: &Slot) -> CapturedReq {
        let Ok(mut guard) = slot.lock() else {
            panic!("capture lock was poisoned");
        };
        match guard.take() {
            Some(request) => request,
            None => panic!("no request was captured by the mock"),
        }
    }

    fn mock_bytes(status: u16, content_type: &str, body: Vec<u8>) -> MockResponse {
        MockResponse {
            status,
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body,
            omit_content_length: false,
        }
    }

    /// The DLP/converter/deferred/archive receiver the oracle stands up: one server,
    /// routed on path. `/files/result.pdf` is deliberately NOT captured, matching the
    /// oracle, so a deferred fetch does not overwrite the primary request.
    fn dlp_server() -> Result<(MockServer, String, Slot), Box<dyn std::error::Error>> {
        let slot: Slot = Arc::new(Mutex::new(None));
        let base: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let bundle = zip_bundle()?;
        let sink = Arc::clone(&slot);
        let base_for_handler = Arc::clone(&base);
        let handler: Handler = Arc::new(move |request: &MockRequest| {
            if request.path != "/files/result.pdf" {
                capture_into(&sink, request);
            }
            match request.path.as_str() {
                "/v1/scan" => MockResponse::json(200, "{\"verdict\":\"clean\",\"score\":0.02}"),
                "/v1/convert" => mock_bytes(
                    200,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    b"DOCX-BYTES".to_vec(),
                )
                .with_header(
                    "Content-Disposition",
                    "attachment; filename=\"converted.docx\"",
                ),
                "/v1/deferred" => {
                    let base_url = base_for_handler
                        .lock()
                        .map(|guard| guard.clone())
                        .unwrap_or_default();
                    MockResponse::json(
                        200,
                        &format!(
                            "{{\"status\":\"done\",\"data\":{{\"downloadUrl\":\"{base_url}/files/result.pdf\"}}}}"
                        ),
                    )
                }
                "/v1/evil" => MockResponse::json(
                    200,
                    "{\"data\":{\"downloadUrl\":\"http://169.254.169.254/latest/meta-data/\"}}",
                ),
                "/files/result.pdf" => {
                    mock_bytes(200, "application/pdf", b"%PDF-1.7 fetched".to_vec())
                }
                "/v1/bundle" => mock_bytes(200, "application/zip", bundle.clone()),
                "/v1/reject" => MockResponse::json(422, "{\"error\":\"policy violation\"}"),
                "/v1/clean" => MockResponse::json(200, "{\"CleanResult\":true}"),
                "/v1/infected" => MockResponse::json(
                    200,
                    "{\"CleanResult\":false,\"FoundViruses\":[{\"VirusName\":\"EICAR\"}]}",
                ),
                _ => MockResponse::json(404, "{\"error\":\"not found\"}"),
            }
        });
        let server = MockServer::start(handler)?;
        let base_url = server.base_url.clone();
        if let Ok(mut guard) = base.lock() {
            *guard = base_url.clone();
        }
        Ok((server, base_url, slot))
    }

    /// A named step, so each test states only what it varies. Mirrors the oracle's
    /// `Step` builder over the seventeen positional controller arguments.
    struct Step {
        path: String,
        method: String,
        body_mode: String,
        file_field_name: String,
        response_mode: String,
        result_url_path: Option<String>,
        response_select: Option<String>,
        require_true: Option<String>,
        fields: Option<String>,
        body_template: Option<String>,
        headers: Option<String>,
        include_context: bool,
        include_file: bool,
        policy_name: Option<String>,
        run_id: Option<String>,
    }

    impl Step {
        fn new(path: &str) -> Self {
            Self {
                path: path.to_owned(),
                method: "POST".to_owned(),
                body_mode: "multipart".to_owned(),
                file_field_name: "file".to_owned(),
                response_mode: "report".to_owned(),
                result_url_path: None,
                response_select: None,
                require_true: None,
                fields: None,
                body_template: None,
                headers: None,
                include_context: false,
                include_file: true,
                policy_name: None,
                run_id: None,
            }
        }

        fn go(
            &self,
            caller: &ExternalApiCaller,
            settings: &ApiConnectionSettings,
            file: &[u8],
        ) -> Result<ExternalApiCallResult, ExternalApiError> {
            let request = ExternalApiCallRequest {
                file_content: file,
                original_filename: Some("claim.pdf"),
                file_content_type: Some("application/pdf"),
                path: Some(&self.path),
                method: Some(&self.method),
                body_mode: Some(&self.body_mode),
                file_field_name: &self.file_field_name,
                response_mode: Some(&self.response_mode),
                result_url_path: self.result_url_path.as_deref(),
                result_url_header: None,
                response_select: self.response_select.as_deref(),
                require_true: self.require_true.as_deref(),
                fields: self.fields.as_deref(),
                body_template: self.body_template.as_deref(),
                headers: self.headers.as_deref(),
                include_context: self.include_context,
                include_file: self.include_file,
                run: RunFacts {
                    policy_name: self.policy_name.as_deref(),
                    run_id: self.run_id.as_deref(),
                    timestamp: TIMESTAMP,
                },
            };
            caller.call(settings, &request)
        }
    }

    #[test]
    fn sends_the_document_and_what_we_know_about_it_to_the_receiver() -> TestResult {
        let (server, _base, slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/scan");
        step.fields = Some(
            "{\"sha256\":\"{{document.sha256}}\",\"label\":\"{{sensitivityLabel.name}}\",\
             \"class\":\"{{classification.label}}\",\"pages\":\"{{document.pageCount}}\"}"
                .to_owned(),
        );
        step.include_context = true;
        step.policy_name = Some("Outbound review".to_owned());
        step.run_id = Some("run-42".to_owned());
        let result = step.go(&caller, &settings, &pdf)?;

        let request = take_captured(&slot);
        assert_eq!(request.method, "POST");
        assert!(
            request
                .content_type
                .as_deref()
                .is_some_and(|value| value.starts_with("multipart/form-data"))
        );
        // Fields the vendor asked for, filled from what Stirling already knew.
        let body = request.body_text();
        assert!(body.contains("name=\"label\"") && body.contains("Confidential"));
        assert!(body.contains("name=\"class\"") && body.contains("invoice"));
        assert!(body.contains("name=\"pages\"") && body.contains('2'));
        let sha_pattern = Regex::new(r#"name="sha256"[\s\S]{0,24}[0-9a-f]{64}"#)?;
        assert!(sha_pattern.is_match(&body));
        // The document itself, under the field name the vendor expects.
        assert!(body.contains("name=\"file\"; filename=\"claim.pdf\"") && body.contains("%PDF"));
        // The context, including which policy and run sent it.
        assert!(
            body.contains("stirlingContext")
                && body.contains("Outbound review")
                && body.contains("run-42")
        );

        let Some(report) = result.report else {
            panic!("report mode must return a report");
        };
        let report: Value = serde_json::from_str(&report)?;
        assert_eq!(report.pointer("/status").and_then(Value::as_i64), Some(200));
        assert_eq!(
            report.pointer("/body/verdict").and_then(Value::as_str),
            Some("clean")
        );
        Ok(())
    }

    #[test]
    fn report_mode_returns_the_document_untouched() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let result = Step::new("/v1/scan").go(&caller, &settings, &pdf)?;

        // Byte-for-byte: an inspecting call-out must not perturb what it inspected.
        assert_eq!(result.body, pdf);
        assert!(result.body.starts_with(b"%PDF"));
        assert_eq!(result.filename, "claim.pdf");
        Ok(())
    }

    #[test]
    fn replace_mode_adopts_the_returned_document_and_its_real_name() -> TestResult {
        let (server, _base, slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/convert");
        step.body_mode = "binary".to_owned();
        step.response_mode = "replace".to_owned();
        let result = step.go(&caller, &settings, &pdf)?;

        let request = take_captured(&slot);
        assert_eq!(request.content_type.as_deref(), Some("application/pdf"));
        assert!(request.body_text().starts_with("%PDF"));
        assert_eq!(result.body, b"DOCX-BYTES");
        // Named for what came back, not what went out: a DOCX must not be called .pdf.
        assert_eq!(result.filename, "converted.docx");
        Ok(())
    }

    #[test]
    fn follows_a_result_url_on_the_connections_own_host() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/deferred");
        step.response_mode = "replace".to_owned();
        step.result_url_path = Some("data.downloadUrl".to_owned());
        let result = step.go(&caller, &settings, &pdf)?;

        assert_eq!(result.body, b"%PDF-1.7 fetched");
        Ok(())
    }

    #[test]
    fn refuses_a_result_url_the_connection_never_authorised() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        // The URL is chosen by the remote service at run time; obeying it is an SSRF.
        let mut step = Step::new("/v1/evil");
        step.response_mode = "replace".to_owned();
        step.result_url_path = Some("data.downloadUrl".to_owned());
        assert_err_contains(step.go(&caller, &settings, &pdf), "does not allow");
        Ok(())
    }

    #[test]
    fn picks_the_wanted_file_out_of_a_returned_archive() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/bundle");
        step.response_mode = "replace".to_owned();
        step.response_select = Some("*.pdf".to_owned());
        let result = step.go(&caller, &settings, &pdf)?;

        assert_eq!(result.body, b"%PDF-1.7 signed");
        assert_eq!(result.filename, "signed.pdf");
        Ok(())
    }

    #[test]
    fn an_unselected_archive_fails_rather_than_becoming_the_document() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/bundle");
        step.response_mode = "replace".to_owned();
        assert_err_contains(step.go(&caller, &settings, &pdf), "responseSelect");
        Ok(())
    }

    #[test]
    fn a_rejected_call_out_fails_the_step() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        // A policy that continued past a rejection would deliver documents the
        // external system believes it never approved.
        let result = Step::new("/v1/reject").go(&caller, &settings, &pdf);
        assert_err_contains(result, "HTTP 422");
        assert_err_contains(
            Step::new("/v1/reject").go(&caller, &settings, &pdf),
            "policy violation",
        );
        Ok(())
    }

    #[test]
    fn a_clean_verdict_lets_the_document_through() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        // Cloudmersive answers HTTP 200 whether clean or not; a clean result must
        // pass the document through untouched.
        let mut step = Step::new("/v1/clean");
        step.require_true = Some("CleanResult".to_owned());
        let result = step.go(&caller, &settings, &pdf)?;

        assert!(result.body.starts_with(b"%PDF"));
        Ok(())
    }

    #[test]
    fn an_infected_verdict_stops_the_run_even_on_http_200() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        // The whole security proposition: HTTP 200 with CleanResult=false must NOT
        // sail through.
        let mut step = Step::new("/v1/infected");
        step.require_true = Some("CleanResult".to_owned());
        assert_err_contains(step.go(&caller, &settings, &pdf), "CleanResult");
        let mut step = Step::new("/v1/infected");
        step.require_true = Some("CleanResult".to_owned());
        assert_err_contains(step.go(&caller, &settings, &pdf), "not true");
        Ok(())
    }

    #[test]
    fn a_missing_verdict_field_fails_closed() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        // /v1/scan answers {"verdict":"clean"} — no CleanResult field at all. A gate
        // that cannot find its verdict must stop the run, not wave the document through.
        let mut step = Step::new("/v1/scan");
        step.require_true = Some("CleanResult".to_owned());
        assert_err_contains(step.go(&caller, &settings, &pdf), "not true");
        Ok(())
    }

    #[test]
    fn sends_a_vendor_shaped_json_body_with_the_document_nested_inside() -> TestResult {
        let (server, _base, slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        // ConsignO's submit shape: the PDF base64'd into documents[0].data.
        let mut step = Step::new("/v1/scan");
        step.body_mode = "json".to_owned();
        step.body_template = Some(
            "{\"name\":\"{{document.filename}}\",\"status\":1,\
             \"documents\":[{\"name\":\"{{document.filename}}\",\"data\":\"{{document.base64}}\"}],\
             \"actions\":[{\"mode\":\"remote\",\"signer\":{\"type\":\"certifio\"}}]}"
                .to_owned(),
        );
        step.go(&caller, &settings, &pdf)?;

        let request = take_captured(&slot);
        assert_eq!(request.content_type.as_deref(), Some("application/json"));
        let sent: Value = serde_json::from_str(&request.body_text())?;
        assert_eq!(
            sent.pointer("/name").and_then(Value::as_str),
            Some("claim.pdf")
        );
        // Numbers keep their type; only strings are substituted.
        assert!(sent.pointer("/status").is_some_and(Value::is_number));
        assert_eq!(
            sent.pointer("/actions/0/signer/type")
                .and_then(Value::as_str),
            Some("certifio")
        );
        let Some(data) = sent.pointer("/documents/0/data").and_then(Value::as_str) else {
            panic!("nested document data missing");
        };
        assert!(STANDARD.decode(data)?.starts_with(b"%PDF"));
        Ok(())
    }

    #[test]
    fn applies_the_connections_credential_and_the_steps_headers_and_verb() -> TestResult {
        let (server, _base, slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(
            &server.base_url,
            &[
                ("authType", json!("BEARER")),
                ("token", json!("s3cr3t-token")),
            ],
        )?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/scan");
        step.method = "PUT".to_owned();
        step.headers = Some("{\"X-Case-Id\":\"{{run.runId}}\"}".to_owned());
        step.run_id = Some("run-99".to_owned());
        step.go(&caller, &settings, &pdf)?;

        let request = take_captured(&slot);
        assert_eq!(request.method, "PUT");
        assert_eq!(request.header("X-Case-Id"), Some("run-99"));
        // The connection's credential, which the step never supplies or sees.
        assert_eq!(request.header("Authorization"), Some("Bearer s3cr3t-token"));
        Ok(())
    }

    #[test]
    fn a_step_cannot_aim_the_call_at_another_host() -> TestResult {
        let (server, _base, _slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        assert_err_contains(
            Step::new("//evil.example/x").go(&caller, &settings, &pdf),
            "must be relative",
        );
        Ok(())
    }

    #[test]
    fn notify_style_call_out_sends_the_facts_without_the_document() -> TestResult {
        let (server, _base, slot) = dlp_server()?;
        let caller = ExternalApiCaller::new(true);
        let settings = settings_with(&server.base_url, &[])?;
        let pdf = rich_pdf()?;

        let mut step = Step::new("/v1/scan");
        step.body_mode = "json".to_owned();
        step.include_context = true;
        step.include_file = false;
        step.policy_name = Some("Outbound review".to_owned());
        step.run_id = Some("run-7".to_owned());
        step.go(&caller, &settings, &pdf)?;

        let request = take_captured(&slot);
        let sent: Value = serde_json::from_str(&request.body_text())?;
        assert_eq!(
            sent.pointer("/document/filename").and_then(Value::as_str),
            Some("claim.pdf")
        );
        assert_eq!(
            sent.pointer("/run/policyName").and_then(Value::as_str),
            Some("Outbound review")
        );
        // No document: the point of a notification is the facts, not the bytes.
        assert!(sent.pointer("/content").is_none());
        assert!(!request.body_text().contains("%PDF"));
        Ok(())
    }

    // ---- focused unit coverage for the highest-risk result parsing ----------

    fn response_with(
        content_type: Option<&str>,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> ApiResponse {
        ApiResponse {
            status: 200,
            content_type: content_type.map(str::to_owned),
            body: body.to_vec(),
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn result_urls_allow_a_subdomain_but_not_a_bare_suffix() -> TestResult {
        // 'vendor.example' authorises itself and any subdomain, but never
        // 'evilvendor.example' (the classic naive-suffix bypass).
        let settings = settings_with(
            "https://api.vendor.example/v1",
            &[("resultUrlHosts", json!(["cdn.vendor.example"]))],
        )?;
        // The connection's own host.
        assert!(ResultUrls::is_allowed_host(&settings, "api.vendor.example"));
        // An exact declared host and a subdomain of it.
        assert!(ResultUrls::is_allowed_host(&settings, "cdn.vendor.example"));
        assert!(ResultUrls::is_allowed_host(
            &settings,
            "deep.cdn.vendor.example"
        ));
        // A bare-suffix impostor and an unrelated host are refused.
        assert!(!ResultUrls::is_allowed_host(
            &settings,
            "evilcdn.vendor.example"
        ));
        assert!(!ResultUrls::is_allowed_host(
            &settings,
            "cdn.vendor.example.evil.com"
        ));
        assert!(!ResultUrls::is_allowed_host(&settings, "attacker.example"));
        Ok(())
    }

    #[test]
    fn result_urls_reject_non_http_userinfo_and_unlisted_hosts() -> TestResult {
        let settings = settings_with("https://api.vendor.example/v1", &[])?;
        // A non-http(s) scheme is a local-file-read vector.
        assert_err_contains(
            ResultUrls::validate(&settings, "file:///etc/passwd", false),
            "not http(s)",
        );
        // Credentials in a URL are a host-spoofing vector.
        assert_err_contains(
            ResultUrls::validate(&settings, "https://user:pass@api.vendor.example/x", false),
            "carrying credentials",
        );
        // A host the operator never declared.
        assert_err_contains(
            ResultUrls::validate(&settings, "https://cdn.other.example/x", false),
            "does not allow",
        );
        Ok(())
    }

    #[test]
    fn result_urls_block_an_allowlisted_host_that_resolves_internal() -> TestResult {
        // An allowlisted name whose DNS points at the metadata service is still
        // blocked: the metadata deny runs on the RESOLVED address.
        let settings = settings_with(
            "https://api.vendor.example/v1",
            &[("resultUrlHosts", json!(["cdn.vendor.example"]))],
        )?;
        let resolve = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("169.254.169.254", 443)])
        };
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "https://cdn.vendor.example/result.pdf",
                false,
                &resolve,
            ),
            "metadata service",
        );
        Ok(())
    }

    #[test]
    fn result_url_metadata_deny_holds_even_under_the_private_opt_in() -> TestResult {
        // The finding, half (b): result URLs previously passed `deny_metadata =
        // false`, so under the private opt-in (which ALSO skips the reserved-range
        // vet) an allowlisted name resolving to the metadata service was accepted.
        // The deny must now fire on the resolved address regardless of the opt-in.
        let settings = settings_with(
            "https://api.vendor.example/v1",
            &[("resultUrlHosts", json!(["cdn.vendor.example"]))],
        )?;

        // Plain IPv4 metadata address, opt-in ON (`allow_private = true`).
        let plain = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![addr("169.254.169.254", 443)])
        };
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "https://cdn.vendor.example/result.pdf",
                true,
                &plain,
            ),
            "metadata service",
        );

        // NAT64 AAAA encoding 169.254.169.254 — the embedded form half (a) unwraps,
        // exercised through the result-URL path under the opt-in.
        let nat64 = |_host: &str, _port: u16| -> std::io::Result<Vec<SocketAddr>> {
            Ok(vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0xa9fe, 0xa9fe)),
                443,
            )])
        };
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "https://cdn.vendor.example/result.pdf",
                true,
                &nat64,
            ),
            "metadata service",
        );
        Ok(())
    }

    #[test]
    fn result_files_name_prefers_disposition_then_content_type_then_request() {
        // Content-Disposition wins, path components stripped.
        let response = response_with(
            Some("application/pdf"),
            &[(
                "Content-Disposition",
                "attachment; filename=\"/etc/signed.pdf\"",
            )],
            b"%PDF",
        );
        assert_eq!(ResultFiles::name_for(&response, "in.pdf"), "signed.pdf");
        // No disposition: the request base name with a content-type extension.
        let response = response_with(
            Some(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=x",
            ),
            &[],
            b"x",
        );
        assert_eq!(ResultFiles::name_for(&response, "claim.pdf"), "claim.docx");
        // An unmapped content type keeps the request name unchanged.
        let response = response_with(Some("application/x-weird"), &[], b"x");
        assert_eq!(ResultFiles::name_for(&response, "claim.pdf"), "claim.pdf");
    }

    #[test]
    fn result_files_disposition_reads_the_rfc5987_form() {
        let response = response_with(
            None,
            &[(
                "Content-Disposition",
                "attachment; filename*=UTF-8''report.pdf",
            )],
            b"x",
        );
        assert_eq!(ResultFiles::name_for(&response, "in.bin"), "report.pdf");
    }

    #[test]
    fn result_files_select_by_glob_index_and_the_error_shapes() -> TestResult {
        let bundle = zip_bundle()?;
        // A glob picks the single matching entry.
        let (name, bytes) = ResultFiles::select_from_archive(&bundle, "*.pdf")?;
        assert_eq!(name, "signed.pdf");
        assert_eq!(bytes, b"%PDF-1.7 signed");
        // A 0-based index selects positionally.
        let (name, _) = ResultFiles::select_from_archive(&bundle, "0")?;
        assert_eq!(name, "audit-trail.txt");
        // An empty match names what was there.
        assert_err_contains(
            ResultFiles::select_from_archive(&bundle, "*.docx"),
            "matched nothing",
        );
        // A multi-match refuses rather than guessing.
        assert_err_contains(
            ResultFiles::select_from_archive(&bundle, "*"),
            "matched 2 entries",
        );
        // An out-of-range index reports the size.
        assert_err_contains(
            ResultFiles::select_from_archive(&bundle, "9"),
            "but the archive has 2",
        );
        Ok(())
    }

    #[test]
    fn a_non_zip_body_is_not_an_archive() -> TestResult {
        assert!(!ResultFiles::is_archive(b"%PDF-1.7 not a zip"));
        assert!(ResultFiles::is_archive(&zip_bundle()?));
        assert!(ResultFiles::is_archive_name("bundle.ZIP"));
        assert!(!ResultFiles::is_archive_name("signed.pdf"));
        Ok(())
    }

    #[test]
    fn verdict_gate_admits_only_a_json_boolean_true() {
        // The strictly-safer divergence: only a JSON boolean `true` passes. A numeric
        // 1, a string "true", a nested false, a missing field, and a non-JSON body all
        // fail closed. (Jackson's asBoolean(false) would have admitted the numeric 1.)
        let caller = ExternalApiCaller::new(true);

        // A local server that echoes a chosen JSON verdict body, so `call` runs the
        // real gate over a real response.
        let verdict = |body: &'static str| -> Result<ExternalApiCallResult, ExternalApiError> {
            let handler: Handler =
                Arc::new(move |_request: &MockRequest| MockResponse::json(200, body));
            let Ok(server) = MockServer::start(handler) else {
                return Err(super::invalid("mock server failed to start"));
            };
            let Ok(settings) = settings_with(&server.base_url, &[]) else {
                return Err(super::invalid("settings failed"));
            };
            let mut step = Step::new("/gate");
            step.require_true = Some("clean.value".to_owned());
            step.go(&caller, &settings, b"%PDF-1.7 mini")
        };

        // JSON boolean true passes (report mode returns the document).
        assert!(verdict("{\"clean\":{\"value\":true}}").is_ok());
        // Everything else fails closed.
        assert_err_contains(verdict("{\"clean\":{\"value\":false}}"), "not true");
        assert_err_contains(verdict("{\"clean\":{\"value\":1}}"), "not true");
        assert_err_contains(verdict("{\"clean\":{\"value\":\"true\"}}"), "not true");
        assert_err_contains(verdict("{\"clean\":{}}"), "not true");
        assert_err_contains(verdict("{\"other\":true}"), "not true");
    }
}
