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
//! Deliberate slice-1 scope limits (each carries a `TODO(slice 3)`):
//! - `TOKEN_LOGIN` sub-config parsing (`ApiTokenLogin.from`) and
//!   `tokenCacheKey()` are **not** ported here. `token_login` is left as a
//!   placeholder [`ApiTokenLogin`] when `authType == TOKEN_LOGIN` and `None`
//!   otherwise; the sub-config is *not* validated in this slice.
//! - No HTTP dispatch, DNS/SSRF network guard (`ApiIntegrationValidator`), or
//!   result-URL fetching — those are later slices.
//!
//! Because slice 1 is pure plumbing not yet wired to any router, the items are
//! exercised only by the inline oracle tests; `dead_code` is allowed at the
//! module level until a later slice mounts the caller.
#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    io::Read as _,
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
/// carries here).
fn normalise_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

fn is_cloud_metadata(ip: IpAddr) -> bool {
    CLOUD_METADATA_IPS.contains(&normalise_ip(ip))
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
/// `deny_metadata` gates the unconditional cloud-metadata block (on for the base
/// host, off for result URLs — matching the oracles: `ApiIntegrationValidator`
/// has the explicit metadata deny, `ResultUrls` relies on the reserved-range
/// rejection alone). The reserved-range rejection is always gated by
/// `allow_private`. Every vetted address is pinned so the socket cannot re-resolve
/// to a different address after the check.
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
        // Even an allowlisted name must not resolve somewhere internal. No metadata
        // deny here (matching ResultUrls): the reserved-range rejection covers the
        // metadata IPs unless the operator opted into private endpoints.
        let pinned = resolve_and_pin(&url, allow_private, RESULT_URL_SETTING, false, resolve)?;
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
        io::{Read as _, Write as _},
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use url::Url;

    use super::{
        ApiConnectionSettings, ApiResponse, ApiTokenLogin, ExternalApiCaller, ExternalApiError,
        OutboundBody, ResultUrls, SendParts, require_public_host, resolve_host, send,
        token_cache_key,
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
        // No metadata opt-out here: the reserved-range rejection covers it (message
        // "private/link-local", matching the oracle's ResultUrls path).
        assert_err_contains(
            ResultUrls::validate_with_resolver(
                &settings,
                "http://169.254.169.254/latest/meta-data/iam/",
                false,
                &metadata,
            ),
            "private/link-local",
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
}
