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
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::OnceLock,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use lopdf::Document;
use rand::RngExt as _;
use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::purview::{AssignmentMethod, PdfSensitivityLabels};

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

/// Placeholder for the token-login sub-config.
///
/// TODO(slice 3): port `ApiTokenLogin.from(Map<String,Object>)` with full
/// validation (`loginPath`; exactly one of `tokenResponseHeader` /
/// `tokenResponseJsonPath`; `tokenHeaderName`; TTL) and `tokenCacheKey()`.
/// Slice 1 records only that `TOKEN_LOGIN` was selected; the sub-config is
/// **not** validated here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ApiTokenLogin;

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
            // Validation of the TOKEN_LOGIN sub-config is deferred (slice 3).
            ApiAuthType::TokenLogin | ApiAuthType::None => {}
        }

        // Evaluated in Java's constructor-argument order so error precedence
        // matches: headers, then token-login, then result hosts, then timeout.
        let headers = parse_headers(options.get(HEADERS_OPTION))?;
        let token_login = if auth_type == ApiAuthType::TokenLogin {
            // TODO(slice 3): ApiTokenLogin::from_options(options) — validates the
            // login sub-config. Slice 1 records selection only.
            Some(ApiTokenLogin)
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
    fn settings_token_login_selection_defers_sub_parse() -> Result<(), Box<dyn std::error::Error>> {
        // Slice 1: TOKEN_LOGIN is accepted (validation deferred to slice 3) and
        // records a placeholder token-login; other auth types leave it None.
        let settings = ApiConnectionSettings::from_options(&options(&[
            ("baseUrl", json!("https://api.example.com")),
            ("authType", json!("TOKEN_LOGIN")),
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
