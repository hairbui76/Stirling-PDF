//! Safe remote web-page to PDF conversion.
//!
//! The legacy endpoint is opt-in because it downloads untrusted remote content.
//! Rust keeps that default and additionally pins the HTTP client to resolved public
//! addresses before fetching, preventing a DNS rebind from reaching local services.

use std::{
    env, fs,
    io::Read as _,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::Path,
    time::Duration,
};

use reqwest::{Url, blocking::Client, redirect::Policy};
use tempfile::TempDir;
use thiserror::Error;

use crate::html_to_pdf::{HtmlToPdfError, convert_html_to_pdf};

const REMOTE_HTML_LIMIT_BYTES: u64 = 20 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const ENABLE_URL_TO_PDF_ENV: &[&str] = &[
    "STIRLING_PROCESSING_ENABLE_URL_TO_PDF",
    "SYSTEM_ENABLEURLTOPDF",
    "SYSTEM_ENABLE_URL_TO_PDF",
];

#[derive(Debug, Error)]
pub enum UrlToPdfError {
    #[error("urlInput must be an absolute HTTP or HTTPS URL")]
    InvalidUrl,
    #[error("urlInput must not include username or password credentials")]
    CredentialsNotAllowed,
    #[error("urlInput resolves to a non-public network address")]
    DisallowedTarget,
    #[error("could not resolve or contact the URL: {0}")]
    Unreachable(String),
    #[error("the remote server redirected the request")]
    Redirected,
    #[error("the remote server returned HTTP {0}")]
    RemoteStatus(u16),
    #[error("the remote HTML response exceeds the {REMOTE_HTML_LIMIT_BYTES}-byte limit")]
    ResponseTooLarge,
    #[error(transparent)]
    HtmlToPdf(#[from] HtmlToPdfError),
    #[error("URL-to-PDF I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Returns whether remote website conversion is explicitly enabled.
#[must_use]
pub fn url_to_pdf_enabled() -> bool {
    ENABLE_URL_TO_PDF_ENV
        .iter()
        .any(|name| env::var(name).is_ok_and(|value| value.trim().eq_ignore_ascii_case("true")))
}

/// Downloads a public HTTP(S) page and renders its sanitized HTML to PDF.
///
/// # Errors
///
/// Returns [`UrlToPdfError`] when the URL is unsafe, unreachable, too large,
/// redirects, responds unsuccessfully, or cannot be rendered to PDF.
pub fn convert_url_to_pdf(url_input: &str, output_path: &Path) -> Result<(), UrlToPdfError> {
    let url = parse_url(url_input)?;
    let html = fetch_remote_html(&url)?;
    let workspace = TempDir::new()?;
    let html_path = workspace.path().join("website.html");
    fs::write(&html_path, html)?;
    convert_html_to_pdf(&html_path, "website.html", output_path).map_err(Into::into)
}

/// Produces the Java-compatible, bounded output filename for a URL.
#[must_use]
pub fn output_filename(url_input: &str) -> String {
    let raw_name = url_input
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .take(50)
        .collect::<String>();
    let mut collapsed = String::with_capacity(raw_name.len());
    let mut previous_was_underscore = false;
    for character in raw_name.chars() {
        if character == '_' && previous_was_underscore {
            continue;
        }
        previous_was_underscore = character == '_';
        collapsed.push(character);
    }
    let collapsed = collapsed.trim_matches('_');
    let name = if collapsed.is_empty() {
        "document"
    } else {
        collapsed
    };
    format!("{name}.pdf")
}

fn parse_url(url_input: &str) -> Result<Url, UrlToPdfError> {
    let url = Url::parse(url_input.trim()).map_err(|_| UrlToPdfError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(UrlToPdfError::InvalidUrl);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlToPdfError::CredentialsNotAllowed);
    }
    Ok(url)
}

fn fetch_remote_html(url: &Url) -> Result<String, UrlToPdfError> {
    let host = url.host_str().ok_or(UrlToPdfError::InvalidUrl)?;
    let addresses = resolve_public_addresses(host, url.port_or_known_default())?;
    let client = Client::builder()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent("Stirling-PDF/URL-to-PDF")
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|error| UrlToPdfError::Unreachable(error.to_string()))?;
    let response = client
        .get(url.clone())
        .send()
        .map_err(|error| UrlToPdfError::Unreachable(error.to_string()))?;
    if response.status().is_redirection() {
        return Err(UrlToPdfError::Redirected);
    }
    if !response.status().is_success() {
        return Err(UrlToPdfError::RemoteStatus(response.status().as_u16()));
    }
    read_bounded_body(response)
}

fn resolve_public_addresses(
    host: &str,
    port: Option<u16>,
) -> Result<Vec<SocketAddr>, UrlToPdfError> {
    let port = port.ok_or(UrlToPdfError::InvalidUrl)?;
    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|error| UrlToPdfError::Unreachable(error.to_string()))?
            .collect::<Vec<_>>()
    };
    if addresses.is_empty() {
        return Err(UrlToPdfError::Unreachable(
            "the hostname did not resolve to an address".to_owned(),
        ));
    }
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(UrlToPdfError::DisallowedTarget);
    }
    Ok(addresses)
}

fn read_bounded_body(mut response: reqwest::blocking::Response) -> Result<String, UrlToPdfError> {
    if response
        .content_length()
        .is_some_and(|length| length > REMOTE_HTML_LIMIT_BYTES)
    {
        return Err(UrlToPdfError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(REMOTE_HTML_LIMIT_BYTES + 1)
        .read_to_end(&mut body)?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > REMOTE_HTML_LIMIT_BYTES {
        return Err(UrlToPdfError::ResponseTooLarge);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address.octets()),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(octets: [u8; 4]) -> bool {
    !matches!(
        octets,
        [0 | 10 | 127 | 224..=255, ..]
            | [100, 64..=127, ..]
            | [169, 254, ..]
            | [172, 16..=31, ..]
            | [192, 0 | 168, ..]
            | [198, 18..=19, ..]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
    )
}

fn is_public_ipv6(address: std::net::Ipv6Addr) -> bool {
    if address.is_unspecified() || address.is_loopback() {
        return false;
    }
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped.octets());
    }
    let segments = address.segments();
    !matches!(
        segments,
        [first, ..] if first & 0xff00 == 0xff00
            || first & 0xfe00 == 0xfc00
            || first & 0xffc0 == 0xfe80
            || (first == 0x2001 && segments[1] == 0x0db8)
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{UrlToPdfError, is_public_ip, output_filename, parse_url};

    #[test]
    fn rejects_non_http_credentials_and_private_targets() {
        assert!(matches!(
            parse_url("file:///etc/passwd"),
            Err(UrlToPdfError::InvalidUrl)
        ));
        assert!(matches!(
            parse_url("https://admin:secret@example.com"),
            Err(UrlToPdfError::CredentialsNotAllowed)
        ));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn preserves_java_style_output_filename_bounds() {
        assert_eq!(
            output_filename("https://example.com/reports/quarterly?year=2026"),
            "https_example_com_reports_quarterly_year_2026.pdf"
        );
        assert_eq!(output_filename("---"), "document.pdf");
    }
}
