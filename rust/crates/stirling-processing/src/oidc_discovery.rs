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

use std::{
    collections::HashMap,
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;
use thiserror::Error;

use crate::security_jwt::issuer_url_scheme_is_allowed;

const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_DISCOVERY_DOCUMENT_BYTES: u64 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Lifetime of a cached provider-metadata entry in [`OidcDiscoveryCache`].
///
/// A provider's discovery document is fairly static — its
/// `authorization_endpoint`/`token_endpoint`/`jwks_uri` change only across
/// deliberate reconfigurations — so caching for a few minutes collapses the
/// per-`/authorize` refetch (an outbound amplification toward the `IdP` plus a
/// `spawn_blocking` thread held for the fetch) down to at most one fetch per
/// issuer per TTL, while keeping staleness bounded: if a provider rotates an
/// endpoint, logins started within the window keep using the previous metadata
/// only until the entry expires (≤ this TTL). Signing-key rotation is a
/// *separate* concern and is unaffected — JWKS material is fetched fresh at
/// id-token verification time, not stored here.
const DEFAULT_DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Absolute cap on the number of distinct issuers held in an
/// [`OidcDiscoveryCache`]. A deployment configures a single OIDC issuer today,
/// so this is generous headroom; the bound is a belt-and-braces memory guard.
/// Unlike the login-state store's cap, this key can never be pushed by an
/// attacker — it is the admin-configured issuer, not request input — so a full
/// cache simply falls back to an uncached fetch rather than needing eviction.
const DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES: usize = 64;

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

/// One cached discovery result and when it stops being served.
struct CachedProviderMetadata {
    metadata: OidcProviderMetadata,
    expires_at: Instant,
}

/// Bounded, TTL'd cache of discovered [`OidcProviderMetadata`], keyed by the
/// issuer string passed to [`Self::discover`]. Repeated logins against the same
/// configured provider reuse one discovery fetch instead of hitting the `IdP`'s
/// `.well-known/openid-configuration` on every `/authorize`.
///
/// **Caching never weakens discovery.** A cache miss or an expired entry falls
/// through to a real [`discover_oidc_provider`] call — the unchanged, SSRF-safe
/// fetch-and-validate path — so a cached entry is always one that already
/// passed every issuer/endpoint check. The network fetch runs *outside* the
/// lock, so a slow or unreachable `IdP` cannot wedge the mutex for other
/// issuers, at the cost of a possible thundering herd of concurrent cold-start
/// misses for the same issuer (each does a real fetch; whichever finishes last
/// wins the cache slot). That is a bounded, cold-start-only cost and still far
/// cheaper than the previous fetch-on-every-call behaviour.
///
/// Modeled on the same `Mutex<HashMap>`-over-monotonic-`Instant` shape as
/// [`crate::oidc_login::OidcLoginStateStore`], and — like that store — built
/// once and shared behind an `Arc` for the lifetime of the secured router.
pub struct OidcDiscoveryCache {
    ttl: Duration,
    max_entries: usize,
    entries: Mutex<HashMap<String, CachedProviderMetadata>>,
}

impl Default for OidcDiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcDiscoveryCache {
    /// A cache with the default [`DEFAULT_DISCOVERY_CACHE_TTL`] and
    /// [`DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl_and_capacity(
            DEFAULT_DISCOVERY_CACHE_TTL,
            DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES,
        )
    }

    /// A cache with an explicit TTL and capacity (a deployment tuning knob; also
    /// lets a test force a zero TTL to disable caching, or a tiny capacity to
    /// exercise the bound).
    #[must_use]
    pub fn with_ttl_and_capacity(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the metadata for `issuer`, serving a live cached copy when one
    /// exists and otherwise performing — and caching — a fresh, SSRF-safe
    /// [`discover_oidc_provider`] fetch.
    ///
    /// # Errors
    ///
    /// Propagates any [`OidcDiscoveryError`] from the underlying discovery fetch
    /// on a cache miss or expiry. A poisoned cache lock is deliberately *not*
    /// fatal: the fetch is still performed, so discovery degrades to uncached
    /// rather than failing the login.
    pub fn discover(&self, issuer: &str) -> Result<OidcProviderMetadata, OidcDiscoveryError> {
        if let Some(cached) = self.cached_fresh(issuer) {
            return Ok(cached);
        }
        // Miss or expiry: fetch OUTSIDE the lock (blocking network I/O up to
        // REQUEST_TIMEOUT). This is the unchanged SSRF-safe validation path.
        let metadata = discover_oidc_provider(issuer)?;
        self.store(issuer, &metadata);
        Ok(metadata)
    }

    /// A live (unexpired) cached copy for `issuer`, if any. A poisoned lock is
    /// treated as a miss.
    fn cached_fresh(&self, issuer: &str) -> Option<OidcProviderMetadata> {
        let entries = self.entries.lock().ok()?;
        let cached = entries.get(issuer)?;
        (cached.expires_at > Instant::now()).then(|| cached.metadata.clone())
    }

    /// Records freshly discovered metadata under `issuer`, stamping its expiry
    /// from the cache TTL and opportunistically dropping expired entries first.
    /// At capacity a *new* issuer is simply not admitted (the next lookup for it
    /// re-fetches); refreshing an already-cached issuer is always allowed since
    /// it does not grow the map. A poisoned lock is a no-op (uncached).
    fn store(&self, issuer: &str, metadata: &OidcProviderMetadata) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        entries.retain(|_, cached| cached.expires_at > now);
        if entries.contains_key(issuer) || entries.len() < self.max_entries {
            entries.insert(
                issuer.to_owned(),
                CachedProviderMetadata {
                    metadata: metadata.clone(),
                    expires_at: now.checked_add(self.ttl).unwrap_or(now),
                },
            );
        }
    }
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
/// issuer, plus an SSRF guard that the issuer check does not need.
///
/// Endpoint URLs aren't required to be credential/query/fragment-free the way
/// an OIDC issuer identifier is — only their scheme and host matter. But
/// unlike the issuer (an admin-configured value the admin already chose to
/// trust), `authorization_endpoint`/`token_endpoint`/`jwks_uri` come *from*
/// that issuer's own discovery response — a compromised or spoofed provider
/// could point one at internal infrastructure (a cloud metadata endpoint, an
/// internal service) instead of itself. So on top of the shared
/// [`issuer_url_scheme_is_allowed`] policy, an HTTPS endpoint whose host is a
/// literal IP address in a private/reserved range is rejected too. This is a
/// literal-address check only (no DNS lookup): it protects a *future* caller
/// that fetches these endpoints over the network from the direct-IP form of
/// this attack (`https://169.254.169.254/...`, `https://10.0.0.5/...`).
/// DNS-based SSRF/rebinding — a domain name that resolves to a private
/// address, possibly only at connect time — is not covered here and remains a
/// documented gap for whoever wires that network fetch to revisit (see
/// `rust/contracts/account-lifecycle.md`).
///
/// The narrow HTTP+loopback allowance in `issuer_url_scheme_is_allowed` is
/// deliberately left alone: it already only matches the three loopback
/// literals (not arbitrary private ranges), which is exactly what this
/// module's own test fixtures rely on for the mock discovery server, and it
/// is not the scheme a real, spoofable production provider would use anyway.
fn validated_endpoint_url(value: &str) -> Result<Url, OidcDiscoveryError> {
    let url = Url::parse(value).map_err(|_| OidcDiscoveryError::InvalidDiscoveryDocument)?;
    if !issuer_url_scheme_is_allowed(&url) {
        return Err(OidcDiscoveryError::InvalidDiscoveryDocument);
    }
    if url.scheme() == "https" && url.host_str().is_some_and(host_is_reserved_ip_literal) {
        return Err(OidcDiscoveryError::InvalidDiscoveryDocument);
    }
    Ok(url)
}

/// True when `host` — as returned by [`Url::host_str`], which brackets an
/// IPv6 literal (e.g. `"[::1]"`) — is a literal IPv4/IPv6 address in a
/// private, loopback, link-local (this also covers the `169.254.169.254`
/// cloud-metadata address), multicast, broadcast, documentation, unspecified,
/// CGNAT/shared-address-space (RFC 6598, `100.64.0.0/10`), benchmarking
/// (RFC 2544, `198.18.0.0/15`), or IETF-protocol-assignment (RFC 6890,
/// `192.0.0.0/24`) range.
///
/// A domain name (anything that doesn't parse as a literal IP once
/// unbracketed) is not resolved and always returns `false` — see
/// [`validated_endpoint_url`]'s doc comment for why (**not covered**: a
/// domain name that resolves to any of the ranges above, including at
/// connect time rather than validation time — DNS-based SSRF/rebinding).
/// Numeric-obfuscated forms (decimal-integer/hex/octal IPv4, e.g.
/// `2852039166`) are not a bypass here: the `url` crate's WHATWG-compliant
/// host parser normalizes those to canonical dotted-decimal before
/// `Url::host_str`/`Url::host` ever exposes them.
///
/// `Ipv4Addr`/`Ipv6Addr::is_global` would be a more direct fit but is not yet
/// stable on this toolchain (confirmed against the pinned Rust 1.94), so this
/// enumerates the specific stable-API reserved categories (plus the three
/// ranges above, which are plain octet-range checks rather than a stdlib
/// predicate) that matter for SSRF instead. Two IPv6 forms that embed an IPv4
/// address are unwrapped and checked as that IPv4 address: the "IPv4-mapped"
/// form (`::ffff:a.b.c.d`, via the stdlib's own
/// [`Ipv6Addr::to_ipv4_mapped`]) and the older, deprecated "IPv4-compatible"
/// form (`::a.b.c.d`, no `ffff` marker, via [`ipv4_compatible`] — there is no
/// stdlib helper for this form).
fn host_is_reserved_ip_literal(host: &str) -> bool {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.parse::<IpAddr>().is_ok_and(ip_addr_is_reserved)
}

/// True when `address` — a concrete IP, whether a literal or one a hostname was
/// resolved to — falls in any of the private/reserved ranges enumerated by
/// [`ipv4_is_reserved`]/[`ipv6_is_reserved`].
///
/// Exposed `pub(crate)` so a caller that has *already resolved* a hostname to
/// concrete addresses can vet each one against the exact same predicate rather
/// than reimplementing it. In particular [`crate::oidc_live_token`]'s live token
/// fetch uses this to reject a domain name that resolves into these ranges — the
/// DNS-based SSRF hole that [`host_is_reserved_ip_literal`]'s literal-only check
/// (documented on [`validated_endpoint_url`]) deliberately leaves open.
pub(crate) fn ip_addr_is_reserved(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => ipv4_is_reserved(address),
        IpAddr::V6(address) => ipv6_is_reserved(address),
    }
}

fn ipv4_is_reserved(address: Ipv4Addr) -> bool {
    address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || address.is_multicast()
        || is_shared_address_space(address)
        || is_benchmarking_range(address)
        || is_ietf_protocol_assignment(address)
}

/// RFC 6598 Shared Address Space (`100.64.0.0/10`, i.e. the second octet in
/// `64..=127`): CGNAT and some cloud/container-network internal ranges. Not
/// exposed as a stable `Ipv4Addr` predicate, so checked directly.
fn is_shared_address_space(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

/// RFC 2544 benchmarking (`198.18.0.0/15`, i.e. the second octet in `18..=19`).
/// Not exposed as a stable `Ipv4Addr` predicate, so checked directly.
fn is_benchmarking_range(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 198 && (18..=19).contains(&octets[1])
}

/// RFC 6890 IETF Protocol Assignments (`192.0.0.0/24`). Not exposed as a
/// stable `Ipv4Addr` predicate, so checked directly.
fn is_ietf_protocol_assignment(address: Ipv4Addr) -> bool {
    address.octets()[..3] == [192, 0, 0]
}

/// Checked against every known, RFC-standardized/IANA-registered fixed-prefix
/// IPv4-in-IPv6 embedding form (see the individual extractor functions below
/// for citations): IPv4-mapped, IPv4-compatible, NAT64 well-known and
/// local-use prefixes, 6to4, Teredo (both its server and its obfuscated
/// client address), and ISATAP. This list was produced by a deliberate
/// enumeration pass over IANA's IPv6 Special-Purpose Address Registry and the
/// RFCs it cites — not just the two forms independently discovered as
/// bypasses before it (IPv4-compatible, then NAT64) — precisely so a *third*
/// standardized notation doesn't defeat this check the same way. See
/// `rust/contracts/account-lifecycle.md` for the residual gaps this pass
/// still can't close (operator-chosen NAT64/6rd prefixes, and DNS
/// resolution).
fn ipv6_is_reserved(address: Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.to_ipv4_mapped().is_some_and(ipv4_is_reserved)
        || ipv4_compatible(address).is_some_and(ipv4_is_reserved)
        || nat64_well_known_prefix_embedded_ipv4(address).is_some_and(ipv4_is_reserved)
        || nat64_local_use_prefix_embedded_ipv4(address).is_some_and(ipv4_is_reserved)
        || six_to_four_embedded_ipv4(address).is_some_and(ipv4_is_reserved)
        || teredo_embedded_ipv4_addresses(address)
            .into_iter()
            .flatten()
            .any(ipv4_is_reserved)
        || isatap_embedded_ipv4(address).is_some_and(ipv4_is_reserved)
}

/// Extracts the embedded IPv4 address from the deprecated "IPv4-compatible"
/// IPv6 form (`::a.b.c.d`, RFC 4291 section 2.5.5.1): the high 96 bits (12
/// octets) all zero, with the low 32 bits carrying the IPv4 address. This is
/// distinct from — and not caught by — [`Ipv6Addr::to_ipv4_mapped`], which
/// only recognizes the newer "IPv4-mapped" form (`::ffff:a.b.c.d`, marked by
/// `0xffff` in octets 10-11 rather than zero); there is no stdlib equivalent
/// for this older form, so the octets are checked directly.
fn ipv4_compatible(address: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = address.octets();
    (octets[..12] == [0; 12]).then(|| Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
}

/// Extracts the embedded IPv4 address from a NAT64 Well-Known Prefix address
/// (`64:ff9b::/96`, RFC 6052 sections 2.1/2.2 — verified against the RFC text,
/// not assumed). The Well-Known Prefix is only ever used at a /96 (the RFC
/// explicitly restricts it to that length), so — like the other /96 forms
/// above — the IPv4 address simply fills the remaining 32 bits with no
/// reserved octet needed.
fn nat64_well_known_prefix_embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    const PREFIX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    let octets = address.octets();
    (octets[..12] == PREFIX).then(|| Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
}

/// Extracts the embedded IPv4 address from a NAT64 Local-Use Prefix address
/// (`64:ff9b:1::/48`, RFC 8215, using RFC 6052 section 2.2's general
/// embedding algorithm for a 48-bit prefix length — verified against the RFC
/// text, not assumed). Unlike the /96 forms, a /48 embedding leaves a
/// reserved "u" octet at bits 64-71 (octet index 8, regardless of prefix
/// length below 96) that is *not* part of the IPv4 address: RFC 6052 requires
/// it to be transmitted as zero, but this extracts the IPv4 bits around it
/// regardless of the "u" octet's actual value, since the concern here is
/// whether the address *can* be used to reach a reserved IPv4 destination,
/// not strict wire-format conformance. The 16 high IPv4 bits sit at octets
/// 6-7 (right after the 48-bit/6-octet prefix) and the 16 low IPv4 bits sit
/// at octets 9-10 (right after the reserved octet 8).
fn nat64_local_use_prefix_embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    const PREFIX: [u8; 6] = [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01];
    let octets = address.octets();
    (octets[..6] == PREFIX).then(|| Ipv4Addr::new(octets[6], octets[7], octets[9], octets[10]))
}

/// Extracts the embedded IPv4 address from a 6to4 address (`2002::/16`,
/// RFC 3056 — verified against the RFC text, not assumed): the 32 bits right
/// after the 16-bit prefix (octets 2-5) carry the IPv4 address of the 6to4
/// host or relay.
fn six_to_four_embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    const PREFIX: [u8; 2] = [0x20, 0x02];
    let octets = address.octets();
    (octets[..2] == PREFIX).then(|| Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]))
}

/// Extracts the two IPv4 addresses embedded in a Teredo address
/// (`2001::/32`, RFC 4380 as amended by RFC 8190 — verified against the RFC
/// text, not assumed; RFC 8190 only corrects registry metadata, not the
/// address layout): the Teredo server's IPv4 address in octets 4-7, stored
/// plain, and the client's (NAT-translated) IPv4 address in octets 12-15, stored
/// bitwise-inverted ("obfuscated" by XOR-ing every bit with 1 — equivalent to
/// `!byte` per octet). Both are worth checking: a malicious discovery
/// document could point either the "server" or "client" slot at a reserved
/// address.
fn teredo_embedded_ipv4_addresses(address: Ipv6Addr) -> [Option<Ipv4Addr>; 2] {
    const PREFIX: [u8; 4] = [0x20, 0x01, 0x00, 0x00];
    let octets = address.octets();
    if octets[..4] != PREFIX {
        return [None, None];
    }
    let server = Ipv4Addr::new(octets[4], octets[5], octets[6], octets[7]);
    let client = Ipv4Addr::new(!octets[12], !octets[13], !octets[14], !octets[15]);
    [Some(server), Some(client)]
}

/// Extracts the embedded IPv4 address from an ISATAP address (RFC 5214 —
/// verified against the RFC text, not assumed): unlike the other forms here,
/// ISATAP has no fixed leading prefix (its 64-bit network prefix can be any
/// on-link unicast prefix) — instead its 64-bit interface identifier is
/// formed by concatenating the 24-bit IANA OUI `00-00-5E`, the fixed octet
/// `0xFE`, and the 32-bit IPv4 address. Per RFC 5214 section 6.1, octets 8-9
/// (the two octets preceding the `5E-FE` marker) are a "u" bit / scope
/// indicator that is `00-00` when the embedded IPv4 address is locally
/// scoped or `02-00` when it is known to be globally unique — *not* part of
/// a fixed prefix. Only octets 10-11 (the `5E-FE` marker itself) reliably
/// identify ISATAP; octets 8-9 are deliberately left unconstrained here
/// rather than enumerating the two documented values, so this doesn't
/// silently miss a third, undocumented, or otherwise-set scope-bit value the
/// same way requiring an exact `00-00-5E-FE` match once missed the `u=1`
/// (`02-00-5E-FE`) case.
fn isatap_embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    const MARKER: [u8; 2] = [0x5e, 0xfe];
    let octets = address.octets();
    (octets[10..12] == MARKER)
        .then(|| Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]))
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
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use super::{OidcDiscoveryCache, OidcDiscoveryError, discover_oidc_provider};

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
    fn rejects_an_https_endpoint_url_targeting_a_private_ip_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        // `10.0.0.1` and `192.168.1.1` are private-range literals, not
        // loopback — they don't hit the existing HTTP+loopback allowlist
        // exception at all, since these are HTTPS. This is the case the
        // ticket asked for explicitly: a non-loopback private IP that would
        // have passed the old (host-unrestricted) HTTPS check.
        for jwks_uri in [
            "https://10.0.0.1/jwks.json",
            "https://192.168.1.1/jwks.json",
        ] {
            let (_, result) = discover_against_fixture(move |issuer| {
                format!(
                    r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"{jwks_uri}"}}"#
                )
            })?;
            assert!(
                matches!(result, Err(OidcDiscoveryError::InvalidDiscoveryDocument)),
                "expected {jwks_uri} to be rejected, got {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_an_https_endpoint_url_targeting_the_cloud_metadata_address()
    -> Result<(), Box<dyn std::error::Error>> {
        // 169.254.169.254 (link-local) is the canonical cloud-metadata SSRF
        // target called out in the ticket background.
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"https://169.254.169.254/latest/meta-data","token_endpoint":"{issuer}/token","jwks_uri":"{issuer}/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    #[test]
    fn rejects_an_https_endpoint_url_targeting_a_loopback_ip_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        // Loopback is allowed for HTTP dev/test tooling (see
        // `issuer_url_scheme_is_allowed`) but not for an HTTPS endpoint URL
        // sourced from the discovery document itself.
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://127.0.0.1/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    #[test]
    fn rejects_an_https_endpoint_url_targeting_an_ipv4_mapped_ipv6_private_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        // `::ffff:169.254.169.254` is the IPv6-mapped form of the same
        // cloud-metadata address; it must be unwrapped and checked as its
        // underlying IPv4 address rather than slipping through as an
        // ordinary-looking IPv6 literal.
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[::ffff:169.254.169.254]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// Regression test for a bypass: `::169.254.169.254` (the deprecated
    /// "IPv4-compatible" IPv6 form, no `ffff` marker) reaches the same
    /// cloud-metadata address as the mapped-form test above, but is a
    /// distinct encoding `Ipv6Addr::to_ipv4_mapped` does not recognize —
    /// `ipv4_compatible` must catch it separately.
    #[test]
    fn rejects_an_https_endpoint_url_targeting_an_ipv4_compatible_ipv6_private_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[::169.254.169.254]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// Regression test for a second bypass, found after the IPv4-compatible
    /// fix above: `64:ff9b::/96` (RFC 6052 NAT64 Well-Known Prefix) is a
    /// *third* standardized notation embedding the same cloud-metadata
    /// address, distinct from both the mapped and compatible forms.
    #[test]
    fn rejects_an_https_endpoint_url_targeting_a_nat64_well_known_prefix_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[64:ff9b::169.254.169.254]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// The RFC 8215 NAT64 Local-Use Prefix (`64:ff9b:1::/48`) embeds the IPv4
    /// address differently from every /96 form above: RFC 6052 section 2.2's
    /// general algorithm splits the 32 IPv4 bits around a reserved "u" octet.
    /// This is `64:ff9b:1:a9fe:a9:fe00::` — expanded, `0064 ff9b 0001 a9fe
    /// 00a9 fe00 0000 0000`, i.e. prefix `0064:ff9b:0001`, IPv4 high octets
    /// `a9:fe` (169.254), the reserved `u` octet `00`, IPv4 low octets
    /// `a9:fe` (169.254) split across the next two octets, then a zero
    /// suffix — embedding 169.254.169.254 split around the reserved octet
    /// rather than contiguously.
    #[test]
    fn rejects_an_https_endpoint_url_targeting_a_nat64_local_use_prefix_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[64:ff9b:1:a9fe:a9:fe00::]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// 6to4 (`2002::/16`, RFC 3056) embeds the IPv4 address directly in the
    /// next 32 bits after the prefix: `2002:a9fe:a9fe::` embeds
    /// 169.254.169.254 (`a9fe:a9fe` is the hex form of `169.254.169.254`).
    #[test]
    fn rejects_an_https_endpoint_url_targeting_a_6to4_embedded_private_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[2002:a9fe:a9fe::]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// Teredo (`2001::/32`, RFC 4380/8190) embeds *two* IPv4 addresses: the
    /// server's (plain) and the client's (bitwise-inverted/"obfuscated").
    /// `2001:0:808:808::5601:5601` carries server `8.8.8.8` (a public,
    /// non-reserved address — deliberately, so this test isolates the
    /// *client* slot) and an obfuscated client address that decodes
    /// (`!0x56=0xa9=169`, `!0x01=0xfe=254`, ...) to 169.254.169.254.
    #[test]
    fn rejects_an_https_endpoint_url_targeting_a_teredo_client_embedded_private_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[2001:0:808:808::5601:5601]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// ISATAP (RFC 5214) has no fixed leading prefix — only its interface
    /// identifier is fixed (`5E-FE` then the IPv4 address, per octets 10-11)
    /// — so this deliberately uses an *arbitrary* global-unicast-shaped
    /// prefix (`2001:db8::`, itself independently unflagged by every other
    /// check here: not loopback/unspecified/multicast/unique-local/
    /// link-local, and not one of the fixed NAT64/6to4/Teredo prefixes)
    /// rather than `fe80::/10` — reusing a link-local prefix here would make
    /// this test pass even without the ISATAP-specific extraction, since
    /// link-local is already independently rejected. This is the "u=0"
    /// (locally-scoped) variant: `2001:db8::5efe:a9fe:a9fe` has `00-00`
    /// immediately before the `5efe` marker. See the "u=1" variant test
    /// below for the regression this was fixed to cover.
    #[test]
    fn rejects_an_https_endpoint_url_targeting_an_isatap_embedded_private_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[2001:db8::5efe:a9fe:a9fe]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    /// Regression test for a bypass in the ISATAP check above: RFC 5214
    /// section 6.1 defines octets 8-9 (immediately before the `5E-FE`
    /// marker) as a "u" bit / scope indicator that is `00-00` when the
    /// embedded IPv4 address is locally scoped (the variant covered by the
    /// test above) or `02-00` when it is known to be globally unique — an
    /// earlier version of this check required an exact `00-00-5E-FE` match,
    /// missing this "u=1" variant entirely. `2001:db8::0200:5efe:a9fe:a9fe`
    /// carries `02-00` before the marker but embeds the same
    /// 169.254.169.254 target.
    #[test]
    fn rejects_an_https_endpoint_url_targeting_an_isatap_u_bit_set_embedded_private_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://[2001:db8::0200:5efe:a9fe:a9fe]/jwks.json"}}"#
            )
        })?;
        assert!(matches!(
            result,
            Err(OidcDiscoveryError::InvalidDiscoveryDocument)
        ));
        Ok(())
    }

    #[test]
    fn rejects_an_https_endpoint_url_targeting_shared_address_space_benchmarking_or_ietf_protocol_ranges()
    -> Result<(), Box<dyn std::error::Error>> {
        for jwks_uri in [
            "https://100.64.0.5/jwks.json",
            "https://198.18.0.5/jwks.json",
            "https://192.0.0.5/jwks.json",
        ] {
            let (_, result) = discover_against_fixture(move |issuer| {
                format!(
                    r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"{jwks_uri}"}}"#
                )
            })?;
            assert!(
                matches!(result, Err(OidcDiscoveryError::InvalidDiscoveryDocument)),
                "expected {jwks_uri} to be rejected, got {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn allows_an_https_endpoint_url_targeting_a_public_ip_literal()
    -> Result<(), Box<dyn std::error::Error>> {
        // A public IP literal is unusual for a real provider but not itself
        // an SSRF target, and should not be rejected by this check.
        let (_, result) = discover_against_fixture(|issuer| {
            format!(
                r#"{{"issuer":"{issuer}","authorization_endpoint":"{issuer}/authorize","token_endpoint":"{issuer}/token","jwks_uri":"https://8.8.8.8/jwks.json"}}"#
            )
        })?;
        let metadata = result?;
        assert_eq!(metadata.jwks_uri, "https://8.8.8.8/jwks.json");
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

    // ---- discovery metadata cache -------------------------------------------

    /// A loopback discovery server that serves the well-formed document for its
    /// own issuer on *every* request (a persistent loop, unlike the one-shot
    /// [`discover_against_fixture`]) and counts how many discovery fetches it
    /// received, so a test can prove the cache collapses repeat lookups to one
    /// outbound fetch.
    struct CountingIdp {
        issuer: String,
        discovery_hits: Arc<AtomicUsize>,
        _handle: JoinHandle<()>,
    }

    fn start_counting_idp() -> Result<CountingIdp, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let issuer = format!("http://{address}");
        let body = well_formed_body(&issuer);
        let discovery_hits = Arc::new(AtomicUsize::new(0));
        let hits_for_server = Arc::clone(&discovery_hits);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buffer = [0_u8; 2048];
                let Ok(read) = stream.read(&mut buffer) else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                if !request.starts_with("GET /.well-known/openid-configuration ") {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    continue;
                }
                hits_for_server.fetch_add(1, Ordering::SeqCst);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
        });
        Ok(CountingIdp {
            issuer,
            discovery_hits,
            _handle: handle,
        })
    }

    #[test]
    fn caches_provider_metadata_and_serves_repeat_lookups_without_refetching()
    -> Result<(), Box<dyn std::error::Error>> {
        let idp = start_counting_idp()?;
        let cache = OidcDiscoveryCache::new();

        let first = cache.discover(&idp.issuer)?;
        let second = cache.discover(&idp.issuer)?;

        // Same metadata both times, but the second lookup was served from the
        // cache — only ONE outbound discovery fetch reached the IdP.
        assert_eq!(first, second);
        assert_eq!(
            idp.discovery_hits.load(Ordering::SeqCst),
            1,
            "a second lookup for the same issuer must not refetch"
        );
        Ok(())
    }

    #[test]
    fn a_disabled_cache_refetches_on_every_lookup() -> Result<(), Box<dyn std::error::Error>> {
        let idp = start_counting_idp()?;
        // A zero TTL disables caching (every entry is already expired by the
        // next lookup). This is the red control for the green test above: with
        // caching effectively off, each lookup must hit the network.
        let cache = OidcDiscoveryCache::with_ttl_and_capacity(Duration::from_secs(0), 64);

        cache.discover(&idp.issuer)?;
        cache.discover(&idp.issuer)?;

        assert_eq!(
            idp.discovery_hits.load(Ordering::SeqCst),
            2,
            "with caching disabled each lookup must refetch"
        );
        Ok(())
    }
}
