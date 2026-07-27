# Account lifecycle compatibility

The reviewed, opt-in Rust security router owns four additional Java account
lifecycle routes. Production secure-mode cutover remains disabled until the
full security review and the remaining identity providers are complete.

## Routes

| Route | Policy | Compatibility behavior |
| --- | --- | --- |
| `POST /api/v1/user/register` | Public | Accepts JSON `username` and `password`, enforces Java's case-insensitive username rules and five-user community allocation, and creates a disabled `ROLE_USER` in the Default team. The response is `201` with the Java user/message shape. An administrator must enable the account before login. |
| `POST /api/v1/user/admin/inviteUsers` | Administrator | Accepts multipart `emails`, optional `role`, and optional `teamId`; immediately creates enabled local accounts with generated credentials, forces password replacement on first login, sends each credential email, and returns Java-compatible partial success/failure counts. |
| `POST /api/v1/user/updateUserSettings` | Authenticated, non-demo | Accepts a JSON string map and transactionally replaces the caller's complete settings map, matching `UserService.updateUserSettings`. Returns `{ "message": "Settings updated successfully" }`. |
| `POST /api/v1/user/complete-initial-setup` | Authenticated, non-demo | Durably marks the caller's initial setup complete and returns `{ "success": true }`. |

Registration rejects reserved identities (`ALL_USERS` and `anonymousUser`),
malformed usernames, case-insensitive duplicates, empty passwords, and
passwords longer than BCrypt's safe 72-byte boundary. It never creates an
active session or an enabled account. The five-user check and insertion occur
in one immediate SQLite transaction, preventing concurrent over-allocation.
Paid-license seat overrides remain part of the unported entitlement subsystem;
the reviewed foundation therefore enforces the Java community default.

Bulk account invitations require both `mail.enableInvites=true` and a usable
SMTP service. Capacity is checked against the raw Java-style comma split before
role and team validation. Blank entries are skipped during processing. Each
nonblank address is independent: invalid addresses, case-insensitive
duplicates, missing teams, and mail failures contribute one error ending in
`; ` without rolling back users already created. Any success returns `200`;
an all-failure batch returns `400`. Generated credentials retain Java's
12-character UUID-prefix form (`xxxxxxxx-xxx`). Rust persists
`forcePasswordChange=true` as the behavioral equivalent of Java's
`firstLogin=true`, because the Rust authentication contract exposes the former
flag to the same first-login completion flow. User creation and the per-user
capacity recheck occur in one immediate transaction.

User-setting requests share the security router's 8 KiB body limit. The store
also limits a profile to 128 entries, keys to 256 bytes, and values to 4 KiB,
rejecting control-bearing keys and NUL-bearing values. Replacement deletes old
keys and inserts the new map in one transaction, so a failure cannot expose a
partially updated profile.

## Generic OIDC login (discovery + authorization-redirect + SSRF-safe token exchange + ID-token verification + login orchestration + the two HTTP routes — complete in the reviewed secured router)

Java's proprietary backend registers a generic OIDC provider via
`OAuth2Configuration.oidcClientRegistration()`, which uses Spring's
`ClientRegistrations.fromIssuerLocation(issuer)` to fetch and validate the
provider's `.well-known/openid-configuration` discovery document. Rust has
ported only that discovery step so far: `oidc_discovery::discover_oidc_provider`
fetches `{issuer}/.well-known/openid-configuration`, checks that the document's
own `issuer` matches the requested issuer (OIDC Discovery 1.0 section 4.3),
and that `authorization_endpoint`, `token_endpoint`, and `jwks_uri` are present
and well-formed under the same HTTPS-first scheme policy as Supabase JWKS
issuer validation in `security_jwt.rs` (HTTPS always allowed, plain HTTP only
against a loopback host) — returning a typed `OidcProviderMetadata` rather than
a raw JSON value.

The three discovered endpoint URLs get one further, SSRF-motivated check the
issuer itself does not: an HTTPS endpoint whose host is a literal IP address
in a private/reserved range is rejected. This matters because, unlike the
admin-typed issuer, these three URLs come *from* the issuer's own response —
a compromised or spoofed provider could point one at internal infrastructure
instead of itself once a later ticket actually fetches it.

Covered ranges, for a plain IPv4/IPv6 literal directly: loopback, RFC 1918
private, link-local (including the `169.254.169.254` cloud-metadata address),
multicast, broadcast, documentation, unspecified (`0.0.0.0`/`::`), RFC 6598
Shared Address Space / CGNAT (`100.64.0.0/10`), RFC 2544 benchmarking
(`198.18.0.0/15`), and RFC 6890 IETF Protocol Assignments (`192.0.0.0/24`).
The first seven use `std::net`'s stable `Ipv4Addr`/`Ipv6Addr` predicates; the
last three have no stable-API equivalent (`is_global`/`is_reserved`/
`is_shared`/`is_benchmarking` are still unstable on the pinned Rust 1.94,
confirmed against the actual toolchain rather than assumed) and are checked as
plain octet-range comparisons instead. Numeric-obfuscated IPv4 (decimal
integer, hex, octal, e.g. `2852039166`) is not a bypass: the `url` crate's
WHATWG-compliant host parser normalizes those to canonical dotted-decimal
before this check ever sees them.

An IPv4 address embedded inside an IPv6 literal is *also* extracted and
checked against the same ranges. This went through two independent rounds of
"a different embedding notation defeats the check" after it first shipped
(IPv4-compatible, then NAT64), so the fix after the second round was a
deliberate, one-time enumeration of IANA's IPv6 Special-Purpose Address
Registry and the RFCs it cites for every *fixed, standardized* IPv4-in-IPv6
embedding form, rather than patching forms in one at a time as they were
independently found. All seven registered/documented fixed forms found by
that pass are covered: IPv4-mapped (`::ffff:a.b.c.d`, RFC 4291), the older
deprecated IPv4-compatible form (`::a.b.c.d`, no `ffff` marker, RFC 4291),
the NAT64 Well-Known Prefix (`64:ff9b::/96`, RFC 6052) and Local-Use Prefix
(`64:ff9b:1::/48`, RFC 8215 — this one splits the IPv4 bits around a reserved
octet per RFC 6052's general embedding algorithm rather than storing them
contiguously; the byte layout was verified against the RFC text, not
assumed), 6to4 (`2002::/16`, RFC 3056), Teredo (`2001::/32`, RFC 4380/8190 —
this one embeds *two* IPv4 addresses, the tunnel server's and the NAT-mapped
client's, and both are checked), and ISATAP (RFC 5214 — identified by a fixed
interface-identifier marker rather than a fixed leading prefix, since
ISATAP's network prefix can be any on-link unicast prefix; the marker itself
is only the `5E-FE` octet pair, not the two octets before it, since RFC 5214
section 6.1 defines those as a "u" bit / scope indicator — `00-00` or
`02-00` — that doesn't affect the embedded IPv4 address; an earlier version
of this check required an exact `00-00-5E-FE` match and missed the `02-00`
case as a live bypass).

**Explicitly not covered**, so this list doesn't silently imply more than it
delivers:

- The check is literal-address-only (no DNS lookup), so a domain name that
  resolves to any of the ranges above — including one that resolves
  differently at validation time than at the real connect time (DNS
  rebinding) — is not caught by anything *in this discovery module*. The live
  token-endpoint fetch closes exactly this hole on its own path (see
  `oidc_live_token` below): it resolves the host, rejects if any resolved
  address is reserved, and pins the vetted address for the actual connect.
  This discovery-time check stays literal-only by design (it's a cheap
  structural screen of an untrusted document, not a network operation); any
  future live fetch of `jwks_uri` still needs the same resolve-and-pin
  treatment `oidc_live_token` applies to `token_endpoint`.
- NAT64's *Network-Specific Prefixes* (RFC 6052 section 2.2 also permits an
  operator to embed IPv4 addresses under a prefix of their own choosing,
  instead of the fixed Well-Known/Local-Use prefixes above) and 6rd
  (RFC 5969, a similarly operator-configured generalization of 6to4) are
  genuinely open-ended: detecting them would require knowing a specific
  deployment's chosen prefix out of band, not just recognizing a fixed,
  registered value the way the seven forms above allow. These are left
  uncovered rather than guessed at.
- This pass audited IPv4-embedded-in-IPv6 forms specifically, not IPv6's own
  special-purpose ranges beyond that — e.g. native IPv6 benchmarking
  (`2001:2::/48`, RFC 5180), Discard-Only (`100::/64`), and narrow anycast
  ranges (AMT, PCP, TURN, AS112-v6, ORCHIDv2). None of these carry an
  embedded IPv4 address, so they were out of this pass's scope rather than
  overlooked within it; whether they're worth blocking too is a separate,
  lower-priority question from the embedding-form gaps above.

The narrow HTTP+loopback allowance for the issuer itself is
unaffected: it already only matches the three loopback literals, not
arbitrary private ranges, and is not the scheme a real provider would use.

Discovery itself is fetch-and-validate only, but `oidc_authorization` now
builds on it for the next slice: given an `OidcProviderMetadata`, a
`client_id`, a `redirect_uri`, and requested scopes,
`oidc_authorization::build_oidc_authorization_request` generates a random
`state` (CSRF protection), `nonce` (replay protection — verified against the
eventual ID token's own `nonce` claim, once token exchange exists), and a PKCE
`code_verifier`/`code_challenge` pair (RFC 7636, mitigates authorization-code
interception), then builds the full `{authorization_endpoint}?...` redirect
URL per OpenID Connect Core 1.0 section 3.1.2.1's Authentication Request
parameters — always including the `openid` scope even if the caller's
requested scopes omit it, per that section's requirement that omitting it
makes the request's behavior "entirely unspecified." `state`/`nonce`/the PKCE
`code_verifier` reuse this codebase's established token-generation convention
(`security.rs`'s `random_secret`: 32 random octets from `rand::rng()`,
base64url-no-pad encoded), which also happens to satisfy RFC 7636 section
4.1's own recommendation for the code verifier specifically (its 43-character
result is exactly the RFC's minimum `code_verifier` length, and base64url's
alphabet is a strict subset of the RFC's required character set). Every
parameter is encoded via the `url` crate's `query_pairs_mut`, so a
`redirect_uri` that carries its own query string is encoded as a single
opaque value rather than merging into (and colliding with) the authorization
URL's own query string, and an `authorization_endpoint` that already has a
query string of its own is appended to rather than clobbered.

This does not persist `state`/`nonce`/`code_verifier` anywhere (no session,
cookie, or other storage) — the caller must hold onto the returned values
until the callback arrives, by whatever mechanism a later ticket wires up.

`oidc_token` is the next slice, still pure functions with no network call:
`build_oidc_token_request` assembles the RFC 6749 section 4.1.3 / RFC 7636
section 4.5 authorization-code-for-token request for the public-client PKCE
case (`grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`,
`client_id`), returning the `application/x-www-form-urlencoded` body, the
target `token_endpoint` (passed through untouched), and the content type —
**constructed, not sent**. The body is form-encoded via the `url` crate's
`form_urlencoded::Serializer` (the same machinery `oidc_authorization` uses for
the authorization URL), so a `code` carrying base64url/opaque `+`/`/`/`=`
characters or a `redirect_uri` with its own query string round-trips without
corrupting the body. `parse_oidc_token_response` takes a response status +
JSON body and returns either a typed `OidcTokenResponse` (`id_token`,
`access_token`, `token_type`, optional `expires_in`) or a typed error: an
RFC 6749 section 5.2 provider error (`error` + optional
`error_description`/`error_uri`), a `MissingIdToken` rejection (OpenID Connect
Core 1.0 section 3.1.3.3 requires `id_token` in the token response, on top of
the OAuth2 success shape), or `Malformed` for a body that is neither a valid
success nor a valid error. The `id_token` is extracted as an **opaque,
unverified** string only.

`oidc_live_token` is the slice that actually sends that request — the first
live network call of the arc, and the first to a provider-controlled URL, so it
is SSRF-gated. `exchange_oidc_token` takes an `OidcTokenRequest`, POSTs its
form body + content type to `token_endpoint` through a resolve-and-pin fetch
primitive, and feeds the response `(status, body)` into
`parse_oidc_token_response`, returning the typed `OidcTokenResponse` or a typed
error (`InvalidEndpoint`, `BlockedAddress`, `Unavailable`, or a wrapped
`OidcTokenError` carrying the provider error / missing-`id_token` /
malformed cases from the parser).

The SSRF guard is where this differs from discovery's literal-only check, and
is deliberately stricter: `token_endpoint`, though it came from a validated
discovery document, is still provider-controlled, and discovery's check does
**not** catch a hostname that *resolves* into a private/reserved range. So
before connecting, `oidc_live_token` (a) resolves the host to concrete
address(es); (b) vets **every** resolved address against the *same*
reserved-range predicate discovery uses — `oidc_discovery::ip_addr_is_reserved`
was exposed `pub(crate)` and reused here, not reimplemented; (c) rejects the
whole request before any TCP connection if *any* resolved address is reserved
(closing the DNS-name → private-IP hole); and (d) pins those exact vetted
addresses via `reqwest`'s `resolve_to_addrs`, so the socket cannot re-resolve
the name to a different address between the check and the connect (anti
DNS-rebinding / TOCTOU). It reuses discovery's other fetch conventions:
no redirects, connect/read timeouts, and a response-size cap enforced
independently of the advertised `Content-Length`. The address policy is
per-scheme, and — after a hardening pass (originally a review finding on the
token-fetch slice) — **neither scheme skips the check**. On `https` (the scheme
a real, spoofable provider uses) *any* resolved reserved/private address rejects
the whole request, matching discovery's own reserved-IP check. On `http` (only
ever admitted for the loopback literals the shared scheme policy allows — the
dev/self-hosted seam) *every* resolved address must **be** loopback: the loopback
mock stays reachable, but an `http` host that resolves *off-box* to a
non-loopback address — an attacker-influenced `localhost` (poisoned
`/etc/hosts`/resolver), or an http-downgrade to some other host — is now refused
rather than silently reached. That closes both the off-box-`localhost` hole and
the earlier http-downgrade asymmetry where the reserved check was skipped
entirely for `http`. Be precise about scope: this closes the DNS-name hole **for
the live-fetch paths** (token POST and, below, the JWKS GET); discovery-time
endpoint validation remains a separate, literal-address check as described
above.

That same resolve-and-pin primitive was generalized to back a bodyless GET
(refactored so the SSRF logic — scheme/host validation, resolve-and-vet, address
pinning, no-redirect, timeouts, and a caller-supplied response cap — is written
once and shared by both the POST and the GET, differing only by method, body,
and cap). The GET is exposed `pub(crate)` so the ID-token verifier can fetch a
provider-controlled `jwks_uri` under the identical protections.

`oidc_id_token` is the slice that finally verifies the `id_token` rather than
extracting it opaquely — a **sibling** to `security_jwt`'s Supabase verifier
(same `jsonwebtoken` rigor), not a modification of it, because the two differ:
the JWKS URL is the provider's discovery-advertised, provider-controlled
`jwks_uri` (not Supabase's hardcoded `{issuer}/.well-known/jwks.json`), the
claims are OIDC ID-token claims, and there is the `nonce` check Supabase lacks.
Given the discovered `OidcProviderMetadata` (for `jwks_uri` + `issuer`), the
`client_id`, the `expected_nonce` from `oidc_authorization`, and the raw
`id_token`, `verify_oidc_id_token`:

- fetches the JWKS from `provider.jwks_uri` via the SSRF-safe GET above (bounded
  to 256 KiB). `verify_oidc_id_token` fetches per verification; the callback
  path goes through `verify_oidc_id_token_cached` and a shared `OidcJwksCache` —
  a bounded `Mutex<HashMap<jwks_uri, CachedJwks>>` combining the discovery
  cache's shape (**5-min TTL**, **64-entry** cap, fetch *outside* the lock,
  retain-unexpired admission, poisoned lock degrades to uncached fetching, at
  capacity a new URI is served uncached rather than evicting) with
  `security_jwt`'s kid-miss-triggered refresh under a per-entry **60-second
  cooldown**: a token whose `kid` misses the fresh cached set forces one early
  refetch (prompt pickup of a genuine signing-key rotation), but at most once
  per cooldown, so a flood of fabricated `kid`s cannot amplify into outbound
  JWKS fetches. The token's shape/algorithm/`kid` are validated **before** the
  cache or network is touched, so a malformed token can never trigger a fetch,
  and only sets that already passed the JWKS validation below are ever cached;
- rejects any non-public-key algorithm **before** decoding, via a public-key-only
  allowlist (RSA PKCS#1-v1.5/PSS, ECDSA, `EdDSA`; **no HMAC**) identical to
  `security_jwt`'s — this is the primary defense against the `alg=HS256`-against-a-
  public-key confusion bypass (an attacker HMAC-signing with the public key
  bytes). `jsonwebtoken`'s own `from_jwk` key-family guard, which refuses to use
  an RSA/EC public key as an HMAC secret, is a redundant second line behind it;
- verifies the signature against the JWK the header's `kid` selects, `iss` ==
  `provider.issuer` (exact), `client_id` ∈ `aud` (and, when present, `azp` ==
  `client_id`), and `exp` not past (same leeway convention as `security_jwt`);
- requires the `nonce` claim to be present and equal (constant-time) to
  `expected_nonce` — the OIDC-specific replay/CSRF binding `jsonwebtoken` does not
  validate itself — and returns a typed `VerifiedOidcIdentity` (`sub`, `iss`, the
  verified `aud`, plus optional `email`/`email_verified`/`name`/
  `preferred_username` and `iat`/`exp`), never a raw JSON value. Signature/`iss`/
  `aud`/`exp`/claim failures collapse to one generic `InvalidToken` (fail-closed,
  no which-check oracle); a missing/unequal nonce surfaces as a distinct
  `NonceMismatch` (a server-side replay signal that reaching it already requires
  an otherwise fully-valid token for this client, so it is not a useful attacker
  oracle).

`oidc_login` is the slice that finally wires all of the above into a
completable login, at the **library level** (still no axum routes — those are
the remaining slice). It adds the three things the primitives deliberately left
to "a later ticket": server-side single-use `state` persistence, provider
configuration, and session issuance for a verified OIDC identity — reusing the
existing session and external-identity machinery rather than forking parallel
systems.

- **Provider config.** `RuntimeConfig::oidc_login_provider_config()` resolves an
  optional `OidcLoginProviderConfig { issuer, client_id, redirect_uri, scopes,
  client_secret }` from the crate's usual env/YAML config (`security.oauth2.*` /
  `SECURITY_OAUTH2_*`, mirroring the fields of Java's discovery-driven
  `ClientRegistration`). `security.oauth2.clientSecret` /
  `SECURITY_OAUTH2_CLIENTSECRET` selects the **confidential-client** token
  exchange (see the orchestration bullet); blank/absent means a public client,
  matching Java, where an unset `clientSecret` leaves Spring's registration on
  the public-client method. The secret is held in a `Zeroizing<String>` (the
  crate's convention for comparable credential material) and is excluded from
  the config's `Debug` output. The `issuer` is the on/off switch — absent ⇒
  `None` (provider disabled), exactly like `security_supabase_jwt_config`; a
  present-but-invalid config is not second-guessed at load but rejected
  fail-closed at the login boundary by `OidcLoginProviderConfig::validate`
  (empty/over-long issuer/client id, empty/unparseable redirect URI, a
  whitespace-bearing scope, or a configured-but-blank/over-long secret — a
  broken secret is rejected, never silently downgraded to a public client),
  called at the top of `initiate_oidc_login`.

- **Single-use, TTL-bounded, size-capped `state` store.** `OidcLoginStateStore`
  is an in-memory `Mutex<HashMap>` over a monotonic `Instant` clock, modeled on
  `mobile_scanner`'s session store, keyed by the CSPRNG `state` and holding one
  pending login's `nonce`, PKCE `code_verifier`, `redirect_uri`, the discovered
  `OidcProviderMetadata` (so the callback uses the exact endpoints discovered at
  initiation), `client_id`, and the optional `client_secret` captured at
  initiation, for a bounded few minutes
  (`DEFAULT_LOGIN_STATE_TTL`, 10 min). Lookup is **delete-on-lookup**: `consume`
  `remove`s the entry, so it is handed out at most once. An unknown `state`
  (never issued, or already consumed) is rejected as `UnknownState`; a
  present-but-expired one is removed anyway and reported as `ExpiredState`. That
  rejection **is** the CSRF defense: because `state` is CSPRNG and only a login
  this server actually started has a matching live entry, a forged/replayed
  callback resolves to nothing. (A store `store` also opportunistically sweeps
  expired entries so abandoned logins can't accumulate.) The store is also
  **size-capped** at `DEFAULT_MAX_LOGIN_STATE_ENTRIES` (4 096) pending logins:
  the TTL bounds one honest login's footprint, but nothing stops an attacker
  spamming `/authorize` from growing the map to (rate × TTL) entries between
  sweeps, so after the opportunistic sweep, if the store is still full, a *new*
  `state` is refused with `AtCapacity` rather than evicting an in-flight entry
  (evicting one would silently destroy an honest user's single-use CSRF state).
  `AtCapacity` is transient/retryable and, like every other `initiate` failure,
  collapses to the authorize route's generic `503` (see below) — leaking neither
  the stage nor the limit. The cap (a few thousand) sits far above any plausible
  count of genuinely-concurrent in-flight logins while keeping the worst-case
  footprint to a few MB; it is tunable via the `with_ttl_and_capacity` seam.

- **`authenticate_oidc_identity`.** A sibling to
  `authenticate_supabase_identity` on `SecurityStore` that maps a
  `VerifiedOidcIdentity` onto the **same** issuer-agnostic external-identity
  shape and runs it through the **unchanged** `validate_external_identity` /
  `resolve_external_user` / `context_for_user` path (reused verbatim, not
  reimplemented), tagging the context with a new `AuthenticationSource::Oidc`.
  Field mapping: `username` = `preferred_username` else `email` else `sub`;
  `authentication_type` = `"oauth2"`; `role` = `"ROLE_USER"`; `session_id` =
  the id token's `sid` if present else a freshly generated random id;
  `permissions` empty; `anonymous` false. Persistence is keyed by
  `(issuer, subject)` in the shared `security_external_identities` table, so an
  OIDC subject and a Supabase subject **cannot collide** unless they share both
  an issuer and a subject (i.e. are the same account at the same provider). The
  id-token verifier gained an optional bounded `sid` claim to feed this mapping.

- **Orchestration.** `initiate_oidc_login(provider, store, discovery)` validates
  the config, resolves the provider metadata through `discovery` (see the
  discovery cache below), builds the authorization request (`state`/`nonce`/PKCE),
  **stores** the state entry, and returns the authorization redirect URL +
  `state`. `complete_oidc_login(state, code, browser_binding, store, jwks_cache,
  security, now, correlation_id)` **consumes** the state entry (rejecting
  unknown/expired before any network call — the CSRF/single-use gate), exchanges
  the code at the stored `token_endpoint` with the stored PKCE verifier, verifies
  the id token against the stored provider metadata and the stored `nonce`
  (resolving the JWKS through the shared `OidcJwksCache` rather than refetching
  per callback), authenticates via `authenticate_oidc_identity`, and issues an
  opaque session through the same `issue_session` every other login path uses
  (default access/refresh TTLs) — returning the session tokens, the
  `AuthContext`, and the verified identity.

- **Confidential-client token exchange.** When `client_secret` is configured,
  the token request carries HTTP Basic credentials per RFC 6749 §2.3.1 — the
  `client_secret_basic` method Spring's `ClientRegistration` infers from Java's
  `security.oauth2.clientSecret` — assembled with the Appendix B subtlety:
  `client_id` and `client_secret` are each `application/x-www-form-urlencoded`
  encoded (space → `+`, reserved bytes percent-encoded, the same algorithm as
  Java's `URLEncoder.encode`) **before** `base64(id:secret)`, so an embedded
  `:` can never masquerade as the separator. The form body is byte-identical
  with and without a secret (the secret moves only into the `Authorization`
  header, attached by the SSRF-safe live POST); the header value is `Zeroizing`
  and redacted from `Debug`. **Deliberate divergence from Java:** Spring
  applies PKCE only to public clients and drops it once a secret is set; this
  port keeps the PKCE `code_verifier` in every token exchange, per RFC 9700's
  recommendation of PKCE for all clients — strictly additive, and every
  mainstream IdP accepts PKCE from confidential clients.

- **Discovery metadata cache.** `OidcDiscoveryCache` (in `oidc_discovery`) is a
  bounded, TTL'd `Mutex<HashMap>` of `OidcProviderMetadata` keyed by issuer,
  built once and shared behind an `Arc` alongside the state store. Without it,
  every `/authorize` did a fresh outbound `.well-known/openid-configuration`
  fetch — an amplification vector toward the configured `IdP` and a
  `spawn_blocking` thread held per call. `discover(issuer)` serves a live cached
  entry when one exists and otherwise falls through to the **unchanged**,
  SSRF-safe `discover_oidc_provider` (a cached entry is therefore always one that
  already passed every issuer/endpoint check — caching never bypasses those
  protections); the network fetch runs *outside* the lock, so a slow/unreachable
  `IdP` can't wedge the mutex (at the cost of a bounded cold-start thundering
  herd of concurrent misses for one issuer, each doing a real fetch). TTL is
  `DEFAULT_DISCOVERY_CACHE_TTL` (5 min) with a `DEFAULT_DISCOVERY_CACHE_MAX_ENTRIES`
  (64) issuer cap; both are tunable via `with_ttl_and_capacity`. **Staleness
  tradeoff:** if a provider rotates an `authorization_endpoint`/`token_endpoint`/
  `jwks_uri` within the window, logins started during it use the previous
  metadata until the entry expires (≤ TTL); signing-**key** rotation is handled
  separately by the id-token verifier's `OidcJwksCache` (5-min TTL plus the
  kid-miss refresh under a 60-second cooldown, see above), so a rotated key is
  picked up on the first token that uses it rather than waiting out a TTL. The
  issuer key comes from admin config, never request input, so an attacker
  cannot push the issuer cap.

- **HTTP routes.** `security_http` now exposes the two routes that put
  `initiate_oidc_login`/`complete_oidc_login` on the wire, inside the opt-in
  reviewed secured router's public auth surface:
  - `POST /api/v1/auth/oidc/authorize` calls `initiate_oidc_login` and returns
    `{ "authorizationUrl", "state" }` as JSON — consistent with the JSON bodies
    every other auth route returns (rather than emitting a `302`; turning the URL
    into a browser redirect is the frontend's job, see below). Every `initiate`
    failure — a bad config, an unreachable/invalid `IdP`, or the state store
    being momentarily at capacity (`AtCapacity`) — collapses to the same generic
    retryable `503`, leaking neither which stage failed nor which limit was hit.
  - `GET /api/v1/auth/oidc/callback?code=…&state=…` calls `complete_oidc_login`
    and, on success, returns the session **exactly** as `POST /api/v1/auth/login`
    does — the same `{ user, session }` `AuthenticationResponse` shape with the
    same opaque `spdf_at_`/`spdf_rt_` tokens — so callers treat an OIDC session
    identically to a password session. Missing/empty `code` or `state` is a
    `400`; every genuine login rejection (unknown/expired/replayed `state`,
    token-exchange or id-token/nonce verification failure, account-level denial)
    collapses to one generic `401`, so the response never reveals whether a
    CSRF-`state` miss or a verification failure tripped. Infrastructure faults (a
    poisoned store lock, a repository/crypto failure while provisioning) are
    retryable `503`s.
  Both routes are **public** (the browser has no session yet), classified in
  `security_policy::endpoint_policy` — `authorize` on `POST`, `callback` on
  `GET`, on those verbs only. The single-use `OidcLoginStateStore`, the
  `OidcDiscoveryCache`, and the id-token verifier's `OidcJwksCache` are each one
  shared `Arc` built once when the secured router is assembled and handed to the
  routes via a request extension (alongside the existing `SecurityStore`) — so
  the state `authorize` persists is the state `callback` consumes, repeated
  `authorize` calls reuse one discovery fetch, and repeated callbacks reuse one
  JWKS fetch.

- **Dedicated per-IP rate limit on `POST /api/v1/auth/oidc/authorize`.** At the
  transport boundary (`apply_transport_limits` in `lib.rs`, the same outermost
  middleware that meters all traffic), that one method+path — matched
  **exactly**, so a confusable sibling like `…/authorizeX` falls to the generic
  auth bucket — is metered against its own keyed bucket of **1 req/s sustained,
  burst 10, per IP**, stricter than the generic auth bucket (5/s, burst 30) that
  covers every other `/api/v1/auth/*` route. Rationale: each admitted authorize
  also mints a pending entry in the 4 096-capacity, 10-min-TTL login-state
  store, so at the generic auth rate two IPs could keep the store full and
  starve honest logins into its refuse-newcomer `503`; at 1/s an IP mints at
  most ~610 entries per TTL, so filling the store needs ~7 cooperating IPs
  instead of two. Exactly **one** bucket is consumed per request — the dedicated
  bucket *replaces* the auth bucket for its route (never both), so an authorize
  burst cannot drain the budget the same IP's `/login` traffic relies on, and
  vice versa. The bucket is pruned alongside the others on the same
  `RATE_LIMIT_PRUNE_INTERVAL` cadence, and its `429` response is byte-identical
  to the existing "Too many requests" shape.
  The provider config
  rides on `SecurityHttpConfig::oidc_login_provider`
  (`RuntimeConfig::oidc_login_provider_config()`); when it is `None` (no
  `security.oauth2.issuer` configured) **neither route is mounted** — a request
  gets a `404` — mirroring the "absent issuer ⇒ feature off" convention the
  Supabase JWT verifier already follows.

This completes the OIDC login path within the reviewed secured router. That
router remains opt-in and still refuses secured-mode startup in the production
binary, so — as with every other auth feature living behind this boundary — the
routes are reachable only from the integration/review harness (`app_with_reviewed_security`)
for now; the boundary is unchanged.

Out of scope here, and noted as follow-ups: the **frontend redirect/cookie UX**
(the callback returning the session tokens as JSON is the backend boundary; a
browser-facing flow that issues a `302` to the provider, then sets the session
in a cookie on callback, is a separate frontend concern). Also still out of
scope: durable (cross-process) `state` storage — the store is in-memory, so
pending logins do not survive a restart, which is acceptable for the short
bounded TTL of an in-flight login handshake. (Two earlier follow-ups have since
landed: confidential-client `client_secret` authentication and the bounded JWKS
cache in the id-token verifier — see the bullets above.)

## MFA recovery codes (backup codes)

Net-new hardening with no Java equivalent, complementing the existing TOTP MFA:
recovery codes let a user whose authenticator is unavailable still complete the
second factor. Slice 1 added the store functions plus login integration; **slice
2 exposes them over HTTP** — an enabled account is auto-issued a set the moment
MFA is turned on, a caller-scoped route regenerates that set, and the unconsumed
count is surfaced in the MFA status.

- **Generation.** `SecurityStore::generate_recovery_codes(user_id, now)` mints
  ten CSPRNG codes, each 80 bits of entropy (10 octets) Base32-encoded (RFC 4648,
  the same alphabet as the TOTP seed) and dash-grouped into four four-character
  groups for transcription (e.g. `AB2C-D3EF-GH4J-K5MN`). It replaces any prior
  set: within one Immediate transaction it `DELETE`s all of the user's existing
  rows, then inserts the new digests — so regenerating invalidates the entire old
  set. The plaintext codes are returned **exactly once** for the caller to
  display; they are never stored, logged, or returned again. The batch-building
  and transactional-replacement steps are shared helpers
  (`build_recovery_code_entries` / `replace_recovery_codes`) reused by every
  issuing path below.

- **Auto-issue on enable.** `enable_mfa(user_id, code, now)` now returns
  `Vec<String>`: in the **same** Immediate transaction that flips MFA on, it
  replaces the user's recovery-code set and returns the fresh plaintext, so an
  account can never be MFA-enabled without a live backup set. `POST
  /api/v1/auth/mfa/enable` surfaces them once as `recoveryCodes` alongside
  `enabled: true`.

- **Regeneration route.** `regenerate_recovery_codes(user_id, code, now)` mirrors
  `disable_mfa`'s re-auth: MFA must be enabled and the caller must submit a fresh,
  non-replayed TOTP step (consumed by bumping `last_used_step` in the same
  transaction that replaces the set), else `InvalidMfa`. `POST
  /api/v1/auth/mfa/recovery-codes/regenerate` returns the new `recoveryCodes` once
  and invalidates the prior set. The route is classified `NonDemoUser` (exactly
  like the sibling `mfa/setup|enable|disable` routes) and is **caller-scoped**:
  the handler operates only on `AuthContext.user_id`, never a request-supplied
  identifier — the `MfaCodeRequest` body carries only `code` and rejects unknown
  fields, so a caller cannot target another account.

- **Status count.** `GET /api/v1/auth/me` reports `mfa: { enabled,
  recoveryCodesRemaining }` (from `mfa_is_enabled` + `remaining_recovery_codes`)
  so a UI can warn when codes run low. Only the count is exposed here — never the
  plaintext codes.

- **Hashed storage.** Only the SHA-256 digest of each code is persisted, in the
  new `security_recovery_codes` table, via the same `token_digest` helper used
  for API-key and invite secrets (recovery codes are high-entropy, so SHA-256,
  not BCrypt). Codes are canonicalized before hashing (dashes/spaces dropped,
  letters upper-cased), so display grouping and casing do not affect matching.

- **Single-use consumption.** `verify_and_consume_recovery_code(user_id,
  submitted, now)` SHA-256s the normalized input and runs
  `UPDATE security_recovery_codes SET consumed_at = ? WHERE user_id = ? AND
  code_hash = ? AND consumed_at IS NULL` inside an Immediate transaction, treating
  rows-affected == 1 as success and rolling back otherwise. This mirrors the TOTP
  `last_used_step` guard exactly, so a code can never be spent twice even under
  concurrent login attempts. `remaining_recovery_codes(user_id)` reports the
  unconsumed count.

- **Login substitution.** `authenticate_login` runs the password stage **first**
  and reaches the recovery path only when MFA is **enabled** for the user. When
  the submitted `mfa_code` is not a valid, non-replayed TOTP step, it is tried as
  a single-use recovery code *before* the failure is recorded. A successful
  consume completes login exactly as a valid TOTP would — the shared lockout
  counter is cleared and the same `AuthContext` is returned for the caller to
  issue a session from. A failed recovery attempt falls through to
  `record_mfa_failure`, feeding the *same* persistent lockout counter as a failed
  TOTP or a failed password. Consequently a recovery code is strictly a second
  factor: it never bypasses a wrong password (the password stage rejects first),
  never works while MFA is disabled (that path returns before any code is
  consulted), and a consumed code never works again.

## Persistence and migration

`security_users.initial_setup_completed` defaults to false. Existing Rust
security databases receive the column through an idempotent migration.
`security_user_settings` uses `(user_id, setting_key)` as its primary key and a
cascading foreign key, so deleting an account also removes its preferences.
`security_recovery_codes` is a brand-new table created in the same
`CREATE TABLE IF NOT EXISTS` init batch (no migration needed); it carries a
cascading `user_id` foreign key (deleting an account removes its codes), a
`UNIQUE` `code_hash`, and a `user_id` index.

## Verification

Store tests cover disabled registration, case-insensitive duplicates, username
validation, durable settings replacement, initial-setup persistence, legacy
schema migration, input limits, and the transactional five-user ceiling. MFA
recovery-code store tests prove a generated code substitutes for TOTP and issues
a working session, single-use consumption (a spent code is refused a second
time), that a failed recovery attempt feeds the shared MFA lockout to the point
of account lockout, that regenerating invalidates the entire prior set while the
new set works, that codes are inert while MFA is disabled, and that a valid code
never bypasses a wrong password. Slice-2 store tests additionally prove
`enable_mfa` auto-issues ten live codes, and that `regenerate_recovery_codes`
requires a fresh (non-replayed) TOTP, refuses a malformed code, requires MFA to
be enabled, and swaps the set. HTTP recovery-code tests (in `security_http.rs`,
alongside the TOTP MFA flow) drive the full wire path: enabling MFA returns ten
codes that authenticate at the login MFA step, the regenerate route requires a
fresh TOTP and its new set logs in while the old set no longer does, `GET
/auth/me` reflects the remaining count decrementing after a code is consumed at
login, and the routes reject unauthenticated callers (`401`) and stay scoped to
the caller (another user's set is untouched; a body naming another user is
rejected). HTTP
coverage proves the public/private policy split, Java response shapes,
administrator activation, post-activation login, preference persistence, and
initial-setup completion against the real processing router. Bulk-invite HTTP
coverage exercises configuration gates, mixed results, extended roles,
case-insensitive duplicates, missing teams, capacity ordering, credential mail,
forced-change login, and retained accounts after SMTP failure. OIDC login HTTP
coverage (`tests/oidc_login_endpoint.rs`) drives the full handshake through the
routes against a loopback mock `IdP`: `authorize` → `callback` issues a working
session whose access token authenticates `GET /api/v1/auth/me`, a never-issued
`state` and a replayed `state` are each rejected `401` at the route (no session),
a mismatched `nonce` collapses to the same generic `401`, missing/empty
`code`/`state` is `400`, and both routes are absent (`404`) when no provider is
configured.
