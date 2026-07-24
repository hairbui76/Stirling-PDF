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

## Generic OIDC login (discovery + authorization-redirect + token request/response construction only — not a login flow yet)

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
  rebinding) — is not caught by anything in this module today. That is a
  documented gap for whoever wires the next OIDC ticket's real network fetch
  against `jwks_uri` to close, most likely by pinning the resolved address
  between validation and the real request rather than re-resolving.
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

Still explicitly not done: the live fetch of the token endpoint (a separate,
SSRF-gated slice — `token_endpoint`, though it comes from a validated discovery
document, needs resolve-and-pin protection before it is POSTed to), `id_token`
signature/issuer/audience/expiry/`nonce` verification, confidential-client
(`client_secret`) authentication, the OAuth2 callback route, and session
creation. There is still no generic OIDC login flow a browser could actually
complete in Rust yet — just discovery, the authorization redirect + PKCE
secrets, and now the token-request construction and token-response parsing that
a later live-fetch slice will string together.

## Persistence and migration

`security_users.initial_setup_completed` defaults to false. Existing Rust
security databases receive the column through an idempotent migration.
`security_user_settings` uses `(user_id, setting_key)` as its primary key and a
cascading foreign key, so deleting an account also removes its preferences.

## Verification

Store tests cover disabled registration, case-insensitive duplicates, username
validation, durable settings replacement, initial-setup persistence, legacy
schema migration, input limits, and the transactional five-user ceiling. HTTP
coverage proves the public/private policy split, Java response shapes,
administrator activation, post-activation login, preference persistence, and
initial-setup completion against the real processing router. Bulk-invite HTTP
coverage exercises configuration gates, mixed results, extended roles,
case-insensitive duplicates, missing teams, capacity ordering, credential mail,
forced-change login, and retained accounts after SMTP failure.
