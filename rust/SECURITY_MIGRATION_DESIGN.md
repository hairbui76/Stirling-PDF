# Security migration design

## Status

**Reviewed opt-in foundation implemented; production cutover remains disabled.**
The Rust security router now has durable local BCrypt users and lockout,
rotating opaque sessions, digest-only API keys, encrypted TOTP seeds with replay
protection, roles, teams, invitations, local-user administration, a central
endpoint policy, bounded parsing, mutation audit records, disabled self-registration,
durable user settings, initial-setup completion, and administrator-only audit
filtering/aggregation/export/retention. Supabase JWT
identity is also implemented behind an optional strict JWKS verifier:
public-key algorithms only, bounded cache/refresh, issuer/expiry/audience and
required-claim checks, and durable `(issuer, subject)` mapping without email
auto-linking. Integration tests exercise the router, but the production binary
still fails closed when `DOCKER_ENABLE_SECURITY=true`, `SECURITY_ENABLELOGIN=true`,
or its underscored alias is requested. Generic
OIDC login, SAML, device identity, broader resource-owner policies, recovery
flows, Java-database migration compatibility, and the final independent review
remain required before that guard can be removed.

**2026-07-23 AI-assisted review pass (not a substitute for the independent
review above):** an adversarially-verified pass against this document's own
threat checklist found and fixed 5 concrete issues, each with a regression
test: invite tokens were captured verbatim into the durable audit log via the
raw request path (now redacted); enabling
`premium.enterpriseFeatures.audit.captureOperationResults` persisted
freshly-rotated API keys, invite tokens, and session-refresh tokens in
plaintext (the three routes are now explicit/`@Audited`-equivalent events, so
their results are never captured); the startup cutover guard only checked
environment variables, never the equivalent persisted `security.enableLogin`
YAML setting (now checked, with a hard failure on a non-Unicode environment
value instead of silently treating it as unset); and
`leave_user_share`/`DELETE .../shares/self` was the one storage-ownership path
that leaked cross-user file-ID existence via distinguishable 404/403
responses (now collapsed to a uniform not-found, matching every sibling
ownership check in `storage.rs`). None of this changes the status above: an
independent review is still required before the production guard is lifted.

The reviewed boundary now also scopes asynchronous job records, status,
cancellation, result metadata, and downloads to the durable authenticated user
ID. Cross-owner lookups deliberately return 404. Administrator settings routes
are only mounted inside this secured router and persist bounded restart-pending
YAML deltas with secret masking and mutation audit coverage. Managed server-certificate
administration is also secured: uploads are strictly parsed and re-wrapped, generated keys use
RSA-2048/SHA-256, filesystem links are rejected, and `certType=SERVER` resolves only from the
server-held service extension. Static proprietary route entitlement now fails closed on a trusted
Normal/Server/Enterprise tier derived from pinned-key offline verification or fixed-account Keygen
validation and machine activation. The five administrator license lifecycle routes now update that
same live verifier configuration with serialized settings persistence and bounded offline uploads.
External KMS/HSM support, seat-allocation integration, and an independent key-storage review still
gate production use.

## Java baseline

The secure variants combine username/password login, JWT issue/refresh/logout,
lockout, TOTP MFA, persistent login, API keys, roles, teams, invitations,
policies, audits, server certificates, OAuth2/OIDC, SAML2, Supabase/SaaS JWTs,
desktop OAuth callbacks, device credentials, and owner-scoped AI/workflow data.
They must be ported as one authenticated principal and tenant-isolation model,
not as independent route stubs.

## Target boundary

The secured runtime introduces an immutable `AuthContext` once per request:
user ID, authentication source, roles, team/tenant scope, token/session ID, and
request correlation ID. Handlers receive that context instead of user or team
IDs from input. One authorization service must evaluate endpoint and resource
policies before a handler can access documents, certificates, sessions, or audit
records.

Durable state requires separate repositories for users, password verifiers,
refresh/session records, API-key hashes, MFA replay state, roles,
teams/memberships/invitations, audit events, signing workflows, and owner-scoped
AI data. Schema, migration, encryption, retention, backup, and tenant-isolation
properties must be reviewed against the Java database before secure mode exists.

## Delivery order

1. Freeze Java endpoint-to-policy matrix, including public health/status/invite
   and OAuth callback routes.
2. Review data model, migration/rollback, encryption-at-rest, and retention.
3. Implement password verification/lockout and rotating, server-side revocable
   sessions or refresh tokens; fix JWT issuer/audience/expiry/algorithm/key
   rotation policy in configuration, never token input.
4. Add authentication middleware, CSRF/cookie/CORS policy, bounded request and
   token parsing, login/refresh limits, authorization checks, and audit events.
5. Port API keys, TOTP, invitations, teams, and resource policies.
6. Port OIDC/SAML/Supabase/desktop account-link only after state/nonce/PKCE,
   issuer, discovery, and key-refresh tests exist.
7. Enable `DOCKER_ENABLE_SECURITY=true` only after threat review and secure
   compatibility tests pass. Open mode is an explicit deployment choice, never a
   fallback when secure initialization fails.

## Threat checklist and review gate

- No password, MFA secret, API key, JWT, invitation, OAuth value, or certificate
  secret reaches logs, errors, metrics, audit payloads, or persistent plaintext.
- Every state-changing route verifies identity, authorization, tenant/resource
  ownership, and CSRF origin when cookies are used.
- Revocation survives restart; logout and credential changes invalidate sessions.
- Key rotation has a bounded verification overlap; malformed/oversized tokens and
  user-enumerating errors are rejected consistently.
- A security reviewer must approve the policy matrix, state model, token/session
  design, secret handling, and negative tests before production activation.
  Cutover also needs an independent cross-tenant/token/MFA/OAuth/API-key review.
