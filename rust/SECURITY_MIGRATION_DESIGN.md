# Security migration design

## Status

**Reviewed opt-in foundation implemented; production cutover remains disabled.**
The Rust security router now has durable local BCrypt users and lockout,
rotating opaque sessions, digest-only API keys, encrypted TOTP seeds with replay
protection, roles, teams, invitations, local-user administration, a central
endpoint policy, bounded parsing, and mutation audit records. Supabase JWT
identity is also implemented behind an optional strict JWKS verifier:
public-key algorithms only, bounded cache/refresh, issuer/expiry/audience and
required-claim checks, and durable `(issuer, subject)` mapping without email
auto-linking. Integration tests exercise the router, but the production binary
still fails closed when `DOCKER_ENABLE_SECURITY=true` is requested. Generic
OIDC login, SAML, device identity, broader resource-owner policies, SMTP delivery,
recovery flows, migration compatibility, and the final independent review
remain required before that guard can be removed.

The reviewed boundary now also scopes asynchronous job records, status,
cancellation, result metadata, and downloads to the durable authenticated user
ID. Cross-owner lookups deliberately return 404. Administrator settings routes
are only mounted inside this secured router and persist bounded restart-pending
YAML deltas with secret masking and mutation audit coverage. Managed server-certificate
administration is also secured: uploads are strictly parsed and re-wrapped, generated keys use
RSA-2048/SHA-256, filesystem links are rejected, and `certType=SERVER` resolves only from the
server-held service extension. Proprietary license entitlement, external KMS/HSM support, and an
independent key-storage review still gate production use.

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
