# Account, team, invite, and user-administration routes

Route inventory for the reviewed secured router's account-management surface
in `rust/crates/stirling-processing/src/security_http.rs` (registrations in
`auth_routes`, around lines 395–468). `contracts/account-lifecycle.md`
deliberately documents only a subset in depth (register, `admin/inviteUsers`,
`updateUserSettings`, `complete-initial-setup`, MFA recovery codes, and the
generic OIDC login); this file enumerates the rest of the surface so every
mounted route has a contract home. Deep behavioral contracts that live
elsewhere are pointed to rather than repeated.

Policies come from `security_policy::endpoint_policy`: **Public** (no
session), **Non-demo** (authenticated, `ROLE_DEMO_USER` denied — every
`/api/v1/user/*` path and the listed `/api/v1/auth/*` self-service paths),
**Admin** (`ROLE_ADMIN` — `/api/v1/user/admin/*`, `/api/v1/team/*`,
`/api/v1/auth/mfa/disable/admin/*`, and the non-public invite routes).

## Session and MFA self-service — Java `AuthController` (`/api/v1/auth`)

| Method | Path | Policy | Java counterpart |
| --- | --- | --- | --- |
| `POST` | `/api/v1/auth/login` | Public | `AuthController.login` |
| `GET` | `/api/v1/auth/me` | Non-demo | `AuthController.getCurrentUser` (`GET /me`) |
| `POST` | `/api/v1/auth/refresh` | Public | `AuthController.refresh` |
| `POST` | `/api/v1/auth/logout` | Public | `AuthController.logout` |
| `GET` | `/api/v1/auth/mfa/setup` | Non-demo | `AuthController` `GET /mfa/setup` |
| `POST` | `/api/v1/auth/mfa/enable` | Non-demo | `AuthController` `POST /mfa/enable` |
| `POST` | `/api/v1/auth/mfa/disable` | Non-demo | `AuthController` `POST /mfa/disable` |
| `POST` | `/api/v1/auth/mfa/setup/cancel` | Non-demo | `AuthController` `POST /mfa/setup/cancel` |
| `POST` | `/api/v1/auth/mfa/disable/admin/{username}` | Admin | `AuthController` `POST /mfa/disable/admin/{username}` |

Java annotates `login`/`logout`/`refresh` with
`@PreAuthorize("!hasAuthority('ROLE_DEMO_USER')")`, which is vacuous for an
unauthenticated caller; Rust classifies them Public and enforces demo
restrictions on the session-bearing self-service routes instead.

`POST /api/v1/auth/mfa/recovery-codes/regenerate` (Non-demo) is documented in
`contracts/account-lifecycle.md`; the OIDC `authorize`/`callback` pair (Public,
mounted only when a provider is configured) likewise.

## Credential changes and personal API key — Java `UserController` (`/api/v1/user`)

All Non-demo (authenticated, demo accounts denied), matching Java's
authenticated controller plus its demo-account guards.

| Method | Path | Java counterpart |
| --- | --- | --- |
| `POST` | `/api/v1/user/change-username` | `UserController` `POST /change-username` |
| `POST` | `/api/v1/user/change-password` | `UserController` `POST /change-password` |
| `POST` | `/api/v1/user/change-password-on-login` | `UserController` `POST /change-password-on-login` (completes a forced first-login change) |
| `POST` | `/api/v1/user/get-api-key` | `UserController` `POST /get-api-key` (returns the caller's key, creating one if absent) |
| `POST` | `/api/v1/user/update-api-key` | `UserController` `POST /update-api-key` (rotates; response `{ "apiKey": … }`) |
| `GET` | `/api/v1/user/users` | `UserController.listUsers` (`GET /users`) |

`GET /api/v1/user/users` is the signing-participant roster: enabled users of
the caller's team with `{ id, username, displayName, teamName, enabled }`.
Callers in the system `Default`/`Internal` teams (or with no team) see only
themselves, matching Java's team-scoped branch. Two known divergences from
Java's `listUsers`: (a) Java reads `storage.signing.userListScope` —
**default `org`**, which opens the roster instance-wide; only a non-`org`
value fails closed to team scope. Rust does not read that setting and always
team-scopes, so with Java's default configuration the Rust roster is
narrower. (b) Java fills `displayName` with the username
(`UserController.java` `toUserSummaryDTO`), while Rust fills it with the
user's e-mail. Java also `403`s SaaS anonymous accounts, which have no Rust
equivalent. Administrator password changes for
*other* users send mail through the relay described in
`contracts/send-email.md`.

## User administration — Java `UserController` `/admin/*`

All Admin.

| Method | Path | Java counterpart |
| --- | --- | --- |
| `GET` | `/api/v1/user/admin/list` | See open questions |
| `POST` | `/api/v1/user/admin/saveUser` | `UserController` `POST /admin/saveUser` |
| `POST` | `/api/v1/user/admin/inviteUsers` | `UserController` `POST /admin/inviteUsers` — contract in `contracts/account-lifecycle.md` |
| `POST` | `/api/v1/user/admin/changeRole` | `UserController` `POST /admin/changeRole` |
| `POST` | `/api/v1/user/admin/changePasswordForUser` | `UserController` `POST /admin/changePasswordForUser` |
| `POST` | `/api/v1/user/admin/changeUserEnabled/{username}` | `UserController` `POST /admin/changeUserEnabled/{username}` |
| `POST` | `/api/v1/user/admin/unlockUser/{username}` | `UserController` `POST /admin/unlockUser/{username}` |
| `POST` | `/api/v1/user/admin/deleteUser/{username}` | `UserController` `POST /admin/deleteUser/{username}` |

Deleting a user preserves audit attribution by nulling only the relational
user id (`contracts/audit.md`).

## Teams — Java `TeamController` (`/api/v1/team`)

All Admin by path prefix. The six mutation routes additionally require a
verified Server or Enterprise license tier
(`EndpointEntitlement::ServerOrEnterprise`); `GET /list` is intentionally
license-unrestricted — both facts and the Java comparison live in
`contracts/license-entitlement.md`.

| Method | Path | Java counterpart |
| --- | --- | --- |
| `GET` | `/api/v1/team/list` | No same-named `TeamController` mapping (see open questions) |
| `POST` | `/api/v1/team/create` | `TeamController` `POST /create` |
| `POST` | `/api/v1/team/rename` | `TeamController` `POST /rename` |
| `POST` | `/api/v1/team/delete` | `TeamController` `POST /delete` |
| `POST` | `/api/v1/team/setOwner` | `TeamController` `POST /setOwner` |
| `POST` | `/api/v1/team/removeOwner` | `TeamController` `POST /removeOwner` |
| `POST` | `/api/v1/team/addUser` | `TeamController` `POST /addUser` |

## Invites — Java `InviteLinkController` (`/api/v1/invite`)

| Method | Path | Policy | Java counterpart |
| --- | --- | --- | --- |
| `POST` | `/api/v1/invite/generate` | Admin | `InviteLinkController` `POST /generate` (optional `sendEmail=true` uses the mail relay — `contracts/send-email.md`) |
| `GET` | `/api/v1/invite/list` | Admin | `InviteLinkController` `GET /list` |
| `DELETE` | `/api/v1/invite/revoke/{inviteId}` | Admin | `InviteLinkController` `DELETE /revoke/{inviteId}` |
| `POST` | `/api/v1/invite/cleanup` | Admin | `InviteLinkController` `POST /cleanup` |
| `GET` | `/api/v1/invite/validate/{token}` | Public | `InviteLinkController` `GET /validate/{token}` |
| `POST` | `/api/v1/invite/accept/{token}` | Public | `InviteLinkController` `POST /accept/{token}` |

The two public invitation routes are part of the frozen public bootstrap
surface asserted by the `security_policy.rs` tests.

## Related routes registered in the same block

`GET /api/v1/usage/fleet-stats` (Admin + Enterprise entitlement) is
documented in `contracts/fleet-usage.md`. The personal portal API-key routes
(`/api/v1/proprietary/ui-data/infrastructure/api-keys*`) are documented in
`contracts/ui-data.md`.

## Verification

The extensive `security_http.rs` `mod tests` fixture drives the real secured
router through login/refresh/logout, MFA setup/enable/disable and the admin
disable path, credential changes, API-key issuance and rotation, the
user-admin lifecycle, team management with the license-tier matrix, and the
invite lifecycle including the public validate/accept pair; the frozen
public-surface and per-policy matrices live in `security_policy.rs` tests,
and `tests/security_foundation_endpoint.rs` / `tests/oidc_login_endpoint.rs`
cover the end-to-end secured-runtime wiring.

## Open questions

- `GET /api/v1/team/list` has no mapping in Java's `TeamController` (the
  premium-gated controller owns only the six mutations —
  `contracts/license-entitlement.md` records the same fact). Java serves team
  listings through the proprietary UI-data aggregation instead; the Rust route
  and its response shape are Rust-defined conveniences for the same frontend
  need.
- `GET /api/v1/user/admin/list` has no same-named mapping in Java's
  `UserController`; the Java admin user roster is served through the
  proprietary UI-data aggregation (`admin-settings` view in
  `contracts/ui-data.md`). Whether a dedicated Java route exists elsewhere
  (or this is a Rust-side convenience endpoint) has not been pinned down —
  treat its response shape (`{ "users": [...] }`) as Rust-defined for now.
- Request/response bodies for the credential-change and team routes were
  verified at the route/policy level here, not field-by-field against Java;
  the `security_http.rs` tests encode the shapes Rust actually serves.
