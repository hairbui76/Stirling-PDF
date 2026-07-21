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
