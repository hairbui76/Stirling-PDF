# UI data compatibility contract

These read-only endpoints are backend metadata consumed by the unchanged
client. They do not implement or modify the user interface.

## Routes

| Route | Rust response |
| --- | --- |
| `GET /api/v1/ui-data/footer-info` | Analytics choice and legal links from `settings.yml` / `custom_settings.yml`. |
| `GET /api/v1/ui-data/home` | `showSurveyFromDocker`, controlled by `SHOW_SURVEY` (unset is `true`). |
| `GET /api/v1/ui-data/licenses` | `{ "dependencies": [...] }` generated from the locked Rust dependency graph at build time. |
| `GET /api/v1/ui-data/pipeline` | Recursive JSON templates from `pipeline/defaultWebUIConfigs`, or the Java placeholder when absent. |
| `GET /api/v1/ui-data/ocr-pdf` | Sorted Tesseract `.traineddata` language names, excluding `osd`. |
| `GET /api/v1/ui-data/sign` | Shared signature-image metadata plus installed packaged/custom font metadata. |
| `GET /api/v1/ui-data/tessdata-languages` | Administrator-only installed/remote language inventory and directory writability. |
| `POST /api/v1/ui-data/tessdata/download` | Administrator-only bounded installation of selected official `.traineddata` files. |
| `GET /api/v1/general/signatures/{filename}` | A PNG/JPEG signature image: authenticated users resolve their personal asset first and then the shared fallback; open mode resolves shared assets only. |

The pipeline template directory follows Java's settings precedence:
`system.customPaths.pipeline.pipelineDir`, then
`system.customPaths.pipeline.webUIConfigsDir`, then its installation default.
Tessdata follows `system.tessdataDir`, `SYSTEM_TESSDATADIR`,
`TESSDATA_PREFIX`, then Java's Linux default path.

## No-login behavior

The open OSS mode has no authenticated user identity. Consequently `sign`
lists only `customFiles/signatures/ALL_USERS` in the `Shared` category, exactly
the subset Java exposes when its current username is empty. In the reviewed
secured router, authenticated users manage bounded personal signature assets and
administrators may manage shared assets through `/api/v1/proprietary/signatures`;
see [`personal-signatures.md`](personal-signatures.md).

The Tessdata management routes exist only in the reviewed secured router and
require `ROLE_ADMIN`, matching the proprietary Java controller. Remote listings
are cached for ten minutes. Downloads accept at most 128 bounded language names,
stream at most 64 MiB per file into the configured direct directory, reject
links and traversal, and persist through a same-directory temporary file.

The image route accepts only Java-safe basename characters, rejects symlinks,
and never resolves outside the shared directory. JPEG suffixes return `image/jpeg`;
every other Java-compatible suffix uses the Java default `image/png` response type.

## Portal UI-data projections (secured router)

`proprietary_ui_data.rs` ports the non-mutating routes of Java `ProprietaryUIDataController`
under `/api/v1/proprietary/ui-data`, as thin read projections over already-ported stores
(`SecurityStore`) and a startup snapshot of server-owned configuration. No route re-parses
settings or makes a UI decision.

| Route | Gate | Rust response |
| --- | --- | --- |
| `GET .../login` | Public | `LoginData`: `enableLogin`, `ssoAutoLogin`, `loginMethod`, OAuth2 `providerList` (`/oauth2/authorization/{name}` → display name), `altLogin`, `firstTimeSetup`/`showDefaultCredentials`, `languages`, `defaultLocale`. |
| `GET .../account` | Authenticated, non-demo | An `/auth/me` superset: the same `user`/`mfa` blocks plus account-page fields (`role`, masked `settings`, `changeCredsFlag`, `oAuth2Login`, `saml2Login`, `mfaEnabled`, `mfaRequired`). The TOTP secret is masked. |
| `GET .../audit-dashboard` | `ROLE_ADMIN` + verified Enterprise | Audit config plus the `AuditLevel` listing (`OFF`/`BASIC`/`STANDARD`/`VERBOSE`), the fixed `AuditEventType` enum, `retentionDays`, and `pdfMetadataEnabled` (`captureFileHash \|\| capturePdfAuthor`). |
| `GET .../teams` | `ROLE_ADMIN` | Teams (internal team excluded) with user counts, per-team last-activity, and team owners. |
| `GET .../teams/{id}` | `ROLE_ADMIN` | One team's members, available users (excluding this team and the internal team), per-user last-activity, and owner user IDs. |
| `GET .../infrastructure/api-keys` | Authenticated | `{ keys: [PortalApiKeyDto…] }` — the caller's own personal keys, newest first. An optional `?tier=` query is accepted for tab symmetry and ignored. |
| `POST .../infrastructure/api-keys` | Authenticated | Mints a personal key from `{ name }` and returns `CreatedApiKeyDto { key, secret }`; the plaintext `secret` is returned exactly once and never re-shown. |
| `DELETE .../infrastructure/api-keys/{id}` | Authenticated | Soft-revokes a key the caller owns; `204` on success, `404` for an unknown or cross-user id. |

`firstTimeSetup`/`showDefaultCredentials` are `true` when there are no real users (the internal
API user excluded) or exactly one real user which is the default `admin` still on its first login.
`retentionDays` is Java's raw unclamped `getRetentionDays()` (default `90`; `≤0` means retain
indefinitely). Last-activity is emitted in epoch milliseconds.

Deliberate divergences from the Java oracle:

- **SAML2 is deferred**, so SAML2 provider entries are omitted from the login `providerList` and
  `altLogin` is OAuth2-only. A SAML2-only configuration therefore yields `altLogin=false` here where
  Java would return `true`; OAuth2 providers (generic + Google/GitHub/Keycloak) are unaffected.
- An unknown `teams/{id}` returns `404` (Java accidentally `500`s from a bare `RuntimeException`);
  the internal team returns `403`. The client's `getTeamDetails` does not distinguish the two, so
  behavior is unchanged and the returned status is the semantically correct one.
- "Last activity" derives from each session's `created_at`; the Rust session store records no
  per-request `lastRequest`.

### Personal API keys (`portal_api_keys.rs`)

Ports Java `PortalApiKeysController` + `ApiKeyManagementService` onto the digest-only
`SecurityStore`. Like the Java `@ProprietaryUiDataApi` annotation these routes are **not**
Enterprise/admin/demo-gated: they classify as `Authenticated`, so the secured middleware admits
any authenticated, non-anonymous caller and each handler operates on that caller's `user_id`.
The store keeps only the SHA-256 digest, a display `name`, and a non-secret `prefix` (the raw
key's first 11 chars); the plaintext is emitted once at creation and is never recoverable
afterwards. `security_api_keys` gained `name`/`prefix`/`last_used_at` columns and an
owner index via an idempotent, column-guarded migration; per-key request counts accumulate in
`security_api_key_daily_usage(key_id, epoch_day, count)`.

`PortalApiKeyDto` (serde camelCase): `id` (the opaque store `key_id`), `name`, `prefix`,
`created` (`yyyy-MM-dd` UTC), `lastUsed` (`yyyy-MM-dd HH:mm` UTC or `"Never"`), `status`
(`active` when `revoked_at` is null, else `revoked`), and `usageToday` / `usageMonth` /
`usageTotal`. Usage is aggregated in one grouped query (no N+1): `usageMonth` is the rolling
30-day window (`epoch_day >= today - 29`) and `usageTotal` is lifetime. Each successful API-key
authentication does a best-effort usage bump and `last_used_at` stamp that can never fail or roll
back the authentication (mirroring Java's async `ApiKeyUsageRecorder`).

Create validation mirrors Java: a blank/absent `name` → `400 "Key name is required"`, a trimmed
name over 100 characters → `400`, and the 51st active key for a user → `429` (cap
`MAX_ACTIVE_KEYS_PER_USER = 50`, enforced atomically in the create transaction). Revoke is
owner-scoped and idempotent; an unknown **or** cross-user id returns `404`, never `403`, so key
ids can't be probed.

Deliberate divergences from the Java oracle:

- The key `id` is the store's opaque `key_id` string, not a DB autoincrement id.
- Java lazily migrates each user's single legacy `users.apiKey` column into a listed row; the
  digest-only Rust store has no such legacy column, so that migration step has no analogue and is
  intentionally absent.

Not ported (still deferred from this controller): the H2-only `ui-data/database` route.

## Cutover boundary

`stirling-processing/build.rs` generates the response manifest from `rust/Cargo.lock`
and the local Cargo registry package metadata at build time, so it no longer embeds
Java dependency notices. Packages whose source metadata has no SPDX `license` field
are labelled `UNKNOWN`; release packaging must fail its compliance review until those
entries and non-Cargo/native dependencies are resolved.

## Verification

`tests/ui_data_endpoints.rs` constructs an isolated installation tree and proves
all six UI-data routes read configuration, pipeline templates, tessdata, shared
signatures, custom fonts, and the bundled dependency manifest.
`tests/personal_signatures_endpoint.rs` proves authenticated personal-first
lookup and the secured management contract.
`tests/tessdata_admin_endpoint.rs` proves administrator-only routing and the
Java-compatible invalid-request response, while the module fixture proves
bounded remote discovery, caching, and atomic installation.
