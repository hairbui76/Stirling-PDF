# Resource grants and integration configs

## Reviewed-security scope

The opt-in reviewed Rust security router owns the Java-compatible resource-grant surface:

- `GET|POST /api/v1/admin/access/grants`
- `GET /api/v1/admin/access/grants/by-principal`
- `DELETE /api/v1/admin/access/grants/{id}`

It also owns `GET|POST /api/v1/integrations`, `GET /api/v1/integrations/capabilities`, and
`GET|PUT|DELETE /api/v1/integrations/{id}`. These routes are not exposed by the open router, and
production secure-mode startup remains fail-closed pending the independent security review.

Grant administration requires `ROLE_ADMIN`. `PORTAL` is the singleton empty resource ID;
`INTEGRATION_CONFIG` requires an ID. User/team principals must exist. A repeated grant atomically
updates the one current `USE` or `MANAGE` permission for that principal/resource pair.

## Ownership and access

Administrators and exact USER owners always use/manage a resource. A TEAM owner is a user whose
durable team membership has `is_owner=1`. `MANAGE` grants imply use. Disabled configs ignore grants
and default access, leaving only administrators/owners. `ORG_ALL` is deployment-wide in this
reviewed self-hosted router; it must be replaced with a tenant-aware resolver before a Rust SaaS
security router is enabled. `ADMINS_AND_TEAM_LEADS` follows the Java owner-sensitive rules.

The list endpoint intentionally retains Java's observable projection: own USER configs, accessible
SERVER configs, accessible configs for the caller's current team, then explicitly granted IDs. An
administrator may therefore directly fetch a config that is absent from the list.

Creation preserves the current Java restrictions for USER/TEAM/SERVER ownership, team-leader
checks, S3 personal ownership, and locked SERVER overrides. Update ignores type/scope/team changes.
Locked configs block non-admin updates but, matching Java, do not block an otherwise authorized
delete.

Authoring a free-form (`API`-type) integration is additionally gated by `requireCustomApiAllowed`,
matching Java: it requires an administrator **and** `policies.allowCustomApiIntegrations` (default
`true`), enforced server-side on both `create` and `update` (editing an API config's `config` is the
same authoring power — it holds the base URL and body). Vendor presets (`S3`/`MCP`) are never gated
here. `GET /api/v1/integrations/capabilities` (portal access required) reports
`{customApi: allowCustomApiIntegrations && isAdmin}` so the portal can show or hide the custom-API
option, but the rule is enforced in the service, not merely hidden in that response. The flag-off
refusal names `policies.allowCustomApiIntegrations`; a non-admin refusal is a distinct message.

## Secrets and persistence

Configs and grants live in the security SQLite transaction domain. Integration JSON is encrypted
with Java's AES-256-GCM row format: standard Base64 of `12-byte IV || ciphertext || 16-byte tag`,
without AAD or a version prefix. This is deliberately separate from Rust's purpose-bound
`enc:v1:` security-secret format.

Sensitive key names are masked recursively as exactly `********`. A masked/blank sensitive update
preserves the stored value; absent keys are removed under PUT replacement semantics; nested
non-sensitive maps merge. Payload size and depth are bounded. S3 save validation is enabled only
when `policies.enabled=true`; it requires explicit bucket/credentials, validates mode and HTTP(S)
endpoint syntax, and rejects private/reserved resolution unless the operator enables
`policies.allowPrivateS3Endpoints`.

Deleting a config and its grants is atomic. User deletion removes user-owned configs and all
associated/principal grants; team deletion is rejected while a TEAM-owned config exists.

## Policy references

The reviewed policy/source configuration store resolves S3 `connectionId` references at save time.
The stored connection owns bucket, region, endpoint, and credentials; only `prefix` and `mode` are
copied from the per-source/output options. Unknown, inaccessible, disabled, non-S3, or malformed
references fail without revealing whether another team's connection exists. Legacy embedded S3
options remain readable and structurally validated.

Integration deletion scans every encrypted `policy_sources.source_json` and
`policies.policy_json` row. A live source or output reference returns `409` with the Java-shaped
usage labels; grants/config are removed only after references are gone. See `policy-config.md`.

## Explicit remaining boundary

MCP remains a storage placeholder, matching its current Java integration-config behavior. The
`external-api-call` step (the `API` integration type) is now **fully ported** (all four slices). The route
`POST /api/v1/integration/external-api-call` is live, the previously fail-closed policy step dispatches
through the ported caller, and the confused-deputy step-validator maps the op to `IntegrationType::Api`.
Slice 4 added: verdict enforcement (`requireTrue` dotted lookup must be JSON `true`, else fail-closed —
strictly safer, can only refuse, never over-admit); report mode (document byte-identical + a capped
`TOOL_REPORT` header); replace mode (non-2xx / empty / resultUrl-less JSON refused); `ResultUrls`
validation (http(s)-only, no userinfo, exact-or-subdomain allowlist-host match — **not** a naive suffix,
so `evilvendor.com` never matches `vendor.com` — then SSRF-vet the *resolved* address, blocking
allowlisted-but-internal hosts and raw metadata IPs; the result fetch forwards no credentials); and
`ResultFiles` (Content-Disposition/Content-Type/name precedence + zip member selection by glob or index,
with empty/multi-match errors). ConsignO is served through the generic `bodyTemplate` (no dedicated
connector). Slice 3 adds the SSRF-safe outbound caller: redirect never followed, a 64 MiB bounded
response read, per-connection timeout, credential-free error messages, the NONE/BEARER/BASIC/HEADER/
TOKEN_LOGIN auth application, and a login-once token cache (TTL, per-credential key, 401→evict→retry-once).
Its base-host gate reuses the OIDC `resolve_to_addrs` pin + `ip_addr_is_reserved` (anti-DNS-rebinding) and
enforces an **unconditional cloud-metadata deny** (169.254.169.254/.253/.250, `fd00:ec2::254`) that runs
*before* the new `policies.allowPrivateApiEndpoints` opt-in (default `false`) — so the metadata endpoints
stay blocked even when private endpoints are allowed. Slice 2 adds `DocumentContext::build` (the templating namespace — base facts filename/
extension/contentType/sizeBytes/sha256/base64 + run facts + best-effort PDF Info metadata + `classification.*`
+ `sensitivityLabel.*`, every PDF/label field omit-not-fatal on a non-PDF/unparseable input) and `buildBody`
(the four outbound body modes: multipart with templated fields, json, raw binary, and `bodyTemplate` via
`resolveTree` with `document.base64`/`safeFilename`/`resolvedContentType` injected). Slice 1 is
the pure, network-free request-construction primitives (`proprietary_external_api.rs`),
each a 1:1 port of its Java oracle: `ExternalApiPaths::resolve` (SSRF path anchor — relative-only,
same-origin, under-base-path, `%2e`/fragment/control-char rejection), `Placeholders` (dotted `{{a.b}}`
templating with URL-path escaping and unknown→error), `ApiConnectionSettings::from` (base-URL/authType/
header/timeout validation with credential-free `Debug`), `ExternalApiHeaders` (name/value/reserved
grammar), and `MultipartBody` (per-request boundary, name-guarded fields, opaque values). S3
references are durable and deletion-safe, and the policy runner now owns paginated conditional S3
input, consume cleanup, and collision-safe conditional output delivery. Cross-node ownership and
recovery remain part of the distributed-runtime boundary.
