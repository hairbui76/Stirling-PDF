# Rust MCP contract (phase two)

## Scope

The reviewed-security Rust router exposes a stateless Model Context Protocol endpoint at `POST
/mcp` whenever `mcp.enabled: true`, in **both** of Java's `McpSecurityConfig` authentication
modes:

```yaml
mcp:
  enabled: true
  auth:
    mode: apikey   # or oauth — and, exactly as in Java, ANY value other than
                   # the exact case-insensitive string "apikey" (including a
                   # blank or a near-miss like "api-key") runs the OAuth chain
```

Beyond the AI engine's reviewed capability manifest (`stirling_describe_operation`,
`stirling_ai`), it exposes reusable file artifacts (`stirling_upload`, `stirling_download`),
Java's per-category PDF tools (`stirling_pages`, `stirling_convert`, `stirling_misc`,
`stirling_security` — see "Per-category PDF tools" below), and direct dispatch of a real
Stirling processing operation (`stirling_operation`, a Rust-only extension), reusing the
existing owner-scoped async-job store and the same in-process router dispatch the pipeline
runner uses. OAuth mode additionally serves the RFC 9728 protected-resource metadata routes
(see "OAuth/JWT mode" below). It does **not** expose SSE/session transport.

### Authorization model

Per-call authorization is Java's `McpCallContext.hasScope`: while `mcp.scopesEnabled` is true
(default), each tool checks its required scope against the caller's granted set — with Java's
exact tool messages and Java's exact check order (a tool's operation/argument resolution runs
before its scope check):

| Tool | Required scope | Refusal message |
|---|---|---|
| `stirling_upload` | `mcp.tools.write` | `Insufficient scope: stirling_upload requires 'mcp.tools.write'.` |
| `stirling_download` | `mcp.tools.read` | `Insufficient scope: stirling_download requires 'mcp.tools.read'.` |
| category tools | `mcp.tools.write` (every PDF operation) | `Insufficient scope: this operation requires 'mcp.tools.write'.` |
| `stirling_ai` | the capability's manifest scope | `Insufficient scope: this capability requires '<scope>'.` |
| `stirling_operation` (Rust-only) | `mcp.tools.write` | `Insufficient scope: this operation requires 'mcp.tools.write'.` |
| `stirling_describe_operation` | none | — |

Where the grant comes from depends on the mode, matching Java:

- **apikey**: every valid, enabled API key is statically granted both scopes
  (`McpApiKeyAuthFilter` parity — Java has no per-key scope store either), so the checks all
  pass and the effective boundary is the key plus the operation allow/block lists.
- **oauth**: the grant is the validated bearer token's real `scope` claim, so the checks
  genuinely gate callers per token.

`mcp.scopesEnabled: false` disables every scope check (Java `hasScope` short-circuit).

The endpoint is mounted only by `app_with_reviewed_security`. The normal open router is unchanged,
and the production binary continues to refuse secure mode until the existing production review
gate is lifted.

## Configuration compatibility

Rust resolves the complete Java `mcp.*` tree:

| Setting | Default | Behavior |
|---|---:|---|
| `mcp.enabled` | `false` | Master mount switch |
| `mcp.scopesEnabled` | `true` | Enables per-tool scope checks (see "Authorization model") and the metadata document's `scopes_supported` advertisement |
| `mcp.engineCapabilityRefreshMinutes` | `5` | Minimum one minute |
| `mcp.allowedOperations` | `[]` | Strict allow-list when non-empty |
| `mcp.blockedOperations` | `[]` | Deny-list applied after the allow-list |
| `mcp.maxRequestBytes` | `10485760` | Caps declared and streamed JSON bodies; non-positive values use 256 KiB |
| `mcp.maxInlineResponseBytes` | `10485760` | Caps `stirling_download`, category-tool, and `stirling_operation` inline (base64) result size; larger results report a `fileId` instead |
| `mcp.auth.mode` | `oauth` | Exactly `apikey` (case-insensitive) selects the API-key chain; anything else selects the OAuth chain |
| `mcp.auth.issuerUri` | `""` | OAuth issuer; blank fails closed against every token |
| `mcp.auth.jwksUri` | `""` | Explicit JWKS URL; blank derives it from the issuer's OpenID discovery document |
| `mcp.auth.resourceId` | `""` | This server's RFC 8707 resource identifier (primary accepted audience) |
| `mcp.auth.acceptedAudiences` | `[]` | Additional accepted audiences; with `resourceId` also blank, audience binding fails closed |
| `mcp.auth.usernameClaim` | `sub` | JWT claim matched (case-insensitively) against a provisioned Stirling username; blank falls back to `sub` |
| `mcp.auth.requireExistingAccount` | `true` | Parsed; Rust always behaves as `true` (documented fail-closed divergence, see below) |
| `endpoints.toRemove` / `endpoints.groupsToRemove` | `[]` | Endpoint-disable configuration; disabled operations vanish from category enums and lookups |

Spring-style environment names such as `MCP_SCOPESENABLED` and underscore-friendly aliases such
as `MCP_SCOPES_ENABLED` are accepted. Lists are comma-separated in environment variables.

## Authentication and identity

### API-key mode (`mcp.auth.mode: apikey`)

Every mounted MCP request requires a live Stirling per-user API key. A nonblank `X-API-KEY`
header takes precedence. Otherwise, `Authorization: Bearer <key>` is accepted with a
case-insensitive scheme. Invalid, revoked, or disabled-account keys return `401` and:

```http
WWW-Authenticate: Bearer realm="Stirling MCP (API key)"
```

The MCP boundary obtains the canonical username from `SecurityStore`; caller-provided identity
headers are never trusted. AI calls forward that trusted value as `X-User-Id`. If
`STIRLING_ENGINE_SHARED_SECRET` is configured, capability pulls and calls also send it as
`X-Engine-Auth`. (The `X-User-Id` / `X-Engine-Auth` forwarding applies identically in OAuth
mode, using the bound account's canonical username.)

Body-size enforcement runs before authentication so unauthenticated clients cannot force an
oversized allocation (both modes; Java's `McpRequestSizeFilter` also precedes its
authentication filters). Both `Content-Length` and chunked bodies are capped. Oversized
requests use the Java-compatible `413` JSON response.

### OAuth/JWT mode (any other `mcp.auth.mode`)

The port of Java's `McpSecurityConfig` OAuth2 resource-server chain. `X-API-KEY` is **not** a
credential here; only `Authorization: Bearer <jwt>` (case-insensitive scheme) is read.

**RFC 9728 metadata.** `GET /.well-known/oauth-protected-resource` and every subpath —
including the path-inserted canonical form `/.well-known/oauth-protected-resource/mcp` — are
served unauthenticated with the document Java's Spring filter + customizer emit:
`resource` (the configured `mcp.auth.resourceId`, else the request URL with the well-known
segment removed), `bearer_methods_supported: ["header"]`,
`tls_client_certificate_bound_access_tokens: true`, `authorization_servers: [<issuerUri>]`
when the issuer is set, and `scopes_supported: ["mcp.tools.read", "mcp.tools.write"]` only
while `mcp.scopesEnabled` is true (advertising scopes the IdP cannot mint breaks
spec-compliant clients). These routes exist only in OAuth mode; in apikey mode they are 404,
matching Java, where only the MCP chain customizes them.

**401 challenge.** A tokenless request (the normal discovery handshake) returns `401` with

```http
WWW-Authenticate: Bearer error="invalid_token", resource_metadata="<scheme>://<authority>/.well-known/oauth-protected-resource/mcp"
```

where scheme/authority come from the client-most `X-Forwarded-Proto` / `X-Forwarded-Host` /
`X-Forwarded-Port` values (default ports elided), falling back to the request `Host` — the
port of Java's `McpAuthenticationEntryPoint`. A **presented and rejected** token adds
`error_description="invalid_token - <reason>"` (CR/LF/quotes sanitized to spaces), and the
rejection is logged. The audience reasons are byte-identical to Java's `McpAudienceValidator`:

- unconfigured binding: `MCP audience binding is not configured; rejecting all tokens until
  mcp.auth.resource-id or mcp.auth.accepted-audiences is set.`
- mismatch: `Token audience does not include this server's resource id or an accepted
  audience (<accepted list, comma-joined>).`

and the unset-issuer reason carries Java's fail-closed-decoder text
`mcp.auth.issuer-uri is not configured`. Other reasons are Rust-authored one-liners (Java
echoes Spring's internal decoder text there, which is not pinned).

**Bearer-JWT validation** reuses the repo's hardened OIDC primitives (`oidc_id_token`'s
shape/alg-confusion pre-gate and bounded JWKS cache with kid-miss refresh cooldown, the
SSRF-safe fetch, `oidc_discovery`'s validated issuer discovery): token shape and
public-key-only algorithm allowlist first (no cache/network reachable by a malformed token),
JWKS from `mcp.auth.jwksUri` or the issuer's discovery document, signature + `iss` + `exp`
(60 s leeway) via the selected `kid`, then the RFC 8707 audience check against
`resourceId` + `acceptedAudiences` (string or array `aud`; empty accepted set fails closed).
The validated token's `scope` claim (space-split string, or string array) becomes the
caller's granted scope set — Java's `JwtGrantedAuthoritiesConverter` with the claim name
pinned to `scope` (`scp` is not consulted, as in Java).

**Account binding** (Java `McpUserBindingFilter`). The configured `mcp.auth.usernameClaim`
value (default `sub`) must be present and must resolve, case-insensitively, to an existing
**enabled** Stirling account; the call then runs as that account's canonical username (jobs,
audit, engine `X-User-Id`). Failures are `403` with Java's exact JSON:

- missing claim: `{"error":"insufficient_account","message":"Token is missing the '<claim>'
  claim used to map to a Stirling user."}`
- no enabled account: `{"error":"insufficient_account","message":"MCP access requires a
  provisioned, enabled Stirling account for this subject."}`

**Documented divergences from Java (all fail-closed or neutral):**

- `mcp.auth.requireExistingAccount=false` is parsed but **not honored**: Java would let any
  IdP-valid token through bound to its raw claim value, but the Rust job store is
  account-keyed, so Rust always requires a provisioned, enabled account and logs a startup
  warning when the flag is false.
- `exp` is required (Java's `JwtTimestampValidator` accepts a token with no `exp`); `nbf` is
  not evaluated (Java honors it when present).
- A `kid` header is required; Spring can select a key without one when the JWKS is
  unambiguous.
- The algorithm allowlist is the repo-wide public-key set (RSA/PSS/ES256/ES384/EdDSA);
  Spring's default is RS256-only. Both reject every HMAC family alg.
- JWKS and discovery fetches use the SSRF-safe client (https or loopback-http only, with
  reserved-IP resolve-and-pin rejection); Java fetches whatever URL is configured. Discovery
  reads only `/.well-known/openid-configuration` (Java also probes the
  `oauth-authorization-server` form) and requires the document's standard OIDC fields.
- The 401/403 **bodies** are small Rust-authored JSON objects; Java's 401 body is the servlet
  container's default error page (`sendError`). The `WWW-Authenticate` header and status
  codes are the contract surface, not the 401 body.
- The JOSE `typ` header is checked: absent, `JWT`, or RFC 9068 `at+jwt` /
  `application/at+jwt` (all case-insensitive) are accepted; any other value is rejected at
  the pre-gate. Java's decoder (Spring's `NimbusJwtDecoder` builder default,
  `NO_TYPE_VERIFIER`) applies no `typ` verification at all, so an exotic `typ` passes Java
  but fails closed here. RFC 9068 access tokens — what conformant IdPs such as Auth0 mint —
  verify on both sides.
- The challenge/metadata URL scheme falls back to `http` when `X-Forwarded-Proto` is absent;
  Java falls back to the request's own scheme (`request.getScheme()`). The Rust server only
  terminates plain HTTP (TLS belongs to a fronting proxy that sets the forwarded headers),
  so the fallback is equivalent in practice.
- IPv6 forwarded-authority edge: Java treats any `X-Forwarded-Host` containing `:`
  (including a bracketed port-less IPv6 literal like `[::1]`) as already carrying a port and
  never appends `X-Forwarded-Port`; Rust parses the bracketed form and appends the forwarded
  port when the literal has none — a byte-level challenge-URL difference only behind
  IPv6-host-forwarding proxies, in the more-correct direction.
- Non-GET requests to the metadata routes return `405` (axum method routing); Java falls
  through to `anyRequest().authenticated()` and returns `401` with the challenge. Cosmetic:
  RFC 9728 clients only ever GET these paths.
- As in the shipped apikey surface, the content-type check (415) runs before authentication;
  Java's filter chain authenticates before Spring MVC's media-type rejection.

## JSON-RPC behavior

The transport accepts `application/json` (parameters such as `charset` are allowed). It implements
these JSON-RPC 2.0 methods:

- `initialize` negotiates `2025-06-18`, `2025-03-26`, or `2024-11-05`, otherwise returning the
  preferred `2025-06-18` version.
- `tools/list` returns nine tools: `stirling_describe_operation`, `stirling_ai`,
  `stirling_upload`, `stirling_download`, the four category tools (`stirling_convert`,
  `stirling_pages`, `stirling_misc`, `stirling_security` — Java enum order), and
  `stirling_operation` (Rust-only extension). Java lists eight: everything except
  `stirling_operation`.
- `tools/call` dispatches all nine tools.
- `ping` and `notifications/initialized` return an empty object when they carry an ID.

Frames with an absent or JSON-null ID are notifications and return `204` without dispatch. Parse
errors use HTTP `400` / JSON-RPC `-32700`; structurally invalid requests use HTTP `400` / `-32600`;
unknown methods use HTTP `200` / `-32601`; invalid tool parameters use HTTP `200` / `-32602`.

## Engine manifest trust boundary

Capabilities are loaded on demand from `GET /api/v1/agents/capabilities`. A successful manifest is
cached for the configured interval. A later timeout, transport failure, non-200 response, invalid
JSON, or invalid top-level shape retains the last known good manifest. Disabling the AI engine
clears the AI catalog.

The manifest is bounded to 1 MiB and 256 entries. IDs, descriptions, scopes, routes, and individual
schemas have independent limits. Malformed entries are skipped. A missing scope fails safe to
`mcp.tools.write`; a missing route remains describable but cannot be invoked.

Engine routes must be relative `/api/` paths and must not contain an authority marker, scheme,
backslash, `..`, whitespace/control character, or colon. This prevents a manifest from steering the
processing service to an arbitrary host or escaping the API namespace.

## Per-category PDF tools

Java splits the PDF operations across four category tools keyed by `/api/v1/` namespace
(`OperationCategory`): `stirling_convert` (`/convert/`), `stirling_pages` (`/general/`),
`stirling_misc` (`/misc/`), `stirling_security` (`/security/`). Rust mirrors this exactly.

**Operation catalog.** Java discovers operations from its live Spring handler mappings
(POST/PUT only). Rust has no reflective route registry, so it derives the same data from two
generated files compiled in via `include_str!`: the AI engine crate's
`operation_catalog.json` **plus** `mcp_operation_supplement.json` in the processing crate.
The supplement exists because the AI catalog is a *curated* subset — its generator excludes
a fixed list of paths for AI-engine reasons (cert-sign, get-info-on-pdf, verify-pdf,
validate-signature, list-attachments, show-javascript, decompress-pdf, add-image,
add-attachments, extract-bookmarks, overlay-pdfs, and the nested convert text-editor pair) —
while Java's `McpToolCatalog` has **no** exclusion list. The supplement restores exactly the
excluded *flat* paths, so the union matches Java's id set; both files come from the same
`task engine:tool-models` run, which remains the only regeneration path. Op ids follow
Java's `extractOpId` semantics: the id is the **flat** URL tail after the category prefix,
and any tail containing `/` or `{` is skipped. Because every Java convert endpoint is nested
(e.g. `/convert/pdf/word`), **the `stirling_convert` enum is genuinely empty in Java, and
Rust reproduces that faithfully** — the tool exists, lists no operations, and reports "No
operations are currently available in this category" when called. Summaries come from the
catalog's request-model description when present, otherwise Java's prettified-id fallback
(`rotate-pdf` → `rotate pdf`); Java itself prefers the `@Operation` annotation summary, which
the generated catalog does not carry, so summary *text* may differ from Java while the shape
does not.

**Input schema** (Java `AbstractCategoryTool.inputSchema`, shape-for-shape): an object with
`additionalProperties: false`, properties `operation` (string enum of the category's enabled
op ids, description listing `- id - summary` lines), `parameters` (free-form object),
`file` (inline base64), `fileName`, `fileId`, and `required: ["operation"]`.

**Filtering.** The enum and all lookups apply, in order: the admin allow/block lists on the
**op id** (a non-empty allow-list is a strict whitelist; the block list always removes — note
`stirling_operation` applies the same lists to the full API path instead, matching each
tool's own addressing), then the endpoint-disable configuration exactly as Java filters via
`EndpointConfiguration.isEndpointEnabledForUri`. Results are sorted by id.

**Call semantics** (Java `AbstractCategoryTool.call`): a missing/blank `operation` returns
"Missing required argument 'operation' for `<tool>`"; an unknown, blocked, endpoint-disabled,
or wrong-category id returns "Unknown or disabled operation '`<id>`' for `<tool>`"; both then
list the category's available operations ("`- id - summary`" per line) or state that none are
available. The `operation` argument is read exactly as Java reads it (`JsonNode.asText()`
with only a blank check): a padded id such as `" rotate-pdf "` is looked up **untrimmed**
and fails the lookup, quoted verbatim in the error; `stirling_describe_operation` and
`stirling_ai` share the same rule. A valid call dispatches through the same
input-resolution → in-process router oneshot → result-storage path as `stirling_operation`,
with the endpoint reconstructed as `prefix + id` and the op id (not the path) naming the
operation in result and error messages, matching Java's executor — including the
missing-input-file message and the fallback of naming a result file after the op id when the
upstream response carries no filename.

**Dispatch-time failures.** The catalog is generated from the Java OpenAPI document, so it
can list an op whose route the Rust router does not implement. Such a call fails at dispatch
with a tool error carrying the op's HTTP status (e.g. `rotate-pdf failed: HTTP 404 ...`).
This is deliberate: axum exposes no cheap route-existence probe, a pre-filter would silently
hide the gap instead of surfacing it, and Java cannot hit this case at all (its catalog is
built from its own live routes). Rust's dispatch error also appends a truncated upstream
error snippet where Java reports only the status code.

**Describe.** `stirling_describe_operation` now resolves **PDF operations first**: a hit
returns `{operation, category: <tool name>, summary, endpoint, requiredScope:
"mcp.tools.write", parametersSchema}` with the catalog's parameter schema. A blocked or
endpoint-disabled PDF operation answers "Unknown or disabled operation" and **never falls
through to a same-id AI capability** (Java's `findByOperationId` rule); only ids with no PDF
operation at all consult the AI capability manifest.

## File artifacts and direct operation dispatch

`stirling_upload` (`{file: <base64>, fileName?}`) and `stirling_download`
(`{fileId: <id>}`) store and retrieve a caller's own files. Both are implemented entirely
in terms of the existing owner-scoped [`JobManager`](../crates/stirling-processing/src/job_manager.rs):
an upload is a synthetic job whose single output is the stored file, so it gets the same
private directory, `fileId` allocation, and result-TTL expiry as any real operation's
result. There is no separate storage mechanism, no new ownership model, and no change to
`JobManager` itself.

`stirling_operation` (`{operation: <API path>, file?: <base64>, fileId?, fileName?,
parameters?}`) is a **documented Rust-only extension — Java has no such tool** (Java
addresses PDF operations exclusively through the category tools' flat op ids). It runs a
real Stirling processing operation identified by its own API path
(e.g. `/api/v1/general/split-pages`), not an AI capability. Unlike the category tools it can
address nested paths, so it is also the only MCP route to the convert namespace. The path is
validated the same
way a pipeline step's operation is (`general`/`misc`/`security`/`convert`/`filter`/`ai/tools/*`
namespaces only) and checked against the same `mcp.allowedOperations`/`blockedOperations`
lists `stirling_ai` uses — operators list both AI capability ids and Stirling API paths in
that one shared allow-list. Input comes from `fileId` (an owner-scoped stored file) or
inline `file` (base64, staged under a request-scoped temporary directory); dispatch reuses
the pipeline runner's own request builder and in-process router `oneshot` call, so it is
the same internal-dispatch mechanism, not a new one. A JSON response is returned inline as
text (matching Java's "structured report" handling); any other response is streamed into a
fresh owned job file (bounded, never fully buffered in memory) and either inlined as base64
when at or under `mcp.maxInlineResponseBytes`, or reported by its new `fileId` for a later
`stirling_download` or as another operation's input.

A foreign caller's `fileId` and a nonexistent `fileId` must be indistinguishable everywhere
in this surface (`stirling_download`, the category tools' and `stirling_operation`'s
`fileId` input): both come from
`JobManager::job_file`'s existing owner check, which already returns the same "not found" for
either case — this contract must never split that into a separate "forbidden" response that
would leak whether a given id exists for someone else.

## AI call compatibility quirk

`stirling_ai` advertises a top-level `fileId` because the Java tool does, but still deliberately
ignores it: only the value under `arguments.parameters` is serialized to the engine route. If an
engine capability owns a `fileId` field, it must appear inside `parameters`. This is a distinct,
narrower `fileId` handling than `stirling_operation`'s and is preserved as-is to match Java's
existing AI-call wire behavior.

Engine responses are capped at 4 MiB. Successful response bytes are returned as MCP text. Engine
connection, status, size, or decoding failures become a successful JSON-RPC response whose tool
result has `isError: true`; details are not reflected to the caller.
