# Rust MCP contract (phase two)

## Scope

The reviewed-security Rust router exposes a stateless Model Context Protocol endpoint at `POST
/mcp` only when both of these settings are true:

```yaml
mcp:
  enabled: true
  auth:
    mode: apikey
```

Beyond the AI engine's reviewed capability manifest (`stirling_describe_operation`,
`stirling_ai`), it exposes reusable file artifacts (`stirling_upload`, `stirling_download`),
Java's per-category PDF tools (`stirling_pages`, `stirling_convert`, `stirling_misc`,
`stirling_security` — see "Per-category PDF tools" below), and direct dispatch of a real
Stirling processing operation (`stirling_operation`, a Rust-only extension), reusing the
existing owner-scoped async-job store and the same in-process router dispatch the pipeline
runner uses. It does **not** expose OAuth metadata, OAuth/JWT authentication, or SSE/session
transport.

### Authorization parity

Java's apikey mode (`McpApiKeyAuthFilter`) statically grants **both** `mcp.tools.read` and
`mcp.tools.write` to every valid, enabled API key — there is no per-key scope store in Java
either. Granular per-caller scopes exist only in Java's OAuth/JWT mode, via token claims.
The Rust apikey boundary (a valid API key plus the operation allow/block lists, with every
mutating operation requiring the write scope Java grants unconditionally) is therefore
already at **full Java parity on authorization**. OAuth/JWT mode itself remains a documented
later phase.

The endpoint is mounted only by `app_with_reviewed_security`. The normal open router is unchanged,
and the production binary continues to refuse secure mode until the existing production review
gate is lifted.

## Configuration compatibility

Rust resolves the complete Java `mcp.*` tree, including fields reserved for later phases:

| Setting | Default | Behavior |
|---|---:|---|
| `mcp.enabled` | `false` | Master mount switch |
| `mcp.scopesEnabled` | `true` | Enforces the manifest's required scope; API keys receive read and write (as in Java's apikey mode) |
| `mcp.engineCapabilityRefreshMinutes` | `5` | Minimum one minute |
| `mcp.allowedOperations` | `[]` | Strict allow-list when non-empty |
| `mcp.blockedOperations` | `[]` | Deny-list applied after the allow-list |
| `mcp.maxRequestBytes` | `10485760` | Caps declared and streamed JSON bodies; non-positive values use 256 KiB |
| `mcp.maxInlineResponseBytes` | `10485760` | Caps `stirling_download`, category-tool, and `stirling_operation` inline (base64) result size; larger results report a `fileId` instead |
| `mcp.auth.mode` | `oauth` | Only the exact, case-insensitive value `apikey` mounts this surface |
| OAuth auth fields | Java defaults | Parsed but never advertised or used yet |
| `endpoints.toRemove` / `endpoints.groupsToRemove` | `[]` | Endpoint-disable configuration; disabled operations vanish from category enums and lookups |

Spring-style environment names such as `MCP_SCOPESENABLED` and underscore-friendly aliases such
as `MCP_SCOPES_ENABLED` are accepted. Lists are comma-separated in environment variables.

## Authentication and identity

Every mounted MCP request requires a live Stirling per-user API key. A nonblank `X-API-KEY`
header takes precedence. Otherwise, `Authorization: Bearer <key>` is accepted with a
case-insensitive scheme. Invalid, revoked, or disabled-account keys return `401` and:

```http
WWW-Authenticate: Bearer realm="Stirling MCP (API key)"
```

The MCP boundary obtains the canonical username from `SecurityStore`; caller-provided identity
headers are never trusted. AI calls forward that trusted value as `X-User-Id`. If
`STIRLING_ENGINE_SHARED_SECRET` is configured, capability pulls and calls also send it as
`X-Engine-Auth`.

Body-size enforcement runs before authentication so unauthenticated clients cannot force an
oversized allocation. Both `Content-Length` and chunked bodies are capped. Oversized requests use
the Java-compatible `413` JSON response.

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
