# Rust MCP phase-one contract

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
`stirling_ai`), it now also exposes reusable file artifacts (`stirling_upload`,
`stirling_download`) and direct dispatch of a real Stirling processing operation
(`stirling_operation`), reusing the existing owner-scoped async-job store and the same
in-process router dispatch the pipeline runner uses. It does **not** expose a per-category
tool split (`stirling_pages`/`stirling_convert`/`stirling_misc`/`stirling_security`), OAuth
metadata, OAuth/JWT authentication, or SSE/session transport. It also does not port Java's
per-caller granular scopes (`mcp.tools.read`/`mcp.tools.write`): there is no Rust API-key
scope store yet, so every tool shares the same authorization boundary as phase one (a valid
API key plus the operation allow/block list), not a narrower one.

The endpoint is mounted only by `app_with_reviewed_security`. The normal open router is unchanged,
and the production binary continues to refuse secure mode until the existing production review
gate is lifted.

## Configuration compatibility

Rust resolves the complete Java `mcp.*` tree, including fields reserved for later phases:

| Setting | Default | Phase-one behavior |
|---|---:|---|
| `mcp.enabled` | `false` | Master mount switch |
| `mcp.scopesEnabled` | `true` | Enforces the manifest's required scope; API keys receive read and write |
| `mcp.engineCapabilityRefreshMinutes` | `5` | Minimum one minute |
| `mcp.allowedOperations` | `[]` | Strict allow-list when non-empty |
| `mcp.blockedOperations` | `[]` | Deny-list applied after the allow-list |
| `mcp.maxRequestBytes` | `10485760` | Caps declared and streamed JSON bodies; non-positive values use 256 KiB |
| `mcp.maxInlineResponseBytes` | `10485760` | Caps `stirling_download` and `stirling_operation` inline (base64) result size; larger results report a `fileId` instead |
| `mcp.auth.mode` | `oauth` | Only the exact, case-insensitive value `apikey` mounts phase one |
| OAuth auth fields | Java defaults | Parsed but never advertised or used in phase one |

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
- `tools/list` returns `stirling_describe_operation`, `stirling_ai`, `stirling_upload`,
  `stirling_download`, and `stirling_operation`.
- `tools/call` dispatches all five tools.
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

## File artifacts and direct operation dispatch

`stirling_upload` (`{file: <base64>, fileName?}`) and `stirling_download`
(`{fileId: <id>}`) store and retrieve a caller's own files. Both are implemented entirely
in terms of the existing owner-scoped [`JobManager`](../crates/stirling-processing/src/job_manager.rs):
an upload is a synthetic job whose single output is the stored file, so it gets the same
private directory, `fileId` allocation, and result-TTL expiry as any real operation's
result. There is no separate storage mechanism, no new ownership model, and no change to
`JobManager` itself.

`stirling_operation` (`{operation: <API path>, file?: <base64>, fileId?, fileName?,
parameters?}`) runs a real Stirling processing operation identified by its own API path
(e.g. `/api/v1/general/split-pages`), not an AI capability. The path is validated the same
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
in this surface (`stirling_download`, `stirling_operation`'s `fileId` input): both come from
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
