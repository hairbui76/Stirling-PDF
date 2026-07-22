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

This is deliberately a narrow vertical slice. It exposes the AI engine's reviewed capability
manifest through `stirling_describe_operation` and `stirling_ai`. It does **not** expose PDF
category tools, upload/download tools, reusable file IDs, job storage, OAuth metadata, OAuth/JWT
authentication, or SSE/session transport.

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
| `mcp.maxInlineResponseBytes` | `10485760` | Retained for compatibility; file results are out of phase-one scope |
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
- `tools/list` returns exactly `stirling_describe_operation` and `stirling_ai`.
- `tools/call` dispatches those two tools.
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

## AI call compatibility quirk

`stirling_ai` advertises a top-level `fileId` because the Java tool does, but phase one deliberately
ignores it. Only the value under `arguments.parameters` is serialized to the engine route. If an
engine capability owns a `fileId` field, it must appear inside `parameters`. This preserves Java's
current wire behavior without implying that Rust file-artifact storage has been ported.

Engine responses are capped at 4 MiB. Successful response bytes are returned as MCP text. Engine
connection, status, size, or decoding failures become a successful JSON-RPC response whose tool
result has `isError: true`; details are not reflected to the caller.
