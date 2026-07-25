# AI engine proxy contract

This contract covers the proprietary Java `AiEngineController` surface ported
into `stirling-processing`, including both transparent engine proxies and the
Java-facing multipart workflow state machine.

## Mounted routes

### `GET /api/v1/ai/health`

- Returns `503 application/problem+json` with `AI engine is not enabled` when
  `aiEngine.enabled` is false.
- Otherwise sends `GET {aiEngine.url}/health` with `Accept: application/json`.
- Sends `X-Engine-Auth` only when `STIRLING_ENGINE_SHARED_SECRET` is nonblank.
- Sends `X-User-Id` only from the trusted Rust `AuthContext.username`. An
  inbound caller-supplied `X-User-Id` is never used as identity.
- On a successful upstream response, returns status `200`, content type
  `application/json`, and the upstream JSON body. As in Java, a non-error 3xx
  upstream response is not followed and its body is surfaced as a 200.

### `POST /api/v1/ai/pdf/edit`

- Requires `Content-Type: application/json` (parameters such as `charset` are
  accepted).
- Returns 400 with Java's controller messages when the body is invalid JSON or
  is not a JSON object.
- Always overwrites client-supplied `enabled_endpoints`. The replacement is the
  sorted intersection of the Rust processing routes and the Rust engine's
  generated PDF-operation catalog, filtered through `RuntimeConfig` endpoint
  availability. Java sends every enabled Spring mapping and the engine drops
  unknown mappings, so the engine-visible planning catalog is equivalent.
- Sends the rewritten JSON to `{aiEngine.url}/api/v1/pdf/edit` with the same
  engine-auth and trusted-user rules as the health proxy.
- Returns status `200`, content type `application/json`, and the successful
  upstream response body without interpreting the plan.

### `POST /api/v1/ai/orchestrate`

- Accepts Java-compatible multipart fields: `userMessage`, repeated
  `fileInputs[i].fileInput`, and optional
  `conversationHistory[i].role`/`content` pairs.
- Streams uploads to a private temporary workspace and assigns the first 16
  hexadecimal characters of each file's SHA-256 digest as its stable engine ID.
- Sends typed JSON turns to `{aiEngine.url}/api/v1/orchestrator`, consumes its
  bounded NDJSON stream incrementally, and preserves engine progress,
  heartbeat, result, and error semantics.
- Resolves `need_content` by extracting the requested one-based PDF pages with
  Java-compatible global page/UTF-16 character budgets. `need_ingest` extracts
  raw page text, writes the caller-owned document to `/api/v1/documents`, and
  resumes the requested capability.
- Executes `tool_call` and multi-step `plan` outcomes through the in-process
  policy dispatcher. Only configured processing endpoints and the exact
  `/api/v1/ai/tools/*` namespace are permitted; recursive orchestration and
  arbitrary internal paths are rejected.
- Preserves Java tool metadata for single/multi-input dispatch and ZIP
  fan-out. JSON responses and `X-Stirling-Tool-Report` headers become typed
  report artifacts when an engine resume is requested.
- Stores every generated or processed output individually under one
  owner-scoped Rust job. The response includes `resultFiles` descriptors and
  mirrors the first descriptor into `fileId`, `fileName`, and `contentType` for
  older clients. Files remain downloadable through
  `GET /api/v1/general/files/{fileId}`.
- One-to-one same-extension transforms reuse the input filename and expose a
  `sourceIndex`. One-to-many outputs keep their tool filenames and omit
  `sourceIndex`, matching the workbench replacement contract.

### `POST /api/v1/ai/orchestrate/stream`

- Runs the same workflow and returns `text/event-stream`.
- Emits named `progress` events for `analyzing`, `calling_engine`,
  `extracting_content`, `executing_tool`, `processing`, and nested
  `engine_progress`; upstream heartbeats become named `heartbeat` events.
- Terminates with exactly one named `result` or `error` event. The timeout is
  controlled by `stirling.ai.streamTimeoutMs`/
  `STIRLING_AI_STREAMTIMEOUTMS` and defaults to 1,800 seconds.
- A downstream disconnect drops the workflow future and its upstream reqwest
  response, cancelling engine generation and preventing further turns or tool
  steps from being scheduled. A native blocking operation already inside a
  non-cancellable library call may still finish before its temporary workspace
  is released.

## Upstream error mapping

The proxy retains `AiEngineClient` behavior:

| Condition | Public status | Detail |
| --- | ---: | --- |
| Engine disabled | 503 | `AI engine is not enabled` |
| Connect/read failure | 503 | `AI engine unreachable: ...` |
| Timeout | 504 | `AI engine timed out` |
| Upstream 4xx | same 4xx | `AI engine returned client error: {body}` |
| Upstream 5xx | 502 | `AI engine returned error: {status}` |

Errors use `application/problem+json` and include the Java-facing type, title,
status, detail, timestamp, and request path fields.

## Authentication boundary

The routes follow the existing processing security boundary. In reviewed
secured mode they require normal authentication because they are not in the
frozen public-route allowlist. In open mode they remain callable, and no user
identity is fabricated for the engine.

## Resource bounds

Multipart text fields and individual NDJSON frames are capped at 1 MiB, field
indices are capped at 10,000, and workflows stop after 16 engine turns. Tool
uploads and outputs remain streamed through files instead of accumulated in
memory. Engine long-running calls use
`aiEngine.longRunningTimeoutSeconds`/`AIENGINE_LONGRUNNINGTIMEOUTSECONDS`
(default 600 seconds); ingested personal documents use the configured security
JWT lifetime (default 1,440 minutes) as their expiry.
