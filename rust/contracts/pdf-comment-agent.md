# AI PDF comment agent

`POST /api/v1/ai/tools/pdf-comment-agent` ports the proprietary Java workflow
that adds AI-selected sticky-note comments to a PDF. It is deliberately a
processing route, not an engine/MCP capability: the public endpoint retains the
PDF and sends only bounded text geometry to the separately configured AI engine.

## Request

The endpoint accepts `multipart/form-data` with:

- `fileInput`: required, exactly `application/pdf`, maximum 50 MiB.
- `prompt`: required non-blank text, at most 4,000 UTF-16 code units.

Unexpected form fields are drained and ignored. Invalid media type, a missing
part, or an invalid prompt returns `400`; an oversize PDF returns `413`.

## Engine contract and privacy boundary

The route is disabled unless `aiEngine.enabled: true` is configured in
`settings.yml`/`custom_settings.yml`, or the equivalent `AIENGINE_ENABLED` or
`STIRLING_AI_ENGINE_ENABLED` environment override is set. It resolves the
engine base URL and timeout from `aiEngine.url`/`aiEngine.timeoutSeconds`, with
`AIENGINE_URL`, `STIRLING_AI_ENGINE_URL`, `AIENGINE_TIMEOUTSECONDS`, and
`AIENGINE_TIMEOUT_SECONDS` overrides. Defaults are `http://localhost:5001` and
120 seconds.

Processing calls `POST /api/v1/ai/pdf-comment-agent/generate` and forwards
`STIRLING_ENGINE_SHARED_SECRET` only as `X-Engine-Auth`; it never includes the
source PDF in that request. The request contains at most 2,000 PDFium text
segments, each truncated to 500 Unicode scalar values, plus the prompt. The
engine returns opaque chunk IDs. Rust resolves them against its original
segment map, discards unknown, blank, or over-2,000-character instructions,
and passes only trusted coordinates to the existing PDF annotation writer.

## Response and failures

On success the response is `application/pdf`, with a
`<source>-commented.pdf` attachment name and a JSON
`X-Stirling-Tool-Report` header:

```json
{"annotationsApplied": 2, "instructionsReceived": 3, "rationale": "..."}
```

`annotationsApplied` is the number of valid annotations actually written; it
can be lower than `instructionsReceived`. Engine disabled/unreachable and bad
engine configuration return `503`; timeout returns `504`; engine 4xx responses
are relayed, and engine 5xx or malformed JSON return `502`. An unavailable
explicitly configured PDFium runtime returns `501`; PDFs without extractable
text or malformed PDFs return `400`.

## Parity notes

Java extracts PDFBox text lines, while Rust uses PDFium text segments (normally
coalesced by PDFium by matching line and font properties). Therefore the
suggested comments and anchors can differ on documents with fragmented text;
the final annotation convention remains the same 20 × 20 point sticky-note box
at the selected segment's lower-left position. The full route needs an actual
PDFium runtime plus a configured structured-output provider in
`stirling-ai-engine`; disabled-engine and input-contract paths are covered
without either dependency.
