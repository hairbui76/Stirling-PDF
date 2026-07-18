# AI Math Auditor agent

`POST /api/v1/ai/tools/math-auditor-agent` ports the public proprietary
workflow that audits mathematical claims in one PDF and returns the engine's
JSON `Verdict`.

## Request and response

The endpoint accepts `multipart/form-data` with:

- `fileInput`: required, exactly `application/pdf`, maximum 50 MiB.
- `tolerance`: optional non-negative decimal; defaults to `0.01`.

It returns the engine's typed `Verdict` JSON. Missing/invalid PDF input and a
negative tolerance return `400`; an unavailable AI engine returns `503`; engine
timeout returns `504`; upstream engine 4xx responses are relayed, while 5xx or
malformed upstream JSON return `502`.

## Protocol and data boundary

The uploaded PDF remains in Rust processing. The service:

1. Uses PDFium to classify each page as `text`, `image`, or `mixed` from a
   bounded text scan and embedded-image presence.
2. Sends only the page-count/type `FolioManifest` to
   `/api/v1/ai/math-auditor-agent/examine`.
3. Fulfils the returned page requisition with at most 4,000 Unicode scalar text
   values per page and in-memory ruled-table CSV from the existing PDFium table
   extractor.
4. Marks OCR-requested pages as `unauditablePages` and sends the resulting
   `Evidence` to `/api/v1/ai/math-auditor-agent/deliberate` with the supplied
   tolerance.

The internal requests carry `X-Engine-Auth` only when
`STIRLING_ENGINE_SHARED_SECRET` is configured. The raw PDF is never sent to the
engine. A missing PDFium runtime returns `501` rather than an approximate audit.

## Compatibility notes

This retains Java's two-round protocol, zero-based page numbering, 20-character
text-presence threshold, 4,000-character page text limit, ruled-table-only
extraction, and Java's present OCR behaviour: OCR is requested for image/mixed
pages but not wired, so those pages are explicitly reported as unauditable.
PDFium text segments replace PDFBox page strings, so whitespace/line boundaries
can differ. Security-mode user identity forwarding remains part of the unported
authentication migration; anonymous mode matches Java's no-user path.
