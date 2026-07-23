# Asynchronous job management — `JobController`

Rust compatibility contract for the single-node portion of Java's general job API.

## Implemented flow

`POST /api/v1/convert/pdf/text-editor?async=true` retains its specialized PDF→JSON worker. In
addition, `?async=true` now opts the ported processing POST endpoints into a generic wrapper. It
streams the exact encoded request body into an isolated private temporary directory before
replying with `{ "jobId": "<random 128-bit id>" }`; the background worker reconstructs the
request for the normal endpoint and streams the successful response into the job directory. This
includes `POST /api/v1/pipeline/handleData?async=true`, so a complete multi-step pipeline can be
queued without changing its multipart or output contract. The wrapper is content-type-agnostic —
it persists and replays whatever bytes the original request body was, so it preserves every
endpoint's own extractor contract (multipart or, as of
`POST /api/v1/security/cert-sign/hardware/pkcs11-certificates?async=true`, a plain JSON body)
without retaining upload or output files in memory. Job status reports `complete`, `error`,
`progress`, `stage`, and `note` at `GET /api/v1/general/job/{jobId}`. The result endpoints are:

- `GET /api/v1/general/job/{jobId}/result` — download the one result file.
- `GET /api/v1/general/job/{jobId}/result/files` — JSON result-file metadata.
- `GET /api/v1/general/files/{fileId}/metadata` — one result-file's metadata.
- `GET /api/v1/general/files/{fileId}` — download the result file.
- `DELETE /api/v1/general/job/{jobId}` — mark an in-flight job cancelled. A completed job returns
  400, and an unknown job returns 404.

Results are kept for 30 minutes after completion and are deleted recursively with their private
directory after expiry. Job and file identifiers are random 128-bit values; neither identifier is
interpreted as a filesystem path.

## Deliberately not claimed

This slice is process-local. Java's `JobController` also has authenticated ownership validation,
distributed `JobStore`/Valkey write-through, sticky-410/503 cluster handling, queue position
reporting, retries/timeouts, and cancellation that can interrupt native processing. The Rust
wrapper supports the ported processing endpoints rather than every Java `@AutoJobPostMapping`
controller: job/control routes, mobile scanner, settings mutation, and Windows certificate
enumeration remain synchronous. PKCS#11 certificate enumeration does support `?async=true` — it is
a POST with a body the wrapper can stream through just like any other ported endpoint, and
PKCS#11 session login/enumeration can genuinely block on real hardware I/O (a slow token, a
blocking driver) where the others are typically fast. Windows certificate enumeration is a `GET`
request with no body, which the wrapper's `?async=true` detection (POST-only, matching Java's
`@AutoJobPostMapping` scope) does not match; making it eligible would mean loosening that
detection for every route sharing the wrapper, not just adding one more path to its allow-list, so
it remains synchronous-only rather than forcing the fit. Cancellation prevents publishing an
in-flight result but cannot forcibly stop a native worker that is already executing.

## Verification

`tests/pdf_text_editor_endpoint.rs` starts the specialized PDF→JSON job and a generic JSON→PDF
processing job. `tests/pipeline_endpoint.rs` queues a multi-step pipeline through the same wrapper.
The tests poll jobs to completion and download/list result files by job and file ID.
`tests/hardware_signing_endpoint.rs` queues a PKCS#11 certificate-enumeration job with a plain
JSON body (no real hardware in test environments, so it polls through to the same
desktop-mode-rejection failure the synchronous call produces) to prove the wrapper's
content-type-agnostic streaming against a non-multipart endpoint.
