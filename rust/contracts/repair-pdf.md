# `POST /api/v1/misc/repair`

Rust compatibility contract for the structural fallback in `RepairController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- Success returns `200 OK`, `application/pdf`, as `<base>_repaired.pdf`.
- PDFs that cannot be parsed return a route-specific `400 Bad Request`; output
  write failures return `500 Internal Server Error`.

## Current implementation boundary

The Rust route implements the Java controller's final, dependency-free repair
strategy: parse the PDF object graph and save a normalized rewrite. This repairs
structural issues the parser can tolerate and removes obsolete incremental
layout during serialization.

Java can first invoke Ghostscript and then qpdf when their endpoint groups are
enabled. Those external repair adapters and their configuration mapping are not
yet ported, so severely corrupt files that require either tool remain an
explicit cutover gap. The route must not become the production owner until the
external-adapter matrix is implemented and exercised with corrupt-document
fixtures.

## Verification

The HTTP test verifies multipart handling, output naming, MIME type, successful
reload, and retained page structure after the normalized rewrite.
