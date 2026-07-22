# `POST /api/v1/misc/repair`

Rust compatibility contract for `RepairController`.

## Request and response

- Content type: `multipart/form-data`
- `fileInput`: one PDF, required
- Success returns `200 OK`, `application/pdf`, as `<base>_repaired.pdf`.
- PDFs that cannot be parsed by the in-process fallback return a route-specific
  `400 Bad Request`. External-tool failures and output write failures return
  `500 Internal Server Error`.

## Repair order

The standalone service retains the exact executable paths accepted during
startup dependency discovery and follows Java's repair order:

1. Ghostscript: `-o <output> -sDEVICE=pdfwrite <input>`.
2. qpdf after Ghostscript failure: `--replace-input --qdf
   --object-streams=disable <input> <output>`. Exit code `3` is accepted as
   success-with-warnings, matching Java's shared process executor.
3. When discovery found neither tool, parse the PDF object graph and save a
   normalized in-process rewrite. This repairs structural issues the parser can
   tolerate and removes obsolete incremental layout during serialization.

If at least one external tool was discovered but every available attempt fails,
the route does not silently substitute the less-capable parser rewrite.
Ghostscript and qpdf use shared Java-compatible process pools (8 and 2 sessions
by default), 30-minute configurable timeouts, concurrent output draining, and
child-tree termination on timeout. Embedded/test router construction does not
probe or invoke native tools and therefore retains deterministic in-process
behavior.

## Verification

The HTTP test verifies multipart handling, output naming, MIME type, successful
reload, and retained page structure after the normalized rewrite. Unit tests
verify Ghostscript-first ordering and arguments, qpdf fallback and warning exit
code handling, in-process fallback, and external failure behavior.
