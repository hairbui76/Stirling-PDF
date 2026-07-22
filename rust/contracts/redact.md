# Secure PDF redaction contract

`POST /api/v1/security/redact`, `POST /api/v1/security/auto-redact`, and
`POST /api/v1/security/redact-execute` accept their existing `multipart/form-data` request shapes
and return `<source>_redacted.pdf` as `application/pdf`.

## Manual request: `redact`

- `fileInput`: required PDF upload.
- `redactions`: optional JSON array of `{ page, x, y, width, height, color }`. `page` is
  one-based; coordinates are PDF points with a top-left origin, matching `RedactionArea`.
  Areas with missing, non-finite, non-positive, or page-zero geometry are safely ignored.
- `pageNumbers`: optional Stirling page-selection expression. Matching pages are fully redacted.
  Omit it or send an empty value to redact no whole pages.
- `pageRedactionColor`: optional full-page colour; Java `Color.decode` compatible values are
  accepted, with black as the fallback.
- `convertPDFToImage`: accepted for compatibility. Rust always produces an image-only PDF, so the
  security property does not depend on this flag.

## Secure output model

The Java manual endpoint appends opaque overlay rectangles unless `convertPDFToImage=true`; the
original text, images, annotations, and other page objects can therefore remain recoverable in its
default output. Rust deliberately does not reproduce that unsafe branch. It renders every page
with annotations and form data through `PDFium`, paints redactions directly into the RGB raster,
and writes a fresh PDF containing only those page images. Source text, annotations, embedded page
objects, and document metadata are not copied into the result.

This stronger guarantee trades vector fidelity, selectable text, form fields, links, and source
metadata for redaction safety. Rendering uses the compatible `SYSTEM_MAXDPI` bound (default 500)
and rejects pages above 100 million raster pixels with HTTP 400. A missing `PDFium` runtime returns
HTTP 501; a malformed PDF, malformed redaction JSON, or unsafe page selection returns HTTP 400.

## Automatic request: `auto-redact`

- `fileInput`: required PDF upload.
- `listOfText`: required newline-delimited search terms. Empty input returns HTTP 400.
- `useRegex`: optional boolean, default `false`. Literal mode escapes every search term.
- `wholeWordSearch`: optional boolean, default `false`. Matches use Unicode word boundaries.
- `redactColor`: optional Java `Color.decode` compatible colour, defaulting to black.
- `customPadding`: optional finite, non-negative point value. Rust adds it to Java's
  glyph-height-proportional vertical safety padding.
- `convertPDFToImage`: accepted for compatibility. The output is always an image-only PDF.

Searches are case-insensitive, matching Java's `CASE_INSENSITIVE | UNICODE_CASE` path. The Rust
regex engine deliberately rejects unsupported Java constructs such as look-around and backreferences
with HTTP 400, rather than silently producing incomplete redaction. Each match is split by visual
line and painted from PDFium character bounds before the same secure raster pipeline writes the
output. No-match documents are also re-emitted as image-only PDFs, so output security is consistent.

## Unified execution request: `redact-execute`

- `fileInput`: required PDF upload.
- `textValues` and `regexPatterns`: repeat the field once per target, or send a JSON string array.
  Exact strings are case-insensitive literals; regex values use the same bounded Rust-regex subset
  as `auto-redact`.
- `wipePages`: one-based page numbers, repeated or in a JSON integer array. Invalid and
  out-of-range values are ignored as in Java.
- `ranges`: JSON array of `{ startString, endString }`. `startString` is required; a blank
  `endString` redacts from its match through the end of the document.
- `imageBoxes`: JSON array of `{ pageIndex, x1, y1, x2, y2 }`. `pageIndex` is zero-based and the
  coordinates are native PDF user-space points (bottom-left origin), matching the Java execution
  service rather than the older manual-area endpoint.
- `redactImagePages`: omit to skip automatic image redaction; send an empty JSON array to scan all
  pages, or send one-based page numbers to limit it. Rust detects PDFium-recognised page image
  objects, descends nested Form XObjects, composes each Form's transformation matrix, and paints
  the resulting page-space bounds. Traversal is capped at 32 Form levels; a deeper Form is covered
  conservatively as one region instead of risking a missed image.
- `style`: optional JSON object (`color`, `padding`, `convertToImage`, `strategy`), with flat
  `style.color`, `style.padding`, `style.convertToImage`, and `style.strategy` equivalents.
  `AUTO`, `OVERLAY_ONLY`, and `IMAGE_FINALIZE` are accepted for wire compatibility.

The Rust endpoint always uses the secure raster finalisation model. `convertToImage=false` and
`OVERLAY_ONLY` therefore cannot produce a recoverable overlay-only PDF. Range anchors try the same
progressively permissive forms as Java: raw bounded regex, literal, collapsed letter spacing,
punctuation-tolerant alphanumeric runs, and the first non-empty line of a multiline anchor. Invalid
Java-regex-only constructs are skipped while the escaped literal candidate remains available.

Range content is planned from PDFium glyph lines and recursively discovered image bounds. A
same-baseline horizontal gap over 14 points splits line segments. Pages become two-column only when
at least three lines of width 100 points or more vote on each side of the page midpoint; otherwise
the planner safely uses a single column. Selected line/image boxes follow `(page, column, y)` reading
order from the start anchor through the end-anchor line. This avoids the previous full-width bands
and whole intermediate-page wipes. PDFium and PDFBox can still produce slightly different glyph
boxes for exotic fonts or unusual three-plus-column layouts, but the returned PDF remains an
image-only redaction result.

## Verification

HTTP tests cover manual JSON validation, automatic pattern/padding validation, and combined
execution-plan parsing. They run the routes against the pinned native runtime to prove the output
has image XObjects and contains no extractable source text.
