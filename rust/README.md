# Stirling Rust Processing

This workspace ports Java document-processing routes while retaining the existing
browser UI and its REST contract. The executable processing service currently
implements `POST /api/v1/general/crop`,
`POST /api/v1/misc/decompress-pdf`,
`POST /api/v1/general/merge-pdfs`,
`POST /api/v1/general/multi-page-layout`,
`POST /api/v1/general/overlay-pdfs`,
`POST /api/v1/general/pdf-to-single-page`,
`POST /api/v1/general/rotate-pdf`,
`POST /api/v1/general/scale-pages`,
`POST /api/v1/general/remove-pages`,
`POST /api/v1/general/rearrange-pages`,
`POST /api/v1/security/remove-cert-sign`,
`POST /api/v1/general/remove-image-pdf`,
`POST /api/v1/general/split-pages`,
`POST /api/v1/general/split-by-size-or-count`,
`POST /api/v1/general/split-pdf-by-chapters`,
`POST /api/v1/misc/unlock-pdf-forms`, and
`POST /api/v1/general/split-pdf-by-sections` in `stirling-processing`. It also
implements all eight current analysis routes under `POST /api/v1/analysis/*`:
`page-count`, `basic-info`, `document-properties`, `page-dimensions`,
`form-fields`, `annotation-info`, `font-info`, and `security-info`. The misc
slice also owns `update-metadata` plus the regular attachment flows
`add-attachments`, `extract-attachments`, `list-attachments`,
`rename-attachment`, and `delete-attachment`. The optional
`convertToPdfA3b=true` attachment branch remains gated until the PDF/A
conversion slice is ported. All six `POST /api/v1/filter/*` pre-check routes
are also implemented: literal text, recursive image, page count, first-page
size, uploaded byte size, and first-page rotation. The security slice includes
the full structural `POST /api/v1/security/sanitize-pdf` option set.
The same slice implements `add-password` and `remove-password` for 40-bit RC4,
128-bit RC4, and 256-bit AES encryption with the existing permission fields.
Document navigation and embedded-content inspection now also implement
`show-javascript`, `extract-bookmarks`, and `edit-table-of-contents`, including
nested name trees, named destinations, nested outlines, and Unicode titles.
The misc slice also owns deterministic sticky-note creation through
`add-comments`, including native text-anchor placement and caller-coordinate
fallbacks. It now also owns `add-page-numbers`, including Java-compatible page
selection, templates, zero padding, placement, Standard 14 font metrics, and
color decoding. The `repair` route also owns the dependency-free parse-and-rewrite fallback;
its Ghostscript/qpdf adapters remain a documented cutover item. `auto-rename`
selects a largest-font title through the native text layer
while retaining a no-native development fallback. Native embedded-image
extraction now emits deduplicated PNG/JPEG/GIF ZIPs through `extract-images`.
Native `flatten` support now covers form-widget flattening and image-only
full-page rasterization with bounded, configuration-compatible DPI handling.
Blank-page removal now classifies text and empty pages structurally, renders
only image-bearing pages, and emits Java-compatible grouped PDF archives.
Form inspection now covers the existing `fields` and `fields-with-coordinates`
JSON contracts plus quoted CSV and valid OOXML/XLSX exports, including optional
value overrides. Form mutation also covers `delete-fields`, including the
legacy name payload shapes and structural widget cleanup, plus strict `fill`
for text, button, and choice values with optional native form flattening. The
form cluster's seventh route, `modify-fields`, supports property and type
updates with collision-safe renaming. Together, the service currently owns 57 compatibility
`POST /api/v1/*` routes,
plus its health endpoint.

Install the pinned PDFium runtime and run locally from the repository root:

```powershell
task rust:install
task rust:run
```

It listens on `127.0.0.1:8081`. The service is not yet wired as the production route
owner; the Java implementation remains the compatibility oracle until every documented
limit in the per-route files under `contracts/` is removed and parity tests pass.

`task rust:install` downloads PDFium revision 7543 for the current platform, verifies
its pinned SHA-256 digest, and keeps the runtime under the ignored `rust/.pdfium`
directory. Deployments may instead set `STIRLING_PDFIUM_LIBRARY_PATH` to an absolute
PDFium shared-library path or its containing directory. A configured runtime is treated
as required; a bad path fails the request instead of silently switching engines.

The merge slice uses PDFium page import and a bounded-memory incremental bookmark/TOC
writer. The rotate slice uses PDFium's intrinsic page rotation. `lopdf` remains as the
no-PDFium development fallback, for sequential metadata inspection during title/date
sorting, and for the targeted PDFBox-compatible signature-field flattening pass when
PDFium detects signatures. It is not used to build the combined document on the
configured native merge path.

Validate the workspace:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The direct Cargo commands use the compatibility implementation when PDFium is not on
the system library path. `task rust:check` installs and configures PDFium so the native
processing paths are exercised by the endpoint tests.
