# Stirling Rust Processing

This workspace ports Java document-processing routes while retaining the existing
browser UI and its REST contract. The executable processing service currently
implements `POST /api/v1/general/crop`,
`POST /api/v1/general/booklet-imposition`,
`POST /api/v1/misc/auto-split-pdf`,
`POST /api/v1/misc/compress-pdf`,
`POST /api/v1/misc/decompress-pdf`,
`POST /api/v1/misc/extract-image-scans`,
`POST /api/v1/general/edit-text`,
`POST /api/v1/convert/pdf/epub`,
`POST /api/v1/convert/pdf/xlsx`,
`GET /api/v1/config/app-config`,
`GET /api/v1/config/login-disclaimer`,
secured `GET /api/v1/admin/login-agreement`,
secured `GET /api/v1/admin/login-agreement/{locale}`,
secured `PUT /api/v1/admin/login-agreement/{locale}`,
`GET /api/v1/config/endpoint-enabled`,
`GET /api/v1/config/endpoints-enabled`,
`GET /api/v1/config/endpoints-availability`,
`GET /api/v1/config/group-enabled`,
`GET /api/v1/settings/get-endpoints-status`,
`POST /api/v1/settings/update-enable-analytics`,
conditional `POST /api/v1/general/send-email`,
`GET /api/v1/info/status`,
`GET /api/v1/info/health`,
`GET /api/v1/info/load`,
`GET /api/v1/info/load/unique`,
`GET /api/v1/info/load/all`,
`GET /api/v1/info/load/all/unique`,
`GET /api/v1/info/requests`,
`GET /api/v1/info/requests/unique`,
`GET /api/v1/info/requests/all`,
`GET /api/v1/info/requests/all/unique`,
`GET /api/v1/info/uptime`,
`GET /api/v1/info/wau`,
`GET /api/v1/ui-data/footer-info`,
`GET /api/v1/ui-data/home`,
`GET /api/v1/ui-data/licenses`,
`GET /js/additionalLanguageCode.js`,
`GET /robots.txt`,
`GET /api/v1/ui-data/pipeline`,
`GET /api/v1/ui-data/ocr-pdf`,
`GET /api/v1/ui-data/sign`,
`GET /api/v1/general/signatures/{filename}`,
secured `/api/v1/proprietary/signatures` management,
`POST /api/v1/mobile-scanner/create-session/{sessionId}`,
`GET /api/v1/mobile-scanner/validate-session/{sessionId}`,
`POST /api/v1/mobile-scanner/upload/{sessionId}`,
`GET /api/v1/mobile-scanner/files/{sessionId}`,
`GET /api/v1/mobile-scanner/download/{sessionId}/{filename}`,
`DELETE /api/v1/mobile-scanner/session/{sessionId}`,
`POST /api/v1/general/merge-pdfs`,
`POST /api/v1/general/multi-page-layout`,
`POST /api/v1/general/overlay-pdfs`,
`POST /api/v1/general/pdf-to-single-page`,
`POST /api/v1/convert/pdf/img`,
`POST /api/v1/convert/pdf/csv`,
`POST /api/v1/convert/pdf/video`,
`POST /api/v1/convert/img/pdf`,
`POST /api/v1/convert/cbr/pdf`,
`POST /api/v1/convert/cbz/pdf`,
`POST /api/v1/convert/pdf/cbr`,
`POST /api/v1/convert/pdf/cbz`,
`POST /api/v1/convert/pdf/pdfa`,
`POST /api/v1/convert/pdf/text`,
`POST /api/v1/convert/pdf/markdown`,
`POST /api/v1/convert/html/pdf`,
`POST /api/v1/convert/markdown/pdf`,
`POST /api/v1/convert/ebook/pdf`,
`POST /api/v1/convert/eml/pdf`,
`POST /api/v1/convert/url/pdf`,
`POST /api/v1/convert/svg/pdf`,
`POST /api/v1/convert/vector/pdf`,
`POST /api/v1/convert/pdf/vector`,
`POST /api/v1/misc/add-image`,
`POST /api/v1/misc/add-stamp`,
`POST /api/v1/security/add-watermark`,
`POST /api/v1/security/auto-redact`,
`POST /api/v1/security/redact`,
`POST /api/v1/security/redact-execute`,
`POST /api/v1/security/verify-pdf`,
`POST /api/v1/security/get-info-on-pdf`,
`POST /api/v1/security/validate-signature`,
`POST /api/v1/security/timestamp-pdf`,
`POST /api/v1/general/rotate-pdf`,
`POST /api/v1/general/scale-pages`,
`POST /api/v1/general/remove-pages`,
`POST /api/v1/general/rearrange-pages`,
`POST /api/v1/security/remove-cert-sign`,
`POST /api/v1/general/remove-image-pdf`,
`POST /api/v1/general/split-pages`,
`POST /api/v1/general/split-by-size-or-count`,
`POST /api/v1/general/split-pdf-by-chapters`,
`POST /api/v1/general/split-for-poster-print`,
`POST /api/v1/misc/unlock-pdf-forms`, and
`POST /api/v1/general/split-pdf-by-sections` in `stirling-processing`. It also
implements all eight current analysis routes under `POST /api/v1/analysis/*`:
`page-count`, `basic-info`, `document-properties`, `page-dimensions`,
`form-fields`, `annotation-info`, `font-info`, and `security-info`. The misc
slice also owns `update-metadata` plus the regular attachment flows
`add-attachments`, `extract-attachments`, `list-attachments`,
`rename-attachment`, and `delete-attachment`. The optional
`convertToPdfA3b=true` branch runs the shared Ghostscript PDF/A-3b conversion,
then records each attachment in the required associated-file catalog metadata.
All six `POST /api/v1/filter/*` pre-check routes
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
color decoding. Booklet imposition now covers saddle-stitch ordering, duplex pass selection,
spine placement, gutters, borders, crop boxes, and rotated source pages. The
poster-print split route emits target-sized, top-to-bottom grid cells with
right-to-left ordering and rotation-aware CropBox normalization. The
QR auto-split route detects the three Stirling divider values with ZXing-compatible
hybrid/global binarization, native 150/high-DPI rendering, and duplex back-page
removal. The
`repair` route follows Java's Ghostscript-first, qpdf-second recovery chain with
bounded shared process pools and uses the dependency-free parse-and-rewrite
fallback when startup discovery finds neither tool. `auto-rename`
selects a largest-font title through the native text layer
while retaining a no-native development fallback. Native embedded-image
extraction now emits deduplicated PNG/JPEG/GIF ZIPs through `extract-images`.
Native PDF-to-image conversion now covers selected-page PNG/JPEG/GIF/WebP
output, color/greyscale/binary rendering, annotation control, per-page ZIPs,
and vertically combined images without the legacy Python WebP helper.
The inverse image-to-PDF route accepts ordered PNG/JPEG/GIF/WebP/BMP uploads
and multi-frame TIFF, applies EXIF orientation, color modes, alpha masks, all
three fit policies, A4 auto-rotation, and the Java-compatible default Stirling
Info metadata without Java or PDFium. Booklet and poster output also rebuild
source Info dictionaries through that same fresh-document policy.
Comic-book conversion now supports CBZ and CBR in both directions: naturally
sorted archive images become pixel-sized PDF pages, while PDFium renders ordered
RGB PNG pages into the existing numbered archive contracts. CBR extraction uses
`unrar` or a read-only 7-Zip fallback; creating CBR requires the `rar` CLI.
PDF/A-1b, PDF/A-2b, PDF/A-3b, and PDF/X conversion uses a sandboxed Ghostscript
adapter with embedded sRGB/Gray ICC profiles; strict PDF/A validation uses the
existing veraPDF command seam when configured.
Image-scan extraction accepts raster images or PDF pages, runs the median-background,
mask/contour, and Canny/Hough splitter natively in Rust, and returns one PNG or a
safe ZIP of detected photos without a Python/OpenCV runtime.
PDF-to-video conversion renders annotated PDFium PNG frames, applies an embedded-font
diagonal watermark without shell interpolation, and encodes MP4 or WebM through FFmpeg.
Set `STIRLING_PROCESSING_FFMPEG_COMMAND` to select a particular executable; the route returns
501 when it is unavailable. The current Java route is commented out while FFmpeg CVEs are assessed,
so enabling the Rust route is an explicit deployment decision.
PDF-to-CSV mirrors Java's Tabula lattice mode: it extracts only fully ruled tables from PDFium
paths and visible character bounds, returning no content, one quoted CSV, or a ZIP of per-table
CSVs as appropriate.
Manual redaction accepts the existing redaction-area JSON and whole-page selection fields, then
always renders a new image-only PDF after painting rectangles. That intentionally replaces Java's
unsafe default overlay output: source text, annotations, page objects, and metadata are not copied
into the redacted PDF. Automatic redaction adds case-insensitive literal or bounded-regex matching
from PDFium glyph bounds before using that same secure output model. Unified execution-plan
redaction supports text, regex, pages, ranges, image boxes, and detected images, but likewise
always rasterises rather than honouring Java's unsafe overlay-only branch.
`edit-text` now applies ordered literal edits to selected-page `Tj`/`TJ` text-showing
content streams, with optional whole-word matching and strict active-font encoding checks;
cross-operation/glyph-level matching remains an explicit editor-parity gap.
PDF text conversion now emits UTF-8 TXT and valid Unicode, text-only RTF
directly in Rust, removing LibreOffice from that route.
PDF compression now combines native structural recompression, target-size
level escalation, embedded-image downsampling/grayscale, native 1-bit line-art,
and optional safe QPDF/Ghostscript adapters without rasterizing text/vector
pages.
Image overlay now accepts raster images and safe SVG content, preserves SVGs as
vector Form XObjects, retains raster alpha, and applies intrinsic-size placement
to the first or every page without Java.
Stamping now covers selected-page text and raster-image stamps, Unicode font
fallback, rotation, opacity, grid/coordinate placement, dynamic date/page/file/
metadata tokens, alpha masks, and Java-style page expressions.
Watermarking now tiles Unicode vector text or alpha-aware raster images across
every page with Java-compatible rotation, spacing, color, opacity, and optional
full-page `PDFium` rasterization.
SVG-to-PDF conversion preserves vector content, intrinsic page sizes, A4
dimension fallback, separate PDF/ZIP output, and combined multi-size pages.
Ghostscript-backed vector conversion now covers PS/EPS/EPSF-to-PDF and
PDF-to-EPS/PS/PCL/XPS, including PDF passthrough, prepress mode, platform
executable discovery, explicit command configuration, and response media types.
PDF standards verification now detects PDF/A, PDF/UA, and WTPDF declarations
from bounded XMP metadata in Rust, emits the Java-compatible non-PDF/A result
natively, and maps safe veraPDF CLI XML reports into the existing JSON contract.
Comprehensive PDF inspection now emits the existing metadata, document,
compliance, encryption, permission, form, embedded-content, per-page, and summary
JSON shape through `get-info-on-pdf`, including the legacy HTTP-200 error response.
Native signature validation now verifies detached CMS integrity and digest
attributes, detects unsigned appended revisions, applies signing-time semantics,
and builds X.509 paths from a custom or native trust anchor while preserving the
existing JSON result shape.
RFC 3161 document timestamping now creates a native incremental PDF revision,
sends only the SHA-256 signature byte ranges to an allowlisted TSA, rejects
redirects, applies Java-compatible 30-second network limits, validates the
returned imprint and nonce, and preserves earlier signed revisions.
HTML-to-PDF now sanitizes HTML and packaged ZIP inputs with a parser-backed
allow-list, removes external render-resource fetches, applies ZIP safety limits,
and renders through the existing WeasyPrint integration when available.
The AI document-creation tool accepts its structured model only, escapes every
model value into a fixed A4 template, and permits only six-digit hexadecimal
colour overrides before using that same renderer; see
[`contracts/create-pdf-agent.md`](contracts/create-pdf-agent.md).
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
updates with collision-safe renaming. The email converter natively parses MIME EML and
Outlook MSG, produces sanitized HTML (including bounded CID images), and renders PDF
through the shared WeasyPrint adapter with optional bounded attachment embedding.
URL-to-PDF is opt-in and pins its initial public HTTP(S) fetch to DNS-validated
addresses before sanitizing and rendering, preventing local-network SSRF.
The configuration layer loads `configs/settings.yml` followed by
`configs/custom_settings.yml` below `STIRLING_BASE_PATH`. It provides the public
configuration and endpoint-availability routes used by the unchanged UI; see
[`contracts/runtime-config.md`](contracts/runtime-config.md) for supported values
and explicit infrastructure gaps. It also exposes a bounded, locale-aware
login-disclaimer reader for anonymous/no-login operation; see
[`contracts/login-disclaimer.md`](contracts/login-disclaimer.md). The reviewed secured router also
provides administrator-only, atomic login-agreement listing, replacement, and clearing while the
public reader remains lock-free; see
[`contracts/login-agreement-admin.md`](contracts/login-agreement-admin.md). The same YAML timestamp settings now feed the
normal Rust server constructor, with timestamp environment aliases taking precedence.
It also implements the anonymous one-time analytics choice used during onboarding:
multipart or URL-encoded `enabled` is persisted to `settings.yml` and immediately
reflected in app-config; repeated choices return Java-compatible `208`.
The mobile-scanner transfer slice now keeps browser/desktop QR sessions in a
private process-local temporary workspace, with safe names, ten-minute inactivity
expiry, immediate download cleanup, and the existing feature gate; see
[`contracts/mobile-scanner.md`](contracts/mobile-scanner.md).
The synchronous pipeline route, `POST /api/v1/pipeline/handleData`, streams
files through the Rust route handlers, supports chained single-input operations,
the confirmed all-`fileInput` multi-input tools, ZIP fan-out, and strict internal
dispatch rules. The processing binary also runs the configured watched-folder
pipeline lifecycle without starting it for router tests; see
[`contracts/pipeline.md`](contracts/pipeline.md).

The read-only UI-data endpoints now provide footer/legal configuration, survey
visibility, dependency notices, pipeline templates, OCR language discovery, and
shared signature/font metadata to the unchanged client; see
[`contracts/ui-data.md`](contracts/ui-data.md). Its dependency-notice manifest is
generated from the Rust lockfile during build; `UNKNOWN` entries and native-tool
notices remain release-compliance gates.

The reviewed secured router also provides the proprietary administrator-only
Tessdata inventory and downloader. It preserves the installed/available/writable
response contract while adding bounded downloads, atomic replacement, and
link-safe storage under the configured Tessdata directory; see
[`contracts/ui-data.md`](contracts/ui-data.md).

The reviewed secured router also owns authenticated saved-signature management
under `/api/v1/proprietary/signatures`. It preserves the personal/shared JSON
and filesystem contract, personal quotas, administrator-only shared mutations,
and personal-first lookup through the existing general signature-asset route;
see [`contracts/personal-signatures.md`](contracts/personal-signatures.md).

The implemented compatibility surface is listed in
[`PORT_STATUS.md`](PORT_STATUS.md) and covered by focused endpoint suites. A
fixed route total is intentionally deferred to the versioned baseline-to-Rust
manifest so nested secured routers and conditional endpoints are counted by
method and path rather than inferred from source literals.

Install the pinned PDFium runtime and run locally from the repository root:

```powershell
task rust:install
task backend:dev
```

`task backend:dev`, `task dev`, and the default `task dev:all` now select the
Rust processing service for open-mode local development. `backend:dev` listens
on `127.0.0.1:8080` by default; `task rust:run` provides the same direct Rust
entry point. Set `PORT` on either Task command, or set `STIRLING_PORT` (or the
Spring-compatible `SERVER_PORT`) when invoking the binary directly. Port `0`
requests an OS-assigned ephemeral port, and startup reports the bound port in
the desktop-compatible `Stirling-PDF running on port: <port>` format. The Java
oracle remains available as `task backend:dev:java`; portal and SaaS development
also remain on their explicit Java profiles. This local default is not the
production-container cutover: Java remains the packaged route owner until every
documented limit in the per-route contracts is removed and the production proof
matrix passes.

For desktop migration validation only, set `STIRLING_NATIVE_BACKEND_PATH` to an
absolute path for a Rust processing executable. The Tauri host then starts it
with an ephemeral port and explicit desktop/base-path settings, migrates the
legacy workspace, accepts the stable startup handshake from either output
stream, and fails a bounded startup on early process exit. The processing binary
prints that handshake even when `RUST_LOG` is unset, exits when the PID/start-time
identity of its Tauri parent disappears, and atomically initializes the packaged
settings template plus empty override only on a fresh install. Java remains the
default when the variable is absent; the Rust binary and PDFium are not yet bundled
or enabled for production desktop builds. Upgrade-time settings migration,
sidecar/PDFium packaging, cross-platform bundle proof, and the default switch remain
cutover gates. See `contracts/desktop-native-startup.md`.

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
