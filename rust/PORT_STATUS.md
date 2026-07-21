# Rust Port Status

Tracks the Java → Rust port of the Stirling-PDF backend (UI excluded). The Rust
service lives in this `rust/` workspace as the `stirling-processing` crate — an
axum HTTP service mirroring the Java `/api/v1/...` endpoints.

**Latest validation:** `task rust:check` passes the full locked workspace with
the pinned PDFium runtime: formatting, strict workspace/all-target clippy, 107
AI-engine unit/binary/integration tests, 362 processing library unit tests, every endpoint
integration suite, and doc tests. External-runtime happy paths remain
conditional on their respective tools and services.

## Ported compatibility endpoints

Each ported surface has a `contracts/<name>.md` compatibility document and focused
unit/integration coverage. Coverage spans merge/split/rearrange/remove/rotate,
crop/scale/layout/booklet/poster, page numbers/stamp/watermark/comments/AI comments/attachments,
metadata/info/analysis/filters, forms (inspect/fill/modify/delete/export), password/
sanitize/flatten/repair/decompress, image↔PDF, PDF→image/text/vector/comic-book,
SVG→PDF, signature validation/verify, bookmarks/TOC, blank-page removal,
auto-rename/auto-split, plus:

- `misc/replace-invert-pdf` — FULL_INVERSION (PDFium raster + invert),
  COLOR_SPACE_CONVERSION (Ghostscript CMYK), and pure-Rust HIGH_CONTRAST/CUSTOM page-background
  plus page/nested-Form text recoloring with Java-compatible color parsing.
- `misc/scanner-effect` — full image pipeline (gradient border, rotation, feather,
  box-blur, brightness/contrast/yellowing/noise) with quality presets + DPI clamp.
- `ai/tools/pdf-comment-agent` — bounded multipart PDF comment workflow: PDFium
  positioned text segments are submitted to the Rust AI engine, trusted returned
  IDs become 20-point sticky-note annotations, and the PDF response carries a
  Java-compatible applied/instructions report. See `contracts/pdf-comment-agent.md`.
- `ai/tools/create-pdf-from-html-agent` — structured AI-document model → fixed,
  escaped A4 HTML template → WeasyPrint PDF. Arbitrary HTML is never accepted by
  this agent route; only six-digit hexadecimal colour overrides are allowed. See
  `contracts/create-pdf-agent.md`.
- `ai/tools/math-auditor-agent` — keeps the PDF locally while orchestrating the
  Rust engine's examine/deliberate rounds with bounded PDFium text and ruled-table
  CSV evidence; OCR requests remain explicitly unauditable as in Java. See
  `contracts/math-auditor-agent.md`.
- `ai/health`, `ai/pdf/edit`, `ai/orchestrate`, and `ai/orchestrate/stream` —
  Java-compatible integration with the separately deployed Rust AI engine. The
  multipart workflow routes drive bounded NDJSON turns, content extraction/RAG
  ingest, local policy tool execution, report resume, owner-scoped multi-file
  downloads, and SSE progress/heartbeat/result/error delivery with disconnect
  cancellation. Engine auth and user identity come only from trusted runtime
  state, and anonymous create/edit/draft orchestration remains available while
  ACL-backed question/review routing requires identity. See `contracts/ai-proxy.md`.
- `convert/file/pdf` — office/text → PDF via LibreOffice shell-out, with strict HTML
  sanitization and bounded OOXML/ODF package rewriting that removes external relationships.
- `convert/pdf/word`, `convert/pdf/presentation`, `convert/pdf/xml` — PDF → office
  via LibreOffice shell-out (`--infilter=writer_pdf_import`/`impress_pdf_import`),
  single-file or ZIP output.
- `misc/ocr-pdf` — OCR via OCRmyPDF shell-out (sidecar → ZIP, `removeImagesAfter`
  via Ghostscript). Tesseract page-by-page fallback NOT ported (→ 501).
- `convert/pdf/html` — PDF → HTML via `pdftohtml -c` shell-out, all output files
  bundled into a ZIP.
- `convert/pdf/markdown` — native text-first Markdown in page order with literal
  escaping, bullets, and soft-hyphen repair. Java's geometry-aware heading/table/
  column/image inference remains a documented parity gap.
- `convert/html/pdf` — sanitized HTML/ZIP package → PDF via WeasyPrint, including
  parser-backed active-content removal, resource SSRF restrictions, and ZIP limits.
- `convert/markdown/pdf` — CommonMark/GFM table Markdown or Markdown ZIP package →
  sanitized HTML → PDF via the shared WeasyPrint renderer.
- `convert/ebook/pdf` — EPUB/MOBI/AZW3/FB2/TXT/DOCX → PDF via Calibre, including
  font/TOC/page-number flags and best-effort Ghostscript e-reader optimization.
- `convert/pdf/epub` — PDF → EPUB/AZW3 through Calibre's `pdftohtml` engine,
  including Java's heuristic, CSS filtering, chapter-detection, and device-profile flags.
- `convert/eml/pdf` — native MIME EML and Outlook MSG parsing, CID-image inlining,
  safe HTML export, and WeasyPrint PDF rendering with bounded PDF attachments.
- `convert/url/pdf` — opt-in, DNS-pinned public HTTP(S) fetch → sanitized HTML →
  WeasyPrint PDF, with Java-compatible redirects for disabled or rejected targets.
- `convert/cbr/pdf` — RAR/CBR → naturally ordered image PDF through `unrar` or
  a read-only 7-Zip fallback, with bounded extraction and link rejection.
- `convert/pdf/cbr` — PDFium-rendered PNG pages → RAR-backed CBR through `rar`.
- `convert/pdf/pdfa` — PDF/A-1b/2b/3b and PDF/X through Ghostscript, with embedded
  sRGB/Gray ICC profiles and optional strict veraPDF validation.
- `misc/extract-image-scans` — PDFium page rasterization or raster upload → the
  native Rust median-background, mask/contour, and Canny/Hough splitter, with
  bounded and link-safe PNG/ZIP output and no Python/OpenCV runtime.
- `convert/pdf/video` — PDFium-rendered frames, native embedded-font watermarking, and
  FFmpeg MP4/WebM encoding. The current Java mapping is commented out while FFmpeg CVEs are
  assessed; Rust exposes the route as a documented opt-in cutover endpoint.
- `convert/pdf/csv` and `convert/pdf/xlsx` — Java-compatible ruled-table (Tabula lattice)
  extraction through PDFium paths and character bounds; no-table 204, CSV/ZIP, or a
  one-sheet-per-table XLSX output.
- `security/redact` — manual areas and whole-page redaction through a deliberately secure,
  image-only PDF pipeline; unlike Java's default overlay branch, source page objects are never
  copied to the response.
- `security/auto-redact` — case-insensitive literal or bounded-regex text matching from PDFium
  glyph bounds, line-aware painted boxes, and the same image-only output guarantee.
- `security/redact-execute` — unified exact/regex, page wipe, range, image-box, and detected-image
  redaction plan, finalised as an image-only PDF regardless of legacy overlay strategy hints.
- `convert/pdf/text-editor/{metadata,partial,page,fonts,clear-cache}` — lazy editor job cache with
  30-minute expiry, per-page COS projection, bounded page-scoped font resources/programs and
  ToUnicode extraction, cache clear, and source-preserving partial export.
- `general/job/{jobId}`, its `/result` and `/result/files` children, and
  `general/files/{fileId}`/`metadata` — configurable-TTL private single-node async job storage and
  result download. `convert/pdf/text-editor?async=true` retains its specialized worker; the
  other ported processing POST endpoints now support generic `?async=true` by streaming their
  original multipart request and result through the job directory instead of RAM. Secured-mode
  jobs and files are isolated by durable local user ID and return 404 across owners. A bounded
  resource-weighted queue gates light/medium/heavy/extra-heavy work, supports queued cancellation
  and queue positions, and exposes Java-compatible admin job/queue stats and cleanup.
- `edit-text` — ordered literal find/replace in selected-page PDF text-showing content streams,
  whole-word filtering, and strict active-font encoding validation.
- `config/app-config`, endpoint/group status/availability,
  `settings/get-endpoints-status`, and `settings/update-enable-analytics` —
  base/custom YAML configuration, public bootstrap values, endpoint-disable status,
  timestamp configuration, and one-time persisted anonymous analytics consent.
- Secured `admin/settings`, `/delta`, `/section/{section}`, and `/key/{key}` — bounded YAML
  delta mutation with section/key allowlisting, transactional nested writes, pipeline-path overlap
  validation, secret masking, masked-placeholder rejection, pending-restart tracking, and
  administrator-only HTTP coverage. Rust delegates restart to its process supervisor.
- Secured `admin/server-certificate/{info,upload,generate,certificate,enabled}` plus the base
  delete route — RSA-2048/SHA-256 self-signed generation, strict PKCS#12/PFX upload validation,
  private-key/leaf-certificate matching, re-wrapping under a random server-held password, bounded
  link-safe storage, and administrator-only mutation. `security/cert-sign` now accepts
  `certType=SERVER`; an authenticated endpoint fixture independently verifies the returned PDF CMS.
- `config/login-disclaimer` — live bounded markdown lookup with Java-compatible
  locale fallback. The reviewed secured router also exposes administrator-only
  list/read/update/clear management under `admin/login-agreement`, using atomic
  link-safe writes. See `contracts/login-agreement-admin.md`.
- `info/status`, `info/health`, request/load counters, uptime, and `info/wau` —
  process-local Java-compatible metrics and no-login weekly-active-browser tracking,
  governed by `metrics.enabled`.
- `ui-data/footer-info`, `home`, `licenses`, `pipeline`, `ocr-pdf`, and `sign` —
  read-only client metadata from the Rust runtime tree: legal/analytics settings,
  survey visibility, bundled notices, pipeline templates, Tesseract languages, and
  shared-signature/font discovery. The Rust dependency manifest is generated from
  `Cargo.lock` at build time, with
  `UNKNOWN` and native-tool notices retained as release-compliance gates.
- `GET /js/additionalLanguageCode.js` — legacy language-bootstrap JavaScript with
  build-time bundled locales and the configured `ui.languages` allowlist.
- `GET /robots.txt` — Java-compatible search-engine policy, controlled by
  `system.googlevisibility` or `SYSTEM_GOOGLEVISIBILITY`.
- `general/signatures/{filename}` — shared PNG/JPEG signature-asset retrieval in
  no-login mode, with basename validation and symlink rejection.
- Secured `proprietary/signatures` management plus authenticated
  `general/signatures/{filename}` lookup — bounded personal/shared PNG/JPEG assets,
  Java-compatible JSON sidecars and legacy-image fallback, personal quotas,
  personal-first reads, and administrator-only shared mutations. See
  `contracts/personal-signatures.md`.
- `mobile-scanner/*` — anonymous QR-session transfer with multipart upload,
  safe temporary storage, ten-minute inactivity expiry, download-after-read cleanup,
  and `system.enableMobileScanner` feature gating.
- `pipeline/handleData` — synchronous multipart pipelines through the in-process
  Rust router, streamed intermediate files, ZIP fan-out, endpoint allowlisting,
  and confirmed SISO/MISO execution shapes. See `contracts/pipeline.md`.
- Watched-folder pipelines — 60-second runtime-owned scans, stable-file and exclusive-lock
  readiness checks, safe `processing` handoff/rollback, and Java-compatible output naming.
- Conditional `general/send-email` — bounded HTML MIME plus one attachment through the existing
  `mail.*` SMTP relay settings, including authentication and plaintext/STARTTLS/implicit-TLS
  modes. The same relay now delivers invitation links and administrator-generated password-change
  notifications with optional temporary credentials. Rust deliberately rejects wildcard
  certificate trust and disabled hostname verification.
  See `contracts/send-email.md`.
- Secured audit APIs — all six `/api/v1/audit/*` dashboard routes plus the eight proprietary
  UI-data audit routes query the durable Rust store with Java-compatible pagination,
  single/multi-value and local-date filters, chart/KPI aggregation, CSV/JSON exports, retention,
  clear-all behavior, and endpoint-visit statistics. One post-handler production event now replaces
  the old mutation pair, including Java's GET/type, WEB/API/AI/AUTOMATION, polling, and fail-open
  semantics. Principal/source/JSON attribution survives user deletion and legacy Rust-schema
  migration; queries and exports have explicit resource bounds. Every route and audit capture
  itself require a verified Enterprise tier. See `contracts/audit.md`.
- Secured self-hosted `usage/fleet-stats` — administrator-only deployed-editor, active-WEB-editor,
  and cumulative processed-PDF aggregates with Java's STANDARD-audit nullability, internal-user
  exclusion, active/deployed clamp, indexed durable queries, and live typed processing-event
  capture, guarded by the verified Enterprise tier. See `contracts/fleet-usage.md`.
- Commercial entitlement policy — exact Java `@PremiumEndpoint` and `@EnterpriseEndpoint`
  method/path matrices, immutable Normal/Server/Enterprise tiers, Java-compatible license
  ProblemDetails, and Enterprise-only audit capture. The reviewed runtime now derives its startup
  tier from pinned-key Ed25519 certificate/`key/` verification or the fixed-account online Keygen
  validation and floating-machine activation flow. Dynamic status refreshes every seven days while
  route aspects retain Java's startup snapshot. See `contracts/license-entitlement.md`.
- Secured administrator license lifecycle — installation fingerprint, direct-key save/clear,
  one-shot resync, live license information, and bounded offline `.lic`/`.cert` upload with
  backup-before-atomic-replacement. Mutations persist through the shared settings writer and update
  the same live configuration consumed by weekly refresh without treating a configured key as an
  entitlement. See `contracts/license-entitlement.md`.
- Secured `ui-data/tessdata-languages` and `ui-data/tessdata/download` — administrator-only
  installed/official language discovery with a ten-minute cache plus bounded, atomic, link-safe
  `.traineddata` installation under the configured runtime directory. See `contracts/ui-data.md`.

## Remaining (not yet ported)

### Large pure-Rust subsystems — fully verifiable, multi-session each

- **PDF ↔ JSON editor model** (`ConvertPdfJson`): the page-level COS model, lazy endpoint surface,
  bounded page-font resource/program export, and an initial pure-Rust parser for page and Form
  XObject text-showing content streams are ported. Text runs preserve device fill/stroke colours,
  rendering mode, and simple-font `/Widths` geometry. Type0 `/ToUnicode` source codes and
  horizontal descendant `/DW`/`/W` advances are now applied. Vertical Type0 writing applies
  `/DW2` defaults and both `/W2` forms to glyph origins, displacement, and `TJ` movement; Type3
  outlines, non-identity CMap code-to-CID mapping and embedded-font reconstruction remain. Direct and Form-nested image
  XObjects now export page-space transforms
  and bounded JPEG or 1/2/4/8/16-bit RGB/gray/CMYK image data, apply `/Decode` ranges and grayscale
  `/SMask` alpha, and expand packed 1/2/4/8-bit Indexed images with Gray/RGB/CMYK palettes;
  JSON-only pages rebuild ordered raster images, including alpha through PDF soft masks.
  Unfiltered and bounded single-filter Flate/LZW/ASCII85/DCT 8-bit device-colour inline
  images are extracted. Color-key `/Mask` arrays and explicit 1-bit stencil masks are applied
  for bounded supported rasters. Complex inline filter parameters and ICC/Separation/DeviceN
  colour spaces remain; DCT CMYK color-key masks are also not projected.
  Full editor responses also inspect root AcroForm fields plus their
  inherited metadata and first widget location, and export structured page annotations (with
  full-mode COS data). JSON→PDF rebuilds root fields/one fresh widget and non-widget page
  annotations. JSON-only pages can draw ordered Latin Standard-14/WinAnsi text and raster images
  with matrix/state/color data. Generated text can also restore bounded embedded font dictionaries,
  nested font-program streams, Type0/CID encodings, and existing Type3 CharProcs, refusing edits that
  cannot round-trip through the source encoding. Document XMP packets round-trip as bounded base64
  metadata. Redrawing edits over preserved source streams, synthesizing new Type3 glyphs,
  nested/multi-widget form hierarchies, and form/annotation appearance streams are still missing, so
  it cannot yet match Java's `PdfJsonConversionService`.
- **Advanced text editing parity** (`edit-text`): selected-page content-stream replacements are
  ported; every edited page receives a private clone of its indirect Form graph so shared source
  Forms cannot leak changes across page filters. Every repeated visual invocation on one selected
  page is also rewritten to a private Form graph, so instance-specific cross-stream matches cannot
  mutate a sibling. Matching joins strings across separate `Tj`/quote operators, `TJ` array entries,
  and page↔invoked/nested-Form stream boundaries in content order, anchors cross-object replacements
  in the first object, and preserves the last object's suffix. Cyclic Form back-edges remain a safe
  sequence boundary.
- **Advanced redaction parity**: `redact-execute` is ported with all request target classes and a
  secure raster output. Automatic image discovery now descends nested Form XObjects with composed
  placement matrices and a conservative depth-limit fallback. Range anchors now use Java-compatible
  regex/literal/letter-spacing/punctuation/first-line fallbacks; range content is selected from
  line and image boxes in detected one/two-column reading order. Exact glyph boxes can still differ
  between PDFium and PDFBox for exotic fonts and unusual three-plus-column layouts.

### App infrastructure

Distributed job storage/backplane, cross-node queue/retry semantics, generic async execution for
the Java-only/control routes, and generic OIDC/SAML/desktop identity remain. The
opt-in Tauri native-launch path now receives an unconditional ephemeral-port
handshake, desktop/base-path/login-agreement environment, legacy-workspace
migration, a bounded startup wait, early-exit reporting, stale-port cleanup,
PID/start-time parent-death enforcement, and atomic fresh-install settings/template
initialization. Java remains the packaged/default backend; Java-compatible
short-file backup and upgrade-template merging, PDFium/sidecar packaging,
cross-platform upgrade proof, and the production default switch remain. See
`contracts/desktop-native-startup.md`. The
hardware-signing capability route reports desktop mode
and safely discovers on-disk PKCS#11 libraries without loading them. Windows desktop builds can
also enumerate current-user signing certificates without exporting key material or prompting for a
PIN. Desktop PKCS#11 certificate enumeration now requires a detected/configured canonical driver,
uses a serialized read-only request session and zeroizing PIN, and only returns X.509 certificates
matched to an eligible private signing key. The same provider now signs detached CMS through an
opaque token handle after strict `CKA_ID` selection and mechanism-capability checks; it supports
RSA/SHA-256 and P-256/P-384 ECDSA with safe raw-mechanism fallbacks. Windows-store signing now
selects an exact CurrentUser thumbprint and uses a bounded PowerShell/.NET `SignedCms` bridge over
anonymous pipes, preserving CSP/CNG ownership and native PIN prompts. A live ECC certificate smoke
test passed end-to-end, including independent PDF byte-range/CMS verification. The production
configuration slice only supports the one-time analytics onboarding choice and deliberately
reports login and storage capabilities as disabled while secure-mode cutover remains gated;
hardware signing remains desktop-loopback gated.

An opt-in secured router now provides durable local BCrypt identities, persistent lockout,
revocable rotating opaque sessions, digest-only one-time-issued API keys, AES-GCM-protected TOTP
seeds with replay protection, roles, teams, one-time invitations, local-user administration,
typed post-handler audit records, and administrator audit retrieval/export/retention/statistics.
Password, username, role, team, and account-state changes
revoke live sessions, and the repository preserves at least one enabled administrator. Existing
foundation databases are backfilled into the Default team. Java-compatible local user/team/invite
routes are covered by negative and end-to-end HTTP tests. Public self-registration now creates a
disabled Default-team user under the Java-compatible five-user community ceiling; authenticated
users can transactionally replace their durable settings and complete initial setup through the
legacy route names. Administrator bulk invitations now create forced-change accounts, deliver
Java-compatible generated credentials, preserve partial-result and missing-team behavior, and
enforce the same community ceiling transactionally. See `contracts/account-lifecycle.md`.
Optional invite-link delivery now reuses
the bounded SMTP relay, reports confirmed delivery without discarding tokens on relay failure, and
uses the configured frontend/backend URL precedence. Administrator password changes support random
credentials, optional SMTP delivery, durable forced-change state, and atomic session revocation;
self-service completion clears the flag. API-key retrieval intentionally does not
recreate Java's recoverable plaintext storage: callers rotate to receive a new value exactly once.
Supabase/SaaS bearer JWTs now use a strict public-key JWKS verifier with HTTPS issuer controls,
bounded response/cache/key selection, explicit algorithm allowlisting, issuer/expiry/audience and
required-claim validation. Verified subjects are persisted by `(issuer, subject)`, never linked by
email, receive isolated personal teams, support one-way anonymous upgrade, and retain live local
role/disable policy on every request. Deleted external subjects receive tombstones so a still-live
upstream token cannot silently recreate them. Async jobs, status, cancellation, metadata, and
downloads are now owner-scoped by trusted `AuthContext`. Recovery codes, generic OIDC login,
SAML2, desktop callbacks, device identities, ownership for additional
durable proprietary resources, and independent security review remain.

The standalone Rust runtime now performs bounded startup discovery for its optional
command-line dependencies, including Java-compatible QPDF and WeasyPrint minimum
versions. Missing tool groups participate in endpoint alternatives and are reported
as `DEPENDENCY`, separately from administrator `CONFIG` disables. The inactive Java
`print-file` method has no registered route and is therefore not a cutover surface.

The signing migration now has a tested source-independent `SigningKey` boundary
and request-lifetime zeroizing secret wrapper. `/api/v1/security/cert-sign`
supports plain/encrypted PKCS#8 and traditional RSA/P-256/P-384 PEM keys,
strictly parsed in-memory PKCS#12/PFX keystores, and authenticated JKS v1/v2
stores, including password and optional alias selection. These paths create an
invisible incremental CMS signature with a fixed `/ByteRange`/`Contents`
reservation; endpoint tests reconstruct the signed ranges and verify CMS.
The same incremental writer now supports visible page widgets with bounded
signer/date/reason text and an optional vector mark while preserving the CMS
byte range. Desktop-loopback PKCS#11 signing now keeps PIN and key use inside one
serialized login/sign/logout session. Windows-store signing similarly keeps the key in its native
provider and has an opt-in live endpoint fixture. Managed server signing uses an encrypted
PKCS#12 file re-wrapped with a separately generated password (or an explicit deployment secret),
rejects links and malformed key/certificate pairs, and is mounted only in the opt-in secured
router. Static proprietary route entitlement and trusted Keygen tier derivation are ported; Windows
secret-file ACL hardening plus an external KMS/HSM option remain review gates. A live SoftHSM/token compatibility
matrix, broader Windows smart-card coverage, and uncommon legacy PEM ciphers/curves
remain explicit gaps. It also lacks certificate policy validation,
public Java/Acrobat compatibility fixtures, and security review, so it is not
full signing or PAdES parity.

When `DOCKER_ENABLE_SECURITY=true` is requested, the Rust binary still refuses
to start instead of silently serving either an unsecured approximation or the
not-yet-approved opt-in security router. See
`SECURITY_MIGRATION_DESIGN.md` and `SIGNING_MIGRATION_DESIGN.md` for the review
gates before either secure mode or signing is implemented.

The separate `stirling-ai-engine` crate now ports the current Python HTTP agent
surface: health/auth, classification, PDF comments, both math-audit rounds,
durable SQLite documents with ACL/TTL and provider embeddings, PDF questions,
bounded long-document map/reduce, contradiction detection, schema-grounded PDF
edit planning, PDF review, structured PDF creation, saved-agent draft/revision,
the current terminal next-action contract, and the NDJSON orchestrator with
math-audit resume. Its MCP manifest publishes all eight completed Python
capabilities. Model-selected evidence and comment anchors are mapped back to
trusted local indices, while edit parameters are validated against a generated
snapshot of the Java operation schemas. PostgreSQL/pgvector now uses the
Python-compatible schema with atomic replace-ingest, bounded pooled TLS
connections, TTL and ACL-gated page/vector reads. The `migrate-sqlite-vec`
binary now performs idempotent Python-store cutover to Rust SQLite or pgvector:
it preserves pages, metadata, TTL and read ACLs while re-embedding content
without loading the sqlite-vec extension, and fails closed on unreconstructable
legacy records.

The processing service now owns the complete Java-facing AI controller surface.
Its orchestration routes are a real state-machine port rather than a multipart
pass-through: uploads receive stable content IDs; requested pages are extracted
or ingested; plans run through the same bounded internal policy dispatcher;
structured reports can resume the engine; every output receives an owned file ID;
and engine NDJSON is translated to sync JSON or SSE with disconnect cancellation.
The engine defers identity enforcement until capability routing, allowing
anonymous edit/create/draft work while still returning 401 before ACL-backed
question/review delegation. See `contracts/ai-proxy.md`.

The reviewed secured router now owns API-key MCP phase one at `POST /mcp`, including
bounded JSON-RPC transport, protocol negotiation, trusted API-key identity, capability
manifest caching/filtering, and the two executable AI tools. OAuth/JWT metadata,
artifact upload/download storage, PDF category tools, and production secured-mode
cutover remain explicit later phases. See `contracts/mcp.md`.

The same reviewed router now owns resource-grant administration and encrypted
S3/MCP/API integration-config CRUD. Ownership, team-leader/default/grant rules,
disabled/locked behavior, recursive secret masking/merge, Java-compatible AES-GCM
rows, and transactional cleanup are covered. Conditional team-scoped policy/source
configuration now uses the Java logical tables, encrypted JSON rows, UUID/order semantics,
folder allowlists, source document-count projections, S3 `connectionId` resolution, source/
integration deletion conflicts, policy-overview projections, and schedule/folder-watch definition
validation. Ad-hoc and stored uploaded runs now use the shared bounded job queue and pipeline
dispatcher, including named supporting assets, owner-scoped status/listing, generic file downloads,
result MIME preservation, and admitted editor-counter writes. A Java-compatible durable processed-
file ledger now supplies atomic claims, bounded interrupted retries, settlement/output consensus,
presence cleanup, and boot recovery. `FULL`/`LIGHT` folder and S3 source sweeps consume that ledger;
inline, atomic folder, and conditional S3 sinks complete delivery. Manual trigger/history routes,
trigger metadata, wall-clock schedules, debounced folder events, startup reconciliation, and
periodic reconciliation are active in the reviewed runtime. Ad-hoc streamed runs emit
Java-compatible started/completed step events and a terminal owner-scoped run view without
cancelling work on disconnect. Java's dormant `WAITING_FOR_INPUT` scaffolding has no live resume
route to port, while automatic trigger state is process-local pending the broader distributed
runtime. See
`contracts/resource-access-integrations.md` and
`contracts/policy-config.md`.

The processing service now also ports team-scoped classification-label CRUD
and the `classify-and-label` PDF bridge. Label mutation is administrator-only in
the reviewed secured router, open mode uses team sentinel `0`, and the bridge
reads only a bounded de-duplicated first-two/last-two page window before writing
the focused `StirlingPDFClassification` Info entry. See
`contracts/classification-labels.md`.
See `contracts/ai-engine-foundation.md` and
`contracts/pdf-comment-agent.md`.

The dispatchable `create-pdf-from-html-agent` tool is also owned by
`stirling-processing`. It keeps Java's multipart structured-document contract,
requires the AI feature setting, and renders escaped fields only through a fixed
template. It does not rely on an AI provider at request time. See
`contracts/create-pdf-agent.md`.

The public `math-auditor-agent` orchestration is likewise owned by
`stirling-processing`: PDFium classifies/extracts local evidence, while the
Rust AI engine receives only the two typed protocol messages. See
`contracts/math-auditor-agent.md`.

The self-contained document-classifier route is also live:
it is available at `POST /api/v1/documents/classify` only with a configured
structured-output provider (Anthropic Messages or OpenAI-compatible). The curated
MCP capability manifest intentionally excludes this internal classification
primitive; it advertises only the eight user-facing capabilities shared with the
legacy oracle.

## How to find gaps precisely

Use `docs/contracts/legacy-runtime-baseline.md` for the cross-surface baseline and
the contract files in `rust/contracts/` for implemented behavior and explicit
gaps. Source-literal counts are not authoritative because Spring composes class
and method mappings while the Rust service composes public, conditional, and
review-only secured routers.
