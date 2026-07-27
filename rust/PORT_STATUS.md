# Rust Port Status

Tracks the Java → Rust port of the Stirling-PDF backend (UI excluded). The Rust
service lives in this `rust/` workspace as the `stirling-processing` crate — an
axum HTTP service mirroring the Java `/api/v1/...` endpoints.

**Latest validation (2026-07-27, after merging the tester-signed OIDC-hardening,
MCP-category-tool, and PDF-JSON-ICC-CMYK work-items):** `cargo fmt --check` and strict
locked all-target workspace Clippy (`--workspace --all-targets --locked -- -D warnings`)
are clean. With PDFium bound via `STIRLING_PDFIUM_LIBRARY_PATH` (as `task rust:test`
does), `cargo test -p stirling-processing --locked` reports **1395 passed / 0 failed**
(one pre-existing ignored test) across the library suite and all integration suites, and
`cargo test -p stirling-ai-engine --locked` reports **147 passed / 0 failed** across
all targets. Four previously-red areas are now green rather than excused: the
`pdf_markdown` heading test (it required PDFium — earlier snapshots ran without the
library bound and misread the fallback as a pre-existing failure); the two
`stirling-ai-engine` `process_smoke` timeouts (root-caused, not environmental:
`tracing-subscriber` wrote ANSI escapes into piped output and broke the handshake
parse); and six endpoint tests that had rotted against later features (webhook
trigger listing, P-521 signing message, admin-only custom-API authoring, and the
OIDC login-CSRF browser-binding cookie). The clean-checkout build defect is fixed:
`build.rs` now stages `version.properties` into `OUT_DIR` (verbatim when the
Gradle-generated file exists, parsed from `build.gradle`'s canonical version
otherwise), so the crate compiles on a fresh clone and the `rust-processing` CI
gate no longer dies before running tests. The security-mode guard now reads every
boolean spelling Spring accepts (`1`/`on`/`yes`, YAML-1.1 strings, numeric `1`) and
**fails closed on unreadable values** — a present-but-malformed
`SECURITY_ENABLELOGIN`/`security.enableLogin` refuses startup, matching Java's
relaxed-binding boot failure, instead of silently starting unauthenticated.
External-runtime happy paths remain conditional on their respective tools and
services.

**Security-review hardening (2026-07-25):** an AI-assisted security review of the secured/crypto/SSRF
surface (adversarially verified) found the surface broadly sound (no critical/high; no auth-bypass /
priv-esc / cross-tenant leak / key leakage / forgeable signature / remote traversal) and surfaced 4 Medium
issues, all now fixed and test-proven: (1) bcrypt no longer runs under the global `Mutex<Connection>` +
per-IP auth rate-limiting; (2) tower-http request/body timeouts + concurrency limit at `into_router()`
(covering the OSS and secured routers) + a bounded webhook body assemble (no 100 MiB pre-HMAC buffer);
(3) OIDC callback `state` is now bound to the initiating browser via a cookie (login-CSRF, RFC 9700);
(4) the cloud-metadata SSRF deny now covers all embedded-IPv4 forms and applies to result URLs. This is
AI-assisted and does not replace the independent human security review the production cutover requires.

**Live Java-vs-Rust parity signal (2026-07-26):** the `differential-parity` CI workflow drives BOTH
backends and semantically diffs their output (`testing/differential/`). **Current result: 13 PASS / 13 —
green**, with 5 declared known differences. The first live run found 4 real divergences; two were fixed
(scale-pages leaked inherited page-tree attributes, causing double rotation; get-info field/format parity,
which took the diff from 116 field mismatches down to 5). The 5 remaining field differences are declared in
`testing/differential/known_diffs.py` with a mandatory root-cause `reason` and pinned expected values:
(a) the word/character/paragraph counts on a rotated page — Java's bare `PDFTextStripper` runs with
`sortByPosition=false`, so its line-breaking splits per glyph on `/Rotate 90`; the Rust value is the correct
reading and replicating the Java quirk is deliberately not planned; (b) `XMPMetadata` — Java re-serialises
the packet through xmpbox while Rust returns it verbatim (equivalent content, unpinnable because it embeds
per-run timestamps). The registry does not blind the gate: a pinned value that drifts, or any unregistered
field, still fails; a declared difference that disappears is reported STALE.

**Route-count scoping note:** the Rust service registers approximately 321 HTTP
routes as of 2026-07-26 (production registrations; an earlier 313 figure was an
undercount that dropped the routes declared after inner `#[cfg(test)]` attributes
in `server_certificate.rs` and `classification.rs`). This figure is a hand count,
not test-pinned — no route-census test asserts it, and a fixed total is
deliberately deferred to the versioned baseline-to-Rust manifest (see `README.md`)
so nested secured routers and conditional endpoints are counted by method and
path rather than inferred from source literals.
Only a subset of those are directly comparable to Java's OSS `controller/api`
PDF-operation surface (~140 endpoint mappings, several of which are the
project's composed `@AutoJobPostMapping` annotation rather than the four plain
Spring mapping annotations). The remaining Rust routes are non-PDF
infrastructure — license/entitlement administration, MCP, durable storage,
audit, workflow signing sessions, tessdata administration, hardware signing
discovery — that has no Java OSS-core equivalent because that logic lives in
`app/proprietary`/`app/saas`. "PDF processing operations are ~90% done" refers
to the PDF-operation-comparable subset, not the raw 313-route total; citing the
raw total as the denominator would understate actual coverage.

## Ported compatibility endpoints

Every ported surface now has a `contracts/<name>.md` compatibility document, and
all have focused unit/integration coverage. The previously listed contract-doc
gaps are closed: `contracts/durable-storage.md` (`storage_http.rs`),
`contracts/workflow-signing.md` (`workflow_signing_http.rs`, beyond the single
route `cert-sign.md` covers), `contracts/admin-settings.md` (settings
delta/section/key plus `admin/server-certificate`), `contracts/admin-jobs.md`
(`admin/job/*`), `contracts/classification-meter.md` (`policies/classify/meter`),
and `contracts/account-admin-routes.md` (the `security_http`
account/team/invite/user-admin/credential-change/API-key routes that
`account-lifecycle.md` deliberately does not enumerate — it covers register,
inviteUsers, settings/initial-setup, OIDC, and MFA recovery codes). Each route in
those docs was verified against the Rust registrations and the Java counterpart
controllers, with the residual divergences recorded in the docs themselves. Coverage spans merge/split/rearrange/remove/rotate,
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
- `misc/ocr-pdf` — OCR via preferred OCRmyPDF shell-out or Java-compatible
  PDFium-rendered, text-aware per-page Tesseract fallback, with tessdata language
  discovery/filtering, ordered page reassembly, and configurable per-tool process
  pools with timeout/tree cleanup (sidecar → ZIP, OCRmyPDF-only
  `removeImagesAfter` via Ghostscript).
- `misc/repair` — Java-compatible Ghostscript-first and qpdf-second recovery,
  retaining startup-discovered executable paths and using the shared bounded
  process runner with qpdf warning-exit handling; the normalized in-process
  rewrite remains the fallback when neither external tool is available.
- Fresh-PDF metadata parity — image-to-PDF now writes the versioned Stirling
  creator/producer label and creation/modification dates; booklet and poster
  outputs retain Java's selected standard source fields and valid dates while
  dropping custom Info keys. Form-only and full-raster flattening now apply the
  corresponding loaded/rebuilt Java policies after PDFium writes the result.
  Pro user-aware metadata substitution remains tied to the secured-mode cutover.
- `convert/pdf/html` — PDF → HTML via `pdftohtml -c` shell-out, all output files
  bundled into a ZIP.
- `convert/pdf/markdown` — Markdown in page order with literal escaping, bullets, and
  soft-hyphen repair. When the PDFium runtime is available, headings are inferred from
  text geometry, porting Java's `HeadingDetector` size-ratio thresholds (dominant glyph
  size vs. the document body median, or line height when sizes are degenerate; ≤12-word,
  non-sentence lines only), and two-column reading order is inferred from line geometry
  (porting Java's `detectsTwoColumns`/`splitIntoColumns` gutter analysis), emitting the left
  column before the right. Falls back to the text-only lopdf baseline (no headings/columns) when
  PDFium is unavailable. Java's geometry-aware table inference (borderless/ruled, cross-page
  stitching), image placement, and bold-label emphasis remain documented parity gaps.
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
  ToUnicode extraction, cache clear, and source-preserving partial export. Cached-page updates now
  distinguish omitted from explicitly empty arrays, preserve incomplete lightweight COS payloads,
  apply complete resource/content/annotation updates in place, and regenerate edited text/images
  over bounded retained vector content while preserving untouched pages, forms, and catalog data.
- `general/job/{jobId}`, its `/result` and `/result/files` children, and
  `general/files/{fileId}`/`metadata` — configurable-TTL private single-node async job storage and
  result download. `convert/pdf/text-editor?async=true` retains its specialized worker; the
  other ported processing POST endpoints now support generic `?async=true` by streaming their
  original multipart request and result through the job directory instead of RAM. Secured-mode
  jobs carry their request audit context through queued background replay, deferring the event
  write until streamed file metadata is available. Jobs and files are isolated by durable local
  user ID and return 404 across owners. A bounded
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
  itself require a verified Enterprise tier. Client IP capture follows Java's forwarded-for,
  real-IP, then peer-address precedence. STANDARD/VERBOSE direct processing, pipeline,
  AI-workflow, and policy uploads now contribute bounded streamed name/size/type context without
  request replay, feeding live portal document rows. Generic async jobs preserve that context
  across their worker boundary without rescanning uploads. Custom storage, collaborative-signing,
  certificate, license, mail, and mobile-scanner upload readers use the same typed hook, and
  storage file mutations retain Java's `FILE_OPERATION` category. Java's default-off operation
  result setting is supported through bounded finite text/JSON/XML capture while streaming,
  binary, UI-data, and explicit auth responses stay excluded. VERBOSE request arguments use the
  typed redacted form map rather than AspectJ-style raw object stringification. See
  `contracts/audit.md`.
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
- Secured durable storage (`storage/files`, `storage/files/{id}` + `/download` + `/folder`,
  `storage/files/folder` bulk move, `storage/folders` + `/{id}`, and user/link shares under
  `storage/files/{id}/shares/*` and `storage/share-links/*`) — owner-scoped local-provider
  file storage that shares the durable security database (so ownership joins `security_users`).
  Java-compatible `storage.*` config (provider, `local.basePath`, `quotas.*`, `sharing.*`),
  path-traversal-safe object keys, per-user/total/file quotas, folder trees, and share-link /
  user-share ACLs with roles. Mounted in the reviewed secured router; unauthenticated access is
  401 and cross-owner access is 404. `config/app-config` now reports the resolved
  `storageEnabled`/`storageSharingEnabled`/`storageShareLinksEnabled`/`storageShareEmailEnabled`/
  `storageGroupSigningEnabled` flags (plus `enableLogin`/`activeSecurity`) in secured mode.
  Closes Java `FileStorageController`, `FolderController`, `FileFolderPlacementController`.
- Secured collaborative (group) signing — owner session/participant lifecycle under
  `security/cert-sign/{sessions,sign-requests}/*` (authenticated) and public token-scoped
  participant access under `workflow/participant/*`. Encrypted participant submissions
  (`ProtectedSecretCipher`), server-certificate-backed signing, wet-signature overlays (typed
  text via Helvetica + raster images, normalized page-relative placement — see the new
  `overlay_signatures_to_file` in `pdf_image_overlay.rs`), an optional summary page, and an
  invisible incremental CMS signature over the finalized PDF. Gated by `storage.signing.enabled`;
  fails closed (403) when disabled. Closes Java `SigningSessionController`,
  `WorkflowParticipantController`.
- Enterprise-gated portal audit views — `GET /api/v1/proprietary/ui-data/documents` (Documents
  review queue) and `GET /api/v1/proprietary/ui-data/infrastructure/audit-log` (Infrastructure →
  Audit tab), matching Java's `@ProprietaryUiDataApi` class prefix and the frontend's calls (an
  earlier Rust registration at the bare unprefixed paths was a live 404 against the portal and is
  fixed; the bare paths are now pinned 404 by test): read-only projections of
  the durable audit store with the faithful Java category/action/target/status/pretty-tool
  shaping, policy-dispatch detection, and read-noise (`UI_DATA`/`HTTP_REQUEST`) exclusion.
  Enforced through the same central Enterprise entitlement + `enforce_security` gate as
  `/api/v1/audit/*`; scope resolves admin → whole-server, team owner → team-principal-scoped,
  else 403. Closes Java `PortalDocumentsController`, `PortalInfraAuditController`. Live policy
  traffic now stamps bounded `policyName`/`policySteps` on parent runs and records each internal
  tool call as `AUTOMATION` with streamed input/supporting `files`, so both projections receive
  real policy events. Shared direct processing uploads and direct pipelines now record bounded
  streamed `files`; Java's opt-in audit flags add streaming lowercase SHA-256 and bounded PDF Info
  Author metadata, while their default-off state adds no file scan. Generic async workers defer
  their event until replay supplies the same context and capture settings. STANDARD/VERBOSE also
  records bounded Java-shaped multipart/URL-encoded `formParams`, preserving repeats and omitting
  `_csrf`; credential-shaped names are intentionally persisted as `[REDACTED]` instead of copying
  Java's secret-disclosure behavior. Default-off operation-result capture adds bounded finite
  textual responses without consuming binary or streaming document bodies.
  An authenticated real repair request proves the durable event creates the corresponding
  documents row, and an async rotate proves queued preservation. Custom administrative multipart
  readers now report through the same explicit typed enrichment boundary. See
  `contracts/portal-audit.md`.
- Secured `GET /api/v1/admin/settings/policies/implied-folder-roots` (ADMIN) — read-only list of the
  Stirling-owned folder roots always permitted for folder automations: the local server-storage base
  path (reason `serverStorage`) and each pipeline watched folder (reason `watchedFolder`), each
  `{path, reason}` with an absolute path. Ports Java `FolderAccessSettingsController` +
  `FolderAccessGuard.impliedRoots`. Paired parity fix: the Rust folder-access decision now models those
  implied roots — a server-storage/watched-folder path is permitted even with an empty/absent
  `policies.allowedFolderRoots` — porting `FolderAccessGuard.requirePermitted` ordering (protected-config
  reject → implied allow → empty-allowlist reject → allowlist membership). See `contracts/policy-config.md`.
- Webhook policy subsystem — a secured-router control plane (a fourth `webhook` input-source type via
  `/api/v1/sources`, with server-minted CSPRNG `webhookId`/`signingSecret`, reveal-on-create-then-mask,
  and the secret encrypted at rest; a matching `webhook` trigger listed by `GET /api/v1/policies/triggers`,
  enabled-only LIGHT delivery dispatch, and a FULL reconcile safety-net) plus the port's **only new PUBLIC
  route** — the HMAC-authenticated receiver `POST /api/v1/webhooks/{webhookId}` (constant-time HMAC-SHA256
  over the raw body, anti-enumeration 404s, Content-Length/DoS bounds enforced before the signature,
  path-safe atomic spool, `@Hidden`, and fail-closed on a missing secret). The public allowlist exposes
  exactly `POST /api/v1/webhooks/*` (other verbs stay Authenticated). Ports Java `WebhookReceiverController`,
  `WebhookSignatures`, `WebhookSpool`, `WebhookIds`, `WebhookConfig`, `WebhookInputSource`, `WebhookTrigger`.
  The subsystem is now **end-to-end**: `resolve_source` has a real `"webhook"` arm, so a fired webhook
  policy consumes the spooled delivery via the folder-consume lifecycle (spool-dir read, `.part`/dotfile
  skip, ledger claim/settle, display-name pipeline filename, cross-policy delete, retain-on-failure;
  `WebhookInputSource.resolve`/`completeConsumed` ported). See `contracts/webhook-receiver.md` and
  `contracts/policy-config.md`.
- Portal-gated `GET /api/v1/integrations/capabilities` — reports `{customApi: allowCustomApiIntegrations
  && isAdmin}` so the portal offers the free-form custom-API option only to callers who can use it. Ports
  Java `IntegrationConfigController.capabilities`; `policies.allowCustomApiIntegrations` defaults `true`.
  Paired parity fix: `IntegrationConfigService::create`/`update` now enforce `requireCustomApiAllowed`
  server-side for `API`-type configs (flag on + admin) rather than merely hiding the option in the
  capability response. See `contracts/resource-access-integrations.md`.
- Secured `GET /api/v1/proprietary/ui-data/{login, account, audit-dashboard, teams, teams/{id}, admin-settings}` — thin
  read projections over already-ported stores (`SecurityStore`) plus a startup snapshot of server-owned
  config, porting the non-mutating routes of Java `ProprietaryUIDataController` (new
  `proprietary_ui_data.rs`). `login` is public (first-time-setup/default-credentials + OAuth2 provider
  list); `account` is an `/auth/me` superset with the MFA secret masked; `audit-dashboard` (admin +
  verified Enterprise) projects the audit config plus the `AuditLevel`/`AuditEventType` enum listings and
  `retentionDays`; `teams`/`teams/{id}` (admin) reuse `list_teams` plus new per-team latest-activity and
  team-leader queries in `security.rs`; `admin-settings` (admin) aggregates the admin roster with
  locked-user enumeration, the full `user_seat_metrics` license/seat block, per-principal session
  activity, and mail/premium config (two documented divergences: `updatedAt` is always omitted — no
  such column — and locked users derive from the persistent lockout store rather than Java's in-memory
  count-threshold that honors a `-1` disable). SAML2 provider entries are deliberately omitted (SAML2 deferred),
  so the login `altLogin` flag is OAuth2-only — a documented divergence for a SAML2-only config; OAuth2
  providers are unaffected. Two minor divergences: an unknown `teams/{id}` returns `404` (Java accidentally
  `500`s) and "last activity" derives from session `created_at` (the Rust store has no per-request
  `lastRequest`). `PortalApiKeysController` (`/proprietary/ui-data/infrastructure/api-keys`, GET/POST/DELETE)
  is now ported — digest-only personal API-key list/create/revoke with a per-user active cap (50 → 429),
  the secret returned once, cross-owner access `404`, and best-effort usage/last-used recorded on key auth;
  authenticated non-anonymous callers only (no admin/Enterprise/demo gate). Only the H2-only
  `ui-data/database` route remains deferred from this controller. See `contracts/ui-data.md`.
- Secured `POST /api/v1/policies/classify/meter` — audit-only classification meter (accepts an optional
  body, clamps `documentCount` to `[1,10000]`, defaults the policy name, stamps a policy-run audit record
  carrying the `classify-and-label` step, and returns `202`); the SaaS billing side is a deliberate no-op
  in proprietary mode. Ports Java `ClassificationMeterController`.
- `settings/update-enable-analytics` and `general/send-email` now honor `?async=true` (added to the
  async-job allowlist), matching Java's `@AutoJobPostMapping`. With these plus `admin-settings`, a
  systematic route cross-check finds no remaining bounded parity gap in the OSS-core + proprietary
  `controller/api` route surface. What remains: the standing deferred-external set (SaaS/cloud, SAML2),
  upstream-blocked items (Windows-cert async), the H2-only `ui-data/database`, and
  unbounded PDF-fidelity work (Type3 glyph synthesis, Type0/Type3 byte-parity — the latter now confirmed
  blocked, needing a net-new embedded-font-program parser AND poisoned by the Java oracle's C0-stripping
  of 2-byte CIDs). The proprietary `external-api-call` step (`API` integration type) was executed
  as a bounded staircase — **all four slices are landed and the feature is COMPLETE** (route
  `POST /api/v1/integration/external-api-call` live; the previously fail-closed policy step now dispatches
  through the ported caller; ConsignO is covered via the generic `bodyTemplate`). Slice 4 added verdict
  enforcement (`requireTrue` must be JSON `true` or fail-closed), report/replace modes, the
  security-sensitive `ResultUrls` validation (http(s)-only, no userinfo, exact-or-subdomain allowlist host
  match — no naive suffix — then SSRF-vet the *resolved* address so an allowlisted-but-internal host and
  raw metadata IPs are still blocked, result fetched with no credentials), and `ResultFiles` archive
  member selection (glob/index, empty/multi-match are errors). All oracle-verified against a loopback mock.
  The earlier slices (`proprietary_external_api.rs`):
  slice 1 = pure request-construction + config primitives; slice 2 = the `DocumentContext` namespace
  (base/run facts + best-effort PDF Info metadata + classification + sensitivity-label, omit-not-fatal on
  non-PDF) and the four `buildBody` modes (multipart / json / binary / bodyTemplate); slice 3 = the
  SSRF-safe outbound caller (redirect=NEVER, 64 MiB bounded read, credential-free errors) with
  NONE/BEARER/BASIC/HEADER/TOKEN_LOGIN auth and a login-once token cache (401→evict→retry-once),
  reusing the OIDC `resolve_to_addrs` pin + `ip_addr_is_reserved`, gated by an **unconditional
  cloud-metadata deny** (169.254.169.254/.253/.250, `fd00:ec2::254`) that runs before the new
  `policies.allowPrivateApiEndpoints` opt-in (default false). See `contracts/resource-access-integrations.md`.
- Secured `integration/purview-apply-label` and `integration/purview-read-label` — fully offline
  Microsoft Purview sensitivity-labelling (no Microsoft Graph call on the label path; the
  app-registration `clientId`/`clientSecret` only gate an unbuilt taxonomy lookup). Apply writes the
  label's `MSIP_Label_<GUID>_<Attr>` pairs onto both the Info dictionary and the XMP packet (replacing
  only the same tenant's labels, refusing a protected/`ENCRYPT` label) and returns the re-saved PDF;
  read returns the PDF byte-for-byte unchanged plus an `X-Stirling-Tool-Report` JSON report. A step's
  `connectionId` resolves to the `PURVIEW` connection through one opaque anti-enumeration error.
  That same confused-deputy guard now also runs at policy **save** and ad-hoc-run time (Java
  `IntegrationStepValidator`): a policy whose step references an inaccessible / wrong-type / disabled
  Purview connection is rejected with `400`, fail-closed for any other `/api/v1/integration/*` op.
  Secured-router-gated (mounts only in the opt-in secured runtime). Ports Java `PurviewLabelController`,
  `ApiConnectionResolver`, `PdfSensitivityLabels`, `IntegrationStepValidator`, and `AiToolResponseHeaders`. See
  `contracts/purview.md`.

## Remaining (not yet ported)

### Large pure-Rust subsystems — fully verifiable, multi-session each

- **PDF ↔ JSON editor model** (`ConvertPdfJson`): the page-level COS model, lazy endpoint surface,
  bounded page-font resource/program export, and an initial pure-Rust parser for page and Form
  XObject text-showing content streams are ported. Text runs preserve device fill/stroke colours,
  rendering mode, and simple-font `/Widths` geometry. Type0 `/ToUnicode` source codes and
  horizontal descendant `/DW`/`/W` advances are now applied. Vertical Type0 writing applies
  `/DW2` defaults and both `/W2` forms to glyph origins, displacement, and `TJ` movement. Embedded
  encoding CMaps now apply bounded `cidchar`/`cidrange` source-code-to-CID mappings before those
  metrics. Named non-identity CMaps additionally resolve bounded recursive `usecmap` inheritance
  from the production image's Poppler Adobe mapping data, with safe collection-scoped paths and a
  shared bounded cache; missing data retains the conservative source-code fallback. Type3 fonts
  now export the Java-shaped bounded CharProc code/name/Unicode metadata and preserve their source
  CharProcs for generated-text rebuilds; outline-derived normalization and broader font synthesis
  remain. Direct and Form-nested image
  XObjects now export page-space transforms
  and bounded JPEG or 1/2/4/8/16-bit RGB/gray/CMYK image data, apply `/Decode` ranges and grayscale
  `/SMask` alpha, and expand packed 1/2/4/8-bit Indexed images with Gray/RGB/CMYK palettes;
  JSON-only pages rebuild ordered raster images, including alpha through PDF soft masks.
  Unfiltered and bounded single-filter Flate/LZW/ASCII85/DCT 8-bit device-colour inline
  images are extracted. Color-key `/Mask` arrays and explicit 1-bit stencil masks are applied
  for bounded supported rasters. ICCBased Gray/RGB/CMYK XObjects and ICCBased Indexed palette bases
  now use their bounded embedded profiles for pure-Rust conversion to sRGB, including Gray/RGB DCT
  images, with compatible declared device-`/Alternate` fallback for invalid profiles. Four-channel
  ICCBased DCT images (including YCCK/Adobe-marker variants) now decode natively and convert
  through their bounded embedded profile to sRGB instead of silently keeping the decoder's device
  projection, and DCT CMYK color-key `/Mask` ranges are applied against the pre-`/Decode` decoder
  output per PDF 32000-1 §8.9.6.4; rasters above the editor byte bound deliberately keep the
  bounded device fallback. Complex inline filter parameters remain. Device-alternate Separation and one-to-eight-component DeviceN XObjects
  with bounded order-1 sampled Type 0, single-input exponential Type 2, recursively bounded
  single-input stitching Type 3, or bounded PostScript calculator Type 4 tint transforms are
  evaluated into Gray/RGB/CMYK, including
  one-component DCT Separation images after applying `/Decode`. The Type 4 interpreter implements the
  full PDF 7.10.5.2 operator set (arithmetic, relational/boolean/bitwise, `if`/`ifelse`, and stack
  operators) over bounded token, step, and stack limits. CalGray/CalRGB/Lab direct images,
  Indexed bases, ICC fallbacks, and spot-color alternates use bounded calibrated conversion,
  including Gray/RGB/Lab DCT. One-to-four-component DCT DeviceN images retain native JPEG planes,
  perform Adobe/`ColorTransform` conversion, apply `/Decode` in PDF.js order, and evaluate their
  tint functions. Separation and DeviceN images whose alternate is an `ICCBased` space now
  convert the tint output through the embedded profile (falling back to the declared device
  `/Alternate` when the profile is invalid); DeviceN DCT above four components remains.
  Full editor responses also inspect root AcroForm fields plus their
  inherited metadata and first widget location, and export structured page annotations (with
  full-mode COS data). JSON→PDF rebuilds root fields/one fresh widget and non-widget page
  annotations. JSON-only pages can draw ordered Latin Standard-14/WinAnsi text and raster images
  with matrix/state/color data. Generated text can also restore bounded embedded font dictionaries,
  nested font-program streams, Type0/CID encodings, and existing Type3 CharProcs, refusing edits that
  cannot round-trip through the source encoding. Document XMP packets round-trip as bounded base64
  metadata. Info and annotation dates now round-trip through the PDF `D:...`↔ISO-8601 conversion
  (offset normalized to `+00'00'`, the key omitted on a parse failure, and the annotation overlay
  converts ISO→`D:` so it never writes an invalid literal), and `/Trapped` is read/written as a COS
  Name — both previously documented parity gaps, now closed. Cached partial export can redraw edited
  text/images over bounded retained vector content.
  The full-document rebuild path now ports that same strip-and-regenerate strategy for a page that
  mixes a preserved `content_streams` entry with edited `textElements`/`imageElements`: it strips only
  the represented text or represented-image draws whose element list was actually resubmitted, and
  leaves the other content type's preserved draws/resources untouched — since the page model's
  `textElements`/`imageElements` are plain lists rather than optional, an empty list is read as "not
  resubmitted," not "delete everything of this type," so a client cannot clear just one content
  type on a mixed page through this endpoint (the lazy/partial endpoint already supports that). This
  is verified PARITY, not a Rust gap: Java behaves identically — `PdfJsonPage` defaults both lists to
  empty (`@Builder.Default`), `convertJsonToPdf` null-coalesces absent/null/empty to the same state
  (`PdfJsonConversionService.java:692-707`), with preserved streams an empty list never strips that
  content type (`:731-772`), and `extractVectorGraphics` strips only image draws whose `objectName`
  is in the submitted list (`:3163-3172` — empty strips nothing). Clearing one content type on a
  mixed page would need a shared nullable-list schema decision across Java, Rust, and the frontend. This
  mixed-edit regeneration is now the fallback: for a text-only mixed edit (non-empty `textElements`, no
  image edits) on a simple `Type1`/`TrueType`/`MMType1` font, the full-document rebuild first attempts
  Java's token-preserving in-place `Tj`/`TJ` rewrite (`rewrite_text_operators`, porting
  `rewriteTextOperators`) — it swaps only each show-text string operand for the replacement re-encoded
  through the same font and carries every other token (positioning, `TJ` kerning, vector ops) through
  byte-for-byte, so a boundary-aligned edit round-trips token-for-token. It defers wholesale to
  strip-and-regenerate, with no partial rewrite, on any unsupported case (`Type0`/`Type3` or
  unresolvable font, a Standard-14 fallback being needed, an encode failure, a glyph-count/cursor
  mismatch, invoked-Form text, or an interior-kerned multi-string `TJ`). This partially closes the
  byte-parity gap with `PdfJsonConversionService`; still open are `Type0`/`Type3`, interior-kerning-run
  rewrite, true Type3 glyph synthesis, and byte-parity for those deferred classes. Two seeming gaps are
  confirmed parity rather than Rust shortfalls: Java's `TextRunAccumulator` also merges same-baseline
  kerned glyphs with no kerning-gap check (so an interior-kerning run defers on both sides), and Java's
  partial-export path (`determineRegenerateMode` with `forceRegenerate=true`) also always regenerates
  (so the Rust `partial/{jobId}` path always regenerating is parity). Generated text that mixes a character the
  restored font (Type3 or otherwise) can represent with one it cannot now degrades gracefully —
  the unrepresentable run falls back to Standard-14 instead of refusing the whole element's edit —
  rather than fabricating a genuinely new glyph. A character representable by neither the restored
  font nor Standard-14 still fails the edit. True Type3 glyph synthesis (drawing a novel outline for
  a character absent from every available source) remains missing and would need a new font-outline
  extraction/Bezier-to-PDF-path subsystem this crate does not have; it is not a bounded follow-on to
  the graceful-fallback work above. One widget per
  field matches Java's own `PdfJsonFormField` wire model (`rect`/`pageNumber` are singular there too,
  and `PdfJsonConversionService` likewise reconstructs only one widget per field) — a radio-button-
  style multi-widget field is not a Rust port gap versus Java; it would need a new shared schema
  design across Java, Rust, and the frontend contract before either side could port it. Restored
  `Tx`/`Ch` (text/choice) form-field widgets now get a real `/AP` normal appearance stream — the
  widget's current value drawn with the shared Helvetica `DR` resource, sized to the field's `rect`
  — so headless consumers (flatteners, rasterizers, printers) that ignore `NeedAppearances` still
  render the value. `Btn` (checkbox) widgets get a two-state `{on_state, Off}` `/AP/N` appearance
  dictionary matching `/AS`, with a plain `X` mark for the checked state (not a byte-match for
  Java's own checkbox glyph). Non-widget annotation appearance streams remain `NeedAppearances`-only.
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

Distributed job storage/backplane and cross-node queue/retry semantics are not an OSS parity gap:
Java's own default (`InProcessJobStore`) is single-node, identical in spirit to what Rust already
has; the Redis-backed `ValkeyJobStore` clustering path is an opt-in proprietary/enterprise add-on
Rust hasn't built, and whether the Rust port should ever target multi-node deployment is a product
decision, not a coding task. Generic async-job wiring for the routes the existing `?async=true`
wrapper doesn't yet cover is narrower than it sounds: PKCS#11 hardware-certificate enumeration is
now wired (the wrapper is content-type-agnostic, so a plain-JSON POST route needed only an allowlist
entry, no new mechanism); Windows certificate enumeration cannot use it because it's a bodyless GET
and the wrapper's shared detection is POST-only for the whole allowlist — matching Java's own
`AutoJobPostMapping` annotation, itself hardcoded POST-only, so this is genuine upstream parity, not
a Rust-specific limitation. Job/control routes (`general/job/*` plus the admin job
stats/queue/cleanup trio), the mobile-scanner API, and admin settings mutation are all wired in
the production routers today (an earlier revision of this paragraph predated them).
Generic SAML/desktop identity remain (OIDC is ported — see below). The
opt-in Tauri native-launch path now receives an unconditional ephemeral-port
handshake, desktop/base-path/login-agreement environment, legacy-workspace
migration, a bounded startup wait, early-exit reporting, stale-port cleanup,
PID/start-time parent-death enforcement, and atomic fresh-install settings/template
initialization. Open-mode local `backend:dev`, `dev`, and default `dev:all` now
launch `stirling-processing`; the explicit Java oracle plus portal and SaaS Task
paths remain available. Java remains the packaged production and desktop backend.
Java-compatible short-file recovery is now ported: a `settings.yml` with fewer than
`MIN_SETTINGS_FILE_LINES` (31, matching `ConfigInitializer`) lines is treated as truncated by an
interrupted write, backed up to `settings.yml.<epoch-millis>.bak`, and recreated from the template,
exactly as Java does; `custom_settings.yml` is never subject to this check. Upgrade-template merging
is now also ported (matching Java's `ConfigInitializer`/`YamlHelper`): when an existing long-enough
`settings.yml` is present, the bundled template is walked line-by-line and each leaf value the user
customized is substituted into the template's own structure — preserving the template's comments,
blank lines, key order, indentation, and inline comments — so new template keys arrive with their
defaults, user-only keys are dropped, and the file is only rewritten if the merge changed it
(idempotent). Values are re-emitted through `serde_yaml`'s own scalar emitter so a plain-styled
value containing `#`/`:`/`*` (e.g. a DB password) is correctly quoted and round-trips exactly
instead of being silently truncated or corrupting the file — a corruption bug an adversarial review
caught and fixed before merge. A user override of a block/nested-map value (the template currently
has no block sequences) falls back to the template default, a documented scalar/inline-scope
limitation. PDFium/sidecar packaging, cross-platform upgrade
proof, and the production default switch have no Rust source-code surface at all — they are
CI/release-pipeline and deployment-decision concerns, not outstanding coding work. See
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
seeds with replay protection, MFA recovery/backup codes (a net-new hardening with no Java
equivalent: 10 single-use codes auto-issued when MFA is enabled, stored only as SHA-256 digests,
substitutable for the TOTP factor at login — never a password bypass — atomically consumed one-time,
feeding the shared MFA lockout on failure; regeneration requires a fresh non-replayable TOTP and the
remaining count surfaces on `/api/v1/auth/me`), roles, teams, one-time invitations, local-user
administration, typed post-handler audit records, and administrator audit
retrieval/export/retention/statistics.
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
downloads are now owner-scoped by trusted `AuthContext`. Generic OIDC login has its first slice:
`oidc_discovery` fetches and validates a provider's `.well-known/openid-configuration` (issuer
match, required-endpoint presence, the same HTTPS/loopback-only scheme policy Supabase JWKS
fetching already uses, a hard response-size cap enforced independent of a server's own
`Content-Length`, and no-redirect fetching), mirroring Java's
`OAuth2Configuration.oidcClientRegistration()`. `oidc_authorization` now builds the authorization
redirect request: CSRF `state`, replay-protection `nonce`, and a PKCE `code_verifier`/`code_challenge`
pair (RFC 7636 S256, cross-checked against the RFC's own worked example), all generated with the
same CSPRNG/base64url-no-pad convention already used for session/API-key tokens elsewhere in this
crate, assembled into the full authorization URL via proper query encoding (not string
concatenation, which would mishandle a `redirect_uri` carrying its own query string). `oidc_token`
now builds the token-exchange request (RFC 6749 §4.1.3 `grant_type=authorization_code` form body for
the public-client PKCE case — constructed, not sent, since the live fetch is SSRF-gated and a later
slice) and parses the token response into typed success/error/malformed shapes, enforcing OIDC
Core's `id_token`-required rule and classifying fail-closed (a contradictory or nonconformant body
is rejected, never mis-accepted). `oidc_live_token` performs the actual token exchange SSRF-safely:
it resolves the `token_endpoint` host, rejects before connecting if ANY resolved address is
reserved/private (reusing the same reviewed reserved-IP predicate as discovery — now shared via a
`pub(crate) ip_addr_is_reserved`, a pure extraction verified to leave all 19 discovery SSRF tests
green), then pins the vetted address via `resolve_to_addrs` so the live TCP connection cannot be
re-resolved (anti DNS-rebinding); the same primitive now also does the JWKS GET. This closes the
DNS-name→private-IP hole for these live-fetch paths (discovery-time validation remains
literal-IP-only, a separate path). The earlier http-path residual is now closed: rather than
skipping the reserved check on `http`, the fetch requires every resolved address to be loopback on
`http` (rejecting a non-loopback resolution of `localhost`), preserving the dev/test loopback seam
while removing the http-downgrade-to-loopback asymmetry. `oidc_id_token` verifies an ID token as a
sibling of the Supabase verifier (which it leaves untouched): it fetches the JWKS SSRF-safely,
checks the signature against a JWK selected by `kid`, and enforces a public-key-only algorithm
allowlist that (double-gated with jsonwebtoken's own key-family guard, and verified against forged
HS256-with-public-key, `alg=none`, oct-key-in-JWKS, and cross-family tokens) prevents algorithm
confusion, plus exact `iss`, `aud`==`client_id` (array membership), `exp` with leeway, `azp` when
present, and — the OIDC-specific check the Supabase verifier lacks — a constant-time `nonce` match
against the expected nonce. `oidc_login` ties these together into the login flow as library
functions (no HTTP route yet): `initiate_oidc_login` discovers the provider, builds the
authorization request, and persists `{state → (nonce, code_verifier, redirect_uri, discovered
metadata, client_id, expiry)}` in an in-memory single-use TTL store (modeled on the mobile-scanner
session store); `complete_oidc_login` consumes the `state` entry *before any network call* (an
unknown/expired/replayed `state` is rejected — this is the CSRF defense, since `state` is CSPRNG),
then exchanges the code, verifies the id_token against the stored nonce, and provisions the user +
issues a session by REUSING the exact reviewed external-identity path the Supabase JWT login uses
(`resolve_external_user`/`context_for_user`/`issue_session`, keyed by `(issuer, subject)` so an
OIDC identity can never collide with a Supabase one; role/permissions are server-derived, not
token-controllable). A minimal `security.oauth2.*` provider config (issuer/client_id/redirect_uri/
scopes, public-client PKCE) drives it, off unless an issuer is set. Both HTTP routes now exist in
the opt-in reviewed secured router: `POST /api/v1/auth/oidc/authorize` (returns the authorization
URL + state) and `GET /api/v1/auth/oidc/callback` (issues a session identically to the password
login handler — same `AuthenticationResponse`/opaque tokens). They are public (a pre-session
browser flow), scoped to exactly those verb+path pairs, mounted only when a provider is configured
(absent → 404), and a callback failure (unknown/expired/replayed state, exchange/verify/nonce
failure) returns one generic 401 that doesn't distinguish CSRF-state-miss from verification failure.
This completes the generic OIDC login path within the opt-in secured router (which still fails
closed in production). The public `/authorize` route is now DoS-hardened: the login-state store has
an absolute size cap (4096 entries; a new login is refused with a generic 503 when full, never
evicting a pending honest login), and OIDC discovery is cached per issuer (5-min TTL, bounded)
instead of refetched per call — so an unauthenticated flood can neither grow memory unboundedly nor
amplify outbound fetches at the IdP. The pre-production hardening trio has landed:
`POST /api/v1/auth/oidc/authorize` now has its own per-IP governor bucket (production 1 req/s,
burst 10 — stricter than the generic auth bucket, selected by exact raw-path match so encoded
spellings fall to the generic bucket instead of bypassing it), closing the refuse-newcomer flood
residual; ID-token verification uses a bounded `OidcJwksCache` (5-min TTL, 64 entries, kid-miss
refresh under a 60-second per-entry cooldown, poisoned-lock degrades to uncached, only
pre-validated key sets admitted); and confidential clients are supported via
`security.oauth2.clientSecret` with the RFC 6749 §2.3.1 Basic header (Appendix B
form-urlencoding before base64, `Zeroizing` secrets, Debug-redacted, blank ⇒ public client),
keeping PKCE for confidential clients per RFC 9700 as a deliberate, documented divergence from
Spring's public-client-only PKCE. Durable cross-process login-flow state would be
beyond-Java-parity, not a gap: Java keeps its OAuth2 authorization-request state in per-process
in-memory HTTP sessions (no persistent session repository is configured), so the Rust in-memory
single-use TTL store is equivalent; a SQLite-backed store remains an optional enhancement for
multi-process deployment. The browser-facing callback UX (Java's success handler 302-redirects
to the SPA with the token in the URL fragment and honors the redirect-path cookie; Rust still
returns raw JSON) is genuine remaining backend work. The discovery document's own returned endpoint URLs
(`authorization_endpoint`/`token_endpoint`/`jwks_uri` — untrusted, provider-controlled values,
unlike the admin-configured issuer itself) are now hardened against SSRF: rejected when the literal
host is a private/reserved IPv4 or IPv6 address, including RFC 1918/loopback/link-local, CGNAT,
IETF-benchmarking/protocol-assignment ranges, and every IANA-registered IPv4-embedded-in-IPv6 form
(mapped, compatible, both NAT64 fixed prefixes, 6to4, Teredo including its XOR-obfuscated client
slot, and ISATAP for either scope-bit value). An adversarially-verified pass against real RFC text
found and closed three successive bypasses of this check before landing here (a missed embedding
form each time), which is itself informative: literal-address enumeration is a whack-a-mole shape,
not a one-and-done fix. Explicitly and deliberately still open: operator-configurable NAT64/6rd
prefixes and DNS-name resolution (a domain that resolves to a private address) are undetectable
without out-of-band deployment knowledge or an actual, TOCTOU-safe resolve-and-pin mechanism neither
of which exist here yet; native IPv6 special-purpose ranges beyond the embedding forms above (e.g.
IPv6 benchmarking, Discard-Only) were not audited. SAML2 (scoped and deferred — no sound pure-Rust
XML-signature/canonicalization foundation exists; it needs a `libxmlsec1` native dependency or a
from-scratch C14N/XSW build, a decision left to the maintainers), desktop callbacks, device
identities, ownership for additional durable proprietary resources, and independent security review
remain.

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
secret-file ACL hardening plus an external KMS/HSM option remain review gates. Traditional (non-PKCS#8)
EC PEM signing supports P-256 and P-384. Its DEK-Info cipher coverage (AES-128/192/256-CBC,
DES-EDE3-CBC, DES-CBC) already matches everything realistically produced by current tooling — RC2/RC4/
CAMELLIA are deprecated legacy PEM ciphers nobody deliberately picks for a signing workflow and are not
planned. **P-521 signing now works** (2026-07-25): rather than the `x509-certificate` 0.25.0 convenience
signer (which only implements `Secp256r1`/`Secp384r1`), the P-521 path signs the CMS `SignerInfo` directly
with the pure-Rust `p521` crate (ECDSA-P521 + SHA-512 → `ecdsa-with-SHA512` / `secp521r1`), reusing the
existing `/ByteRange`+`/Contents` reservation. Independently verified with OpenSSL 3 (`cms -verify` passes;
tampered content and wrong keys are rejected). **A pre-existing P-384 CMS bug uncovered by that work is
also fixed** (2026-07-25): the P-384 path used to emit a SHA-256 `digestAlgorithm` against an
`ecdsa-with-SHA384` `signatureAlgorithm` — a curve inconsistency strict verifiers (OpenSSL, Adobe) reject.
It now emits SHA-384, verified the same way (OpenSSL `cms -verify` passes where the pre-fix output failed).
Every EC curve is now digest-consistent: P-256/SHA-256, P-384/SHA-384, P-521/SHA-512.
A live SoftHSM/token compatibility matrix and broader Windows smart-card coverage
remain explicit gaps. It also lacks certificate policy validation,
public Java/Acrobat compatibility fixtures, and security review, so it is not
full signing or PAdES parity.

When `DOCKER_ENABLE_SECURITY=true`, `SECURITY_ENABLELOGIN=true`, or its underscored
alias is requested, the Rust binary still refuses to start instead of silently
serving either an unsecured approximation or the not-yet-approved opt-in security router. See
`SECURITY_MIGRATION_DESIGN.md` and `SIGNING_MIGRATION_DESIGN.md` for the review
gates before either secure mode or signing is implemented.

The separate `stirling-ai-engine` crate now ports the current Python HTTP agent
surface: health/auth, classification, PDF comments, both math-audit rounds,
durable SQLite documents with ACL/TTL and provider embeddings, PDF questions,
bounded long-document map/reduce, contradiction detection, schema-grounded PDF
edit planning, PDF review, structured PDF creation, saved-agent draft/revision,
the next-action contract (which, matching the Python oracle, is a live stub:
`POST /api/v1/agents/next-action` always returns
`cannot_continue`/"Execution planning is not implemented yet" — see
`contracts/ai-engine-foundation.md`), and the NDJSON orchestrator with
math-audit resume. The smart and fast model tiers share the Python-compatible
process-wide `STIRLING_MODEL_MAX_CONCURRENCY` ceiling, in addition to narrower
per-agent worker limits. Its MCP manifest publishes all eight completed Python
capabilities. Model-selected evidence and comment anchors are mapped back to
trusted local indices, while edit parameters are validated against a generated
snapshot of the Java operation schemas. Deterministic saved-agent steps reuse
that catalog plus the three typed Python agent operations, while `ai_tool`
steps remain restricted to generated processing endpoints; both reject unknown
endpoints, and deterministic steps reject mismatched parameter objects on
inbound requests and model output. PostgreSQL/pgvector now uses the
Python-compatible schema with atomic replace-ingest, bounded pooled TLS
connections, TTL and ACL-gated page/vector reads. The `migrate-sqlite-vec`
binary now performs idempotent Python-store cutover to Rust SQLite or pgvector:
it preserves pages, metadata, TTL and read ACLs while re-embedding content
without loading the sqlite-vec extension, and fails closed on unreconstructable
legacy records.

The engine also ports the Python oracle's admin config-push subsystem (Python
PR #7069): `POST /api/v1/config` accepts Java's `AiEngineConfigSync` body (both
camelCase and snake_case field spellings; unknown fields tolerated, matching
the oracle's `TolerantApiModel`), is gated by the Python-compatible
`STIRLING_ALLOW_CONFIG_PUSH` flag (default on, same as Python; flag-off → 403
naming the flag), rebuilds the live model tiers with a fresh shared semaphore
while in-flight requests keep their runtime snapshot, and persists the pushed
config through an encrypted at-rest cache restored on boot (0600 files;
corrupt/wrong-key cache falls back to environment config, matching
`_restore_cached_config`). One documented divergence: the cache cipher is
AES-GCM rather than Python's Fernet — the cache is engine-private, never read
across languages. The two `process_smoke` timeouts previously written off as
environmental are fixed: `tracing-subscriber` emitted ANSI escapes into piped
output, breaking the handshake parse; smoke tests now capture child stderr and
all five pass in under a second. See `contracts/ai-engine-foundation.md`.

Structured provider inference now includes the Python-compatible native
`ollama:<model>` path for both model tiers: keyless local or optionally
authenticated remote endpoints, normalized OpenAI-compatible URLs, and
schema-constrained native JSON output. A compiled-binary process test proves an
HTTP agent request completes through a fake Ollama server without inventing an
authorization header. The generated operation snapshot no longer passes through
Pydantic: the typed `stirling-operation-catalog` crate translates Java OpenAPI
directly, retains validation/default semantics, and supplies a deterministic
`--check` drift gate while the Python artifact remains an independent oracle.

Environment-backed AI-engine booleans and numeric limits now parse strictly before the listener
binds. Malformed or non-Unicode auth flags terminate startup instead of substituting the permissive
default, and token/concurrency/chunking/contradiction/pgvector bounds plus the typed document-backend
selection are validated at the same fail-closed boundary.

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
manifest caching/filtering, and the two executable AI tools. It also now owns reusable
file artifacts (`stirling_upload`/`stirling_download`, reusing the existing owner-scoped
async-job store verbatim) and direct dispatch of a real Stirling processing operation by
its API path (`stirling_operation`, reusing the pipeline runner's own in-process router
dispatch — a Rust-only convenience; Java's server exposes eight tools without it). Phase two
has landed: Java's four per-category tools (`stirling_pages`/`stirling_convert`/
`stirling_misc`/`stirling_security`) and `stirling_describe_operation` are ported with
byte-matched `operationListError`, input-schema, and describe texts. Their operation-id sets
reproduce Java's `McpToolCatalog.extractOpId` exactly: because the curated AI operation
catalog deliberately excludes eleven flat POST paths, a generated
`mcp_operation_supplement.json` restores them and an enum-completeness test pins the union
against Java's id set (the empty `stirling_convert` enum is genuine Java behavior — every
convert path has a nested tail). The scope framing previously recorded here was wrong and is
corrected: Java's `McpApiKeyAuthFilter` statically grants both `mcp.tools.read`/
`mcp.tools.write` to every valid API key — Java has no per-key scope store either — so
sharing phase one's authorization boundary is exact parity in apikey mode, and granular
scopes only become meaningful in the unported OAuth/JWT mode. OAuth/JWT metadata and
production secured-mode cutover remain explicit later phases. See `contracts/mcp.md`.

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
periodic reconciliation are active in the reviewed runtime. The webhook input-source type, its
enabled-only trigger dispatch, the FULL reconcile safety-net, and the public HMAC receiver/spool
(`POST /api/v1/webhooks/{webhookId}`) are now ported. **The webhook subsystem is now end-to-end: a
delivery is spooled by the receiver and consumed by a webhook policy run — `resolve_source` has a real
`"webhook"` arm that reads the per-webhook spool dir through the folder-consume lifecycle (ledger
claim/settle, display-name filename, cross-policy delete, retain-on-failure), porting
`WebhookInputSource.resolve`/`completeConsumed`.** Ad-hoc streamed runs emit
Java-compatible started/completed step events and a terminal owner-scoped run view without
cancelling work on disconnect. Java's dormant `WAITING_FOR_INPUT` scaffolding has no live resume
route to port, while automatic trigger state is process-local pending the broader distributed
runtime. See
`contracts/resource-access-integrations.md`,
`contracts/policy-config.md`, and
`contracts/webhook-receiver.md`.

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

### SaaS hosted-cloud layer (`app/saas/`) — PAUSED, unverifiable in this env

With durable storage and collaborative signing ported, the OSS core, the
proprietary `controller/api` route surface, and the processing backend are ported.
The remaining unported Java controllers live in the hosted-SaaS product **plus one
proprietary-module subsystem**: `stirling.software.proprietary.accountlink` — the
`@Profile("!saas")` self-hosted combined-billing `AccountLinkController`
(`/api/v1/account-link`: `link`/`status`/`unlink`/`usage`/`sync-now`, admin-only,
gated behind `stirling.billing.account-link.enabled`) and its
`InstanceEntitlementInterceptor`, which `AccountLinkWebMvcConfig` registers over
`/api/v1/**` as a request-time 402 entitlement gate with per-request metering.
Both call the same un-ported external cloud-billing domain as the SaaS layer
(Supabase auth, payment gateways, cloud billing/entitlement, instance registry)
that cannot be exercised or verified in this dev environment — the same rationale
that PAUSED the external-tool converters. All are deliberately deferred:

- `AiCreateController` / `AiCreateInternalController` — `ai/create/sessions/*`
  (AI document-creation sessions + `JobChargeService` metering).
- `AiProxyController` (SaaS extras) — `ai/{generate_section, generate_all_sections,
  chat/*, edit/sessions/*, pdf-editor/*, intent/check, progressive_render,
  style/{userId}, versions/{userId}, import_template, output, pdf/answer}`.
- `UserRoleWebhookController` — `user-role/*` (Supabase/billing role webhooks).
- `AccountLinkController` (`account-link/*`), `InstanceController`,
  `Payg{Wallet,Invoices,PaymentMethod}Controller`, `PricingPolicyAdminController`,
  `ProcurementController`, `SaasTeamController`, `SaasFleetUsageController` (a `@Profile("saas")`
  team-scoped alternative on the already-served `usage/fleet-stats` path — needs a saas-mode
  switch, not a standalone port).
- `DatabaseController`/`DatabaseControllerEnterprise` — H2-only
  (`@Conditional(H2SQLCondition)`) DB backup/restore; N/A for the Rust sqlite store
  (a sqlite-backup equivalent would be net-new, not strict parity).
- `PaygCucumberThrowController` — a `@Profile("payg-cucumber")` hidden test stub
  that forces a 500 for cucumber runs; never registered in production, nothing to port.

`CertSignController`'s base `/api/v1/security` and `PrintFileController`'s
`/api/v1/misc/print-file` show up in naive scans but are false positives — the real
cert-sign routes are ported and the Java print-file mapping is commented out (inactive).

## How to find gaps precisely

Use `docs/contracts/legacy-runtime-baseline.md` for the cross-surface baseline and
the contract files in `rust/contracts/` for implemented behavior and explicit
gaps. Source-literal counts are not authoritative because Spring composes class
and method mappings while the Rust service composes public, conditional, and
review-only secured routers. When diffing Java `@*Mapping` literals against the Rust
route constants, STRIP Java comments first — several controllers keep inactive
endpoints commented out (e.g. `AuditDashboardController`'s `/stats/range`,
`/principals`, `/latest`; `PrintFileController`'s `/print-file`), and a naive grep
reports those as false "unported" gaps.
