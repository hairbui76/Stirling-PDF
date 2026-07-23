# Rust Backend Replacement — Design & Plan

Decision (2026-07-15): the Rust service is to **replace the entire Java backend**,
not act as a PDF-only sidecar. This document scopes that work so it can be reviewed
and sequenced before coding, rather than ground out endpoint-by-endpoint.

Two areas need a plan before code: **application infrastructure** (auth, config,
pipeline, signing, app shell) and the **PDF↔JSON editor subsystem** (the single
largest, hardest-to-port piece). PDF processing operations are ~90% done and
continue under the existing per-endpoint pattern.

---

## Part A — Application infrastructure

The Java app is Spring Boot 4 (Jackson 3, JDK 21/25). These pieces are not PDF
logic and each is a track of its own.

### A1. Configuration & app shell
- **Java:** `SPDFApplication`, `ConfigInitializer`, `ApplicationProperties`,
  YAML config (`settings.yml`) + `STIRLING_*`/`SYSTEM_*` env overrides, runtime
  settings files, `SettingsController`, `ConfigController`, `UIDataController`,
  `app-config`/`capabilities`/`endpoints-*`.
- **Rust plan:** a typed `AppConfig` (serde + `figment`/`config` crate) loading the
  same YAML + env keys. The Rust service already reads several `SYSTEM_*`/`STIRLING_*`
  vars ad hoc (`max_upload_bytes`, `SYSTEM_MAXDPI`, tool paths) — consolidate these
  into one config type. Expose the read-only config/capability endpoints.
- **Risk:** low–medium. Mechanical but must match key names and precedence exactly.

### A2. Security / auth  ⚠️ highest-risk track
- **Java:** Spring Security, optional auth gated by `DOCKER_ENABLE_SECURITY`, user
  management, sessions (`create-session`/`validate-session`), login, SaaS/OAuth,
  API keys, per-endpoint authorization.
- **Rust status:** an opt-in `axum`/`tower` boundary now provides durable BCrypt
  identities, lockout, rotating digest-only opaque sessions/API keys, encrypted
  replay-safe TOTP, role/team/invite administration, Supabase JWT verification,
  disabled self-registration, durable user settings, initial-setup completion,
  administrator audit query/export/retention, and owner-scoped jobs. Generic OIDC/SAML/device identity, broader resource
  ownership, Java database migration, and independent review remain.
- **Risk:** HIGH. Security-critical; needs its own design doc + threat review before
  any code. Do NOT auto-generate in a loop. Recommend: port with security disabled
  first (matches OSS default), design the secured mode separately.
- **Design:** [`SECURITY_MIGRATION_DESIGN.md`](SECURITY_MIGRATION_DESIGN.md). The
  Rust binary currently fails closed when `DOCKER_ENABLE_SECURITY=true` or the
  compatible `SECURITY_ENABLELOGIN=true` alias is set.

### A3. Pipeline
- **Java:** `PipelineController`, `PipelineProcessor`, `PipelineDirectoryProcessor` —
  chains operations from a JSON pipeline config, optional directory watching.
- **Rust status:** the synchronous runner dispatches equivalent JSON pipelines through
  the in-process multipart routes. The binary owns a separate 60-second watched-folder
  lifecycle with readiness checks, processing handoff/rollback, and output templates.
  Generic pre-validation against the legacy OpenAPI metadata remains a compatibility gap.
- **Risk:** medium. Self-contained; fully verifiable.

### A4. Signing / timestamps  ⚠️ security-sensitive
- **Java:** `CertSignController`, `TimestampController`, `HardwareSigningController`,
  PKCS#11 / Windows certificate stores, `sign`, `timestamp-pdf`.
- **Rust plan:** signature *validation* + verify are already ported (x509/CMS crates).
  Signing (attach a PAdES/CMS signature) is feasible with `cryptographic-message-syntax`
  + `p12`/`pkcs8`; PKCS#11 via the `cryptoki` crate; Windows cert store via
  `windows`/`schannel`. RFC-3161 timestamps via an HTTP TSA client.
- **Risk:** HIGH (crypto correctness + private-key handling). Own design doc.
- **Design:** [`SIGNING_MIGRATION_DESIGN.md`](SIGNING_MIGRATION_DESIGN.md).

### A5. Misc app endpoints
`login-disclaimer`, `licenses`, `additionalLanguageCode`, `robots.txt`,
`update-enable-analytics`, and footer/home data are now ported. The legacy
`/js/additionalLanguageCode.js` response bakes the bundled locale directories
into the Rust binary at build time and applies the strict `ui.languages`
allowlist. The proprietary administrator-only Tessdata inventory/downloader is
also ported with bounded atomic installation. `print-file` remains unported; its
Java controller is itself a TODO.

### Suggested A-sequence
A1 (config) → A3 (pipeline) → A5 (misc) → **design docs for A2 + A4** → A2 → A4.
Rationale: unlock the verifiable, low-risk infrastructure first; gate the two
security-critical tracks behind dedicated review.

---

## Part B — PDF↔JSON editor subsystem

`ConvertPdfJsonController` + `PdfJsonConversionService` (**6,958 lines**, 320
font/glyph references). Endpoints: `/pdf/text-editor` (PDF→JSON), `/text-editor/pdf`
(JSON→PDF), `/pdf/text-editor/metadata`, `/pdf/text-editor/partial/{jobId}`,
`/pdf/text-editor/page/{jobId}/{pageNumber}`, `/pdf/text-editor/fonts/{jobId}/{pageNumber}`,
`/pdf/text-editor/clear-cache/{jobId}`.

### Why this needs a plan, not a blind port
The JSON model captures **per-glyph** text (position, text matrix, char codes,
rendering mode, fill/stroke color, spacing) and **full font programs** (embedded
Type1/TrueType/Type0-CID/Type3, encodings, ToUnicode, `unitsPerEm`, descriptor
flags, plus re-encoded "web" and "pdf" font programs and Type3 glyph procedures).
Java gets this from PDFBox's `PDFGraphicsStreamEngine`, `PDFStreamParser`,
`ContentStreamWriter`, and the `PDFont` hierarchy.

**No Rust crate provides this.** `pdfium-render` exposes text with positions but
not the COS-level content-stream engine or font-program reconstruction; `lopdf` is
low-level (no glyph metrics/encoding/graphics state). A faithful port means either
(a) building a content-stream interpreter + font subsystem in Rust, or (b) binding
to a native library. And the output JSON must match the frontend editor's schema
**exactly** (it is a strict contract, even though the UI itself is out of scope).

### Font-program strategy — selected: pure Rust

The user objective requires the whole backend to move to Rust, so the editor uses a
pure-Rust font subsystem. The current implementation exports page-scoped font resources,
bounded embedded programs, descriptors, and `ToUnicode` data directly through `lopdf`; it also
parses page-local text-showing content streams into an initial text-element model. It deliberately
does not claim glyph-accurate extraction or font reconstruction yet.

- **Option 1 — pure Rust font subsystem:** use `pdf`/`pdf-canvas`, `font`/`ttf-parser`,
  `allsorts`, `freetype-rs` to parse embedded programs, extract glyph metrics, and
  re-encode. Highest fidelity, very large effort (weeks), the only fully-Rust path.
- **Option 2 — bind PDFBox-equivalent native:** e.g. MuPDF (`mupdf` crate) exposes
  structured text + fonts; still not a 1:1 match to the PDFBox JSON, and adds a
  native dep.
- **Option 3 — keep this subsystem in a small embedded JVM/PDFBox sidecar** the Rust
  service calls. Pragmatic, guarantees byte-identical JSON, but retains a JVM dep —
  contradicts "replace entire backend" unless accepted as an exception.

### Phased plan (independent of the above)
- **Phase 1 (done):** Rust serde data model mirroring all `PdfJson*` types +
  `/pdf/text-editor/metadata` core (document metadata, `pageDimensions`, rotation, and
  bounded font resource/program extraction). The lazy metadata response intentionally omits
  form fields like Java.
- **Phase 2 (initial implementation):** JSON→PDF for a no-source-stream page with ordered Latin
  Standard-14/WinAnsi text, text state/matrix, basic device colors, and ordered raster images with
  alpha soft masks. Applying edits over a preserved source stream and embedded-program round-trip
  remain deferred.
- **Phase 3 (in progress):** PDF→JSON text extraction. Page and invoked Form-XObject
  content-stream text/state, resource scopes, and affine transforms are now exported. Type0
  `/ToUnicode` source-code segmentation plus horizontal descendant `/DW`/`/W` advances are
  applied. Embedded encoding CMaps apply bounded `cidchar`/`cidrange` source-code-to-CID mappings
  before those metrics. Installed Poppler Adobe collections also resolve bounded named CMaps and
  recursive `usecmap` inheritance. Vertical writing applies `/DW2` defaults plus both `/W2` forms to
  glyph origins, displacement, and `TJ` movement. Type3 code/name/Unicode metadata and source
  CharProcs round-trip; outline-derived normalization, unavailable CMap collections, and full layout
  remain.
  Direct and Form-nested image XObjects export
  page-space transforms plus bounded JPEG or 1/2/4/8/16-bit DeviceRGB/DeviceGray/DeviceCMYK payloads,
  applying `/Decode` ranges and grayscale `/SMask` alpha, and expanding packed 1/2/4/8-bit
  Indexed images with Gray/RGB/CMYK palettes. ICCBased Gray/RGB/CMYK XObjects convert through their
  bounded embedded profiles to sRGB, including ICCBased Indexed palette bases, with compatible
  device-`/Alternate` fallback; the external profile cannot yet be applied to DCT CMYK after decoder
  projection. Bounded filtered inline images, color-key `/Mask` arrays, and 1-bit stencil masks are
  also handled. Device-alternate Separation and one-to-eight-component DeviceN images with bounded
  order-1 sampled Type 0, single-input exponential Type 2, recursively bounded single-input
  stitching Type 3, or bounded PostScript calculator Type 4 tint transforms are evaluated, including
  one-component DCT Separation images
  after applying `/Decode`. CalGray/CalRGB/Lab direct images, Indexed bases, ICC fallbacks, and
  spot-color alternates convert through bounded calibrated color math, including Gray/RGB/Lab DCT.
  Separation/DeviceN images with an `ICCBased` alternate convert the tint output through the
  embedded profile, with device-`/Alternate` fallback on invalid profiles.
  DCT DeviceN tint conversion (above four components) and complex inline filter parameters remain.
  Full-document exports inspect root
  AcroForm fields and their first widget locations, plus structured page annotations. JSON→PDF
  reconstructs fresh root fields and one attached widget from the structured field model, and
  recreates non-widget page annotations. `Tx`/`Ch` widgets now get a generated `/AP` appearance
  stream from their current value, and `Btn` widgets get a two-state on/off appearance dictionary.
  One widget per field and no annotation reply-chain (`/IRT`) field match Java's own
  `PdfJsonFormField`/`PdfJsonAnnotation` wire models — not a Rust port gap versus Java. Non-widget
  annotation appearance streams remain.
- **Phase 4:** outline-derived Type3 normalization, broader font synthesis, complex CID/layout, and
  preserved-stream editing — full fidelity.
- **Job cache** (`partial`/`page`/`fonts`/`clear-cache`): an in-memory `jobId`→state
  store; straightforward once the model exists.

---

## Open questions for you

1. **A2 (auth) & A4 (signing)** — confirm these get their own design docs + review
   before any code (recommended), and that porting starts with security *disabled*
   (the OSS default) to avoid shipping a weaker secured mode.
2. **Verification env** — for the external-tool converters and for signing (TSA),
   is there a CI/host with the tools installed to verify happy paths?

The next editor milestone is pure-Rust glyph extraction and Standard-14 drawing;
embedded-font reconstruction follows after its parser and width model are verified.
