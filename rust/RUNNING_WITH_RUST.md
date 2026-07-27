# Running Stirling-PDF with the Rust backend (replacing Java)

This is the operator's guide to running this repository with the Rust processing
service (`stirling-processing`) in place of the Java Spring Boot backend, plus the
optional Rust AI engine (`stirling-ai-engine`) in place of the legacy Python engine.

**Status in one paragraph:** the Rust service serves the same `/api/v1/...` REST
surface the unchanged web UI talks to, and it is already the *default* backend for
local development tasks (`task dev`, `task backend:dev`, `task dev:all`). Open mode
(no login) is the supported way to run it today. Secured mode (login/users/teams)
exists behind an opt-in review gate and the binary deliberately **refuses to start**
when `SECURITY_ENABLELOGIN=true` or `DOCKER_ENABLE_SECURITY=true` is set — see
[Limitations](#what-does-not-run-on-rust-yet). Java remains the packaged
production/desktop backend until the cutover gates in
[`PORT_STATUS.md`](PORT_STATUS.md) are closed.

---

## 1. Prerequisites

| Requirement | Why | Install |
|---|---|---|
| Rust toolchain (stable) | builds the workspace in `rust/` | <https://rustup.rs> |
| [Task](https://taskfile.dev) | unified command runner used below | `brew install go-task` / see site |
| PDFium (pinned revision 7543) | native PDF rendering/processing paths | `task rust:install` (automatic) |
| Node.js + npm | only if you also run the frontend dev server | `task frontend:install` |

`task rust:install` fetches the Cargo dependencies and downloads the pinned PDFium
build for your platform into the git-ignored `rust/.pdfium/` directory, verifying
its SHA-256 digest. Deployments can instead point
`STIRLING_PDFIUM_LIBRARY_PATH` at an absolute PDFium shared-library path (or its
containing directory). A configured PDFium is treated as required: a bad path fails
the request rather than silently switching engines. Without any PDFium, the service
still starts and uses pure-Rust fallbacks where they exist, but the native
processing paths (and many endpoint tests) need it — install it.

### Optional external tools

Like the Java backend, some conversions shell out to external tools. The Rust
service discovers them at startup (bounded discovery, with minimum versions where
Java requires them). A missing tool does not crash anything: the affected endpoints
report as unavailable with reason `DEPENDENCY` in
`GET /api/v1/config/endpoints-availability`, exactly like Java's alternatives
mechanism.

| Tool (binary) | Enables | Notes |
|---|---|---|
| LibreOffice (`soffice`) | office ↔ PDF (`convert/file/pdf`, `pdf/word`, `pdf/presentation`, `pdf/xml`) | |
| Ghostscript (`gs`) | PDF/A / PDF/X, repair, compress assist, color-space conversion, e-reader optimisation | |
| qpdf | repair (second choice), compress assist | minimum version 12 |
| OCRmyPDF (`ocrmypdf`) | preferred OCR path for `misc/ocr-pdf` | |
| Tesseract (`tesseract`) | OCR fallback path; language data under the configured tessdata dir | |
| WeasyPrint (`weasyprint`) | HTML/Markdown/EML/URL → PDF, AI create-PDF | minimum version 58 |
| Poppler (`pdftohtml`) | PDF → HTML, and Calibre's PDF→EPUB engine | |
| Calibre (`ebook-convert`) | ebook ↔ PDF | |
| `unrar` (or 7-Zip fallback) / `rar` | CBR → PDF / PDF → CBR (creating CBR requires `rar`) | |
| FFmpeg | PDF → video (route is an explicit opt-in, see below) | set `STIRLING_PROCESSING_FFMPEG_COMMAND` |
| veraPDF | strict PDF/A validation (optional) | set `STIRLING_PROCESSING_VERAPDF_COMMAND` |

Every tool's executable can be overridden explicitly with
`STIRLING_PROCESSING_<TOOL>_COMMAND` (e.g. `STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND`,
`..._SOFFICE_COMMAND`, `..._QPDF_COMMAND`, `..._WEASYPRINT_COMMAND`,
`..._OCRMYPDF_COMMAND`, `..._TESSERACT_COMMAND`, `..._PDFTOHTML_COMMAND`,
`..._EBOOK_CONVERT_COMMAND`, `..._UNRAR_COMMAND`, `..._RAR_COMMAND`).

---

## 2. Quick start

From the repository root:

```bash
task rust:install     # once: deps + pinned PDFium
task backend:dev      # Rust backend on http://127.0.0.1:8080
```

In a second terminal, if you want the web UI:

```bash
task frontend:dev     # Vite dev server, proxies /api/* to localhost:8080
```

Or run both together on automatically chosen free ports:

```bash
task dev              # backend (Rust) + frontend
task dev:all          # backend (Rust) + frontend + Rust AI engine
```

`task backend:dev`, `task dev`, and `task dev:all` all select the **Rust** backend
by default. The Java backend remains available as the compatibility oracle:

```bash
task backend:dev:java # Java Spring Boot backend instead
```

Direct entry point without Task:

```bash
cd rust
STIRLING_PDFIUM_LIBRARY_PATH="$PWD/.pdfium/current" \
  cargo run -p stirling-processing --locked
```

Smoke-check a running instance:

```bash
curl http://127.0.0.1:8080/api/v1/info/status
curl http://127.0.0.1:8080/api/v1/config/app-config
```

### Ports and binding

- `task backend:dev` / `task rust:run` default to `127.0.0.1:8080`; pass
  `PORT=<n>` to either Task command.
- Invoking the binary directly: `STIRLING_PORT` (or the Spring-compatible
  `SERVER_PORT`) selects the port; `0` requests an OS-assigned ephemeral port.
  Startup prints `Stirling-PDF running on port: <port>`.
- The binary binds **loopback only** unless `STIRLING_HOST` (or Spring-compatible
  `SERVER_ADDRESS`) is set to an explicit IP. Container-shaped runs use
  `STIRLING_HOST=0.0.0.0`. Malformed host/port values fail startup instead of
  falling back.

---

## 3. Configuration

The Rust service reads the same YAML files as Java:
`configs/settings.yml` then `configs/custom_settings.yml`, resolved below
`STIRLING_BASE_PATH` (default: the working directory). Behavior matches Java's
`ConfigInitializer`, including:

- template merge on upgrade (new template keys arrive with defaults; user-set leaf
  values are preserved; comments/ordering kept; idempotent),
- truncated-file recovery (a `settings.yml` under 31 lines is backed up to
  `settings.yml.<epoch-millis>.bak` and recreated from the template),
- environment overrides layered on top (`SYSTEM_*`, `SECURITY_*`, `STIRLING_*`
  spellings that Java's relaxed binding accepts).

Commonly used environment variables:

| Variable | Purpose |
|---|---|
| `STIRLING_BASE_PATH` | root for `configs/` settings files |
| `STIRLING_HOST` / `SERVER_ADDRESS` | bind address (default loopback) |
| `STIRLING_PORT` / `SERVER_PORT` | port (default 8080; `0` = ephemeral) |
| `STIRLING_PDFIUM_LIBRARY_PATH` | PDFium shared library (file or directory) |
| `STIRLING_PROCESSING_MAX_UPLOAD_BYTES` | multipart upload cap |
| `SYSTEM_MAXFILESIZE`, `SYSTEM_MAXDPI` | Java-compatible processing limits |
| `SYSTEM_GOOGLEVISIBILITY` | `robots.txt` policy |
| `SYSTEM_ENABLEMOBILESCANNER` | mobile-scanner QR transfer feature gate |
| `STIRLING_PROCESSING_ENABLE_URL_TO_PDF` / `SYSTEM_ENABLEURLTOPDF` | opt-in URL→PDF (SSRF-guarded) |
| `STIRLING_JOB_QUEUE_*`, `STIRLING_JOB_RESULT_EXPIRY_MINUTES` | async job queue/result tuning |
| `AIENGINE_URL`, `AIENGINE_ENABLED`, `AIENGINE_TIMEOUTSECONDS` | AI-engine proxy wiring |

Async processing works on the ported POST endpoints via the same `?async=true`
contract as Java (`general/job/{jobId}`, `/result`, `/result/files`,
`general/files/{fileId}` serve status/results).

---

## 4. Optional: the Rust AI engine

The AI features (`/api/v1/ai/*`, MCP, classification, PDF question answering,
document creation, math audit, orchestration) are served by the separate
`stirling-ai-engine` crate, which replaced the Python engine (the Python oracle
remains under `engine/` for compatibility testing).

```bash
task engine:dev       # Rust AI engine on localhost:5001
# or: task dev:all    # starts it alongside backend + frontend
```

Point the processing service at it with `AIENGINE_URL` (default
`http://localhost:5001`) and `AIENGINE_ENABLED=true`. Provider credentials follow
the engine's own configuration (structured-output-capable providers, including
Anthropic/OpenAI-compatible APIs and native `ollama:<model>` for local models).
`STIRLING_ENGINE_SHARED_SECRET` protects the engine boundary when set.
The engine's quality gate is `task engine:check`; the legacy Python oracle keeps
`task engine:legacy:*`.

---

## 5. Verifying parity yourself

- `task rust:check` — fmt + clippy + full test suite with PDFium bound (the
  same gate CI runs; see `PORT_STATUS.md` for the latest full-gate numbers).
- **Differential harness** (`testing/differential/`) — drives BOTH backends with
  the same requests and semantically diffs the responses; known, root-caused
  differences are declared with pinned values in `known_diffs.py`. CI runs this as
  the `differential-parity` workflow; `run_smoke.sh` is the local entry point
  (needs both backends runnable).
- **Per-surface contracts** (`rust/contracts/*.md`) — each ported surface documents
  routes, Java counterparts, parity notes, and explicit gaps.

---

## 6. What does NOT run on Rust yet

These are deliberate, documented limits — the authoritative list with rationale is
[`PORT_STATUS.md`](PORT_STATUS.md):

- **Secured mode (login/users/teams).** A reviewed opt-in security router exists
  and is extensively tested, but production secure mode is gated on independent
  human security review. Setting `SECURITY_ENABLELOGIN=true` or
  `DOCKER_ENABLE_SECURITY=true` makes the Rust binary refuse startup (fail-closed,
  including on malformed boolean values) instead of serving an unsecured
  approximation. Run open mode, or use the Java backend for secured deployments.
- **SaaS / hosted-cloud layer** (`app/saas`, account-link billing): deliberately
  deferred; depends on external cloud services unverifiable here.
- **SAML2 SSO**: deferred pending a maintainer decision on a native XML-signature
  dependency. (Generic OIDC login is ported inside the opt-in secured router;
  Supabase JWT verification is ported.)
- **H2 database backup/restore routes**: N/A — the Rust store is SQLite.
- **PDF → video** route: implemented but an explicit opt-in
  (`STIRLING_PROCESSING_FFMPEG_COMMAND`) while upstream FFmpeg CVEs are assessed —
  the current Java route is itself commented out.
- **Desktop packaging**: the Tauri desktop app can *validate* against a Rust
  backend via `STIRLING_NATIVE_BACKEND_PATH` (ephemeral-port handshake, workspace
  migration), but Java remains the bundled desktop backend; PDFium/sidecar
  packaging is a release-pipeline task.
- **Deep PDF-fidelity edges** in the PDF↔JSON editor model (e.g. Type3 glyph
  synthesis, Type0/Type3 byte-parity, >4-component DeviceN JPEGs): see the
  "Remaining" section of `PORT_STATUS.md`.

## 7. Production cutover position

Local development defaults to Rust; the packaged production containers and desktop
builds still ship Java. The remaining cutover gates are: independent security
review of the secured router and signing subsystem, desktop/CI packaging of the
Rust binary + PDFium, and the residual fidelity gaps above. Follow
`PORT_STATUS.md`, `SECURITY_MIGRATION_DESIGN.md`, and `SIGNING_MIGRATION_DESIGN.md`
for the live state of each gate.
