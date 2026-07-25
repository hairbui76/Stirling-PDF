# Running Stirling-PDF with the Rust backend

Stirling-PDF's document-processing backend has been ported from Java (Spring Boot) to
Rust. The Rust service is the `stirling-processing` crate in [`rust/`](rust/) — an
[axum](https://github.com/tokio-rs/axum) HTTP server that mirrors the Java
`/api/v1/...` REST contract, so the existing browser UI talks to it unchanged.

This guide covers running the app on the Rust backend for local development.

> **Status.** The Rust backend is functionally complete for the OSS + processing
> surface and is the default for open-mode local dev. **Java is still the packaged
> production and desktop backend** — the production cutover is not yet flipped, and
> secured mode (login/auth) is intentionally not served by Rust yet (see
> [Security mode](#security-mode)). For the exact ported/unported surface, see
> [`rust/PORT_STATUS.md`](rust/PORT_STATUS.md).

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Rust toolchain ≥ 1.94** | Workspace pins `rust-version = 1.94`, edition 2024. Install via [rustup](https://rustup.rs). |
| **[Task](https://taskfile.dev/)** | The unified command runner (`task <command>`). All commands below use it. |
| **Node.js ≥ 20** | Only needed to run the browser UI (`frontend:dev`). |
| **PDFium** | Installed automatically by `task rust:install` (pinned binary, no system install). |

Optional external command-line tools enable specific converters — see
[Optional external tools](#optional-external-tools). They are **not required** to
start the server; endpoints that need a missing tool report it as a `DEPENDENCY`
availability gap.

---

## One-time setup

```bash
# Installs frontend deps, fetches Rust deps, and downloads the pinned PDFium runtime
task install

# ...or just the Rust side:
task rust:install
```

`task rust:install` downloads a pinned [PDFium](https://github.com/bblanchon/pdfium-binaries)
build into `rust/.pdfium/current`. If you ever need it on its own:

```bash
task rust:pdfium:install
```

---

## Quick start (backend + UI)

Run the Rust backend and the browser UI together:

```bash
task dev
```

This starts the Rust backend (open mode) and the Vite frontend concurrently, each on
a free port, and **prints the chosen URLs at startup** — open the frontend URL in your
browser (the frontend proxies `/api/*` to the backend). To also start the AI engine:

```bash
task dev:all
```

Or run the pieces in separate terminals, where each uses its fixed default port:

```bash
task backend:dev      # Rust processing service on :8080 (open mode)
task frontend:dev     # UI on :5173, proxying to :8080
task engine:dev       # (optional) Rust AI engine on :5001
```

> `task backend:dev` runs the **Rust** backend. To run the legacy Java backend for
> comparison instead, use `task backend:dev:java`.

---

## Running only the Rust API server

To start just the processing service (no UI):

```bash
task rust:run
```

It listens on `127.0.0.1:8080` by default. Override behaviour with these variables
(pass as `task rust:run VAR=value`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `HOST` | `127.0.0.1` | Bind address |
| `PORT` | `8080` | Listen port |
| `AIENGINE_URL` | `http://localhost:5001` | AI engine base URL |
| `AIENGINE_ENABLED` | `false` | Enable AI-proxy routes |
| `AIENGINE_TIMEOUTSECONDS` | `120` | AI engine request timeout |
| `SECURITY_ENABLELOGIN` | `false` | See [Security mode](#security-mode) |
| `POLICIES_ENABLED` | `false` | Enable policy/pipeline routes |

The task sets `STIRLING_PDFIUM_LIBRARY_PATH` to `rust/.pdfium/current` for you. If you
run the binary directly with `cargo`, set it yourself:

```bash
cd rust
export STIRLING_PDFIUM_LIBRARY_PATH="$PWD/.pdfium/current"
cargo run -p stirling-processing --locked
```

---

## AI engine (optional)

The AI features are served by a separate `stirling-ai-engine` crate. The Rust
backend proxies to it through the same Java-compatible `/api/v1/ai/*` routes.

```bash
task engine:dev                          # Rust AI engine on :5001
task rust:run AIENGINE_ENABLED=true      # point the backend at it
```

You will need a structured-output-capable model provider configured (Anthropic
Messages, OpenAI-compatible, or a local `ollama:<model>`). See the AI-engine notes in
[`rust/PORT_STATUS.md`](rust/PORT_STATUS.md).

---

## Security mode

When `SECURITY_ENABLELOGIN=true`, `DOCKER_ENABLE_SECURITY=true`, or their underscored
aliases are set, the Rust binary **deliberately refuses to start** rather than serve
an unsecured approximation. Secured mode (login, users, auth) is gated behind an
in-progress security review — run the backend in the default open mode, or use the
Java backend (`task backend:dev:java`) if you need authentication today. See
[`rust/SECURITY_MIGRATION_DESIGN.md`](rust/SECURITY_MIGRATION_DESIGN.md).

---

## Optional external tools

Certain converters shell out to external tools, exactly as the Java backend does. If a
tool is missing, only the endpoints that need it are affected (reported as a
`DEPENDENCY` availability gap); the rest of the server runs normally.

| Feature / endpoints | Tool(s) |
|---------------------|---------|
| Office ↔ PDF (`convert/file/pdf`, `convert/pdf/word\|presentation\|xml`) | LibreOffice |
| PDF/A, CMYK conversion, e-reader optimization, repair | Ghostscript |
| Repair | qpdf |
| HTML / Markdown / EML / URL → PDF | WeasyPrint |
| eBook ↔ PDF (`convert/ebook/pdf`, `convert/pdf/epub`) | Calibre |
| OCR (`misc/ocr-pdf`) | OCRmyPDF and/or Tesseract |
| Comic book (`convert/cbr/pdf`, `convert/pdf/cbr`) | unrar / rar (7-Zip fallback) |
| PDF → video (opt-in) | FFmpeg |

---

## Developer commands

```bash
task rust:build     # cargo build --workspace
task rust:test      # cargo test --workspace
task rust:lint      # clippy (strict, -D warnings)
task rust:format    # rustfmt
task rust:check     # full quality gate: fmt + clippy + tests
```

Run `task rust:check` before submitting changes.

---

## Ports at a glance

| Service | Port |
|---------|------|
| Rust processing backend | 8080 |
| Frontend (Vite dev server) | 5173 |
| Rust AI engine | 5001 |

---

## Troubleshooting

- **`the configured PDFium runtime is unavailable` / PDFium errors** — run
  `task rust:pdfium:install`, or ensure `STIRLING_PDFIUM_LIBRARY_PATH` points at
  `rust/.pdfium/current` when running `cargo` directly.
- **The server exits immediately when enabling login** — expected; see
  [Security mode](#security-mode).
- **A converter returns a dependency/availability error** — the corresponding
  [external tool](#optional-external-tools) is not installed or not on `PATH`.
- **Port 8080 or 5173 already in use** — pass `PORT=<n>` to `task rust:run`, or stop
  the process using the port.

---

## See also

- [`rust/README.md`](rust/README.md) — the Rust workspace overview
- [`rust/PORT_STATUS.md`](rust/PORT_STATUS.md) — precise ported/unported surface and known gaps
- [`rust/contracts/`](rust/contracts/) — per-endpoint compatibility notes vs. the Java backend
- Root `AGENTS.md` / `CLAUDE.md` — full project development guide
