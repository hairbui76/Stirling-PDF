# Stirling Rust Processing

This workspace ports the Java backend while retaining the existing browser UI and
its REST contract. It contains three crates:

- **`stirling-processing`** — the axum HTTP service mirroring the Java
  `/api/v1/...` surface: the PDF-operation routes (merge/split/convert/security/
  forms/redaction/…), configuration and UI-data endpoints, pipelines and
  watched folders, async jobs, and — inside an opt-in reviewed secured router —
  accounts, storage, collaborative signing, audit, policies, and MCP.
- **`stirling-ai-engine`** — the Rust port of the Python AI engine
  (classification, PDF questions, document creation, math audit, orchestration).
- **`stirling-operation-catalog`** — generates the typed operation catalog from
  the Java OpenAPI document (`task engine:tool-models`).

**Where to look things up:**

- **How to run the repo on Rust instead of Java** — see
  [`RUNNING_WITH_RUST.md`](RUNNING_WITH_RUST.md) (prerequisites, external tools,
  ports, configuration, AI engine, limitations).
- **What is ported, and how faithfully** — see [`PORT_STATUS.md`](PORT_STATUS.md)
  (the authoritative ledger) and the per-surface compatibility contracts in
  [`contracts/`](contracts/) (routes, Java counterparts, parity notes, explicit
  gaps).

The route surface is deliberately **not** enumerated here — an earlier hand-kept
list in this file drifted dozens of routes behind reality. A fixed route total is
likewise deferred to the versioned baseline-to-Rust manifest so nested secured
routers and conditional endpoints are counted by method and path rather than
inferred from source literals. Illustrative examples of the breadth:
`POST /api/v1/general/merge-pdfs`, `POST /api/v1/convert/pdf/img`,
`POST /api/v1/security/redact-execute`, `POST /api/v1/pipeline/handleData`,
`GET /api/v1/config/app-config`, `POST /api/v1/webhooks/{webhookId}`, and the
secured `storage/`, `security/cert-sign/`, `audit/`, and `auth/oidc/` families.

## Quick start

Install the pinned PDFium runtime and run locally from the repository root:

```bash
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

The binary remains loopback-only unless `STIRLING_HOST` or the Spring-compatible
`SERVER_ADDRESS` is set to an explicit IP address. Container-shaped runs use
`STIRLING_HOST=0.0.0.0`; malformed or non-Unicode host/port values fail startup.

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

## Implementation notes

The merge slice uses PDFium page import and a bounded-memory incremental bookmark/TOC
writer. The rotate slice uses PDFium's intrinsic page rotation. `lopdf` remains as the
no-PDFium development fallback, for sequential metadata inspection during title/date
sorting, and for the targeted PDFBox-compatible signature-field flattening pass when
PDFium detects signatures. It is not used to build the combined document on the
configured native merge path.

The UI-data dependency-notice manifest is generated from the Rust lockfile during
build; `UNKNOWN` entries and native-tool notices remain release-compliance gates.

## Validate the workspace

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The direct Cargo commands use the compatibility implementation when PDFium is not on
the system library path. `task rust:check` installs and configures PDFium so the native
processing paths are exercised by the endpoint tests.
