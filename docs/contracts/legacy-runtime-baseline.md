# Legacy Runtime Baseline for the Rust Port

Generated facts collected from the working tree on 2026-07-15. This document is a
navigation baseline, not a substitute for the versioned request/response fixtures
required before each legacy surface is removed.

## Surface Inventory

| Surface | Contract count | Current source of truth |
| --- | --- | --- |
| Java HTTP server | 259 OpenAPI paths; 271 operations | Generated `SwaggerDoc.json`, hash recorded in `docs/product/rust-port.md` |
| Document-tool API | 87 generated endpoint/parameter contracts | `frontend/editor/src/core/types/toolApiTypes.ts` |
| Python AI engine | 15 HTTP operations: 14 gated router operations plus unauthenticated `/health` | `engine/src/stirling/api` |
| Tauri desktop bridge | 36 commands registered in `tauri::generate_handler!` | `frontend/editor/src-tauri/src/lib.rs` |
| SaaS SQL history | 38 versioned Flyway migration files | `app/saas/src/main/resources/db/migration/saas` |

## AI Engine Contract

All non-health routes use both the shared-secret middleware and required-user-id
dependency. The Rust replacement must retain those boundary rules as well as response
models and document ownership semantics.

| Method | Path |
| --- | --- |
| GET | `/health` |
| GET | `/api/v1/agents/capabilities` |
| POST | `/api/v1/agents/draft` |
| POST | `/api/v1/agents/next-action` |
| POST | `/api/v1/agents/revise` |
| POST | `/api/v1/ai/math-auditor-agent/deliberate` |
| POST | `/api/v1/ai/math-auditor-agent/examine` |
| POST | `/api/v1/ai/pdf-comment-agent/generate` |
| POST | `/api/v1/documents` |
| DELETE | `/api/v1/documents/by-id/{document_id}` |
| DELETE | `/api/v1/documents/by-owner` |
| POST | `/api/v1/documents/classify` |
| POST | `/api/v1/orchestrator` |
| POST | `/api/v1/pdf/edit` |
| POST | `/api/v1/pdf/questions` |

## Desktop Bridge Contract

The current Rust desktop host starts the Java backend and loads the TypeScript
application. It is retained during the initial Java-processing migration, so its
command contract must remain compatible.

| Command group | Registered commands |
| --- | --- |
| Local backend | `start_backend`, `get_backend_port`, `proxy_local_pdf_request` |
| Files and windows | `get_opened_files`, `pop_opened_files`, `clear_opened_files`, `open_in_new_window`, `open_files_in_new_window`, `pop_window_file_ids` |
| Connection and setup | `get_connection_config`, `set_connection_mode`, `is_first_launch`, `reset_setup_completion` |
| Default-app and platform | `is_default_pdf_handler`, `set_as_default_pdf_handler`, `get_desktop_os`, `print_pdf_file_native` |
| Authentication and identity | `login`, `save_auth_token`, `get_auth_token`, `clear_auth_token`, `save_refresh_token`, `get_refresh_token`, `clear_refresh_token`, `save_user_info`, `get_user_info`, `clear_user_info`, `start_oauth_login` |
| Logs and updates | `get_tauri_logs`, `can_install_updates`, `check_for_update`, `download_and_install_update`, `get_app_version`, `get_update_mode`, `set_update_mode`, `restart_app` |

## Data and External-Adapter Boundaries

The Java-processing Rust service must provide explicit adapters and migration proof for
the processing-relevant boundaries below. The browser UI, Python AI engine, and desktop
host remain intentionally retained adjacent surfaces in this phase:

- existing H2-compatible local data and PostgreSQL-backed SaaS data;
- 38 current versioned SaaS migrations, including billing, policy, audit, account-link,
  classification, and procurement data;
- Redis-backed caching/session use and S3-compatible storage;
- SAML, OAuth2/OIDC, Supabase, Stripe, PostHog, and Telegram/provider integrations;
- LibreOffice/unoserver, Calibre, Ghostscript, OCRmyPDF/Tesseract, FFmpeg, and PDFium.

No claim is made that every listed native tool must remain a subprocess. Decision 0009
permits well-defined Rust adapters where needed for compatible behaviour; native
replacement is decided per operation.

## Required Next Artifact

Before changing any legacy implementation, create a versioned fixture for the relevant
surface that includes request bytes/encodings, response status/headers/body, failure
cases, authorization, and golden document output. The inventory above identifies where
to take those fixtures from; it does not provide parity proof by itself.
