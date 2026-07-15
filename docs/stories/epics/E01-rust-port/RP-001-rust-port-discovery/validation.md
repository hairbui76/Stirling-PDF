# Validation

## Proof Strategy

Proof is parity-oriented. A Rust component is not accepted merely because it compiles;
it must match the relevant legacy contract and work in every supported deployment
surface before the legacy implementation is removed.

## Test Plan

| Layer | Cases |
| --- | --- |
| Unit | Pure document/domain rules, typed input parsing, policy decisions, and error mapping. |
| Integration | HTTP multipart handling, external tool adapters, storage, database, identity, audit, billing, and AI-provider seams. |
| E2E | Browser and desktop document workflows for every supported tool family and product flavour. |
| Platform | Container, self-hosted, SaaS, and supported desktop packaging/startup/upgrade paths. |
| Performance | Large-document memory, throughput, latency, concurrency, and 100 GB workflow behaviour where currently supported. |
| Logs/Audit | Canonical request logging, redaction, audit records, and authorization failures. |

## Fixtures

- A versioned manifest of legacy routes, Tauri commands, AI routes, and operations.
- Golden documents covering PDF structure, signatures, encryption, OCR, images,
  forms, metadata, malformed inputs, and expected errors.
- Deterministic users, tenants, roles, plans, and provider responses.
- Upgrade fixtures for existing databases, configuration, storage, and pipelines.

## Commands

From `rust/`:

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The equivalent repository commands are `task rust:format:check`, `task rust:lint`,
and `task rust:test`; `task rust:check` runs all three.

## Acceptance Evidence

- Baseline inventory and Java-processing contract are recorded in
  `docs/product/rust-port.md`.
- The legacy server OpenAPI baseline has been generated as 259 paths and 271 operations
  (SHA-256 `294BEB84F51C2374D01597D73DD6218DC64242AC730007D9D2CFE92326F22A06`).
- The AI engine, Tauri bridge, SaaS migration, and external-adapter baselines are
  recorded in `docs/contracts/legacy-runtime-baseline.md`.
- The exact route/capability manifests and fixtures are checked into the selected Rust
  workspace before their legacy counterparts are replaced.
- Decision 0009 accepts the processing scope and migration architecture.
- The initial Rust merge slice has unit and multipart integration coverage, while its
  explicit pre-cutover limitations remain recorded in `rust/contracts/merge-pdfs.md`.
- Every later migration story supplies fresh parity proof before legacy deletion.
