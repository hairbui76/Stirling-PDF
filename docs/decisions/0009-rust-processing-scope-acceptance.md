# 0009 Rust Processing Scope Acceptance

Date: 2026-07-15

## Status

Superseded by 0010

## Context

Decision 0008 identified the browser, native-dependency, and compatibility choices
needed before a Rust port could begin. The user clarified that the existing browser UI
must stay and that Java document processing is the primary Rust migration target.

## Decision

- Keep the TypeScript/React browser UI unchanged.
- Replace Java document-processing implementations with Rust behind compatible REST
  routes and response behaviour.
- Keep Java authoritative for a route until its Rust slice passes parity proof; do
  not require a coordinated browser rewrite for cutover.
- Permit existing external processing tools behind explicit Rust adapters where they
  are needed for compatible behaviour.
- Keep the Python AI engine and Tauri host outside this initial migration phase.

## Consequences

The Rust workspace can now implement contract-tested document-operation slices. The
first slice is `POST /api/v1/general/merge-pdfs`; its deliberate pre-cutover limits
are recorded in `rust/contracts/merge-pdfs.md`. Those limits prevent the new service
from becoming the route owner before it can preserve forms, signatures, bookmarks,
sorting, and large-document behaviour.
