# 0010 Full Non-UI Rust Port Scope

Date: 2026-07-15

## Status

Accepted

## Context

Decision 0009 accepted Java document processing as the first migration phase and
left the Python AI engine and Tauri host for a later scope decision. The user has
now explicitly set the terminal objective to port everything except the existing
user interface to Rust.

## Decision

- Keep the TypeScript/React browser and desktop presentation code unchanged.
- Port all non-UI Java server responsibilities to Rust, including document
  processing, HTTP APIs, security, persistence, workflows, observability, billing,
  storage, and flavour-specific server behavior.
- Port the Python AI engine's contracts and reasoning-service runtime to Rust.
- Replace Tauri commands and host code where needed so the desktop product no longer
  starts or depends on the Java backend; existing Rust Tauri UI integration remains.
- Port non-UI build, packaging, Docker, CI, and operational wiring required to ship
  the Rust runtime across supported variants.
- Preserve the existing public API, data, deployment, and UI contracts throughout a
  vertical-slice migration. Java and Python remain behavioral oracles until each
  replacement passes its migration proof.
- Existing native tools may remain behind explicit Rust adapters when full behavior
  depends on them; removing those tools is operation-specific, not implied by the
  language-port objective.

## Consequences

Java processing remains the first implementation phase because it provides isolated,
testable slices, but it is no longer the completion boundary. The port is complete
only after the non-UI runtime inventory has no unapproved Java or Python dependency,
the Tauri host targets the Rust services, and all supported deployment variants pass
contract, security, data-upgrade, performance, and end-to-end verification.
