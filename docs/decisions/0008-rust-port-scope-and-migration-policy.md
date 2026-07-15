# 0008 Rust Port Scope and Migration Policy

Date: 2026-07-15

## Status

Superseded by 0009

## Context

The requested objective is to port Stirling-PDF's Java document-processing
implementation to Rust. The current implementation spans a Java server, Python AI
engine, TypeScript browser UI, and a Rust Tauri host that starts the Java backend.
The browser UI must remain in place, so its existing HTTP contract is a compatibility
constraint on the Rust processing service.

## Decision

Use a contract-first, vertical-slice migration that preserves existing behaviour
until a Rust replacement passes parity proof.

1. Keep the existing TypeScript/React browser UI unchanged. It continues to call the
   existing REST routes and remains the product UI during this migration.
2. Port Java document-processing endpoints and their shared processing code to a
   Rust service. Start with independently testable PDF operations, then move their
   HTTP, authorization, workflow, and observability integration.
3. Preserve public REST compatibility during the migration. A legacy Java route may
   delegate to the Rust service while a route is being cut over; the browser must not
   need a coordinated rewrite.
4. Retain required native tools (for example LibreOffice, Ghostscript, Tesseract,
   FFmpeg, and PDFium) behind explicit Rust adapters when they are needed for
   behavioural compatibility. Replacing those tools natively is a later operation-
   specific decision, not a prerequisite for the first Rust slice.
5. Keep the Python AI engine and Tauri shell outside the initial Java-processing
   migration. Their contracts remain protected and can be evaluated after the Java
   document-processing surface is complete.

## Alternatives Considered

1. Big-bang rewrite: leaves no reliable parity oracle and has unacceptable product risk.
2. Rewriting the browser UI: conflicts with the accepted requirement to retain it.
3. Framework-first rewrite: commits to a technical direction before an operation's
   observable contract is captured.

## Consequences

Positive:

- Gives the Rust service a clear, compatible processing scope.
- Preserves the current system as an oracle while each Rust slice is verified.
- Prevents a browser rewrite from being hidden in backend work.

Tradeoffs:

- Java and Rust coexist during route-by-route migration.
- External tools remain runtime dependencies until individual operations replace them.

## Follow-Up

- Create the Rust workspace and first contract-tested processing slice.
- Version the endpoint manifest and document fixtures before removing Java routes.
