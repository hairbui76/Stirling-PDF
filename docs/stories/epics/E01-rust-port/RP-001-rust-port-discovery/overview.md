# Overview

## Current Behavior

Stirling-PDF is an open-core document platform implemented by a Spring Boot server,
a FastAPI AI engine, a React browser UI, and a Tauri desktop host. The desktop host
already uses Rust but launches the Java backend and embeds the TypeScript UI.

## Target Behavior

Java document processing is replaced by Rust while the TypeScript/React browser UI
continues unchanged against compatible REST endpoints. RP-001 establishes the
measurable contract and migration boundary for that work; it does not claim to
complete the port.

## Affected Users

- Browser users of the self-hosted and SaaS products.
- Desktop users on supported operating systems.
- API consumers and pipeline users.
- Administrators, tenant owners, and security operators.
- Operators of self-hosted, container, and managed deployments.

## Affected Product Docs

- `docs/product/rust-port.md`

## Non-Goals

- Silently dropping features to obtain an earlier Rust build.
- Replacing a public contract without explicit approval.
- Rewriting the browser UI as part of the processing migration.
- Treating an empty Rust workspace as completion of any product surface.
