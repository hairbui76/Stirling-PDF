# Exec Plan

## Goal

Create the accepted contract, migration inventory, Rust processing workspace, and
verification plan needed to replace Java document processing without losing observable
browser or API behaviour.

## Scope

In scope:

- Baseline inventory of Java processing and adjacent protected surfaces.
- Processing contract and migration completion criteria.
- Route, capability, dependency, data, and platform manifest design.
- An accepted Rust architecture and migration policy.
- Validation gates that prevent unproven legacy removal.
- Contract-tested Rust processing slices.

Out of scope in this phase:

- Rewriting the TypeScript/React browser UI, Python AI engine, or Tauri host.
- Removing, disabling, or changing a legacy API before its Rust parity proof passes.
- Migrating user data or secrets without a dedicated migration story.

## Risk Classification

Risk flags:

- Auth and authorization.
- Data model, migration, and retention.
- Audit and security.
- External systems and provider integrations.
- Public contracts and existing behaviour.
- Cross-platform delivery.
- Weak proof and multi-domain scope.

Hard gates:

- Auth, authorization, data migration, audit/security, and external provider
  behaviour.

## Work Phases

1. Establish the baseline inventory and external dependency manifest.
2. Freeze contract fixtures for HTTP, document operations, data, and platform flows.
3. Record the accepted scope, native-dependency, and compatibility policy.
4. Create the Rust workspace with layer boundaries, task integration, and test
   harnesses.
5. Port complete vertical slices in dependency order, keeping legacy components as
   the oracle until proof passes.
6. Perform release, upgrade, security, performance, and platform validation.
7. Remove retired Java processing paths only after the final migration matrix is
   complete.

## Stop Conditions

Pause for human confirmation if:

- a required document capability has no equivalent Rust-native implementation;
- a compatibility, data, security, or external-provider contract must change; or
- a framework choice would exclude a supported platform or delivery mode.
