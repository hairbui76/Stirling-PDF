# Design

## Domain Model

The final Rust codebase must separate document-processing domain rules from framework,
database, provider, UI, and platform concerns. Stable product types include documents,
pages, operations, workflows, identities, tenants, policies, plans, usage, and tool
execution requests.

## Application Flow

Each migrated vertical slice must follow this boundary:

```text
HTTP, desktop, browser, job, or provider input
  -> parsed typed request
  -> application command or query
  -> domain rule and document operation
  -> persistence or external-tool adapter
  -> typed response and canonical observability event
```

The implementation must not duplicate an operation's parameter schema between API,
AI planning, browser/desktop UI, and execution. A generated or shared Rust contract
will be selected only after the source-of-truth policy is approved.

## Interface Contract

The legacy REST service is the initial oracle. RP-001 will produce an exact manifest
for its routes, methods, request encodings, status codes, headers, bodies, security
rules, and flavour availability. The generated OpenAPI baseline currently has 259
paths and 271 operations; its versioned fixture remains a required follow-up. The AI
engine and Tauri command contracts require equivalent manifests.

## Data Model

The migration must account for existing embedded and server databases, schema history,
storage locations, session/identity data, audit records, pipeline definitions, and
user-uploaded document handling. No schema, migration, or retention behaviour changes
are approved in this discovery story.

## UI / Platform Impact

The TypeScript/React browser UI remains unchanged. Rust processing endpoints must
preserve its existing API contracts, including multipart encodings, download headers,
and error handling. The Tauri host and Python AI engine remain adjacent systems in
this initial scope; their integration contracts are preserved rather than rewritten.

## Observability

Every Rust request path will emit structured request logs with a request identifier,
identity when known, action, duration, status, and message. Audit records remain
separate durable product records. Contract comparison failures must retain a safe,
reproducible fixture reference without logging document contents or secrets.

## Alternatives Considered

1. Rewrite the browser UI: rejected because the accepted scope retains it.
2. Big-bang rewrite: rejected as the default because it cannot preserve or prove the
   current product's broad contract during development.
3. Contract-first, vertical-slice processing migration: accepted because it ports
   the Java processing target while making browser compatibility measurable.
