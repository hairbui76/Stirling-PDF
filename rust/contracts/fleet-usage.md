# Self-hosted fleet usage compatibility

The reviewed secured Rust router ports the self-hosted Java fleet card at
`GET /api/v1/usage/fleet-stats`. It has no request parameters, body, upstream
service, or cache. Authentication and `ROLE_ADMIN` are required.

## Response and counting rules

The successful camel-case response always contains all three fields:

```json
{
  "editorsDeployed": 7,
  "activeThisMonth": 4,
  "pdfsProcessed": 1234
}
```

`editorsDeployed` counts every durable user except the reserved
`STIRLING-PDF-BACKEND-API-USER`, including disabled users and every other
authentication source. When `premium.enterpriseFeatures.audit.enabled` is
false, or its signed level clamped to `0..3` is below STANDARD (`2`), the other
two fields are JSON `null` because the source data cannot exist.

With STANDARD audit enabled, `activeThisMonth` counts distinct principals from
`WEB` events other than `UI_DATA` strictly newer than 30 days, then clamps the
result to deployed users. `pdfsProcessed` cumulatively counts `WEB`
`PDF_PROCESS` and `FILE_OPERATION` events strictly after the Unix epoch. The
store has matching composite indexes for both aggregates. Repository failures
return `500` without exposing database details.

## Current cutover boundary

Java exposes this controller only on self-hosted Enterprise deployments. Rust's
reviewed router is self-hosted and enforces both administrator authorization and
the verified Enterprise tier. Denials use the Java license ProblemDetail. The
deployment-facing reviewed runtime remains fail-closed at `Normal` until Keygen
tier derivation is ported; integration tests inject Enterprise only through
trusted router construction. See `contracts/license-entitlement.md`.

Production capture now writes one post-handler event per controller call and
emits `PDF_PROCESS`/`FILE_OPERATION` for operational routes. Password,
access-token, and Supabase users are `WEB`; API-key, automation, and AI traffic
use separate sources, so a live Rust-only database feeds the same fleet
aggregates without the former doubled mutation rows or zero-PDF blind spot.

Java can infer categories from controller class names. Axum middleware instead
uses reviewed route families with processing as the default; any newly ported
non-processing mutation must be added to the user/admin/file family map before
secured-mode cutover. Per-file metadata and multi-file cardinality are not
inputs to Java's fleet query, which counts audit events rather than uploaded
files.

The SaaS controller at the same path is intentionally outside this contract: it
uses authenticated team-scoped aggregation rather than the self-hosted
administrator-wide counts.

## Verification

`tests/fleet_usage_endpoint.rs` proves the authentication boundary, internal
user exclusion, WEB/source/type/time filtering, cumulative PDF count, active
editor clamping, exact camel-case/null response shape, and disabled/BASIC/
negative audit-level behavior against durable SQLite state. Security middleware
tests additionally prove one-event processing capture, Java's returned-error
outcome rule, source separation, and a live fleet increment from WEB traffic.
