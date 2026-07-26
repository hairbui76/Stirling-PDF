# Portal audit-derived surfaces

Ports the proprietary Java `PortalDocumentsController` / `PortalDocumentsService`
and `PortalInfraAuditController` / `PortalInfraAuditService` read-only endpoints.
Both shape recent `audit_events` into portal DTOs. They live in the reviewed,
opt-in security router (`crate::portal_audit`, mounted in `auth_routes()` beside
`security_audit_http`).

Both Java controllers are `@ProprietaryUiDataApi`, which carries the class-level
`@RequestMapping("/api/v1/proprietary/ui-data")` prefix; the frontend portal
calls these prefixed paths.

| Route | Behavior |
| --- | --- |
| `GET /api/v1/proprietary/ui-data/documents` | Documents review queue derived from file-bearing audit events. |
| `GET /api/v1/proprietary/ui-data/infrastructure/audit-log` | Recent audit events shaped for the Infrastructure -> Audit tab. |

Both accept an optional `tier` query parameter that is **accepted and ignored**
(mock-seam symmetry with Java; neither surface is tier-scoped).

## Access control

Enforced in two layers, mirroring the Java `@EnterpriseEndpoint` +
`PortalAuditScopeResolver` design:

1. **Enterprise gating** (central security middleware). Both routes are added to
   `endpoint_entitlement` as `EndpointEntitlement::Enterprise`. A verified tier
   below Enterprise is rejected with `403` + a problem+json body
   (`"This endpoint requires an Enterprise license"`), exactly like the
   `/api/v1/audit/*` routes.
2. **Scope resolution** (handler). The endpoint policy is `Authenticated`, so any
   authenticated caller reaches the handler; the handler then resolves the audit
   scope:
   - `ROLE_ADMIN` -> whole-server view (`fullServer = true`).
   - team leader (owner of their `team_id`, per `SecurityStore::is_team_owner`)
     -> team-scoped view over that team's member principals (`fullServer = false`).
   - otherwise -> `403` with an empty body (so the Java tab shows its access
     message rather than a generic 500).

   This combines Java's `DefaultPortalAuditScopeResolver` (self-hosted,
   admin-only) and `SaasPortalAuditScopeResolver` (admin + team leader).

## Event fetch (mirrors `PortalAuditReadService`)

- Reads the newest events per scope, up to `SCAN_LIMIT = 400`, newest-first.
  The reviewed store caps one query page at 200 rows, so the fetch pages twice.
- The server view is unfiltered by principal; a team scope filters by the team's
  member principals, and an empty principal set yields an empty log.
- Read/polling noise (`UI_DATA`, `HTTP_REQUEST`) is excluded at the query level.
  Java uses a `NOT IN` query; the reviewed store filter only expresses a positive
  `IN`, so the equivalent allow-list of the seven meaningful standard event types
  is used (`USER_LOGIN`, `USER_LOGOUT`, `USER_FAILED_LOGIN`, `USER_PROFILE_UPDATE`,
  `SETTINGS_CHANGED`, `FILE_OPERATION`, `PDF_PROCESS`).

## Infrastructure audit shaping (`PortalInfraAuditService`)

`RETURN_LIMIT = 40`. Per event: parse `data` JSON safely (empty map on
null/parse-failure), then:

- **category** (`categoryFor`): auth (`USER_LOGIN`/`USER_LOGOUT`/`USER_FAILED_LOGIN`),
  config (`SETTINGS_CHANGED`/`USER_PROFILE_UPDATE`), processing/security for
  `PDF_PROCESS`/`FILE_OPERATION` (security when the path matches `isSecurityPath`:
  contains `/security/`, `password`, `watermark`, `sign`, `cert`, or `redact`),
  else processing. A genuine policy dispatch (`isPolicyRunPath`: contains
  `/policies/` and ends with `/run` or `/run/stream`, and **not** an automation
  step) is its own `policy` category. A spoofed `policyName` on a direct call
  cannot flip category/action.
- **action** (`actionFor`/`baseActionFor`/`prettyTool`): fixed labels for
  auth/config events; a policy dispatch shows its policy name (or "Policy run");
  an automation step is suffixed `(policy: X)` or `(automation)`. Tool paths are
  title-cased from the last segment with the acronym map
  pdf->PDF, pdfs->PDFs, ocr->OCR, img->Image, csv->CSV, html->HTML, url->URL,
  xml->XML; default label "PDF operation".
- **target** (`targetFor`): policy dispatch -> first three `policySteps`
  (`+N more`), else "Pipeline"; auth -> "Web session"; config -> the path or
  "System settings"; processing/security -> first file name, else the pretty tool
  or "Document".
- **status** (`statusFor`): `USER_FAILED_LOGIN` -> danger; `status == failure` or
  `statusCode >= 500` -> danger; `statusCode >= 400` -> warning; config -> info;
  else success.
- **timestamp**: `yyyy-MM-dd HH:mm:ss` in UTC from the real event timestamp.
- **latencyMs**: `data.latencyMs` (0 when absent/non-numeric).

Summary counts (over the returned <=40 events): `totalEvents`, `policy`,
`processing`, `elevation`, `config`. As in Java, no event ever maps to
`elevation`, so that count is always 0. `fullServer` marks the admin view.

## Documents shaping (`PortalDocumentsService`)

`RETURN_LIMIT = 40`. Only file-bearing events (`PDF_PROCESS`, `FILE_OPERATION`)
carrying a `files` array produce rows: one review-document row per named file.

- **source/product**: an automation step reads `Policy: <name>` / "Policy
  automation" and product "Automation"; otherwise the request origin maps to
  "API integration"/"System"/"Web upload" and product "API"/"Editor".
- **action** (documents `prettyTool`): title-cases the last path segment, but
  recognizes `/convert/{from}/{to}` and renders "Convert X to Y"; default
  "Processed". Acronym map here is the smaller pdf/pdfs/ocr/img/csv set.
- **status/kind**: `failure`/`statusCode >= 400` -> status "error", kind
  "flagged", detail "<action> failed"; else status "processed", kind "extracted",
  detail "<action> via <source>".
- **type** (`docType`): PDF / Image / Word / Document from content-type or file
  extension.
- **time**: relative ("just now", "Nm ago", "Nh ago", "Nd ago") from the real
  event timestamp.
- Extraction fields never exist for audit-derived rows: `confidence = null`,
  `fieldsExtracted = 0`, `sensitive = false`, `extractions = []`.

Summary: `totalInQueue`, `processed`, `errors`, `processedToday` (non-failed rows
whose timestamp is within the last day).

All JSON field names are camelCase to match the Java Lombok DTOs.

## Field mapping (reviewed Rust audit store -> Java `PortalAuditEventRow`)

| Java `data` / event field | Rust source |
| --- | --- |
| `event.id()` | `SecurityAuditEvent.id` |
| `event.principal()` | `SecurityAuditEvent.principal` |
| `event.type()` | `SecurityAuditEvent.event_type` |
| `event.timestamp()` (Instant) | `SecurityAuditEvent.timestamp` (unix seconds) |
| `data.__origin` | `SecurityAuditEvent.source` column (`API`/`SYSTEM`/`WEB`/...) |
| `data.path`, `data.statusCode`, `data.status`, `data.latencyMs` | same keys in `SecurityAuditEvent.data` |
| `data.files`, including optional `fileHash` / `pdfAuthor`, plus `data.formParams`, `data.automation`, `data.policyName`, `data.policySteps` | same keys in `SecurityAuditEvent.data` |

## Parity gaps

- **`__origin` -> `source` column.** Java reads an `__origin` key from the event
  `data`; the reviewed store carries the same request origin in the durable
  `source` column, so the origin is read from `event.source` instead. This is a
  faithful behavioral mapping, not a divergence.
- **Direct-controller file enrichment.** Live ad-hoc/stored policy dispatches
  carry bounded `policyName`/`policySteps`, and every internal tool call records
  `automation` plus its input/referenced supporting `files` at
  STANDARD/VERBOSE level. Direct processing uploads that use the shared
  streamed file/byte reader, direct pipelines, AI workflow uploads, and policy
  inputs now record bounded name/size/type metadata through the same
  request-scoped context. When Java's optional audit flags are enabled, these
  file entries also retain lowercase SHA-256 and PDF Info Author metadata; the
  documents projection ignores those extra fields, as Java does. A secured real
  `misc/repair` request is covered all the way through the durable event and
  this documents projection, including hash/author persistence, and a direct
  pipeline independently verifies its persisted file context and outer JSON
  `formParams`. The projection ignores form parameters, as Java does. Generic
  `?async=true` processing jobs share the context with their background replay
  and defer event persistence until it completes, preserving the same metadata
  without a second upload pass. Custom storage, collaborative-signing,
  server-certificate, license, mail-attachment,
  and mobile-scanner readers use the same hook. Storage file mutations also use
  Java's `FILE_OPERATION` category. Rust does not buffer every request body in
  middleware; each typed streaming boundary reports completed uploads directly.
- **Positive event-type allow-list vs `NOT IN`.** Excluding noise via a positive
  `IN` of the seven known standard types means a hypothetical unknown/custom
  event type (never emitted by the reviewed recorder, whose universe is the nine
  Java `AuditEventType` values) would be dropped, whereas Java's `NOT IN` would
  keep it. No parity difference for any event the port actually records.
- **Float-encoded numbers.** `statusCode`/`latencyMs` are read only when JSON
  integers (as Java's `instanceof Number` excludes strings). A float-encoded
  number would not be coerced; the recorder only ever emits integers for these.
- **Team-leader identity.** "Team leader" maps to team ownership
  (`security_team_memberships.is_owner`), the closest reviewed-store concept to
  Java's SaaS `isCurrentUserTeamLeader()`. A team scope with more than 32 member
  principals exceeds the store's audit filter bound and fails the query
  (returns 503); Java has no such bound.
