# Audit API compatibility

The reviewed, opt-in Rust security router owns both proprietary Java audit API
families. Every route is administrator-only and is protected by the central
security policy before query parsing or database access. Every route also
requires a verified Enterprise tier.

## Dashboard routes

| Route | Behavior |
| --- | --- |
| `GET /api/v1/audit/data` | Newest-first page with `page`, `size`, optional exact `type`, case-insensitive principal substring, and paired `startDate`/`endDate` filters. Returns `content`, `totalPages`, `totalElements`, and `currentPage`. |
| `GET /api/v1/audit/stats` | Counts by event type, principal, and local calendar day for the last `days` (default 7). |
| `GET /api/v1/audit/types` | Sorted union of stored and standard Java event types. |
| `GET /api/v1/audit/export/csv` | Filtered technical CSV with `ID,Principal,Type,Timestamp,Data`. |
| `GET /api/v1/audit/export/json` | Filtered `PersistentAuditEvent`-shaped JSON download. |
| `DELETE /api/v1/audit/cleanup/before?date=YYYY-MM-DD` | Deletes events strictly before local midnight on the supplied non-future date. |

## Proprietary UI-data routes

The second Java controller remains a backend compatibility surface even though
no frontend code is being ported:

- `GET /api/v1/proprietary/ui-data/audit-events`
- `GET /api/v1/proprietary/ui-data/audit-charts`
- `GET /api/v1/proprietary/ui-data/audit-event-types`
- `GET /api/v1/proprietary/ui-data/audit-users`
- `GET /api/v1/proprietary/ui-data/audit-stats`
- `GET /api/v1/proprietary/ui-data/audit-export`
- `POST /api/v1/proprietary/ui-data/audit-clear-all`
- `GET /api/v1/proprietary/ui-data/usage-endpoint-statistics`

The event route accepts repeated or comma-separated `eventType` and `username`
filters, paired local-date filters, and Java's `page`/`pageSize` pagination. The
charts and KPI responses retain the Java camel-case shapes, including current
and previous-period totals, success rate, error count, average latency, top
event/user/tool maps, and a 24-hour distribution. CSV export supports Java's
ordered selected fields as well as the default technical export; JSON uses the
same persistent-event shape as the dashboard export.

The endpoint-usage route accepts Java's optional signed `limit`, `dataType`,
and `days` parameters. `days` clamps to 1–365, positive limits truncate only
the returned ranking, and unknown untrimmed data types return an empty 200.
`ui` selects exact `UI_DATA` events; `api` means every non-`UI_DATA` event,
not API-key authentication. Audit JSON resolves `endpoint`, then `path`, then
`requestUri`, strips the first query string, prefixes a missing slash, merges
normalized duplicates, and computes totals before limiting. Percentages retain
their share of all visits and round to one decimal. Unlike Java's unbounded
materialization, Rust rejects a matching set above 50,000 rows with `413`.

## Durable event model

Rust audit rows retain the immutable principal string, authentication source,
JSON data, session/correlation IDs, event type, path, outcome, and timestamp.
Existing Rust databases are migrated idempotently: principal is backfilled from
the still-present user row, source defaults to `WEB`, and data defaults to an
empty object while legacy path/outcome columns remain available. When the
verified tier is Enterprise, the reviewed middleware writes one event after
each mapped controller response, matching
Java rather than the earlier attempt/outcome pair. GETs use the exact `UI_DATA`
prefix matrix or `HTTP_REQUEST`; security/admin mutations use their typed
categories, upload/download routes use `FILE_OPERATION`, and remaining
operations use `PDF_PROCESS`.

Password/access-token/Supabase identities are `WEB`, API keys are `API`, and
WEB traffic is refined with Java's precedence to `AUTOMATION` or `AI`. Public
traffic is `SYSTEM`. Explicit Java `@Audited` routes do not contribute to a
named source aggregate; the older Rust NOT NULL schema represents Java's null
source with an empty string. A returned 4xx/5xx remains a successful controller
outcome, as in Java. Audit persistence is fail-open and cannot replace the
original HTTP response.

Deleting a user nulls only the relational user ID; the retained principal keeps
historical audit attribution. Clearing the audit table is itself audited by the
outer middleware, so its `PDF_PROCESS` controller event becomes the first row
in the new log. Statistics readers are also audited after they query, so a call
can appear only in later statistics responses.

## Bounds and remaining capture parity

Page size is limited to 200, filters to 32 values per dimension, query strings
to 16 KiB/128 pairs, and in-memory exports/stat scans to 50,000 events. Exports
over that limit return `413` instead of exhausting the process.

The generic Rust boundary records timestamp, principal, HTTP method, path,
request/session IDs, latency, outcome/status, and response status at the levels
where Java does. Java can additionally attach client IP, multipart parameters,
file hash/PDF author, verbose method arguments, automation policy labels, and
optionally operation results. Rust preserves and aggregates those fields when
present, but payload-level enrichment remains controller-by-controller work.

Java's event inference can inspect controller class names. Rust uses frozen
route families because Axum middleware does not receive handler type metadata;
the known user, auth, admin, UI-data, upload/download, AI, and automation
families are explicit, with processing as the default. Normal and Server tiers
cannot capture events, and all audit/statistics routes return Java-compatible
license ProblemDetails unless the tier is Enterprise. Keygen tier derivation
remains separate work; see `contracts/license-entitlement.md`. The endpoint-usage Java
controller also appears in SaaS without tenant scoping; Rust intentionally
mounts this global reader only on the reviewed standalone security router
rather than reproducing that likely cross-tenant exposure.

## Verification

Store tests cover legacy migration, immutable attribution, filtering,
pagination, normalized outcome data, export bounds, distinct values, retention,
clear behavior, endpoint normalization, pre-limit totals, and percentage
rounding. HTTP integration coverage proves administrator enforcement, both
response families, aggregation, repeated filters, technical and selected CSV,
JSON export, cleanup validation, non-admin denial, audited clear-all, one-event
production capture, WEB/API/AI/AUTOMATION separation, Supabase-to-WEB
attribution, endpoint-usage filters, self-capture ordering, the complete license
tier matrix, and live fleet aggregation against the real processing router.
