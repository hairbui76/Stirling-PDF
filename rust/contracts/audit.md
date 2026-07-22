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
where Java does. It captures Java's client-address precedence from the first
`X-Forwarded-For` value, then `X-Real-IP`, then the Axum peer socket. The
compatibility `__ipAddress` field is present whenever an address is available;
STANDARD/VERBOSE records also carry `clientIp`. Proxy header values are capped
at 512 characters before persistence. Policy run handlers use a typed
request-scoped audit context to
add the bounded policy name and first 50 ordered step paths after their
multipart definition has streamed and parsed. Each internal policy tool
dispatch writes its own `AUTOMATION` event with the parent policy name and, at
STANDARD/VERBOSE levels, the streamed input and referenced supporting-file
name, size, and effective multipart type. This gives the live portal policy and
document projections real events without replaying request bodies.

At STANDARD/VERBOSE levels, the same request-scoped context now captures
completed direct uploads from the shared processing stream/file reader, the
direct pipeline reader, AI workflow orchestration, and policy-run input reader.
The same hook is present at the custom storage, collaborative-signing,
server-certificate, license-file, email-attachment, and mobile-scanner
boundaries, so those controllers retain file context without a second body
pass. Storage file mutations are explicitly classified as `FILE_OPERATION`,
matching Java's `FileStorageController` class-based inference.
Accepted generic `?async=true` jobs carry the same context into their queued
background replay. Their fail-open audit write is deferred until that worker
finishes, so the submission still returns its job identifier immediately while
the eventual event contains the handler's streamed file metadata. This shares
the already-persisted request stream and does not scan or buffer the upload a
second time.
The handler records the sanitized original name, streamed byte count, and
content type after a successful write. Metadata is capped at 100 files per
event, 255 characters per filename, and 128 characters per content type. BASIC
capture creates the same context for policy annotations but deliberately
ignores file metadata.

Java's optional file enrichment is also supported at STANDARD/VERBOSE. The
`premium.enterpriseFeatures.audit.captureFileHash` setting (or
`PREMIUM_ENTERPRISEFEATURES_AUDIT_CAPTUREFILEHASH`) adds the lowercase SHA-256
as `fileHash`. The `capturePdfAuthor` setting (or
`PREMIUM_ENTERPRISEFEATURES_AUDIT_CAPTUREPDFAUTHOR`) adds the PDF Info `Author`
as `pdfAuthor`, capped at 512 characters, only when the multipart content type
is exactly `application/pdf` ignoring case. Both settings default to false.
With both disabled, the streaming boundary performs no hash or PDF metadata
I/O. When enabled for a temporary-file stream, enrichment reads the completed
file after the write, matching Java's documented extra-I/O behavior; bounded
byte-oriented boundaries reuse the bytes they already own rather than
buffering the request again. Async workers and internal policy steps inherit
the same capture settings.

STANDARD/VERBOSE records also carry Java-shaped `formParams`: a map from form
field name to its ordered string-value array for POST/PUT/PATCH multipart and
URL-encoded inputs. Typed streaming readers report a value only after its
bounded read succeeds; repeated fields retain arrival order, `_csrf` is omitted,
and nested in-process pipeline dispatch is isolated from the parent request so
only the outer form is attached there. Explicit policy-step audit events receive
their own operation parameters. Capture is capped at 128 values per event, 128
characters per name, and 2,048 characters per value.

Java writes every request parameter without sensitivity filtering, which can
persist fields such as `password` or `participantToken`. Rust intentionally
does not reproduce that credential disclosure: password/passphrase, secret,
token, API-key, private-key, credential, authorization, cookie, and PIN-shaped
field names retain their key and store `[REDACTED]` as the value. This preserves
the audit shape and request diagnosis while maintaining the security boundary's
no-secret-persistence invariant.

The default-off Java `captureOperationResults` switch is also accepted as
`premium.enterpriseFeatures.audit.captureOperationResults` or
`PREMIUM_ENTERPRISEFEATURES_AUDIT_CAPTUREOPERATIONRESULTS`. When enabled, Rust
adds `result` for ordinary non-`UI_DATA` controller events. Capture is limited
to complete UTF-8 text/JSON/XML responses whose body has an exact size no larger
than 64 KiB, then truncated to Java's 1,000-character persisted limit. The
response is reconstructed byte-for-byte before it leaves the middleware.
Unknown-size/streaming, binary, oversized, and invalid-UTF-8 bodies are never
consumed for audit. The currently ported Java `@Audited` matrix has
`includeResult = false` everywhere, so explicit login/profile/settings events
remain excluded even when the deployment flag is on. The flag defaults off and
adds no response-body work in that state.

Java VERBOSE uses AspectJ reflection to persist Java controller class/method
names and each raw method argument's `toString()`. Axum deliberately has no
equivalent reflection boundary, and reproducing it by debugging handler state
would persist framework internals and credentials (including password-bearing
request objects). Rust therefore uses the bounded, typed, redacted
`formParams` map above as its request-argument record and does not fabricate
Java `className`, `methodName`, or `arg_*` values. This is an intentional
security and architecture divergence, not a missing body-buffering path.

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
tier matrix, proxy/real/peer client-IP precedence, and live fleet aggregation
against the real processing router.
Live secured-router coverage additionally posts a real PDF with an Info Author
to `misc/repair`, verifies its persisted name/size/type, SHA-256, and PDF author,
and proves the event becomes a real `/api/v1/documents` row. A direct pipeline
independently verifies file metadata plus its outer JSON form parameter, while a
queued generic rotate job proves the deferred event retains both file metadata
and its array-shaped angle parameter after background multipart replay. Unit
and policy-step coverage prove bounds, repeated ordering, `_csrf` exclusion,
credential redaction, independent internal operation parameters, default-off
result configuration, text-response preservation, result bounds, and
UI-data/explicit-auth result exclusion.
