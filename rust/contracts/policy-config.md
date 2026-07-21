# Policy and source configuration

## Conditional reviewed routes

The following routes exist only inside the opt-in reviewed-security router and only when
`policies.enabled=true`:

- `GET|POST /api/v1/sources`
- `GET|DELETE /api/v1/sources/{sourceId}`
- `GET /api/v1/sources/{sourceId}/document-counts`
- `GET|POST /api/v1/policies`
- `GET /api/v1/policies/overview`
- `PUT /api/v1/policies/order`
- `POST /api/v1/policies/run`
- `POST /api/v1/policies/run/stream`
- `GET /api/v1/policies/run/{runId}`
- `GET /api/v1/policies/runs`
- `GET /api/v1/policies/triggers`
- `GET|DELETE /api/v1/policies/{policyId}`
- `POST /api/v1/policies/{policyId}/run`
- `POST /api/v1/policies/{policyId}/trigger`
- `DELETE /api/v1/policies/{policyId}/processed-history`

The open router and a reviewed router with policies disabled return `404`. Router construction is
side-effect free; the host explicitly starts automatic trigger tasks after the reviewed runtime is
assembled.

## Storage compatibility

Rust uses Java's logical SQLite tables and scalar projections: `policy_sources` with
`source_json`, and `policies` with `policy_json`, `trigger_type`, and `sort_order`. JSON writes use
the same unversioned AES-256-GCM/Base64 format as Java's credential encryption. Reads are lenient:
they decrypt current rows and fall back to pre-encryption plaintext JSON. Existing policy tables
gain `sort_order` without replacing their data.

Missing IDs are assigned RFC 4122 version-4 UUIDs. Creation stamps owner and team from trusted
`AuthContext`; update preserves stored ownership. Reads, updates, deletes, source references, and
ordering are scoped to the caller's exact team, including for administrators. Mutations require an
administrator or the durable owner of the caller's current team in this reviewed self-hosted
boundary.

Secret-bearing option keys use the shared recursive `********` masking and restore rules. Source
options and policy-output options are encrypted at rest and never returned in plaintext.

## Source and policy rules

`editor` remains a virtual, non-mutable source and is pinned first in the source overview. Source
deletion returns `409` while a visible policy references it. Policy ordering ignores unknown and
cross-team IDs. Folder sources/outputs require a normalized path inside
`policies.allowedFolderRoots` and always reject the Stirling config directory.

S3 sources and outputs accept Java's legacy embedded options or a stored integration
`connectionId`. Save-time resolution enforces type, enabled state, ownership/grants/default access,
endpoint restrictions, and required credentials. Stored connection values win except for the
per-use `prefix` and `mode` fields.

The policy overview is derived from the caller's team-scoped policy and source rows. It reports
total/active/paused KPIs and case-insensitively sorted policy views with status,
manual-or-configured trigger type, resolved source names, step count, output type, and owner.
Trigger definitions are validated at write time: schedules enforce their type-specific fields,
time, and IANA time zone; folder-watch policies must reference a folder source.

The Java-compatible `policy_source_doc_counts` and `policy_source_doc_totals` tables back lifetime,
rolling 24-hour/30-day, and 30-day daily-series reads. No synthetic totals are returned; missing
rows naturally produce zero. Successfully admitted uploaded runs atomically add their primary-file
count to the caller team's virtual `editor` source. Invalid definitions and queue rejection do not
inflate the counters.

The Java-compatible `policy_processed_files` ledger is also durable in SQLite. It implements
atomic gate/content claims, `PROCESSING`/`DONE`/`ERROR`/`INTERRUPTED` transitions, the
three-attempt interrupted retry bound, output recording and cross-policy consensus, presence
pruning, per-policy clearing, and startup recovery of abandoned processing claims.

Folder and S3 source sweeps consume that ledger. Folder identity is the canonical path; readiness,
metadata or streaming SHA-256 gates, hidden-subtree filtering, durable claims, version-guarded
settlement, and cross-policy delete consensus match the Java lifecycle. S3 uses the configured
credentials and endpoint only, paginates listings, ignores placeholders/hidden objects, claims by
ETag, and conditionally downloads and deletes objects. A `FULL` sweep also marks presence and
prunes vanished inputs; event-driven `LIGHT` sweeps deliberately do neither.

## Queued execution

Ad-hoc and stored-policy multipart runs use the same bounded, resource-weighted Rust job queue and
the same in-process dispatcher as `/api/v1/pipeline/handleData`. The accepted response remains
Java-compatible `202 {"async":true,"jobId":"...","result":null}`. A run status exposes the
Java `PolicyRunView` fields; stored-policy run listing excludes ad-hoc work and is scoped by the
trusted durable job owner. Results are registered in the generic job store and remain downloadable
through `GET /api/v1/general/files/{fileId}`. Run metadata disappears with its generic job TTL.

Primary `fileInput` documents flow from step to step. `assets[i].key` / `assets[i].file` uploads are
grouped by key and bound to each step's named multipart fields through `fileParameters`; they never
enter the primary stream. Scalar/flat-array parameters retain the pipeline form contract, while
nested arrays and objects are serialized as a single JSON field. Operations are restricted to the
reviewed internal `/api/v1/{general,misc,security,convert,filter}/...` namespaces. Single outputs
preserve the tool response MIME type; multiple outputs use the existing deterministic ZIP result.

All three Java delivery kinds are active. `inline` registers an owner-scoped downloadable result.
Folder delivery stages below `.stirling/tmp`, records the output hash before an atomic no-overwrite
publish, retries Java-compatible collision names, and cleans stale staging files. S3 delivery uses
a predicted MD5 ETag, records the output before conditional create, retries name collisions, and
falls back to an existence check only when the endpoint rejects conditional PUT. Actual returned
ETags replace the prediction in the ledger.

The run is registered before queue admission. Queue saturation therefore returns the same `202`
job envelope with a durable terminal `FAILED` run whose `errorCode` is `POLICY_QUEUE_FULL`, instead
of losing the run ID. Malformed multipart or definitions return `400`.

`POST /run/stream` performs the same request-thread validation, then returns server-sent events.
Each successful step emits `step`/`started` and `step`/`completed` payloads with one-based
`stepIndex`, `stepCount`, and `operation`; the stream ends with `completed`, `failed`, or
`cancelled` carrying the owner-scoped `PolicyRunView`. The Java-compatible
`policies.streamTimeoutMs` default is 1,800,000 ms. Closing or timing out the stream does not cancel
the queued run, so its status and outputs remain available through the ordinary job routes.

## Trigger runtime

`POST /{policyId}/trigger` performs a manual `FULL` source sweep; every member of the owning team
may invoke it even when the policy is disabled. `DELETE /{policyId}/processed-history` is limited
to administrators and current team leaders. `GET /triggers` returns the exact supported automatic
types, `folder-watch` and `schedule`.

The schedule task establishes a first-seen baseline and then submits at most the latest due wall
clock occurrence, collapsing missed intervals. It supports minute/hour/day intervals plus
daily/weekly/monthly schedules in the configured IANA time zone; invalid short-month dates are
skipped. Schedule state is retained by policy ID while the process is alive.

The folder-watch task watches each existing configured directory non-recursively. Create and
modify events are quiet-period debounced into `LIGHT` sweeps, while startup and periodic
reconciliation perform `FULL` sweeps. Policy and source mutations refresh the active watch set,
and one policy failure does not stop the remaining automatic work.

## Explicit remaining boundary

Java's `WAITING_FOR_INPUT` types remain dormant scaffolding: no current step raises the pause
exception, no resume HTTP route exists, and `PolicyEngine.resume` throws
`UnsupportedOperationException`. Rust therefore does not claim a resume handshake. Automatic
trigger schedules, debounce state, and watchers are process-local; distributed trigger ownership,
queue/backplane coordination, and cross-node recovery belong to the broader distributed-runtime
work rather than this compatibility slice.
