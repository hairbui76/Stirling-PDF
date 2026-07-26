# Info and runtime metrics contract

Rust compatibility contract for the Java `MetricsController` and its request/WAU
filters.

## Routes

- `GET /api/v1/info/status` and `GET /api/v1/info/health` return
  `{ "status": "UP", "version": "<application version>" }`. The version is
  loaded from the repository's authoritative `version.properties` file. Because
  that file is gitignored (Gradle's `writeVersion` generates it), the crate's
  `build.rs` stages a copy into `OUT_DIR`: the Gradle artifact is copied
  verbatim when present, otherwise the version is parsed from the canonical
  `version = '<x.y.z>'` assignment in `build.gradle`, so a clean checkout
  compiles and reports the same version.
- `GET /api/v1/info/load[?endpoint=<path>]` and `/load/unique` return the total
  or unique-session count for GET requests.
- `GET /api/v1/info/load/all` and `/load/all/unique` return ordered
  `{ "endpoint": "<path>", "count": <number> }` entries for GET requests.
- `GET /api/v1/info/requests[?endpoint=<path>]`, `/requests/unique`,
  `/requests/all`, and `/requests/all/unique` are their POST equivalents.
- `GET /api/v1/info/uptime` returns Java's `0d 0h 0m 0s` duration format.
- `GET /api/v1/info/wau` returns `weeklyActiveUsers`, `totalUniqueBrowsers`,
  `daysOnline`, and ISO-8601 `trackingSince` while login is disabled.

## Collection and configuration

The process-local collector mirrors the Java filters: it counts trackable
requests before dispatch, excludes static and `/api/v1/info/*` paths, groups by
method/path/session, and treats a missing `JSESSIONID` cookie as `no-session`.
When `security.enableLogin=false`, non-empty `X-Browser-Id` values are retained
for seven days for WAU statistics.

`metrics.enabled` (or `METRICS_ENABLED`) defaults to `true`. When disabled, all
metric query routes except status/health return `403 This endpoint is disabled.`.
When login is configured, the WAU route returns `404` with Java's no-login-mode
message. Metrics are process-local, matching Java's default in-memory Micrometer
registry; counters reset when the Rust service restarts.

## Verification

Unit tests cover version discovery, request filtering, session uniqueness, and
browser identifiers. HTTP tests cover health/status, request counting, WAU,
login-mode rejection, and `metrics.enabled=false`.
