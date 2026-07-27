# Administrator job statistics and cleanup

Rust compatibility contract for Java's `AdminJobController`
(`app/proprietary/.../controller/api/AdminJobController.java`). The three
routes are registered alongside the general job routes in
`rust/crates/stirling-processing/src/lib.rs` and served by
`admin_job_stats` / `admin_job_queue_stats` / `admin_job_cleanup` over the
shared `JobManager` and `JobQueue` (see `contracts/job-management.md` for the
user-facing job API these administrate).

## Routes

| Method | Path | Java counterpart | Response |
| --- | --- | --- | --- |
| `GET` | `/api/v1/admin/job/stats` | `AdminJobController.getJobStats` | Java-shaped camel-case `JobStats`: `totalJobs`, `activeJobs`, `completedJobs`, `failedJobs`, `successfulJobs`, `fileResultJobs`, `oldestActiveJobTime`, `newestActiveJobTime`, `averageProcessingTimeMs`. |
| `GET` | `/api/v1/admin/job/queue/stats` | `AdminJobController.getQueueStats` | Queue counters: `queuedJobs`, `queueCapacity`, `runningJobs`, `resourceBudget`, `availableResourceUnits`, `totalQueuedJobs`, `rejectedJobs`, `resourceStatus` (`"BOUNDED"`). |
| `POST` | `/api/v1/admin/job/cleanup` | `AdminJobController.cleanupOldJobs` | `{ "message": "Cleanup complete", "removedJobs": n, "remainingJobs": n }` after expiring completed jobs past their retention window. |

## Auth gating

In secured mode `security_policy::is_administrator_path` matches every
`/api/v1/admin/` path, so all three require `ROLE_ADMIN` — matching Java's
class- and method-level `@PreAuthorize("hasRole('ADMIN')")`. Non-admin
sessions receive `403`, unauthenticated callers `401`. The routes are part of
the general (OSS) route set, so in the unsecured open-mode runtime they are
reachable without authentication, mirroring Java's behavior when security is
disabled.

## Behavior and parity notes

- `queue/stats` reflects the Rust resource-weighted queue described in
  `contracts/job-management.md` (`queueCapacity`, `resourceBudget`,
  `availableResourceUnits` are Rust-native counters; Java's map has its own
  executor-oriented keys). The shared keys (`queuedJobs`, `totalQueuedJobs`,
  `rejectedJobs`) carry the same meaning as Java's `JobQueue.getQueueStats()`.
- Cleanup removes only jobs past the 30-minute post-completion retention
  (the same expiry the background sweeper enforces); it then reports the
  removed count and the remaining total, functionally matching Java's
  before/after count arithmetic without logging noise.
- Failures reading manager state return a bare `500`.

## Verification

Administrator gating is covered by the secured-router tests in
`security_http.rs` (`/api/v1/admin/job/stats` succeeds for an admin token and
`/api/v1/admin/job/queue/stats` is denied for a non-admin token) and by the
policy matrix in `security_policy.rs` tests. `job_manager.rs` `mod tests`
covers stats derivation and expiry/cleanup behavior.

## Open questions

- The exact Java `JobStats` field-by-field parity (particularly the active
  job timestamp string format) has not been diffed against a live Java
  response; Rust emits RFC 3339-style strings from the manager's clock.
