# Classification meter

Rust compatibility contract for Java's `ClassificationMeterController`
(`app/proprietary/.../policy/controller/ClassificationMeterController.java`).
Kept as its own small file rather than a section of
`contracts/classification-labels.md` because it meters **client-side**
classification runs and performs no classification itself — it shares only
the audit vocabulary with the labels/classify surface.

## Route

| Method | Path | Java counterpart | Response |
| --- | --- | --- | --- |
| `POST` | `/api/v1/policies/classify/meter` | `ClassificationMeterController.meterClassification` | `202 Accepted`, empty body. |

Implemented in `rust/crates/stirling-processing/src/policy_http.rs`
(`classify_meter`). The route is part of the policy router, so it exists only
when policies are enabled (`policies.enabled` / `POLICIES_ENABLED`); in
secured mode it requires an authenticated caller like the rest of the policy
surface (no admin gate — Java's controller likewise has no `@PreAuthorize`).

## Behavior

- The body is optional. An absent, empty, or malformed JSON body collapses to
  defaults, matching Java's `@RequestBody(required = false)`; the accepted
  shape is `{ policyName?, documentCount?, labels? }` (`labels` is carried by
  the frontend but unused, as in Java).
- `documentCount` is clamped to `[1, 10000]`; missing or non-positive counts
  become `1`.
- A blank or missing `policyName` defaults to `"Classification"`.
- The request's `SecurityAuditContext` (when audit capture is active) is
  stamped as a policy run — the resolved policy name plus a single
  `classify-and-label` step — mirroring Java's
  `AuditContext.REQ_ATTR_POLICY_NAME` / `REQ_ATTR_POLICY_STEPS` request
  attributes so the audit trail records it like the AI classify path.
- **SaaS billing is a deliberate no-op.** Java resolves an optional
  `ClassificationRunBiller` and tolerates billing failure; that biller only
  exists in SaaS deployments. The Rust proprietary runtime has no biller, so
  the metered count is only traced. The endpoint still returns `202` so the
  frontend contract is identical.

## Verification

`policy_http.rs` `mod classify_meter_tests` covers the `202` happy path,
absent/empty/malformed-body tolerance, count clamping at both bounds, and
policy-name defaulting.
