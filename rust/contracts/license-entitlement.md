# Commercial license entitlement compatibility

The reviewed Rust security boundary has a typed, immutable startup license tier:
`Normal`, `Server`, or `Enterprise`. A route is either unrestricted,
Server-or-Enterprise, or Enterprise-only. Authentication and role authorization
run first, followed by the license check and then the handler.

The tier comes only from trusted verification. `premium.enabled`, a nonempty
license key, YAML values, headers, and request data never grant entitlement.
The reviewed runtime synchronously verifies the configured key before building
its secured router and copies that result into the immutable route policy.

## Key sources and verification

`premium.enabled=false`, a missing/blank key, or an unreadable `file:` source
resolves to Normal without network access. Direct keys and file contents are not
trimmed. The temporary Java `enterpriseEdition.enabled/key` migration fallback
is retained when the current premium block is disabled or still has the zero
UUID placeholder.

Three Java-compatible formats are supported:

- `-----BEGIN LICENSE FILE-----` envelopes contain Base64 JSON with `enc`,
  `sig`, and exact `base64+ed25519` algorithm fields. The pinned Stirling public
  key verifies `license/{enc}` before the inner payload is accepted.
- `key/{payload}.{signature}` verifies `key/{payload}` with the same pinned
  Ed25519 key. Standard, URL-safe, padded, and unpadded Base64 forms follow the
  Java decoder's permissive padding/trailing-bit behavior.
- Opaque standard keys are posted to Stirling's fixed Keygen account. The
  client uses JSON:API headers, no redirects, a ten-second connect timeout, and
  Java's five whole-flow attempts with 3/6/9/12-second backoff.

Standard validation preserves Java's machine-scope flow. `NO_MACHINE`,
`NO_MACHINES`, and `FINGERPRINT_SCOPE_MISMATCH` trigger activation followed by
revalidation. Floating licenses list current machines, retain an already
matching fingerprint, and at capacity deregister exactly the oldest parseable
machine before activation. The machine fingerprint hashes the primary MAC,
falls back to a non-loopback MAC and then hostname, and uses `GenericID` when
host identity cannot be resolved.

Certificate/JWT parse, signature, date, status, or semantic failures resolve to
Normal. Online transport or malformed-response failures retry and fail secured
startup after the fifth attempt, as Java does. Unexpected HTTP responses with
valid JSON are not retried. Keys and authorization values use zeroizing wrappers
and are never included in logs or errors.

## Reviewed route matrix

The six Java `@PremiumEndpoint` team mutations require Server or Enterprise:

- `POST /api/v1/team/create`
- `POST /api/v1/team/rename`
- `POST /api/v1/team/delete`
- `POST /api/v1/team/setOwner`
- `POST /api/v1/team/removeOwner`
- `POST /api/v1/team/addUser`

`GET /api/v1/team/list` is intentionally unrestricted by license. Java's
premium-gated controller does not own that route.

All six `/api/v1/audit/*` routes, the eight proprietary UI-data audit/statistics
routes, and `GET /api/v1/usage/fleet-stats` require Enterprise. The policy is an
exact method/path table so an unrelated or newly ported route cannot inherit a
paid tier from a broad prefix.

Denied calls return Java-compatible `403 application/problem+json` with
`type=/errors/403`, title/status/detail, an RFC 3339 timestamp, and request path.
The detail is exactly `This endpoint requires an Enterprise license` or `This
endpoint requires a Server or Enterprise license`.

## Audit coupling

Java's audit service is itself Enterprise-only. Rust therefore enables
controller audit capture only when the verified tier is Enterprise and the
nested audit configuration permits the event. Normal and Server requests never
write audit rows; denied paid routes are rejected before audit planning.

## Refresh and static gates

The runtime owns a seven-day refresh task. A valid or explicitly invalid result
replaces the dynamic license state; exhausted online retries retain the prior
state. `/api/v1/config/app-config` exposes the dynamic `runningProOrHigher`,
`runningEE`, and uppercase `license` fields. Route tiers deliberately remain the
startup snapshot, matching Java's endpoint aspects, so a tier change requires a
restart before paid routes change availability.

Administrator license changes and the refresh task share one live configuration,
so refresh never falls back to the startup key after an administrator mutation.

## Administrator lifecycle

The reviewed secured router exposes Java's five administrator-only lifecycle
routes:

- `GET /api/v1/admin/installation-id`
- `POST /api/v1/admin/license-key`
- `POST /api/v1/admin/license/resync`
- `GET /api/v1/admin/license-info`
- `POST /api/v1/admin/license-file`

Key saves trim with Java `String.trim` semantics, persist `premium.key` before
verification, update dynamic status immediately, and persist the resulting
`premium.enabled` plus valid `premium.maxUsers` values through the same serialized
settings writer as administrator configuration. Empty input clears a key. The
response preserves Java's live-property quirk: an invalid key writes
`premium.enabled=false` while the current response still reports `enabled=true`.
`license-info` deliberately returns the configured key because the entire route
is administrator-only, matching Java's upgrade workflow.

Offline uploads accept one `.lic` or `.cert` file of at most one MiB and require
the license-file header. Basename, traversal, symlink, and directory checks keep
the target inside `configs/`; an existing file is copied to `configs/backup/`
before an atomic replacement. The persisted value remains
`file:configs/<filename>`. As in Java, a correctly headed but cryptographically
invalid certificate is saved and reports a successful activation at `NORMAL`;
the trusted verifier still grants no entitlement.

SaaS's unconditional Enterprise override, durable user-seat synchronization,
the Pro-only actuator filter,
boot-time storage/cluster gates, and service-specific server-certificate
behavior remain separate contracts rather than broad HTTP route rules. The
shipping executable still refuses secured mode, so this verifier is reachable
through the opt-in reviewed runtime until the overall security review closes.

## Verification

Policy tests enumerate every reviewed route and prove that adjacent routes and
wrong HTTP methods remain unrestricted. HTTP tests prove both license levels,
ProblemDetail responses, Normal/Server audit suppression, and Enterprise-only
capture. Verifier tests cover valid test-key-signed certificates and `key/`
payloads, forged production-key input, Java Base64/coercion/date quirks, direct
and file sources, exact validation requests, activation/revalidation,
oldest-machine replacement, non-success JSON behavior, and five-attempt
exhaustion without secret disclosure. A refresh regression proves administrator
configuration replaces the startup key. The authenticated lifecycle suite proves
all five routes reject anonymous and non-administrator callers, persists key and
enabled changes, exercises every upload bound plus backup replacement, and checks
dynamic app-config status. Audit, fleet, and endpoint-statistics integration
suites construct an explicit Enterprise-tier test boundary.
