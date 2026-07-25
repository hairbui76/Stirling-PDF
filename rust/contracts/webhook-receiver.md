# Public inbound webhook receiver — `WebhookReceiverController`

Rust compatibility contract for the single public HMAC-authenticated webhook-delivery
endpoint. Ported from Java `WebhookReceiverController` (+ `WebhookSignatures` for the HMAC
check, `WebhookSpool` for the atomic spool, `WebhookIds` for the id format, and
`RequestUriUtils` for the public allowlist).

Lives in `crates/stirling-processing/src/webhook_receiver.rs`. The webhook *source* type
and the *trigger* this route dispatches are documented in `contracts/policy-config.md`;
this contract covers only the public receiver.

## Route

- `POST /api/v1/webhooks/{webhookId}` — accepts one raw document delivery, verifies its
  HMAC signature, atomically spools it, and dispatches every enabled webhook policy
  referencing the id.

This is the port's **only** new PUBLIC route (HMAC-authed, session-unauthenticated). It is
mounted in the reviewed secured runtime alongside the other policy routes, but reaches its
handler without a login session because the endpoint boundary
(`security_policy::endpoint_policy` → `is_public_webhook`) allowlists it. The allowlist is
deliberately narrowed to **POST only** — `GET`/`PUT`/`DELETE /api/v1/webhooks/*` stay
`Authenticated`, so nothing else inherits the exemption (the frozen-public-surface test was
extended to prove exactly `POST /api/v1/webhooks/*` is exposed). Mirrors Java's
`RequestUriUtils` allowlisting of `/api/v1/webhooks/`.

It is `@Hidden`: absent from every OpenAPI/tool/operation catalog.

## Authentication and the fixed check order

The HMAC signature over the exact body is the ONLY authenticator, so the ordering below is
a **security property, not a stylistic choice** — reordering it would leak webhook-id
existence or let a forged body be spooled / fire a policy. The handler runs, in this order:

1. **webhookId format** — `^[A-Za-z0-9_-]{16,128}$` (`WebhookIds.VALID_ID`). A malformed id
   → `404 "No such webhook"`.
2. **All-sources lookup** — `find_webhook_source` scans every persisted source with **no
   team scope** (a delivery is authenticated by its signed id/secret, not a caller's team).
   Not found → `404` with a **byte-for-byte identical** body ("No such webhook"), so a probe
   cannot distinguish "malformed id" from "no such source" — the anti-enumeration property.
   A store read error → `500 "Webhook receiver unavailable"`.
3. **Signing secret present** — the resolved source's decrypted `signingSecret` must be
   non-blank. Absent/blank → `500 "Webhook source is misconfigured"`. **Fail-closed**: a
   missing secret is never a bypass.
4. **Body-size bounds, BEFORE any signature work** —
   - absent/unparseable `Content-Length` → `411 "A Content-Length header is required"` (a
     chunked body cannot be pre-bounded safely);
   - `declared > webhookMaxBytes` → `413 "Delivery exceeds the {n}-byte limit"` **before a
     byte is read** (the bound is `declared > max`, so a delivery exactly at the cap passes);
   - the read is capped at `declared`; actual `> declared` → `400 "Body exceeds the declared
     Content-Length"`; actual `< declared` → the actual bytes are accepted and everything
     below runs over them.
5. **Constant-time HMAC-SHA256** over the ACTUAL received bytes, verified BEFORE the
   enabled/empty checks. Invalid → `401 "Invalid signature"`.
6. **Paused source** — source not enabled → `403 "Webhook source is paused; deliveries are
   not accepted"`.
7. **Empty body** → `400 "Empty request body"`.
8. **Atomic spool** (below). Store failure → `500 "Could not store delivery"`.
9. **Dispatch** — `fire_for_webhook(webhookId)` fires every enabled referencing policy as a
   LIGHT sweep (see `policy-config.md`); per-policy errors are swallowed so a broken policy
   cannot fail the delivery response.
10. **`202 Accepted`** — `{"accepted":true,"filename":<displayName>,"bytes":<actual len>}`.

Because the signature is verified (step 5) strictly before "paused" (6) and "empty" (7),
neither a paused source nor an empty body is distinguishable from a valid delivery to a
caller who cannot sign — both still surface as `401` when the signature is wrong.

## HMAC signature (`WebhookSignatures`)

Header `X-Stirling-Signature`. The value is trimmed; an optional case-insensitive `sha256=`
prefix is stripped (a bare hex digest is also accepted); the remainder is hex-decoded (mixed
case allowed) and compared to the computed MAC in **constant time** (the `subtle` crate's
`ct_eq`). A missing header, a non-hex / odd-length value, a wrong-length digest, an
HMAC key-init failure, or any parse/format error all yield the **same indistinguishable
`401`** — no branch leaks why. The MAC is keyed on the source's decrypted `signingSecret`;
secrets and the `webhookId` are never logged.

## Body-size / DoS bounds

`webhookMaxBytes` defaults to `104857600` (100 MiB; `policies.webhookMaxBytes`, env
`POLICIES_WEBHOOKMAXBYTES`). The route carries its own `DefaultBodyLimit::disable()` and is
mounted **OUTSIDE** the shared upload `DefaultBodyLimit`, so a legitimate large delivery
within `webhookMaxBytes` is not silently `413`'d by an outer limit; the handler enforces the
bound itself via the declared `Content-Length` plus a capped read (never buffering past
`declared` bytes), matching Java's servlet reading at most `Content-Length` bytes.

## Path-safe atomic spool (`WebhookSpool`)

A verified delivery is staged at:

```
<installRoot>/policy-webhook-spool/<webhookId>/<32-hex-uuid>-<sanitizedName>
```

- The per-webhook directory must be a **direct child** of the spool root — a
  lexically-normalized parent-equality guard rejects any `webhookId` carrying separators or
  `..` (defense in depth; step 1 already rejects such ids).
- The body is written to a **hidden `.<name>.part` temp file**, then **atomically renamed**
  into place (a single in-directory rename replaces Java's `ATOMIC_MOVE`→`REPLACE_EXISTING`);
  a failed rename removes the temp so no stray `.part` is left.
- Both the temp and the target are lexically normalized and must resolve strictly **inside**
  the per-webhook directory.
- The filename comes from the untrusted `X-Stirling-Filename` header, reduced to a safe
  **basename** (`\`→`/`, then every char outside `[A-Za-z0-9._-]`→`_`, trimmed, **all
  leading dots stripped**), falling back to `document.pdf` when nothing usable remains. The
  32-char dashless-hex unique prefix never contains `-`, so the first `-` in a stored name is
  always the display separator; the `202` reports the **display name** (prefix stripped).

## Delivery consumption (resolve) — end-to-end (CLOSED)

The earlier `resolve_source → Unsupported("webhook")` gap is **CLOSED**: `resolve_source` now has
a real `"webhook"` arm, so a fired webhook policy consumes exactly what this receiver spooled,
mirroring Java `WebhookInputSource.resolve`/`completeConsumed`. The source runner is threaded the
engine `install_root`, derives the per-webhook dir via `spool_dir` (containment-checked), and runs
the folder-consume lifecycle with `{snapshot=false, recursive=false, identity=stat}`:

- A **missing or non-directory** spool path is a **no-op** — it reports an empty present set and
  resolves zero inputs, never an error (mirrors `Files.isDirectory` being false for both), unlike
  the folder source which errors on an absent directory. Reporting present-empty (not vetoing
  cleanup) lets a FULL sweep still prune stale ledger rows for already-consumed deliveries.
- Lists the dir **non-recursively**, **skipping the receiver's hidden `.<name>.part`/dotfile
  temps**, then applies the readiness check + `size:mtime` stat-gate and **claims each delivery
  through the ledger** (stat-only identity, so `hash_path` is always `None`) so it is processed once.
- The pipeline filename is the **display name** (via `display_name`, now `pub(crate)`: the 32-hex
  UUID prefix is stripped → e.g. `invoice.pdf`), so a downstream step never sees `<32hex>-…`.
- Reuses the shared `finish_consumed` settle path: on success it re-checks the stat-gate is
  unchanged AND `all_settled_done` (cross-policy — a delivery shared by N webhook policies is
  deleted only after every one is Done) then removes the file; on failure the file is **retained
  and retried** (the immutable spool file's unchanged stat-gate parks a re-claim, never auto-lost).
- **LIGHT** = per-delivery consume (from `fire_for_webhook`); **FULL** = reconcile sweep that also
  prunes ledger rows for deliveries that vanished from disk, excluding `PROCESSING` so an in-flight
  LIGHT claim is not pruned by a concurrent FULL sweep.

`install_root` is threaded through the source runner and this receiver in `lib.rs` so the fired run
reads exactly what the receiver wrote. See `contracts/policy-config.md`.

## Java oracle

`WebhookReceiverController`, `WebhookSignatures`, `WebhookSpool`, `WebhookIds`,
`RequestUriUtils` (public allowlist).
