# Native desktop processing startup

The Tauri launcher can opt into a Rust processing executable with
`STIRLING_NATIVE_BACKEND_PATH`; Java remains the packaged/default sidecar.

The native path now provides:

- an unconditional `Stirling-PDF running on port: <port>` handshake even without `RUST_LOG`;
- an ephemeral loopback port, bounded 90-second launcher wait, stderr/stdout handshake parsing,
  early-exit reporting, stale-process protection, and stale-port cleanup;
- desktop/base/config/log/work environment parity and legacy-workspace migration;
- PID-plus-start-time parent monitoring through `TAURI_PARENT_PID`, with orphan shutdown normally
  observed within one 250 ms poll interval;
- fresh-install configuration initialization in Tauri mode: the packaged Java
  `settings.yml.template` is atomically persisted only when `configs/settings.yml` is absent, and
  an empty `custom_settings.yml` is created only when absent;
- short-file backup recovery: a `settings.yml` shorter than `MIN_SETTINGS_FILE_LINES` (31) is
  treated as truncated/corrupted, moved aside to `settings.yml.<epoch-millis>.bak`, and recreated
  from the template (`custom_settings.yml` is never subject to this);
- upgrade-time template merge: when `settings.yml` already exists and is long enough, any keys the
  bundled template has gained across app versions are folded into the user's file while their
  customized values are preserved.

## Upgrade-time template merge

Matches Java's `ConfigInitializer` upgrade path (and the `YamlHelper` it drives):

- the output is **template-shaped** — the template's structure, comments, blank lines and inline
  comments are kept verbatim, not the user's;
- for each leaf key present in **both** files, the template's default value is replaced by the
  **user's** value, keeping the template's inline comment;
- brand-new template keys absent from the user file keep their template **default**;
- user keys **absent from the template are dropped** (the merge walks the template, so unmatched
  user keys are never carried);
- the file is rewritten **only when the merged result differs** from what is on disk, so re-running
  on an already-current file is a no-op (idempotent).

**Value rendering (quoting).** A carried-over value is re-emitted in the template leaf's own quoting
style: a double- or single-quoted template value keeps that style, and a **plain-styled** value is
emitted as an inline scalar that reparses to **exactly** the user's value. A plain value that is not
plain-safe — one carrying `#`, `:`, `*`, `!`, `@` or another leading/embedded indicator, a
leading/trailing space, an empty string, or text that would otherwise reparse as a bool/number/null
(`true`, `123`, `null`) — is **automatically quoted** (the decision is delegated to serde_yaml's own
scalar emitter, not a hand-maintained character list). So a real database password or secret is never
silently truncated at an inline `#` comment and the file always reparses; a plain-safe value
(`postgres`) still renders bare, with no quoting churn. This matches Java's snakeyaml, which likewise
quotes such values on write — there is no plain-scalar corruption on carry-forward.

`custom_settings.yml` is never merged. Java's two historical `migrate*` key renames
(`migrateEnterpriseEditionToPremium`, `migrateProFeaturesKeyCasing`) are intentionally **not**
ported — they are Java-schema-specific migrations, out of scope.

**Documented scope limitation (follow-up):** the merge carries across only values that live inline
on their key's line — scalars and inline flow sequences (`[]`, `[a, b]`). The template currently has
**no block sequences**, so this covers effectively the whole file; but a user override expressed as a
nested mapping (or a block sequence) under a key is not carried, and that key falls back to the
template default. A `settings.yml` that is long enough to reach the merge path but no longer parses
as YAML is left untouched (a warning is logged) rather than failing desktop startup — Java throws
here; the Rust port prefers not to regress a previously-tolerated file into a hard boot failure.

Production sidecar/PDFium packaging, cross-platform signed-bundle upgrade proof, and switching the
default away from Java remain.
