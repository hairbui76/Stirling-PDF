# Microsoft Purview sensitivity labels — `PurviewLabelController`

Rust compatibility contract for the two Microsoft Purview label steps. Ported from Java
`PurviewLabelController` (+ `ApiConnectionResolver` for the connection lookup and
`AiToolResponseHeaders` for the report-header name), backed by the `SensitivityLabel` /
`PdfSensitivityLabels` pair (Java `SensitivityLabel` / `PdfSensitivityLabels`, with the
15 `PdfSensitivityLabelsTest` cases — including save→reload round-trips — ported).

Lives in `crates/stirling-processing/src/purview.rs` (settings + label read/write) and
`purview_http.rs` (the HTTP boundary). Both routes are mounted **only** in the opt-in
reviewed secured router, like the rest of the proprietary surface; production secure-mode
startup remains fail-closed pending independent security review.

For the separate, always-mounted classification vocabulary and the
`classify-and-label` bridge (a different feature that writes its own Info entry), see
`contracts/classification-labels.md` — not duplicated here.

## Fully offline

A sensitivity label is metadata — a flat `MSIP_Label_<GUID>_<Attribute>` key/value set —
so applying and reading one involves **no call to Microsoft Graph** on the in-scope path,
no network, and no app registration. The app-registration credentials
(`clientId`/`clientSecret`) buy exactly one thing: reading the tenant's label taxonomy from
Graph so a UI could offer a label list instead of a pasted GUID. That taxonomy lookup is
**intentionally not built** here (see Gaps), so the credentials currently gate nothing that
runs; only `tenantId` is used.

## Routes

- `POST /api/v1/integration/purview-apply-label` — writes the label metadata onto the PDF
  and returns the **re-saved** document (`application/pdf`).
- `POST /api/v1/integration/purview-read-label` — reports the labels a PDF already carries
  via the `X-Stirling-Tool-Report` header (Java `AiToolResponseHeaders.TOOL_REPORT`, which
  the pipeline already parses) and returns the document **byte-for-byte unchanged**, so a
  read never perturbs the file it inspected.

Both are `multipart/form-data`.

- apply fields: `fileInput` (PDF, required), `connectionId` (required), `labelId`
  (required), `labelName`, `method` (default `STANDARD`), `contentBits` (optional int;
  blank treated as absent).
- read fields: `fileInput` (required), `connectionId` (required).

apply resolves the connection **first**, then parses `method` (matching the Java
controller's ordering, so a bad connection is reported before a bad method), stamps the
label's `SetDate` with the current wall-clock instant, applies it, and re-saves. Output
filename is the upload's basename or `labelled.pdf` (Java `safeFileName`).

Errors return `{"error": message}`: an unknown/inaccessible connection, a protected label,
a bad `method`, an unparseable `contentBits`, or an unreadable PDF are `400`; internal
failures `500`.

## `PurviewConnectionSettings`

Parsed from the stored/incoming config map (Java `PurviewConnectionSettings.from`):

- `tenantId` — **required**, must match the GUID pattern
  (`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`); ASCII-lowercased
  (`Locale.ROOT`) and used as the label **`SiteId`**.
- `clientId` / `clientSecret` — **both or neither** (half an app registration is rejected
  at save, not on first taxonomy read). `clientSecret` carries a "secret" hint, so the
  shared integration masking/merge redacts it on read; `Debug` never prints it.
- `graphBaseUrl` — default `https://graph.microsoft.com`.
- `loginBaseUrl` — default `https://login.microsoftonline.com`.

`PURVIEW` is a registered integration type. Its config is schema-validated on **save**
regardless of the S3 policy toggle (mirroring Java's always-registered
`PurviewIntegrationValidator`); a rejected payload is a `400`. Save-validation is a pure
side effect — the stored config is not rewritten, so `tenantId` keeps its original casing
at rest (lowercasing is a read-time concern), matching Java.

### `resolve_config` (anti-enumeration)

Dereferences a step's `connectionId` to the stored config of a `PURVIEW` connection (Java
`ApiConnectionResolver.resolveConfig`). Every "you may not have this" outcome — no such
row, wrong integration type, not permitted for this caller, or disabled — collapses into
**one opaque error**, so a caller cannot probe which connection ids exist. Java reports the
disabled case with a distinct message; this port folds it into the same opaque error,
leaking strictly less than Java. Unlike Java, the caller identity is passed explicitly
(not read from a thread-local), so the `can_use` check always runs.

### Step validator (`validate_steps`) — save-time confused-deputy guard

Ported from Java `IntegrationStepValidator` (a `PipelineStepValidator` run by
`PolicyValidator.validateSteps`). An integration step names a connection by id, but the
worker thread that later runs it carries **no** principal — so `resolve_config` lets the
lookup through unchecked there. `validate_steps` runs on the request thread, while the
saving caller's identity is available, and forces the ownership check by resolving each
step's connection (the resolved config is discarded — the call *is* the check). Without
it, a caller could name any connection id in a step and have the server dial that tenant's
endpoint with that tenant's stored credentials.

Wiring / behaviour:

- Called from `save_policy` (between the source loop and output validation — Rust order
  sources → steps → output → trigger → size) and from the ad-hoc run path
  (`submit_ad_hoc`, steps-then-output), mirroring Java's `PolicyValidator.validate` and
  `PolicyController.validateAdHocRun`.
- A step whose operation is not under `/api/v1/integration/` is skipped.
- A prefixed operation with no registered connection type → `unknown integration step: <op>`
  (fail-closed).
- `connectionId` is parsed with a dedicated `Value → i64` mirroring
  `ApiConnectionResolver.connectionId(Object)`: absent / JSON null / blank string →
  `<op> requires a 'connectionId' parameter`; a number or numeric string → that id;
  anything else → `'connectionId' is not a valid connection reference: <value>`.
  (Not the S3 `connection_id` helper, whose message is hard-coded to the s3 path.)
- **Divergence:** the registry lists only the *ported* subset —
  `purview-apply-label` and `purview-read-label` (both `PURVIEW`). Java's map also carries
  `external-api-call` (`API`) and `consigno-submit` / `consigno-fetch-signed` (`CONSIGNO`);
  neither the custom-API step nor Consigno exists in this port, so those operations are
  *not* registered and, being under the integration prefix, fail closed as
  `unknown integration step` rather than being resolved.

## `SensitivityLabel` — the MSIP key contract

A label is persisted as ordered `MSIP_Label_<GUID>_<Attribute>` pairs (Java
`SensitivityLabel`; insertion order matches its `LinkedHashMap`):

| Attribute | Written | Read |
|---|---|---|
| `Enabled` | always `true` | must be `true` (case-insensitive) or the pairs are not a label |
| `SiteId` | the tenant GUID | mandatory in contract; a non-compliant label with none is kept and defaulted to `unknown` |
| `Method` | `Standard` / `Privileged` wire form; omitted when unset | tolerant parse (trim/upper-case), unrecognised → absent |
| `SetDate` | extended-ISO `%Y-%m-%dT%H:%M:%S%z`, always UTC (`+0000`); omitted when unset | extended-ISO, falling back to a bare RFC-3339 instant; garbage → absent |
| `Name` | capped at 255 chars; a blank name is omitted entirely (never written empty) | as stored |
| `ContentBits` | integer; omitted when unset | parsed int; garbage → absent |

`labelId` must be a GUID (36 chars, hex + hyphens only) — an **injection guard**, because
the id is spliced verbatim into XMP/Info key names, so a stray space or `<`/`>`/`&` would
corrupt or inject metadata. `siteId` must be non-blank.

Content marks are a bitmask: `HEADER 0x1`, `FOOTER 0x2`, `WATERMARK 0x4`, `ENCRYPT 0x8`.
`is_protected` is `contentBits & 0x8` — only the `ENCRYPT` bit is read by production; the
other three are named for the contract and exercised only by tests.

## Read / apply / clear (`PdfSensitivityLabels`)

Microsoft documents *what* a label is but not *where* it lives in a PDF, so both surfaces a
PDF can hold such pairs on are treated as valid: the **Document Information dictionary** and
the **XMP packet**.

- **`read_all`** — scans both surfaces, de-duplicated by GUID, keeping only enabled labels.
  Info pairs are collected **before** XMP and the first value per `(GUID, attribute)` wins,
  so **Info wins** — a stale XMP copy cannot override what a labelling client wrote to Info.
  (`read` = the first of `read_all`; Java-oracle parity surface, test-only for now.)
- **`apply`** — **refuses** a label that claims encryption
  (`is_protected`) with a "…can apply the label metadata but cannot protect the content"
  error, since writing `ContentBits=ENCRYPT` onto plaintext would lie to every downstream
  reader. Otherwise it does a **tenant-scoped replace on BOTH surfaces**: only labels whose
  `SiteId` matches this tenant (case-insensitive) are removed, so **other tenants' labels
  are left untouched** ("one label per organization"), then the new pairs are written to
  Info and spliced into XMP.
- **`clear`** — strips every label from both surfaces (Java-oracle parity, test-only for
  now).

### XMP-packet splice primitive (net-new)

The XMP surface is edited **textually**, not re-serialised, because a document's packet may
carry schemas a structured writer would silently drop. Label properties are written into the
Adobe **pdfx** namespace (`http://ns.adobe.com/pdfx/1.3/`), spliced into the first
`rdf:Description` (adding `xmlns:pdfx=` if absent); when there is no `rdf:Description`, the
Info dictionary carries the label alone.

Java balanced each entry's closing tag with a `\1\2` regex **backreference**; Rust's `regex`
has no backreferences, so the opening tag is matched by regex and the matching close
(`</`, optional same prefix, same key, `>`) is located by **manual balanced-tag matching**.
The label-key match is **case-sensitive** (`MSIP_Label_`), while the XMP tag scan is
**case-insensitive** (parity with Java's two patterns). Values are XML escape/unescaped over
the five entities. The packet is bounded to **8 MiB** — a reader tolerates an oversized
packet as "no packet"; a writer propagates the error rather than dropping a huge packet.

## Read report (`buildReport`)

`read_label` serialises this tenant's label plus a bare list of others:

- `labelled` (bool) — whether this tenant has a label.
- When present: `labelId`, `labelName`, `method` (the enum **constant name**
  `STANDARD`/`PRIVILEGED` — deliberately not the MIP wire form), `setDate`
  (`Instant.toString()` = RFC-3339 UTC with `Z`), `contentBits` (int|null), `protected`
  (bool). These per-label fields are omitted entirely when this tenant has no label
  (Java's `ifPresent`).
- `otherTenantLabels` — `[{labelId, siteId}]` for every other tenant's label, so a policy
  can still see them.

## Gaps (explicit)

- The Graph taxonomy lookup is **intentionally not built** — `clientId`/`clientSecret`
  therefore gate nothing that currently runs.

## Verification

Unit tests cover the GUID/injection guard, both-or-neither credentials, the tenant-lowercase
`SiteId`, the metadata key ordering / optional-attribute omission / 255-char `Name` cap,
tolerant `SetDate`/`ContentBits`/`Method` parsing, the `ENCRYPT` protected bit, XMP
escape/splice/strip primitives (prefixed and bare close tags, case-insensitively), Info-wins
de-duplication, the opaque `resolve_config` outcomes, the protected-label refusal, and the
apply→reload round-trip preserving other tenants' labels. The step validator adds coverage
for the ported-subset registry (Consigno / external-api fail closed), the
`ApiConnectionResolver.connectionId` parsing matrix, the skip / unknown-step /
required-parameter / invalid-reference messages, and an end-to-end `validate_steps` proving
the resolve authz actually runs (a bad id → the opaque `resolve_config` error).
`task engine:check` is clean.
