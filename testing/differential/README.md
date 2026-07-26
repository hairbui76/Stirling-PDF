# Java-vs-Rust differential test harness

Posts the **same input** to the Java and Rust Stirling-PDF backends, then
**semantically** compares the responses and reports parity per endpoint. It is
the regression net for the Rust port: prove the Rust backend produces output
equivalent to the Java oracle, endpoint by endpoint.

```
same input  ──►  POST  ──►  Java backend  ─┐
            └─►  POST  ──►  Rust backend  ─┴─►  semantic compare  ──►  PASS / DIFF / SKIP / ERROR
```

The comparison is **language-neutral**: it never diffs raw PDF bytes. It rasterizes
PDFs with Ghostscript and compares pixels, deep-compares JSON, and compares ZIP
members structurally — so two different PDF producers (PDFBox vs lopdf/pdfium)
that render the same page compare equal.

---

## Why this shape (environment reality)

A live Java-vs-Rust comparison **cannot run in the dev sandbox**, and the harness
is built around that fact:

| | dev sandbox (here) | JDK-25 CI host |
|---|---|---|
| JDK | 17 (project needs 25) — no runnable `bootJar` | 25 |
| Native tools | only Ghostscript + bundled PDFium; **no** LibreOffice / Tesseract / qpdf / WeasyPrint / Calibre / ffmpeg / unrar | full toolchain installed |
| Rust backend | builds + serves fine | builds + serves fine |

So the harness has two halves:

- **Rust half — runs and is validated here.** `--rust-only` drives every case
  against the live Rust backend and checks each response is a well-formed
  artifact. This is proven working in the sandbox.
- **Java half — parameterized by URL.** Point `--java-url` at a Java backend
  running in a JDK-25 + tools environment and the harness diffs the two. When
  `--java-url` is unset or unreachable, Java is skipped gracefully (never a hard
  failure).

The comparison **engine itself** is fully validated here, without Java, by
`selftest.py` (see below): it synthesizes known-equivalent and known-different
pairs from the Rust backend and asserts the engine reaches the right verdict.

---

## Files

| File | Role |
|---|---|
| `manifest.py` | The deterministic endpoint cases (name, path, input fixtures, form params, response type). |
| `known_diffs.py` | The known-difference registry: analysed, accepted Java-vs-Rust differences, each with a mandatory reason and optional pinned values. |
| `fixtures.py` | Resolves input files; generates the multi-page fixture with Ghostscript on demand. |
| `httpclient.py` | Multipart POST. Uses `requests` if importable, else a pure-stdlib multipart encoder. |
| `compare.py` | The semantic comparison engine (PDF visual / JSON deep / ZIP structural) + single-artifact validation. |
| `differential.py` | The CLI driver (`--rust-only` / `--diff`). |
| `selftest.py` | Validates the compare engine against the live Rust backend (proves it can tell PASS from DIFF). |
| `run_smoke.sh` | Convenience: boot the Rust backend, run `--rust-only`, tear it down. |
| `_generated/` | Generated fixtures (git-ignored). |

**Dependencies:** Python 3 + Ghostscript (`gs`) only. `requests` and `Pillow` are
**not** required — the HTTP client falls back to stdlib multipart, and the image
compare parses raw PPM with stdlib (no Pillow). `requests` is used automatically
if present.

---

## Run it HERE (`--rust-only`)

The Rust backend binary is at `rust/target/debug/stirling-processing`; it reads
`STIRLING_PORT` / `SERVER_PORT` and runs in open mode.

**One-shot (boots + tears down the backend):**

```bash
cd testing/differential
./run_smoke.sh                 # starts Rust on :8091, runs --rust-only, stops it
PORT=9099 ./run_smoke.sh       # different port
```

**Manual:**

```bash
# 1. build once if needed
cargo build -p stirling-processing        # or: task engine:build

# 2. start the Rust backend
STIRLING_PORT=8091 ./rust/target/debug/stirling-processing &

# 3. drive + validate it
cd testing/differential
python3 differential.py --rust-url http://localhost:8091 --rust-only -v
```

`--rust-only` POSTs every case and checks the response status is 2xx and the body
is a well-formed artifact of the declared type (PDF parses and has ≥1 page / ZIP
opens with valid members / JSON parses). No Java needed.

**Validate the compare engine itself (also runs here):**

```bash
python3 selftest.py --rust-url http://localhost:8091
```

---

## Run the FULL diff in CI (`--diff`)

In a JDK-25 host with the native toolchain installed:

```bash
# 1. Java backend, security disabled, on :8080
export DOCKER_ENABLE_SECURITY=false
# (start the Java Spring Boot app / container so /api/v1/... is served on :8080,
#  with LibreOffice/Tesseract/qpdf/etc present if you later widen the manifest)

# 2. Rust backend on :8091
STIRLING_PORT=8091 ./rust/target/debug/stirling-processing &

# 3. diff them
cd testing/differential
python3 differential.py \
    --rust-url http://localhost:8091 \
    --java-url http://localhost:8080 \
    --diff -v
```

Exit code is **non-zero if any case is DIFF or ERROR**; SKIP-java-absent and PASS
do not fail the run. Wire that exit code into CI. Differences that have been
analysed and accepted are declared in
[`known_diffs.py`](#known-difference-registry-known_diffspy) so they report as
`KNOWN` instead of `DIFF` — visibly, and without blinding the gate.

### CLI reference

```
--rust-url URL     Rust backend base URL (required; default http://localhost:8091)
--java-url URL     Java backend base URL (enables --diff)
--rust-only        Capture + validate the Rust backend only
--diff             Diff Rust vs Java (requires --java-url)
--filter SUBSTR    Only run cases whose name contains SUBSTR
--timeout SECONDS  Per-request timeout (default 300; large-file friendly)
--list             List cases and exit
-v / --verbose     Print all per-case messages (DIFF/ERROR always print)
--no-color         Disable ANSI color
```

Mode is auto-selected: `--java-url` present ⇒ `--diff`, else `--rust-only`.

### Per-case outcomes

| Outcome | Meaning | Fails run? |
|---|---|---|
| `PASS` | Outputs semantically equivalent (or, in `--rust-only`, a valid artifact). | no |
| `DIFF` | A real semantic difference (page count, pixels, JSON field, ZIP entries, status). | **yes** |
| `SKIP-java-absent` | Rust responded; the Java backend was unreachable for this case. | no |
| `ERROR` | Rust unreachable, non-2xx where success expected, or malformed body. | **yes** |

A `PASS` case may still carry per-field annotations, printed **at every verbosity**:

| Line | Meaning | Fails run? |
|---|---|---|
| `KNOWN>` | This field differs, and the difference is registered in `known_diffs.py` with a reason (and, ideally, pinned values). | no |
| `STALE>` | A registered known difference did **not** show up — the field agrees now (or is gone). Delete the entry. | no (warn) |

---

## Known-difference registry (`known_diffs.py`)

**The problem it solves.** A permanently-red gate is a worthless gate: everyone
learns to ignore it, and the next *real* regression rides in on the noise. But
deleting a field from the comparison to get green is worse — that blinds the gate
forever. The registry is the middle path: differences that have been **analysed
and accepted** stop failing the run, while staying fully visible and still being
watched for change.

Each entry is keyed by **(case name, field path)** and **requires a
human-readable `reason`**. It may additionally **pin** the expected values
(`expect_rust` / `expect_java`), independently per side.

```python
KnownDiff(
    case="get_info_single",
    field="BasicInfo.CharacterCount",
    reason="Java's bare PDFTextStripper runs with sortByPosition=false ...",
    expect_rust=14,
    expect_java=18,
),
```

`field` is the dotted JSON path exactly as the report prints it
(`BasicInfo.CharacterCount`, `Other.XMPMetadata`); for JSON nested in a ZIP member
the path is relative to that member.

### Classification

| Observed | Classified | Fails run? |
|---|---|---|
| Field differs, **not** in the registry | `DIFF` (unchanged behaviour) | **yes** |
| Field differs, registered, observed values **match the pins** (or the side is unpinned) | `KNOWN` | no |
| Field differs, registered, **pinned values no longer hold** | `DIFF` — *"the known-difference expectation is stale"* | **yes** |
| Field registered but **does not differ any more** | `STALE` warning | no |

**Pinned values are what make an entry regression-proof.** Unpinned, an entry
accepts *any* difference in that field forever — if Rust's character count later
collapsed to `0`, the gate would stay green. Pinned, the entry accepts *exactly*
the difference that was analysed: the moment either side moves, the run fails with
a message saying the expectation itself is stale and must be re-verified against
the Java oracle. So: **pin whenever the values are deterministic**, and justify in
the reason whenever they are not (e.g. `Other.XMPMetadata` embeds generation-time
timestamps and UUIDs, so its value varies run to run and *cannot* be pinned).

Registering a field also takes precedence over the generic
`INFORMATIONAL_JSON_KEYS` heuristic — an explicit entry is more specific, and
routing it to `(informational)` would make it look permanently stale.

### Visibility — nothing is ever hidden

Known differences are printed on every run, verbose or not:

```
PASS             get_info_single  (4 known diffs)
    KNOWN> BasicInfo.CharacterCount: rust=14 java=18 [expect_rust=14 expect_java=18]
        why: Java's bare PDFTextStripper runs with sortByPosition=false. [...]
------------------------------------------------------------------------
SUMMARY  PASS=13  (total 13)  (2 with known diffs: 5 field(s))
OK: no unexplained parity differences (5 known, accepted)
```

The per-case marker, the `KNOWN>` lines and the summary count all stay in the
report; `-v` prints each full reason instead of the abridged first sentence. The
header also prints the registry size (`known diffs : 5 entries over 2 case(s), 4
pinned`).

### Removing a stale entry

When the underlying difference is fixed (or the field disappears), the run prints:

```
    STALE> Other.XMPMetadata: registered as a known difference but the backends now
           AGREE (or the field is gone) -- delete this entry from known_diffs.REGISTRY
------------------------------------------------------------------------
WARNING: 1 STALE known-difference entry in known_diffs.REGISTRY ... does NOT fail the run.
```

**Stale entries warn loudly but deliberately do NOT fail the run.** Closing a
known parity gap must never break the build of the person who closed it — the
gate's job is to catch *divergence*, not to punish convergence. Cleanup is a
one-line deletion:

1. Delete the `KnownDiff(...)` entry from `REGISTRY` in `known_diffs.py`.
2. Re-run — the field is now covered by the normal DIFF rules again, so any
   future divergence in it fails immediately.

Registry hygiene is checked at startup (missing reason, duplicate key, unknown
case name ⇒ hard error, exit 2), and the classification rules have offline
assertions:

```bash
python3 known_diffs.py     # prints the registry, then self-checks the rules (no backend needed)
```

### What is registered today

| Case | Field | Pinned | Why |
|---|---|---|---|
| `get_info_single` | `BasicInfo.CharacterCount` | rust=14 java=18 | Java's bare `PDFTextStripper` runs with `sortByPosition=false`; on the fixture's `/Rotate 90` page its line-breaking splits per glyph and it counts more. Replicating the quirk needs a text-layout work-item that is deliberately not planned. |
| `get_info_single` | `BasicInfo.WordCount` | rust=4 java=7 | same root cause |
| `get_info_single` | `BasicInfo.ParagraphCount` | rust=2 java=6 | same root cause |
| `get_info_single` | `PerPageInfo.Page 1.Text Characters Count` | rust=14 java=18 | same root cause — the per-page mirror of `BasicInfo.CharacterCount`, pinned to the values the first live CI run reported. |
| `get_info_multipage` | `Other.XMPMetadata` | no — **cannot** be pinned (embeds generation-time timestamps/UUIDs, varies per run) | Java re-serialises the packet through xmpbox (normalised namespaces/indentation, `+00:00` instead of `Z`, elements instead of attributes); Rust returns the stored packet verbatim. Content equivalent. |

The registry was originally seeded defensively for **both** `get_info` cases
(the residuals were reported per case, not per field). The first live CI run
reported the speculative entries `STALE` — the multipage count entries and the
single-page XMP entry — and they were deleted exactly as their notes instructed.
That is the registry working as designed, not a defect.

---

## Scope: which endpoints, and why only these

The manifest is deliberately limited to **deterministic, tool-light** operations
that run with only **pdfium / lopdf / Ghostscript** — i.e. page-geometry ops and
pure PDF JSON reads that need none of the missing native tools:

| Case | Endpoint | Out |
|---|---|---|
| `rotate_90`, `rotate_270` | `general/rotate-pdf` | pdf |
| `merge_two` | `general/merge-pdfs` | pdf |
| `rearrange_reverse` | `general/rearrange-pages` | pdf |
| `remove_pages_2_4` | `general/remove-pages` | pdf |
| `scale_a4`, `scale_keep_2x` | `general/scale-pages` | pdf |
| `crop_box` | `general/crop` | pdf |
| `to_single_page` | `general/pdf-to-single-page` | pdf |
| `split_after_2_4` | `general/split-pages` | zip |
| `remove_blank_pages` | `misc/remove-blanks` | zip |
| `get_info_single`, `get_info_multipage` | `security/get-info-on-pdf` | json |

**Excluded here**, on purpose:

- **Converters** (`convert/*`), **OCR** (`misc/ocr-pdf`), **repair**
  (`misc/repair`), **compression** (`misc/compress-pdf`, which shells to qpdf),
  **signing / certs** (`security/cert-sign`, `validate-signature`), ebook, etc.
  These need LibreOffice / Tesseract / qpdf / WeasyPrint / Calibre / ffmpeg /
  certificates that are **absent in the sandbox**, and several are inherently
  **non-deterministic** (embedded timestamps, OCR heuristics, lossy re-encode),
  so they cannot yield a meaningful byte- or pixel-stable parity verdict here.

Adding a case is a one-liner in `manifest.py` once the required tools exist in the
target environment — the driver and compare engine already handle pdf/zip/json.

---

## How the comparison works

### Status code
Compared first. A status mismatch is itself a DIFF. If **both** backends return
the same non-2xx status, that is treated as parity (both refuse identically).

### JSON (`get-info-on-pdf`)
Both bodies are parsed and deep-compared field by field.

- **Hard-required to match:** structural/count fields — `Number of pages`,
  `WordCount`, `CharacterCount`, `ParagraphCount`, per-page sizes, etc. Any
  difference here is a DIFF.
- **Informational only (reported, never a DIFF):** fields that can legitimately
  differ between backends —
  `FileSizeInBytes`, `CreationDate` / `ModificationDate` / `ModDate`, `Producer`,
  `PDF version`, and any `/ID` / document/instance IDs. These are echoed in the
  report tagged `(informational)` so nothing is hidden, but they don't fail the
  run. (Rationale: byte size and date/producer formatting are producer-specific
  even for identical content.)

The informational key list lives in `compare.INFORMATIONAL_JSON_KEYS`.

- **Known, accepted differences (reported as `KNOWN>`, never a DIFF):** specific
  `(case, field)` pairs registered in `known_diffs.py` with a written reason and,
  where deterministic, pinned values. Unlike the informational list, this is
  *per-case and per-field*, and a pinned entry fails the run the moment the values
  move. See [Known-difference registry](#known-difference-registry-known_diffspy).

### PDF — visual, never byte-diff
Raw PDF bytes are **never** compared. Instead:

1. **Page count** via Ghostscript. Mismatch ⇒ DIFF (and per-page compare is
   skipped as meaningless).
2. **Per-page visual raster.** Each page is rendered to a raw PPM with
   `gs -sDEVICE=ppmraw -r100` and compared.

Volatile PDF metadata (`/CreationDate`, `/ModDate`, `/ID`, producer, PDF version)
lives in the header/trailer and **does not affect rendered pixels**, so the visual
compare ignores it for free — no metadata scrubbing needed.

**Why not a plain pixel diff?** Two different producers render the same glyph with
slightly different antialiasing, and pages are *sparse*: a full 180° rotation of a
mostly-white text page moves under 1% of the pixels, so a whole-page pixel-fraction
threshold cannot separate "rotated" from "antialiasing noise".

**Ink-density grid.** Each page raster is reduced to an `N×N` grid (default 36×36)
where every cell holds the average ink (`255 − luminance`) over its block.
Averaging cancels glyph-edge antialiasing while preserving *where the ink is*. A
cell whose density shifts by more than `CELL_DELTA_TOL` (default 12/255) is
"significant"; too many significant cells ⇒ DIFF. Different page **dimensions** at
the same DPI are an immediate DIFF (geometry changed).

Calibrated separation on this repo's fixtures (36×36, r100):

| pair | significant cells | max cell delta |
|---|---|---|
| antialiasing only (same content, diff producer) | 0 | ~5 |
| 180° rotation (real change) | 37 | ~112 |
| entirely different page | 15 | ~172 |
| identical | 0 | 0 |

Because these page-geometry ops **copy** content streams rather than re-render
text, real Java-vs-Rust output should sit at the antialiasing-noise level (≈0
significant cells). Every threshold is env-overridable so CI can retune against
the real Java backend without editing code:

```
DIFF_RASTER_DPI=100        # raster resolution
DIFF_GRID_CELLS=36         # N in the N×N ink grid
DIFF_CELL_DELTA_TOL=12     # per-cell avg-ink delta (0..255) to count a cell "significant"
DIFF_SIG_CELLS_RATIO=0.004 # fraction of cells allowed significant before DIFF
```

### ZIP (`split-pages`, `remove-blanks`)
Compare the set of entry **basenames** first (path-prefix differences tolerated).
Then each shared entry is compared with the PDF or JSON rules above, dispatched by
extension / sniffed content. Any entry-set or per-entry difference ⇒ DIFF.

---

## Fixtures

Inputs are byte-identical across both backends within a run.

- Single-page inputs come straight from the committed `testing/*.pdf`
  (`test_pdf_1.pdf`, `test_pdf_2.pdf`, `crop_test.pdf`).
- The multi-page input (`_generated/multipage_5.pdf`, 5 pages) is generated once
  with Ghostscript and cached (git-ignored). It is created on first run; delete
  `_generated/` to force regeneration.

Determinism note: Ghostscript stamps a `/CreationDate` into the generated file,
but the **same** file is uploaded to both backends in a run, so that is irrelevant
to parity; and the cached file is reused across runs for reproducibility.
