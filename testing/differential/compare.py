"""Semantic, language-neutral comparison of backend outputs.

Three response families, three comparators:

* JSON  -> parse both, deep field-level compare. Numeric identity fields (page /
  word / char counts) are hard requirements; volatile fields (byte size, dates,
  producer version, IDs, PDF version) are reported as *informational* only, never
  a DIFF.
* PDF   -> NEVER byte-diff. Compare (i) page count and (ii) a per-page VISUAL
  raster. Volatile PDF metadata (/CreationDate, /ModDate, /ID, producer) lives in
  the header/trailer and does not affect rendered pixels, so the visual compare
  ignores it for free.
* ZIP   -> compare the set of entry basenames, then compare each shared entry
  with the PDF or JSON rules above (by extension / sniffed content).

Known differences
-----------------
A JSON field difference is additionally classified against ``known_diffs.REGISTRY``
when the caller passes the case name. A registered (case, field) whose values
satisfy the registered pins becomes a KNOWN difference: still reported (never
hidden), but not a DIFF. A registered field whose *pinned* values no longer hold
stays a DIFF, tagged as a stale expectation. Everything unregistered is a DIFF
exactly as before. See ``known_diffs.py``.

Visual compare (the hard part)
------------------------------
Two *different* PDF producers (PDFBox on the Java side, lopdf/pdfium on the Rust
side) serialize the same page differently, and gs re-rasterizing them yields
sub-pixel antialiasing noise even when the content is identical. A naive
per-pixel or whole-page-fraction compare is defeated by *sparse* pages: a full
180-degree rotation of a mostly-white text page moves under 1% of the pixels, so
a pixel-fraction threshold cannot separate "rotated" from "antialiasing noise".

Instead we rasterize each page to a raw PPM (``gs -sDEVICE=ppmraw``, pure stdlib
to parse -- no Pillow), then reduce it to an NxN **ink-density grid**: each cell
holds the average ink (255 - luminance) over its block of pixels. Averaging
suppresses glyph-edge antialiasing noise while preserving *where the ink is*. A
cell whose density shifts by more than ``CELL_DELTA_TOL`` is "significant"; too
many significant cells means the pages genuinely differ. Calibrated separation
on this repo's fixtures (36x36 grid, r100):

    antialiasing-only (same content)   0 significant cells, max cell delta ~5
    180-degree rotation (real change) 37 significant cells, max cell delta ~112
    entirely different page            15 significant cells, max cell delta ~172

All thresholds are env-overridable (see the constants) so CI can retune against
the real Java backend without editing code. Because these page-geometry ops
*copy* content streams rather than re-render text, real Java-vs-Rust output
should sit at the antialiasing-noise level (~0 significant cells).
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import known_diffs


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Tunables (env-overridable)
# ---------------------------------------------------------------------------
RASTER_DPI = _env_int("DIFF_RASTER_DPI", 100)
GRID_CELLS = _env_int("DIFF_GRID_CELLS", 36)  # NxN ink-density grid
CELL_DELTA_TOL = _env_int("DIFF_CELL_DELTA_TOL", 12)  # 0..255 avg-ink delta per cell
# Fraction of grid cells allowed to be "significant" before a page is DIFF.
SIG_CELLS_RATIO_MAX = _env_float("DIFF_SIG_CELLS_RATIO", 0.004)


def _sig_cells_max() -> int:
    return max(4, int(SIG_CELLS_RATIO_MAX * GRID_CELLS * GRID_CELLS))


# JSON keys (matched case-insensitively, as substrings of the leaf key OR the
# dotted path) allowed to differ between backends -> informational, not a DIFF.
INFORMATIONAL_JSON_KEYS = (
    "filesizeinbytes",
    "filesize",
    "creationdate",
    "modificationdate",
    "moddate",
    "producer",
    "pdf version",
    "pdfversion",
    "/id",
    "documentid",
    "instanceid",
)


def gs_bin() -> str:
    gs = shutil.which("gs")
    if gs is None:
        raise RuntimeError("Ghostscript (gs) not found on PATH -- required for PDF comparison")
    return gs


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class KnownFinding:
    """An accepted, registered difference that was actually observed."""

    field: str  # dotted JSON path (zip-prefixed once merged into a parent result)
    detail: str  # observed values + the registered pins
    reason: str  # why this difference is accepted (from the registry)


@dataclass
class CompareResult:
    verdict: str  # PASS | DIFF | ERROR
    diffs: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    # Accepted known differences (see known_diffs.py). Reported, never fatal.
    known: list[KnownFinding] = field(default_factory=list)
    # (case, field) registry keys this comparison actually hit -- the driver uses
    # them to spot registry entries that no longer correspond to any difference.
    known_keys: set[tuple[str, str]] = field(default_factory=set)

    @staticmethod
    def error(msg: str) -> "CompareResult":
        return CompareResult(verdict="ERROR", diffs=[msg])

    def merge_child(self, prefix: str, child: "CompareResult") -> None:
        if child.verdict == "ERROR" and self.verdict != "DIFF":
            self.verdict = "ERROR"
        elif child.verdict == "DIFF" and self.verdict != "ERROR":
            self.verdict = "DIFF"
        self.diffs.extend(f"{prefix}: {d}" for d in child.diffs)
        self.info.extend(f"{prefix}: {i}" for i in child.info)
        self.known.extend(KnownFinding(f"{prefix}: {k.field}", k.detail, k.reason) for k in child.known)
        self.known_keys |= child.known_keys


# ---------------------------------------------------------------------------
# PDF helpers (Ghostscript)
# ---------------------------------------------------------------------------
def pdf_page_count(pdf_bytes: bytes) -> int | None:
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp:
        tmp.write(pdf_bytes)
        tmp.flush()
        proc = subprocess.run(
            [
                gs_bin(),
                "-q",
                "-dNODISPLAY",
                "-dNOSAFER",
                "-c",
                f"({tmp.name}) (r) file runpdfbegin pdfpagecount = quit",
            ],
            capture_output=True,
            text=True,
        )
    out = proc.stdout.strip()
    if not out:
        return None
    try:
        return int(out.split()[0])
    except ValueError:
        return None


def render_pdf_pages(pdf_bytes: bytes, dpi: int = RASTER_DPI) -> list[bytes]:
    """Rasterize every page to a raw PPM (P6) via gs. Raises on gs failure."""
    with tempfile.TemporaryDirectory() as td:
        pdf_path = Path(td) / "in.pdf"
        pdf_path.write_bytes(pdf_bytes)
        out_pattern = str(Path(td) / "pg%04d.ppm")
        proc = subprocess.run(
            [
                gs_bin(),
                "-q",
                "-dBATCH",
                "-dNOPAUSE",
                "-dSAFER",
                "-sDEVICE=ppmraw",
                f"-r{dpi}",
                "-dTextAlphaBits=4",
                "-dGraphicsAlphaBits=4",
                f"-sOutputFile={out_pattern}",
                str(pdf_path),
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"gs raster failed: {proc.stderr.strip() or proc.stdout.strip()}")
        pages = sorted(Path(td).glob("pg*.ppm"))
        return [p.read_bytes() for p in pages]


# ---------------------------------------------------------------------------
# PPM parsing + ink-density grid (pure stdlib)
# ---------------------------------------------------------------------------
def parse_ppm(b: bytes) -> tuple[int, int, memoryview]:
    """Parse a binary PPM (P6). Returns (width, height, RGB-pixel-view)."""
    if b[:2] != b"P6":
        raise ValueError("not a P6 PPM")
    idx = 2
    fields: list[int] = []
    while len(fields) < 3:
        while idx < len(b) and b[idx : idx + 1].isspace():
            idx += 1
        if b[idx : idx + 1] == b"#":  # gs writes a comment line
            while idx < len(b) and b[idx : idx + 1] != b"\n":
                idx += 1
            continue
        start = idx
        while idx < len(b) and not b[idx : idx + 1].isspace():
            idx += 1
        fields.append(int(b[start:idx]))
    idx += 1  # single whitespace after maxval
    w, h, _maxval = fields
    return w, h, memoryview(b)[idx : idx + w * h * 3]


def ink_grid(ppm: bytes, cells: int = GRID_CELLS) -> tuple[int, int, list[int]]:
    """Reduce a PPM to an ink-density grid. Returns (w, h, cells*cells ink values)."""
    w, h, data = parse_ppm(ppm)
    g = cells
    colmap = [x * g // w for x in range(w)]
    total = [0] * (g * g)
    count = [0] * (g * g)
    green = data[1::3]  # green channel ~ luminance proxy; cheap and accurate for text
    for y in range(h):
        cy = (y * g // h) * g
        base = y * w
        row = green[base : base + w]
        for x in range(w):
            gi = cy + colmap[x]
            total[gi] += row[x]
            count[gi] += 1
    grid = [255 - (total[i] // count[i]) if count[i] else 0 for i in range(g * g)]
    return w, h, grid


@dataclass
class ImageCompare:
    equal: bool
    detail: str


def compare_images(a_ppm: bytes, b_ppm: bytes) -> ImageCompare:
    if a_ppm == b_ppm:
        return ImageCompare(True, "byte-identical raster")
    wa, ha, ga = ink_grid(a_ppm)
    wb, hb, gb = ink_grid(b_ppm)
    if (wa, ha) != (wb, hb):
        return ImageCompare(False, f"page dimensions differ {wa}x{ha} vs {wb}x{hb}")
    deltas = [abs(x - y) for x, y in zip(ga, gb)]
    sig = sum(1 for d in deltas if d > CELL_DELTA_TOL)
    max_cell = max(deltas)
    mean_cell = sum(deltas) / len(deltas)
    limit = _sig_cells_max()
    equal = sig <= limit
    detail = (
        f"grid {GRID_CELLS}x{GRID_CELLS}: significant-cells={sig} (limit {limit}, "
        f"tol {CELL_DELTA_TOL}), max-cell-delta={max_cell}, mean-cell-delta={mean_cell:.3f}"
    )
    return ImageCompare(equal, detail)


# ---------------------------------------------------------------------------
# PDF compare
# ---------------------------------------------------------------------------
def compare_pdf(rust: bytes, java: bytes, dpi: int = RASTER_DPI) -> CompareResult:
    result = CompareResult(verdict="PASS")
    rc = pdf_page_count(rust)
    jc = pdf_page_count(java)
    if rc is None or jc is None:
        return CompareResult.error(
            f"could not read page count (rust={rc}, java={jc}); is the body a valid PDF?"
        )
    if rc != jc:
        result.verdict = "DIFF"
        result.diffs.append(f"page count differs: rust={rc}, java={jc}")
        return result  # per-page compare is meaningless once counts diverge

    try:
        rust_pages = render_pdf_pages(rust, dpi)
        java_pages = render_pdf_pages(java, dpi)
    except RuntimeError as exc:
        return CompareResult.error(f"raster failed: {exc}")

    if len(rust_pages) != len(java_pages):
        result.verdict = "DIFF"
        result.diffs.append(
            f"rendered page count differs: rust={len(rust_pages)}, java={len(java_pages)}"
        )
        return result

    for idx, (rp, jp) in enumerate(zip(rust_pages, java_pages), start=1):
        cmp = compare_images(rp, jp)
        if not cmp.equal:
            result.verdict = "DIFF"
            result.diffs.append(f"page {idx} visual mismatch: {cmp.detail}")
        else:
            result.info.append(f"page {idx} ok: {cmp.detail}")
    result.info.append(f"page count match: {rc}")
    return result


# ---------------------------------------------------------------------------
# JSON compare
# ---------------------------------------------------------------------------
def _is_informational(path: str, leaf: str) -> bool:
    path_l = path.lower()
    leaf_l = leaf.lower()
    return any(tok in leaf_l or tok in path_l for tok in INFORMATIONAL_JSON_KEYS)


def _walk_json(rust, java, path: str, out: CompareResult, case: str | None) -> None:
    if isinstance(rust, dict) and isinstance(java, dict):
        for key in sorted(set(rust) | set(java), key=str):
            child_path = f"{path}.{key}" if path else str(key)
            if key not in rust:
                _record(child_path, str(key), "<missing in rust>", java[key], out, case)
            elif key not in java:
                _record(child_path, str(key), rust[key], "<missing in java>", out, case)
            else:
                _walk_json(rust[key], java[key], child_path, out, case)
    elif isinstance(rust, list) and isinstance(java, list):
        if len(rust) != len(java):
            out.diffs.append(f"{path or '<root>'}: list length rust={len(rust)} java={len(java)}")
        for i, (r, j) in enumerate(zip(rust, java)):
            _walk_json(r, j, f"{path}[{i}]", out, case)
    else:
        if rust != java:
            leaf = path.rsplit(".", 1)[-1].split("[")[0]
            _record(path or "<root>", leaf, rust, java, out, case)


def _short(value, limit: int = 110) -> str:
    """repr() capped for report lines -- an XMP packet is kilobytes long."""
    text = repr(value)
    return text if len(text) <= limit else f"{text[:limit]}...({len(text)} chars)"


def _record(path: str, leaf: str, rust_val, java_val, out: CompareResult, case: str | None) -> None:
    line = f"{path}: rust={rust_val!r} java={java_val!r}"

    # The registry is checked FIRST: an explicit (case, field) entry is more
    # specific than the generic informational key heuristic, and routing a
    # registered field to `info` would make it look permanently stale.
    verdict = known_diffs.classify(case, path, rust_val, java_val)
    if verdict.entry is not None:
        out.known_keys.add(verdict.entry.key)
        if verdict.kind == known_diffs.KNOWN:
            pins = verdict.entry.pins_text() if verdict.entry.pinned else "UNPINNED"
            out.known.append(
                KnownFinding(
                    field=path,
                    detail=f"rust={_short(rust_val)} java={_short(java_val)} [{pins}]",
                    reason=verdict.entry.reason,
                )
            )
        else:  # PIN_MISMATCH -> a real DIFF, the expectation itself has rotted
            out.diffs.append(f"{line} -- {verdict.message}")
        return

    if _is_informational(path, leaf):
        out.info.append("(informational) " + line)
    else:
        out.diffs.append(line)


def compare_json(rust: bytes, java: bytes, case: str | None = None) -> CompareResult:
    """Deep-compare two JSON bodies.

    ``case`` enables known-difference classification for this case's registry
    entries; without it every difference is a plain DIFF (previous behaviour).
    """
    try:
        rj = json.loads(rust.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return CompareResult.error(f"rust body is not valid JSON: {exc}")
    try:
        jj = json.loads(java.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return CompareResult.error(f"java body is not valid JSON: {exc}")
    result = CompareResult(verdict="PASS")
    _walk_json(rj, jj, "", result, case)
    result.verdict = "DIFF" if result.diffs else "PASS"
    return result


# ---------------------------------------------------------------------------
# ZIP compare
# ---------------------------------------------------------------------------
def _sniff_kind(name: str, data: bytes) -> str:
    lower = name.lower()
    if lower.endswith(".pdf") or data[:5] == b"%PDF-":
        return "pdf"
    if lower.endswith(".json"):
        return "json"
    if data.lstrip()[:1] in (b"{", b"["):
        return "json"
    return "bytes"


def _normalize_names(names: list[str]) -> list[str]:
    # Compare on basename to tolerate harmless path-prefix differences.
    return [n.rsplit("/", 1)[-1] for n in names if not n.endswith("/")]


def _orig_name(zf: zipfile.ZipFile, basename: str) -> str:
    for n in zf.namelist():
        if n.rsplit("/", 1)[-1] == basename:
            return n
    return basename


def compare_zip(rust: bytes, java: bytes, case: str | None = None) -> CompareResult:
    try:
        rz = zipfile.ZipFile(io.BytesIO(rust))
    except Exception as exc:  # noqa: BLE001
        return CompareResult.error(f"rust body is not a valid zip: {exc}")
    try:
        jz = zipfile.ZipFile(io.BytesIO(java))
    except Exception as exc:  # noqa: BLE001
        return CompareResult.error(f"java body is not a valid zip: {exc}")

    result = CompareResult(verdict="PASS")
    rnames = _normalize_names(rz.namelist())
    jnames = _normalize_names(jz.namelist())
    if set(rnames) != set(jnames):
        result.verdict = "DIFF"
        only_rust = sorted(set(rnames) - set(jnames))
        only_java = sorted(set(jnames) - set(rnames))
        if only_rust:
            result.diffs.append(f"entries only in rust: {only_rust}")
        if only_java:
            result.diffs.append(f"entries only in java: {only_java}")
    result.info.append(f"entry count: rust={len(rnames)}, java={len(jnames)}")

    for name in sorted(set(rnames) & set(jnames)):
        rdata = rz.read(_orig_name(rz, name))
        jdata = jz.read(_orig_name(jz, name))
        kind = _sniff_kind(name, rdata)
        if kind == "pdf":
            child = compare_pdf(rdata, jdata)
        elif kind == "json":
            # Registry field paths are relative to the zip member.
            child = compare_json(rdata, jdata, case)
        else:
            child = _compare_bytes(rdata, jdata)
        result.merge_child(f"entry[{name}]", child)
    return result


def _compare_bytes(rust: bytes, java: bytes) -> CompareResult:
    if rust == java:
        return CompareResult(verdict="PASS", info=["byte-identical"])
    return CompareResult(
        verdict="DIFF",
        diffs=[f"opaque bytes differ (rust={len(rust)}B, java={len(java)}B)"],
    )


# ---------------------------------------------------------------------------
# Single-backend validation (rust-only smoke)
# ---------------------------------------------------------------------------
def validate_artifact(body: bytes, response_type: str) -> CompareResult:
    """Confirm a single backend produced a well-formed artifact of the declared type."""
    if response_type == "json":
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            return CompareResult.error(f"not valid JSON: {exc}")
        keys = list(parsed.keys()) if isinstance(parsed, dict) else f"<{type(parsed).__name__}>"
        return CompareResult(verdict="PASS", info=[f"valid JSON, top-level keys: {keys}"])
    if response_type == "pdf":
        if body[:5] != b"%PDF-":
            return CompareResult.error("body does not start with %PDF-")
        count = pdf_page_count(body)
        if count is None or count < 1:
            return CompareResult.error(f"could not read a valid page count ({count})")
        return CompareResult(verdict="PASS", info=[f"valid PDF, {count} page(s)"])
    if response_type == "zip":
        try:
            zf = zipfile.ZipFile(io.BytesIO(body))
        except Exception as exc:  # noqa: BLE001
            return CompareResult.error(f"not a valid zip: {exc}")
        entries = _normalize_names(zf.namelist())
        if not entries:
            return CompareResult.error("zip has no file entries")
        problems = []
        for name in entries:
            data = zf.read(_orig_name(zf, name))
            kind = _sniff_kind(name, data)
            if kind == "pdf":
                if pdf_page_count(data) is None:
                    problems.append(f"{name}: not a readable PDF")
            elif kind == "json":
                try:
                    json.loads(data.decode("utf-8"))
                except Exception as exc:  # noqa: BLE001
                    problems.append(f"{name}: bad JSON ({exc})")
        if problems:
            return CompareResult.error("; ".join(problems))
        return CompareResult(verdict="PASS", info=[f"valid zip, entries: {entries}"])
    return CompareResult.error(f"unknown response_type {response_type!r}")


def capabilities() -> str:
    return (
        f"gs={shutil.which('gs') or 'MISSING'}, "
        f"raster=ppmraw@{RASTER_DPI}dpi, "
        f"grid={GRID_CELLS}x{GRID_CELLS} tol={CELL_DELTA_TOL} sig-max={_sig_cells_max()}"
    )
