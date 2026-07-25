"""Fixture resolution for the differential harness.

Fixtures are the *inputs* uploaded (byte-for-byte identically) to both the Rust
and Java backends. Most come straight from the committed ``testing/*.pdf`` files.
Multi-page operations (split / rearrange / remove-pages / to-single-page) need a
deterministic multi-page PDF, which we generate once with Ghostscript into
``testing/differential/_generated/`` and then reuse.

Determinism notes:
- The generated multi-page PDF is created once and cached on disk. Within a
  single harness run the exact same file bytes are posted to both backends, so
  the volatile ``/CreationDate`` Ghostscript stamps into it is irrelevant to
  parity (both sides ingest identical input).
- We never regenerate an existing fixture, so results are reproducible across
  runs on the same machine.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
# testing/differential -> testing -> repo root
REPO_ROOT = HERE.parent.parent
TESTING_DIR = REPO_ROOT / "testing"
FIXTURE_DIR = HERE / "_generated"


@dataclass(frozen=True)
class Fixture:
    key: str
    path: Path
    pages: int
    note: str


def _committed(name: str, pages: int, note: str) -> Fixture:
    return Fixture(key=name, path=TESTING_DIR / name, pages=pages, note=note)


# Committed single-page inputs (mediaboxes verified via gs):
#   test_pdf_1.pdf -> [0 0 612 792] (US Letter), 1 page, small text
#   crop_test.pdf  -> [0 0 499.9 631.99], 1 page
SINGLE_LETTER = _committed("test_pdf_1.pdf", 1, "1-page US-Letter text pdf")
SINGLE_2 = _committed("test_pdf_2.pdf", 1, "1-page text pdf")
SINGLE_3 = _committed("test_pdf_3.pdf", 1, "1-page text pdf")
CROP_SRC = _committed("crop_test.pdf", 1, "1-page pdf, mediabox 499.9x631.99")

# Generated multi-page input.
MULTIPAGE_5 = Fixture(
    key="multipage_5.pdf",
    path=FIXTURE_DIR / "multipage_5.pdf",
    pages=5,
    note="generated 5-page US-Letter pdf, one big 'Page N' per page",
)

_COMMITTED = [SINGLE_LETTER, SINGLE_2, SINGLE_3, CROP_SRC]
_GENERATED = [MULTIPAGE_5]

BY_KEY = {f.key: f for f in (_COMMITTED + _GENERATED)}


def _postscript_for_pages(pages: int) -> str:
    lines = [
        "/drawpage { /n exch def",
        "  /Helvetica findfont 120 scalefont setfont",
        "  72 400 moveto (Page ) show n 3 string cvs show",
        "  showpage } def",
    ]
    lines.append(" ".join(f"{i} drawpage" for i in range(1, pages + 1)))
    return "\n".join(lines) + "\n"


def _generate_multipage(fx: Fixture, pages: int) -> None:
    gs = shutil.which("gs")
    if gs is None:
        raise RuntimeError(
            "Ghostscript (gs) is required to generate the multi-page fixture "
            f"{fx.path}; install it or provide the file manually."
        )
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    ps_path = FIXTURE_DIR / f".{fx.key}.gen.ps"
    ps_path.write_text(_postscript_for_pages(pages))
    try:
        subprocess.run(
            [
                gs,
                "-q",
                "-dBATCH",
                "-dNOPAUSE",
                "-sDEVICE=pdfwrite",
                f"-sOutputFile={fx.path}",
                "-dDEVICEWIDTHPOINTS=612",
                "-dDEVICEHEIGHTPOINTS=792",
                "-dFIXEDMEDIA",
                str(ps_path),
            ],
            check=True,
            capture_output=True,
        )
    finally:
        ps_path.unlink(missing_ok=True)
    if not fx.path.exists():
        raise RuntimeError(f"failed to generate fixture {fx.path}")


def ensure_fixtures() -> list[str]:
    """Make sure every fixture exists on disk. Returns list of problems (empty=OK)."""
    problems: list[str] = []
    for fx in _COMMITTED:
        if not fx.path.exists():
            problems.append(f"missing committed fixture: {fx.path}")
    for fx in _GENERATED:
        if not fx.path.exists():
            try:
                _generate_multipage(fx, fx.pages)
            except Exception as exc:  # noqa: BLE001 - surfaced to caller
                problems.append(str(exc))
    return problems


def resolve(key: str) -> Path:
    fx = BY_KEY.get(key)
    if fx is None:
        raise KeyError(f"unknown fixture key: {key!r}")
    return fx.path


if __name__ == "__main__":
    issues = ensure_fixtures()
    if issues:
        for line in issues:
            print("PROBLEM:", line)
        raise SystemExit(1)
    for fixture in BY_KEY.values():
        print(f"{fixture.key:20} {fixture.pages}p  {fixture.path}")
