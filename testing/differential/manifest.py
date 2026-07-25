"""Deterministic differential-test cases.

Scope is deliberately narrow: only operations that run with the tools available
in *both* a minimal Rust host and a JDK-25 Java host WITHOUT the heavy native
toolchain -- i.e. pdfium / lopdf / Ghostscript page-geometry ops and pure PDF
JSON reads. Converters, OCR, repair, compression-via-qpdf, signing, and anything
needing LibreOffice / Tesseract / WeasyPrint / Calibre / ffmpeg are intentionally
excluded: they are non-deterministic and/or unavailable, so they cannot yield a
meaningful Java-vs-Rust parity verdict here.

Every field name below was read out of the live Rust multipart handlers in
``rust/crates/stirling-processing/src/lib.rs`` (see the request parsers:
read_rotate_request, read_page_numbers_request, read_rearrange_pages_request,
read_scale_pages_request, read_crop_request, read_remove_blanks_request,
read_multipart_request, get_info_on_pdf). They are the same @ModelAttribute names
the Java controllers bind, so one multipart body drives both backends.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import fixtures


@dataclass(frozen=True)
class Case:
    name: str
    path: str
    response_type: str  # pdf | zip | json
    files: list[tuple[str, str]]  # (form field name, fixture key)
    params: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    method: str = "POST"
    note: str = ""

    def resolved_files(self):
        return [(field_name, fixtures.resolve(key)) for field_name, key in self.files]


SINGLE = fixtures.SINGLE_LETTER.key
SINGLE2 = fixtures.SINGLE_2.key
CROP = fixtures.CROP_SRC.key
MP5 = fixtures.MULTIPAGE_5.key


CASES: list[Case] = [
    # ---- page-geometry ops that return a single PDF --------------------------
    Case(
        name="rotate_90",
        path="/api/v1/general/rotate-pdf",
        response_type="pdf",
        files=[("fileInput", SINGLE)],
        params={"angle": "90"},
        note="rotate a 1-page pdf by 90 degrees",
    ),
    Case(
        name="rotate_270",
        path="/api/v1/general/rotate-pdf",
        response_type="pdf",
        files=[("fileInput", SINGLE)],
        params={"angle": "270"},
    ),
    Case(
        name="merge_two",
        path="/api/v1/general/merge-pdfs",
        response_type="pdf",
        files=[("fileInput", SINGLE), ("fileInput", SINGLE2)],
        note="merge two 1-page pdfs -> expect a 2-page pdf",
    ),
    Case(
        name="rearrange_reverse",
        path="/api/v1/general/rearrange-pages",
        response_type="pdf",
        files=[("fileInput", MP5)],
        params={"pageNumbers": "5,4,3,2,1"},
        note="explicit reverse-order rearrange of the 5-page fixture",
    ),
    Case(
        name="remove_pages_2_4",
        path="/api/v1/general/remove-pages",
        response_type="pdf",
        files=[("fileInput", MP5)],
        params={"pageNumbers": "2,4"},
        note="drop pages 2 and 4 -> expect 3 pages (1,3,5)",
    ),
    Case(
        name="scale_a4",
        path="/api/v1/general/scale-pages",
        response_type="pdf",
        files=[("fileInput", SINGLE)],
        params={"pageSize": "A4", "orientation": "PORTRAIT", "scaleFactor": "1.0"},
        note="reflow a Letter page onto A4",
    ),
    Case(
        name="scale_keep_2x",
        path="/api/v1/general/scale-pages",
        response_type="pdf",
        files=[("fileInput", SINGLE)],
        params={"pageSize": "KEEP", "scaleFactor": "2.0"},
        note="keep page size, scale content 2x",
    ),
    Case(
        name="crop_box",
        path="/api/v1/general/crop",
        response_type="pdf",
        files=[("fileInput", CROP)],
        params={"x": "50", "y": "50", "width": "300", "height": "400"},
        note="crop a fixed box out of crop_test.pdf (mediabox 499.9x631.99)",
    ),
    Case(
        name="to_single_page",
        path="/api/v1/general/pdf-to-single-page",
        response_type="pdf",
        files=[("fileInput", MP5)],
        note="stack the 5-page fixture into one tall page",
    ),
    # ---- ops that return a ZIP ----------------------------------------------
    Case(
        name="split_after_2_4",
        path="/api/v1/general/split-pages",
        response_type="zip",
        files=[("fileInput", MP5)],
        params={"pageNumbers": "2,4"},
        note="split after pages 2 and 4 -> 3 zip members (1-2, 3-4, 5)",
    ),
    Case(
        name="remove_blank_pages",
        path="/api/v1/misc/remove-blanks",
        response_type="zip",
        files=[("fileInput", MP5)],
        params={"threshold": "10", "whitePercent": "99.9"},
        note="none of the fixture pages are blank -> all pages retained",
    ),
    # ---- pure JSON reads -----------------------------------------------------
    Case(
        name="get_info_single",
        path="/api/v1/security/get-info-on-pdf",
        response_type="json",
        files=[("fileInput", SINGLE)],
        note="counts (pages/words/chars) must match; size/dates informational",
    ),
    Case(
        name="get_info_multipage",
        path="/api/v1/security/get-info-on-pdf",
        response_type="json",
        files=[("fileInput", MP5)],
    ),
]


def by_name(pattern: str | None) -> list[Case]:
    if not pattern:
        return list(CASES)
    return [c for c in CASES if pattern in c.name]


if __name__ == "__main__":
    for c in CASES:
        files = ",".join(f"{fn}:{k}" for fn, k in c.files)
        print(f"{c.name:22} {c.response_type:4} {c.path:38} [{files}] {c.params}")
