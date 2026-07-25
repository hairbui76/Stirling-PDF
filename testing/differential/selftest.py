#!/usr/bin/env python3
"""Self-test for the differential *compare engine* (not a backend parity run).

This drives the live Rust backend to synthesize known-different and
known-equivalent artifact pairs, then asserts the comparison engine reaches the
right verdict for each. It is what proves the harness can actually TELL PASS from
DIFF -- including the two properties that matter most:

  * a genuine cross-producer, same-content pair (original file vs the same page
    round-tripped through the backend) must compare PASS -- i.e. serializer /
    metadata differences do NOT create false DIFFs; and
  * real content changes (rotation, page count, page size, different pages,
    changed JSON counts, changed zip entry sets) must compare DIFF.

Run against the live Rust backend:
    python3 selftest.py --rust-url http://localhost:8091
Exits non-zero if any engine assertion fails.
"""

from __future__ import annotations

import argparse
import json
import sys

import compare
import fixtures
import httpclient


class _Backend:
    def __init__(self, base: str, timeout: float = 120.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def post(self, path: str, files: list[tuple[str, str]], params: dict[str, str]) -> bytes:
        res = httpclient.post_multipart(
            self.base + path,
            fields=params,
            files=[(fn, fixtures.resolve(k)) for fn, k in files],
            timeout=self.timeout,
        )
        if not res.reached:
            raise RuntimeError(f"POST {path} unreachable: {res.error}")
        if not res.ok:
            raise RuntimeError(f"POST {path} -> {res.status}: {res.body[:200]!r}")
        return res.body


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-url", default="http://localhost:8091")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    problems = fixtures.ensure_fixtures()
    if problems:
        for p in problems:
            print("FIXTURE PROBLEM:", p, file=sys.stderr)
        return 2

    be = _Backend(args.rust_url, args.timeout)
    health = httpclient.get(be.base + "/api/v1/info/status", timeout=8.0)
    if not health.reached:
        print(f"Rust backend unreachable at {be.base}: {health.error}", file=sys.stderr)
        return 2

    single = fixtures.SINGLE_LETTER.key
    single2 = fixtures.SINGLE_2.key
    mp5 = fixtures.MULTIPAGE_5.key

    print(f"compare engine: {compare.capabilities()}")
    print(f"driving backend: {be.base}\n")

    # Synthesize artifacts from the live backend.
    orig = fixtures.resolve(single).read_bytes()
    roundtrip = be.post("/api/v1/general/rearrange-pages", [("fileInput", single)], {"pageNumbers": "1"})
    rot90 = be.post("/api/v1/general/rotate-pdf", [("fileInput", single)], {"angle": "90"})
    rot270 = be.post("/api/v1/general/rotate-pdf", [("fileInput", single)], {"angle": "270"})
    merged = be.post("/api/v1/general/merge-pdfs", [("fileInput", single), ("fileInput", single2)], {})
    scaled = be.post("/api/v1/general/scale-pages", [("fileInput", single)], {"pageSize": "A4", "scaleFactor": "1.0"})
    split24 = be.post("/api/v1/general/split-pages", [("fileInput", mp5)], {"pageNumbers": "2,4"})
    split3 = be.post("/api/v1/general/split-pages", [("fileInput", mp5)], {"pageNumbers": "3"})
    info1 = be.post("/api/v1/security/get-info-on-pdf", [("fileInput", single)], {})
    info5 = be.post("/api/v1/security/get-info-on-pdf", [("fileInput", mp5)], {})

    passed = failed = 0

    def check(label: str, got: str, want: str, extra: str = "") -> None:
        nonlocal passed, failed
        ok = got == want
        passed += ok
        failed += not ok
        mark = "OK " if ok else "XX "
        print(f"[{mark}] {label}: {got}" + (f"  {extra}" if (extra and not ok) else ""))

    # --- PDF: cross-producer same-content must PASS (the key false-positive guard)
    r = compare.compare_pdf(orig, roundtrip)
    check("PDF same-content/different-producer -> PASS", r.verdict, "PASS", str(r.diffs))
    # --- PDF: real content / geometry / count differences must DIFF
    check("PDF 180-degree rotation -> DIFF", compare.compare_pdf(rot90, rot270).verdict, "DIFF")
    check("PDF page-count diff -> DIFF", compare.compare_pdf(orig, merged).verdict, "DIFF")
    check("PDF page-size diff -> DIFF", compare.compare_pdf(orig, scaled).verdict, "DIFF")
    check("PDF identical -> PASS", compare.compare_pdf(orig, orig).verdict, "PASS")

    # --- JSON
    check("JSON count diff -> DIFF", compare.compare_json(info1, info5).verdict, "DIFF")
    j = json.loads(info1)
    j["BasicInfo"]["FileSizeInBytes"] = 10**9
    j.setdefault("Metadata", {})["CreationDate"] = "D:19990101"
    j["DocumentInfo"]["PDF version"] = "9.9"
    check("JSON size/date/version-only diff -> PASS", compare.compare_json(info1, json.dumps(j).encode()).verdict, "PASS")
    j2 = json.loads(info1)
    j2["BasicInfo"]["WordCount"] += 7
    check("JSON WordCount diff -> DIFF", compare.compare_json(info1, json.dumps(j2).encode()).verdict, "DIFF")

    # --- ZIP
    check("ZIP identical -> PASS", compare.compare_zip(split24, split24).verdict, "PASS")
    check("ZIP different entry set -> DIFF", compare.compare_zip(split24, split3).verdict, "DIFF")

    # --- artifact validation
    check("validate garbage-as-pdf -> ERROR", compare.validate_artifact(b"nope", "pdf").verdict, "ERROR")
    check("validate real pdf -> PASS", compare.validate_artifact(orig, "pdf").verdict, "PASS")
    check("validate real zip -> PASS", compare.validate_artifact(split24, "zip").verdict, "PASS")
    check("validate real json -> PASS", compare.validate_artifact(info1, "json").verdict, "PASS")

    print(f"\nSELF-TEST: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
