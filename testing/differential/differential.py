#!/usr/bin/env python3
"""Java-vs-Rust differential test harness for Stirling-PDF.

Posts the SAME input to the Rust backend (required) and the Java backend
(optional) and semantically compares the outputs, reporting per-case parity.

Modes
-----
--rust-only   Drive + validate the Rust backend alone. Every case is POSTed and
              its response checked for a well-formed artifact (PDF parses / zip
              opens / JSON parses) and a 2xx status. This is the mode that runs
              in THIS sandbox, where no Java bootJar/toolchain exists.

--diff        Post to both backends and semantically diff. Requires --java-url.
              If the Java backend is unreachable for a case, that case is
              SKIP-java-absent (not a failure). Any real semantic DIFF makes the
              process exit non-zero.

Auto: if --java-url is given, defaults to --diff; otherwise --rust-only.

Examples
--------
  # here, against the live Rust backend on 8091
  python3 differential.py --rust-url http://localhost:8091 --rust-only

  # in a JDK-25 + tools CI host, full parity
  python3 differential.py \
      --rust-url http://localhost:8091 \
      --java-url http://localhost:8080 --diff
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

import compare
import fixtures
import httpclient
import manifest

RESET = "\033[0m"
COLORS = {
    "PASS": "\033[32m",
    "DIFF": "\033[31m",
    "ERROR": "\033[31m",
    "SKIP": "\033[33m",
    "SKIP-java-absent": "\033[33m",
    "head": "\033[1m",
}


def _c(tag: str, text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS.get(tag, '')}{text}{RESET}"


CONTENT_TYPE_FOR = {
    "pdf": "application/pdf",
    "zip": "application/zip",
    "json": "application/json",
}


@dataclass
class CaseOutcome:
    name: str
    status: str  # PASS | DIFF | ERROR | SKIP-java-absent
    rust_status: int | None
    java_status: int | None
    messages: list[str]


def _probe(url: str) -> httpclient.HttpResult:
    return httpclient.get(url.rstrip("/") + "/api/v1/info/status", timeout=8.0)


def _content_type_note(case: manifest.Case, res: httpclient.HttpResult) -> str | None:
    expected = CONTENT_TYPE_FOR.get(case.response_type)
    got = res.content_type
    if expected and got and got != expected:
        return f"content-type {got!r} (expected {expected!r})"
    return None


def run_rust_only(case: manifest.Case, rust_url: str, timeout: float) -> CaseOutcome:
    res = httpclient.post_multipart(
        rust_url.rstrip("/") + case.path,
        fields=dict(case.params),
        files=case.resolved_files(),
        query=dict(case.query),
        timeout=timeout,
    )
    if not res.reached:
        return CaseOutcome(case.name, "ERROR", None, None, [f"rust unreachable: {res.error}"])
    msgs: list[str] = [f"rust {res.status} {res.content_type} {len(res.body)}B {res.elapsed:.2f}s"]
    if not res.ok:
        snippet = res.body[:200].decode("utf-8", "replace")
        return CaseOutcome(case.name, "ERROR", res.status, None, msgs + [f"non-2xx body: {snippet}"])
    ct_note = _content_type_note(case, res)
    if ct_note:
        msgs.append(ct_note)
    verdict = compare.validate_artifact(res.body, case.response_type)
    msgs.extend(verdict.info)
    if verdict.verdict == "ERROR":
        return CaseOutcome(case.name, "ERROR", res.status, None, msgs + verdict.diffs)
    return CaseOutcome(case.name, "PASS", res.status, None, msgs)


def run_diff(case: manifest.Case, rust_url: str, java_url: str, timeout: float) -> CaseOutcome:
    rust = httpclient.post_multipart(
        rust_url.rstrip("/") + case.path,
        fields=dict(case.params),
        files=case.resolved_files(),
        query=dict(case.query),
        timeout=timeout,
    )
    if not rust.reached:
        return CaseOutcome(case.name, "ERROR", None, None, [f"rust unreachable: {rust.error}"])

    java = httpclient.post_multipart(
        java_url.rstrip("/") + case.path,
        fields=dict(case.params),
        files=case.resolved_files(),
        query=dict(case.query),
        timeout=timeout,
    )
    if not java.reached:
        return CaseOutcome(
            case.name,
            "SKIP-java-absent",
            rust.status,
            None,
            [f"rust {rust.status}; java unreachable: {java.error}"],
        )

    msgs = [
        f"rust {rust.status} {rust.content_type} {len(rust.body)}B / "
        f"java {java.status} {java.content_type} {len(java.body)}B"
    ]

    # Status-code compare.
    if rust.status != java.status:
        msgs.append(f"STATUS MISMATCH rust={rust.status} java={java.status}")
        # differing status is itself a real diff; still try to compare bodies below
        status_diff = True
    else:
        status_diff = False

    # If both errored the same way, that's parity (both refuse identically).
    if not rust.ok and not java.ok:
        outcome = "DIFF" if status_diff else "PASS"
        msgs.append("both non-2xx" + ("" if status_diff else " with matching status"))
        return CaseOutcome(case.name, outcome, rust.status, java.status, msgs)
    if rust.ok != java.ok:
        return CaseOutcome(
            case.name, "DIFF", rust.status, java.status,
            msgs + [f"one backend succeeded and the other did not (rust ok={rust.ok}, java ok={java.ok})"],
        )

    # Both 2xx -> semantic body compare.
    if case.response_type == "pdf":
        cmp = compare.compare_pdf(rust.body, java.body)
    elif case.response_type == "zip":
        cmp = compare.compare_zip(rust.body, java.body)
    elif case.response_type == "json":
        cmp = compare.compare_json(rust.body, java.body)
    else:
        cmp = compare.CompareResult.error(f"unknown response_type {case.response_type!r}")

    msgs.extend(cmp.info)
    msgs.extend(f"DIFF> {d}" for d in cmp.diffs)
    verdict = cmp.verdict
    if status_diff and verdict == "PASS":
        verdict = "DIFF"
    return CaseOutcome(case.name, verdict, rust.status, java.status, msgs)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rust-url", default="http://localhost:8091", help="Rust backend base URL (required)")
    parser.add_argument("--java-url", default=None, help="Java backend base URL (enables --diff)")
    parser.add_argument("--rust-only", action="store_true", help="capture/validate the Rust backend only")
    parser.add_argument("--diff", action="store_true", help="diff Rust vs Java (needs --java-url)")
    parser.add_argument("--filter", default=None, help="only run cases whose name contains this substring")
    parser.add_argument("--timeout", type=float, default=300.0, help="per-request timeout seconds")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color")
    parser.add_argument("--verbose", "-v", action="store_true", help="print all per-case messages")
    parser.add_argument("--list", action="store_true", help="list cases and exit")
    args = parser.parse_args(argv)

    color = sys.stdout.isatty() and not args.no_color

    if args.list:
        for c in manifest.CASES:
            print(f"{c.name:24} {c.response_type:4} {c.path}")
        return 0

    # Mode resolution.
    if args.rust_only and args.diff:
        print("error: choose one of --rust-only / --diff", file=sys.stderr)
        return 2
    if args.diff and not args.java_url:
        print("error: --diff requires --java-url", file=sys.stderr)
        return 2
    if not args.rust_only and not args.diff:
        mode = "diff" if args.java_url else "rust-only"
    else:
        mode = "diff" if args.diff else "rust-only"

    # Fixtures.
    problems = fixtures.ensure_fixtures()
    if problems:
        for p in problems:
            print(f"FIXTURE PROBLEM: {p}", file=sys.stderr)
        return 2

    print(_c("head", f"Stirling-PDF differential harness  [mode={mode}]", color))
    print(f"  http backend : {httpclient.backend()}")
    print(f"  compare tools: {compare.capabilities()}")
    print(f"  rust-url     : {args.rust_url}")
    if mode == "diff":
        print(f"  java-url     : {args.java_url}")

    # Health probes.
    rp = _probe(args.rust_url)
    print(f"  rust health  : {'OK ' + str(rp.status) if rp.reached else 'UNREACHABLE (' + str(rp.error) + ')'}")
    if not rp.reached:
        print("error: Rust backend is required and is unreachable", file=sys.stderr)
        return 2
    if mode == "diff":
        jp = _probe(args.java_url)
        print(f"  java health  : {'OK ' + str(jp.status) if jp.reached else 'UNREACHABLE (' + str(jp.error) + ')'}")

    cases = manifest.by_name(args.filter)
    print(f"  cases        : {len(cases)}")
    print("-" * 72)

    outcomes: list[CaseOutcome] = []
    for case in cases:
        if mode == "rust-only":
            outcome = run_rust_only(case, args.rust_url, args.timeout)
        else:
            outcome = run_diff(case, args.rust_url, args.java_url, args.timeout)
        outcomes.append(outcome)
        tag = outcome.status
        print(f"{_c(tag, tag.ljust(16), color)} {outcome.name}")
        show = args.verbose or outcome.status in ("DIFF", "ERROR")
        if show:
            for m in outcome.messages:
                print(f"    {m}")

    # Summary.
    print("-" * 72)
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.status] = counts.get(o.status, 0) + 1
    summary = "  ".join(f"{_c(k, k, color)}={v}" for k, v in sorted(counts.items()))
    print(f"SUMMARY  {summary}  (total {len(outcomes)})")

    real_diffs = [o for o in outcomes if o.status in ("DIFF", "ERROR")]
    if real_diffs:
        print(_c("DIFF", f"FAIL: {len(real_diffs)} case(s) with DIFF/ERROR", color))
        return 1
    print(_c("PASS", "OK: no parity differences", color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
