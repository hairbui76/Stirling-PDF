"""Registry of KNOWN, accepted Java-vs-Rust differences.

A permanently-red gate is a worthless gate: it trains everyone to ignore the
report, and the next *real* regression slips through with the noise. But simply
deleting a field from the comparison is worse -- it blinds the gate forever.

This module is the middle path. Each entry declares one (case, field path) pair
that is *known* to differ, why it differs, and -- when the values are stable --
exactly which values are expected on each side. Classification then splits a raw
field difference three ways:

===================  =================================================  =======
observed             classification                                     fails?
===================  =================================================  =======
not in the registry  DIFF (unchanged behaviour)                          yes
registered, values   KNOWN -- printed as ``KNOWN>`` in the report, kept
match the pins       visible in the per-case marker and the summary       no
registered, pinned   DIFF, flagged as a stale known-difference
values NO LONGER     expectation: something moved on one of the two
match                backends and nobody has re-verified it              yes
===================  =================================================  =======

And the fourth state, detected by the *driver* after the compare (see
``stale_entries``): a registered field that does **not** differ any more. That is
reported as ``STALE>`` plus a summary warning so the entry gets deleted, but it
does **not** fail the run -- a Rust fix that closes a known gap must never break
the build for the person who fixed it.

Rules for adding an entry
-------------------------
* ``reason`` is mandatory and must explain the *root cause*, not restate the
  symptom. "counts differ" is not a reason; "Java's PDFTextStripper runs with
  sortByPosition=false" is.
* PIN the values (``expect_rust`` / ``expect_java``) whenever they are
  deterministic. A pinned entry is regression-proof: it accepts exactly the
  difference that was analysed and nothing else. Leaving a value ``UNPINNED``
  accepts *any* difference in that field and must be justified in the reason.
* Each side is pinned independently, so a field whose Rust value is stable but
  whose Java value drifts can still pin the Rust half.

``field`` is the dotted JSON path exactly as the comparison reports it
(e.g. ``BasicInfo.CharacterCount``). For JSON nested inside a ZIP member the path
is relative to that member.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Classification kinds returned by classify().
KNOWN = "KNOWN"
PIN_MISMATCH = "PIN_MISMATCH"
UNREGISTERED = "UNREGISTERED"


class _Unpinned:
    """Sentinel: this side's value is deliberately not pinned."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "<unpinned>"


UNPINNED = _Unpinned()


@dataclass(frozen=True)
class KnownDiff:
    case: str
    field: str
    reason: str
    expect_rust: Any = UNPINNED
    expect_java: Any = UNPINNED

    @property
    def key(self) -> tuple[str, str]:
        return (self.case, self.field)

    @property
    def pinned(self) -> bool:
        return not (isinstance(self.expect_rust, _Unpinned) and isinstance(self.expect_java, _Unpinned))

    def pins_text(self) -> str:
        return f"expect_rust={self.expect_rust!r} expect_java={self.expect_java!r}"

    def matches(self, rust_val: Any, java_val: Any) -> bool:
        """True if the observed pair satisfies whichever side(s) are pinned."""
        if not isinstance(self.expect_rust, _Unpinned) and rust_val != self.expect_rust:
            return False
        if not isinstance(self.expect_java, _Unpinned) and java_val != self.expect_java:
            return False
        return True


@dataclass(frozen=True)
class Classification:
    kind: str  # KNOWN | PIN_MISMATCH | UNREGISTERED
    entry: KnownDiff | None
    message: str


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
_TEXT_STRIPPER_REASON = (
    "Java's bare PDFTextStripper runs with sortByPosition=false. On a /Rotate 90 "
    "page its line-breaking splits per glyph, so it counts more than Rust does. "
    "The Rust value is the correct reading of the page; replicating the Java "
    "quirk would need a text-layout work-item that is deliberately not planned. "
    "Accepted, not a Rust defect."
)

_PER_PAGE_MIRROR_NOTE = (
    " This is the per-page mirror of BasicInfo.CharacterCount: GetInfoOnPDF reports "
    "the same stripper-derived count again under PerPageInfo, so the identical quirk "
    "surfaces on both paths and both are pinned to the values the first live "
    "Java-vs-Rust CI run reported."
)

_XMP_REASON = (
    "Java re-serialises the XMP packet through xmpbox (normalised namespaces and "
    "indentation, '+00:00' instead of 'Z', elements instead of attributes) while "
    "Rust returns the stored packet verbatim. The content is equivalent. "
    "DELIBERATELY UNPINNED: the packet embeds generation-time timestamps and "
    "UUIDs, so its value VARIES between runs and CANNOT be pinned -- any pin "
    "here would fail on the next run."
)


REGISTRY: tuple[KnownDiff, ...] = (
    # -- get_info_single: test_pdf_1.pdf, a 1-page US-Letter page with /Rotate 90.
    KnownDiff(
        case="get_info_single",
        field="BasicInfo.CharacterCount",
        reason=_TEXT_STRIPPER_REASON,
        expect_rust=14,
        expect_java=18,
    ),
    KnownDiff(
        case="get_info_single",
        field="BasicInfo.WordCount",
        reason=_TEXT_STRIPPER_REASON,
        expect_rust=4,
        expect_java=7,
    ),
    KnownDiff(
        case="get_info_single",
        field="BasicInfo.ParagraphCount",
        reason=_TEXT_STRIPPER_REASON,
        expect_rust=2,
        expect_java=6,
    ),
    KnownDiff(
        case="get_info_single",
        field="PerPageInfo.Page 1.Text Characters Count",
        reason=_TEXT_STRIPPER_REASON + _PER_PAGE_MIRROR_NOTE,
        expect_rust=14,
        expect_java=18,
    ),
    # -- get_info_multipage: the generated 5-page fixture.
    # Its pages carry no /Rotate, so the PDFTextStripper quirk above does not fire and
    # the two backends agree on every count -- CI reported the speculative count entries
    # STALE on the first live run and they were deleted, exactly as their note instructed.
    KnownDiff(
        case="get_info_multipage",
        field="Other.XMPMetadata",
        reason=_XMP_REASON,
    ),
)


# ---------------------------------------------------------------------------
# Lookup / classification
# ---------------------------------------------------------------------------
def lookup(case: str | None, field: str, registry: tuple[KnownDiff, ...] = REGISTRY) -> KnownDiff | None:
    if case is None:
        return None
    for entry in registry:
        if entry.case == case and entry.field == field:
            return entry
    return None


def classify(
    case: str | None,
    field: str,
    rust_val: Any,
    java_val: Any,
    registry: tuple[KnownDiff, ...] = REGISTRY,
) -> Classification:
    """Classify an observed field difference against the registry."""
    entry = lookup(case, field, registry)
    if entry is None:
        return Classification(UNREGISTERED, None, "")
    if entry.matches(rust_val, java_val):
        return Classification(KNOWN, entry, entry.reason)
    return Classification(
        PIN_MISMATCH,
        entry,
        (
            "UNEXPECTED CHANGE: the known-difference expectation is stale -- "
            f"known_diffs.REGISTRY pins {entry.pins_text()} for this field. "
            "Re-verify the behaviour against the Java oracle, then update or "
            "remove the entry; do not just re-pin it."
        ),
    )


def entries_for(case: str, registry: tuple[KnownDiff, ...] = REGISTRY) -> list[KnownDiff]:
    return [entry for entry in registry if entry.case == case]


def stale_entries(
    case: str,
    matched: set[tuple[str, str]],
    registry: tuple[KnownDiff, ...] = REGISTRY,
) -> list[KnownDiff]:
    """Registered entries for ``case`` that produced no difference at all.

    The field converged (or vanished): the entry is dead weight and should be
    deleted. Reported as a loud warning; deliberately NOT a failure.
    """
    return [entry for entry in entries_for(case, registry) if entry.key not in matched]


# ---------------------------------------------------------------------------
# Registry hygiene
# ---------------------------------------------------------------------------
def validate(
    registry: tuple[KnownDiff, ...] = REGISTRY,
    valid_cases: set[str] | None = None,
) -> list[str]:
    """Structural problems with the registry itself. Empty list == healthy."""
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    for entry in registry:
        where = f"{entry.case}/{entry.field}"
        if not entry.reason or not entry.reason.strip():
            problems.append(f"{where}: a known difference REQUIRES a human-readable reason")
        if entry.key in seen:
            problems.append(f"{where}: duplicate registry entry")
        seen.add(entry.key)
        if not entry.case or not entry.field:
            problems.append(f"{where}: case and field are both required")
        if valid_cases is not None and entry.case not in valid_cases:
            problems.append(
                f"{where}: no such case in the manifest (typo? renamed case?) -- "
                "this entry can never match and would silently accept nothing"
            )
    return problems


def summary_line() -> str:
    pinned = sum(1 for e in REGISTRY if e.pinned)
    cases = len({e.case for e in REGISTRY})
    return f"{len(REGISTRY)} entr{'y' if len(REGISTRY) == 1 else 'ies'} over {cases} case(s), {pinned} pinned"


def _self_check() -> int:
    """Offline assertions on the classification rules (no backend needed)."""
    reg = (
        KnownDiff("c", "A.B", "pinned", expect_rust=1, expect_java=2),
        KnownDiff("c", "A.C", "unpinned"),
    )
    failures = 0

    def check(label: str, got: Any, want: Any) -> None:
        nonlocal failures
        ok = got == want
        failures += not ok
        print(f"[{'OK ' if ok else 'XX '}] {label}: {got!r}" + ("" if ok else f" (want {want!r})"))

    check("pinned + matching values -> KNOWN", classify("c", "A.B", 1, 2, reg).kind, KNOWN)
    check("pinned + rust moved -> PIN_MISMATCH", classify("c", "A.B", 0, 2, reg).kind, PIN_MISMATCH)
    check("pinned + java moved -> PIN_MISMATCH", classify("c", "A.B", 1, 9, reg).kind, PIN_MISMATCH)
    check("unpinned -> KNOWN whatever the values", classify("c", "A.C", "x", "y", reg).kind, KNOWN)
    check("unregistered field -> UNREGISTERED", classify("c", "A.D", 1, 2, reg).kind, UNREGISTERED)
    check("unregistered case -> UNREGISTERED", classify("other", "A.B", 1, 2, reg).kind, UNREGISTERED)
    check("no case context -> UNREGISTERED", classify(None, "A.B", 1, 2, reg).kind, UNREGISTERED)
    check("stale sweep finds the untouched entry", [e.field for e in stale_entries("c", {("c", "A.B")}, reg)], ["A.C"])
    check("no-reason entry is rejected", bool(validate((KnownDiff("c", "A.B", ""),))), True)
    check("duplicate key is rejected", bool(validate(reg + (reg[0],))), True)
    check("unknown case is rejected", bool(validate(reg, valid_cases={"nope"})), True)
    check("shipped registry is healthy", validate(), [])
    print(f"\nKNOWN-DIFF SELF-CHECK: {'FAIL' if failures else 'OK'} ({failures} failure(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    print(f"known-difference registry: {summary_line()}\n")
    for known in REGISTRY:
        pins = known.pins_text() if known.pinned else "UNPINNED (accepts any difference)"
        print(f"{known.case:20} {known.field:26} {pins}")
        print(f"{'':20} reason: {known.reason}\n")
    raise SystemExit(_self_check())
