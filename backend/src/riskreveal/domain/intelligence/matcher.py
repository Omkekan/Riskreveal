"""Match a detected software CPE against CVE applicability data.

A pure function over in-memory records: no database, no network. It answers
one question: *which of these CVEs list this vendor/product/version as
vulnerable?*

What a match means, and does not mean
-------------------------------------
A match says the **advertised version** falls in a vulnerable range. It does
not prove the host is exploitable: a banner can lie, a distribution may have
back-ported the fix (see ``distro.py``), and the vulnerable feature may be
switched off. Callers must record such findings with
``confidence="inferred"``, never "confirmed".

Some matches are weaker still, and say so through ``CveMatch.needs_review``:

* ``all_versions``: the NVD lists the product with no version limit. Real data
  shows this is typical of disputed or unfixable entries.
* ``conditional``: the NVD says the bug needs an additional platform. Real data
  shows these are often platform-specific (for example Windows-only Apache
  bugs, or a Red Hat-only package compromise), which do not apply to a Linux
  host. ``requires`` says which platform.

Callers should not turn ``needs_review`` matches into ordinary findings
automatically.

When the answer is "don't know" the matcher says nothing rather than guess:
no version, an unparseable version, or an unparseable range bound produce no
match.

Known limit: vendor/product names are compared as written. Where Nmap and the
NVD spell the same product differently (a vendor rename or alias), no match is
found. Run ``scripts/nvd_match_demo.py`` against real data to find such cases.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from riskreveal.domain.intelligence.cpe import Cpe, full_version, join_version
from riskreveal.domain.intelligence.records import CpeRange, CveRecord
from riskreveal.domain.intelligence.versions import ParsedVersion, compare_versions, parse_version

MatchReason = Literal["exact_version", "version_range", "all_versions"]

_REASON_ORDER: dict[MatchReason, int] = {"exact_version": 0, "version_range": 1, "all_versions": 2}


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    reason: MatchReason
    conditional: bool
    """NVD says this applies only together with another component (for
    example a particular operating system). Treat as less certain."""
    requires: tuple[str, ...] = ()
    """``vendor:product`` of the platform(s) a conditional match needs."""

    @property
    def needs_review(self) -> bool:
        """True for matches too weak to report automatically (see module docs)."""
        return self.conditional or self.reason == "all_versions"


def match_cves(cpe: Cpe, records: Iterable[CveRecord]) -> list[CveMatch]:
    """CVEs among ``records`` that list ``cpe``'s version as vulnerable.

    At most one match per CVE (its strongest reason), sorted by CVE number.
    """
    if cpe.part not in ("a", "o"):
        return []
    subject = parse_version(full_version(cpe))
    if subject is None:
        return []

    matches: list[CveMatch] = []
    for record in records:
        best: CveMatch | None = None
        for rng in record.ranges:
            reason = _range_reason(rng, cpe, subject)
            if reason is None:
                continue
            candidate = CveMatch(record.cve_id, reason, rng.conditional, rng.requires)
            if best is None or _rank(candidate) < _rank(best):
                best = candidate
        if best is not None:
            matches.append(best)

    matches.sort(key=_cve_sort_key)
    return matches


def _rank(match: CveMatch) -> tuple[int, bool]:
    return (_REASON_ORDER[match.reason], match.conditional)


def _cve_sort_key(match: CveMatch) -> tuple[int, int]:
    _, year, number = match.cve_id.split("-")
    return (int(year), int(number))


def _range_reason(rng: CpeRange, cpe: Cpe, subject: ParsedVersion) -> MatchReason | None:
    if rng.part != cpe.part or rng.vendor != cpe.vendor or rng.product != cpe.product:
        return None

    bounds = (rng.start_including, rng.start_excluding, rng.end_including, rng.end_excluding)
    if any(bound is not None for bound in bounds):
        return "version_range" if _within_bounds(rng, subject) else None

    if rng.version in ("*", ""):
        return "all_versions"
    if rng.version == "-":
        return None

    exact = parse_version(join_version(rng.version, rng.update))
    if exact is not None and compare_versions(subject, exact) == 0:
        return "exact_version"
    return None


def _within_bounds(rng: CpeRange, subject: ParsedVersion) -> bool:
    checks: tuple[tuple[str | None, int, bool], ...] = (
        # (bound text, required comparison of subject vs bound, allow equal)
        (rng.start_including, 1, True),
        (rng.start_excluding, 1, False),
        (rng.end_including, -1, True),
        (rng.end_excluding, -1, False),
    )
    for text, direction, allow_equal in checks:
        if text is None:
            continue
        bound = parse_version(text)
        if bound is None:
            return False  # can't evaluate this bound: no claim
        order = compare_versions(subject, bound)
        if order == 0:
            if not allow_equal:
                return False
        elif order != direction:
            return False
    return True
