"""Plain data types for vulnerability intelligence.

Everything here is standard library plus the ``Severity`` enum, so the
intelligence core can be imported and tested without a database, a network
connection or the web stack.

All of this data comes from outside (the NVD) and is treated as untrusted input
by the parsers: shapes are checked, strings are cleaned and clipped, and
nothing is ever evaluated or used as a file path. CVE ids are validated with
the shared ``cve_id.normalize_cve_id``; parse failures raise ``FeedParseError``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from riskreveal.domain.findings.enums import Severity


@dataclass(frozen=True)
class CpeRange:
    """One "vulnerable" CPE applicability entry of a CVE (NVD ``cpeMatch``).

    ``version`` is ``*`` when the entry is a range (the ``start_*`` /
    ``end_*`` bounds then apply), a concrete version for an exact entry, or
    ``-`` for "not applicable".
    """

    part: str
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None
    conditional: bool = False
    """True if NVD says this only applies in combination with another
    component (an AND configuration, e.g. "when running on Windows")."""
    requires: tuple[str, ...] = ()
    """For a conditional entry: the ``vendor:product`` of the platform
    components it must run on (for example ``microsoft:windows``), taken from
    the non-vulnerable entries of the same configuration. Empty if unknown."""


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    description: str
    published: datetime | None
    last_modified: datetime | None
    cvss_score: float | None
    cvss_severity: str | None
    """NVD's own label, lower-case: none, low, medium, high or critical."""
    cvss_version: str | None
    cvss_vector: str | None
    ranges: tuple[CpeRange, ...]


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS v3-style base score to our severity scale (0-10 only)."""
    if isinstance(score, bool) or math.isnan(score) or not 0.0 <= score <= 10.0:
        raise ValueError("CVSS score must be a number between 0 and 10.")
    if score == 0.0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL
