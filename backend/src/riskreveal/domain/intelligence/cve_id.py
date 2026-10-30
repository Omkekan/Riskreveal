"""CVE identifier validation shared by every intelligence source.

A CVE id is ``CVE-<4-digit year>-<4 to 10 digits>``. The check is deliberately
strict and ASCII-only: Python's ``\\d`` also matches non-ASCII digits (for
example full-width digits), which would let look-alike strings into the
database. The same rule is repeated as a CHECK constraint on the tables.
"""

from __future__ import annotations

import re

_CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,10}")

# Longest string the pattern above can match: len("CVE-2026-") + 10 digits.
MAX_CVE_ID_LENGTH = 19

# Same rule, as a PostgreSQL regular expression (used in CHECK constraints).
CVE_ID_SQL_REGEX = "^CVE-[0-9]{4}-[0-9]{4,10}$"


def normalize_cve_id(raw: object) -> str | None:
    """Return the upper-cased CVE id, or ``None`` if ``raw`` is not a valid one."""
    if not isinstance(raw, str) or not raw.isascii():
        return None
    candidate = raw.strip().upper()
    if len(candidate) > MAX_CVE_ID_LENGTH:
        return None
    return candidate if _CVE_RE.fullmatch(candidate) else None
