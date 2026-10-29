"""Finding vocabulary: severity, confidence, status, source.

Values follow ``02_RiskReveal_Master_Plan.md`` §4.2 and Appendix A. Stdlib
only, so the scan normalizer and its tests don't need SQLAlchemy.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How sure we are. inferred -> detected -> confirmed (Appendix A)."""

    INFERRED = "inferred"
    DETECTED = "detected"
    CONFIRMED = "confirmed"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    REOPENED = "reopened"


class FindingSource(StrEnum):
    NMAP = "nmap"
    # Later: NMAP_NSE, NUCLEI, VERSION_MATCH, AUTHENTICATED_PKG, AGENT_FOLLOWUP.
