"""Combine CVSS, CISA KEV, and FIRST EPSS into one prioritized risk score.

A CVE's CVSS score alone is a poor priority signal: a 9.8 nobody is
exploiting matters less, right now, than a 7.5 CISA has confirmed is being
used in active attacks. This module combines severity (CVSS) with real
threat evidence (KEV, EPSS) into one 0-100 score with an explicit
breakdown attached -- "why is this a 72?" should always have an answer,
not just a number.

"Don't know is the honest answer" (the same rule ``versions.py`` states for
unparseable versions, applied here to missing threat data): if there is
neither a CVSS score nor a KEV listing for a CVE, ``score()`` returns
``None`` rather than fabricating a number from nothing. A CVE that's in
KEV but missing a CVSS score (this happens -- newer or disputed CVEs
sometimes lack one) is still scored: confirmed active exploitation is
itself a severity signal, not something that requires a CVSS number first.

Severity is the *base* of the score, not half of a plain average with
threat evidence -- an earlier version of this module used a 50/50 average
and a test caught that it capped any finding with no KEV/EPSS evidence at
49 ("Medium"), no matter how high the CVSS was. That's backwards for a
scanner: catching a critical vulnerability before it's exploited is the
point. See docs/decisions/0003-risk-score-weighting-is-a-starting-point.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from riskreveal.domain.findings.schemas import VulnerabilityContext

# A CVE confirmed in KEV but with no CVSS score is scored as if its
# severity were this. Deliberately high but not maximal (1.0): confirmed
# real-world exploitation is strong evidence of real severity, but a
# missing CVSS score means the evidence is incomplete, not conclusive.
_KEV_SEVERITY_FLOOR = 0.7

# Any KEV listing floors the final score here, regardless of what CVSS
# alone would have produced. CISA's inclusion criteria already imply
# real-world significance beyond a raw CVSS number -- a low-CVSS KEV entry
# (these exist: auth-bypass or info-leak steps used inside a larger attack
# chain) still deserves more than what its CVSS alone would suggest.
_KEV_FLOOR = 50

# A KEV entry CISA has also flagged for ransomware use floors the final
# score here, on top of _KEV_FLOOR -- meant to read as an unambiguous
# "treat this one differently," not a middling nudge.
_RANSOMWARE_FLOOR = 95

# severity_component (CVSS-derived) is the base of the score. Threat
# evidence (KEV/EPSS) boosts that base by up to 30%: zero threat evidence
# keeps 70% of the severity score; confirmed active exploitation (KEV)
# reaches the full 100%. Chosen so a maxed-out CVSS with zero threat
# evidence lands solidly in High (not capped in the middle of Medium the
# way a plain 50/50 severity/threat average would).
_BASE_SEVERITY_SHARE = 0.7
_THREAT_BOOST_SHARE = 0.3


class RiskBand(StrEnum):
    """Matches the bands already documented in the project's architecture
    notes: Critical >= 85, High 65-84, Medium 40-64, Low 15-39, Info < 15.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


_BAND_THRESHOLDS: tuple[tuple[int, RiskBand], ...] = (
    (85, RiskBand.CRITICAL),
    (65, RiskBand.HIGH),
    (40, RiskBand.MEDIUM),
    (15, RiskBand.LOW),
)


def _band_for(value: int) -> RiskBand:
    for threshold, band in _BAND_THRESHOLDS:
        if value >= threshold:
            return band
    return RiskBand.INFO


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A finding's prioritized risk score, with its own explanation."""

    value: int
    """0-100."""
    band: RiskBand
    severity_component: float
    """0.0-1.0 -- what drove the "how bad" half of the score."""
    threat_component: float
    """0.0-1.0 -- what drove the "how likely to be exploited" half."""
    asset_criticality: float
    """The multiplier actually used (1.0 = neutral/default)."""
    reasons: tuple[str, ...]
    """Short, human-readable notes, in the order they were decided."""


def score(context: VulnerabilityContext, *, asset_criticality: float = 1.0) -> RiskScore | None:
    """Score one finding's CVE context.

    Returns ``None`` when there isn't enough signal to score honestly (no
    CVSS score and not in KEV) -- a fabricated number would be worse than
    admitting there isn't one.

    ``asset_criticality`` is a plain multiplier (1.0 = neutral), not yet
    backed by a real field on the ``Asset`` model -- it doesn't have one
    yet. A future caller passes something like 0.75/1.0/1.25/1.5 for
    low/medium/high/critical once that field exists; every caller today
    gets the neutral default.
    """
    reasons: list[str] = []

    if context.cvss_score is not None:
        # Defensive clamp: upstream CVE storage already validates CVSS is
        # within 0-10, but this function shouldn't silently trust that for
        # a VulnerabilityContext built some other way.
        severity_component = max(0.0, min(1.0, context.cvss_score / 10.0))
        reasons.append(f"CVSS {context.cvss_score:.1f}")
    elif context.in_kev:
        severity_component = _KEV_SEVERITY_FLOOR
        reasons.append("No CVSS score available; scored from its KEV listing alone")
    else:
        return None

    if context.in_kev:
        threat_component = 1.0
        reasons.append("Listed in CISA's Known Exploited Vulnerabilities catalog")
        if context.kev_ransomware_use:
            reasons.append("Associated with ransomware campaigns")
    elif context.epss is not None:
        threat_component = max(0.0, min(1.0, context.epss))
        reasons.append(f"EPSS {context.epss:.0%} predicted exploitation probability")
    else:
        threat_component = 0.0

    threat_multiplier = _BASE_SEVERITY_SHARE + _THREAT_BOOST_SHARE * threat_component
    raw = severity_component * 100 * threat_multiplier * asset_criticality
    value = max(0, min(100, round(raw)))

    if context.in_kev:
        value = max(value, _KEV_FLOOR)
    if context.in_kev and context.kev_ransomware_use:
        value = max(value, _RANSOMWARE_FLOOR)

    if asset_criticality != 1.0:
        reasons.append(f"Asset criticality weight {asset_criticality:.2f}x")

    return RiskScore(
        value=value,
        band=_band_for(value),
        severity_component=severity_component,
        threat_component=threat_component,
        asset_criticality=asset_criticality,
        reasons=tuple(reasons),
    )
