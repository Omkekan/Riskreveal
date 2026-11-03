"""Turn "this service matches this CVE" into the text of a finding.

Pure (standard library plus the project's enums and ``distro``), so every
wording and severity rule is unit-tested without a database. The result is a
draft; ``matching_service.py`` stores it.

What a ``version_match`` finding is and is not: it says the version the service
*advertises* lies in a vulnerable range the NVD publishes for the CVE. It does
not say the host is exploitable. The description says so every time, and adds
the back-port warning when the host looks like a distribution package.

Banner text from the host is used only to decide *whether* to add a caveat; it
is never copied into the finding's text (the product/version columns already
carry what the host reported, and they are stored as plain text).
"""

from __future__ import annotations

from dataclasses import dataclass

from riskreveal.domain.findings.enums import Severity
from riskreveal.domain.intelligence.cpe import Cpe
from riskreveal.domain.intelligence.distro import detect_distro
from riskreveal.domain.intelligence.matcher import CveMatch
from riskreveal.domain.intelligence.records import severity_from_cvss

MAX_TITLE_CHARS = 255
MAX_DESCRIPTION_CHARS = 8000

_REASONS = {
    "exact_version": "lists that exact version as affected",
    "version_range": "lists a version range that includes it",
    "all_versions": "lists every version as affected",
}
_SEVERITY_RANK = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}


@dataclass(frozen=True)
class DetectedService:
    """A service Nmap found, as the matcher sees it."""

    asset_id: str
    port: int | None
    protocol: str | None
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    os_name: str | None
    cpe_text: str
    """The CPE exactly as Nmap reported it."""


@dataclass(frozen=True)
class CveInfo:
    cve_id: str
    description: str
    cvss_score: float | None


@dataclass(frozen=True)
class VersionMatchDraft:
    cve_id: str
    asset_id: str
    title: str
    description: str
    severity: str
    port: int | None
    protocol: str | None
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    cpe: str
    raw_evidence: str
    distro: str | None = None
    """Distribution packaging the software, when the banner shows one."""


def severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


def severity_for(score: float | None) -> str:
    """Our severity for a CVSS base score; an unscored CVE is ``info``."""
    if score is None:
        return Severity.INFO.value
    try:
        return severity_from_cvss(score).value
    except ValueError:  # a score outside 0-10 should be impossible; never crash on it
        return Severity.INFO.value


def build_draft(
    service: DetectedService, cve: CveInfo, match: CveMatch, cpe: Cpe
) -> VersionMatchDraft:
    label = _label(service, cpe)
    reason = _REASONS.get(match.reason, "lists that version")
    paragraphs = [
        cve.description or "The NVD has not published a description for this CVE.",
        (
            f"Why this was reported: the service reports {label}, and the NVD {reason} for "
            f"{cve.cve_id}. This is an inference from an advertised version; RiskReveal has "
            "not tested whether the flaw can be exploited on this host."
        ),
    ]
    if cve.cvss_score is None:
        paragraphs.append(
            "The NVD has not assigned a CVSS score to this CVE yet, so its severity is unrated."
        )
    distro = detect_distro(service.version, service.extra_info, service.os_name)
    if distro is not None:
        paragraphs.append(
            f"This host appears to run a {distro} package. Distributions usually back-port "
            "security fixes without changing the version number, so this may be a false "
            "positive. Verify the installed package version against the distribution's own "
            "security advisory before acting on it."
        )

    return VersionMatchDraft(
        cve_id=cve.cve_id,
        asset_id=service.asset_id,
        title=f"{cve.cve_id}: {label} may be affected"[:MAX_TITLE_CHARS],
        description="\n\n".join(paragraphs)[:MAX_DESCRIPTION_CHARS],
        severity=severity_for(cve.cvss_score),
        port=service.port,
        protocol=service.protocol,
        service=service.service,
        product=service.product,
        version=service.version,
        extra_info=service.extra_info,
        cpe=service.cpe_text,
        raw_evidence=f"Matched detected CPE {service.cpe_text} against NVD record {cve.cve_id}.",
        distro=distro,
    )


def _label(service: DetectedService, cpe: Cpe) -> str:
    if service.product and service.version:
        return f"{service.product} {service.version}".strip()
    return service.product or f"{cpe.vendor}:{cpe.product}"
