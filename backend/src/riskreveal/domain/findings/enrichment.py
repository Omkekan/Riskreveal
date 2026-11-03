"""Attach CVSS / KEV / EPSS context to findings that carry a CVE id."""

from __future__ import annotations

from collections.abc import Collection, Iterable

from sqlalchemy.orm import Session

from riskreveal.domain.findings.schemas import FindingRead, VulnerabilityContext
from riskreveal.domain.intelligence import cve_repository, repository


def vulnerability_contexts(
    db: Session, cve_ids: Collection[str]
) -> dict[str, VulnerabilityContext]:
    """One context per CVE id, from two bulk queries (CVE rows, threat feeds)."""
    if not cve_ids:
        return {}
    cves = cve_repository.get_cves(db, list(cve_ids))
    signals = repository.get_threat_signals(db, cve_ids)
    contexts: dict[str, VulnerabilityContext] = {}
    for cve_id in cve_ids:
        cve = cves.get(cve_id)
        signal = signals.get(cve_id)
        contexts[cve_id] = VulnerabilityContext(
            cve_id=cve_id,
            cvss_score=cve.cvss_score if cve else None,
            cvss_severity=cve.cvss_severity if cve else None,
            cvss_vector=cve.cvss_vector if cve else None,
            published_at=cve.published_at if cve else None,
            in_kev=signal.kev if signal else False,
            kev_date_added=signal.kev_date_added if signal else None,
            kev_ransomware_use=signal.kev_ransomware_use if signal else False,
            epss=signal.epss if signal else None,
            epss_percentile=signal.epss_percentile if signal else None,
            epss_date=signal.epss_date if signal else None,
        )
    return contexts


def attach_context[T: FindingRead](db: Session, items: Iterable[T]) -> list[T]:
    """Fill ``vulnerability`` on every item that has a ``cve_id``."""
    listed = list(items)
    contexts = vulnerability_contexts(db, {i.cve_id for i in listed if i.cve_id})
    for item in listed:
        if item.cve_id:
            item.vulnerability = contexts.get(item.cve_id)
    return listed
