"""Attach CVSS / KEV / EPSS context to findings that carry a CVE id."""

from __future__ import annotations

from collections.abc import Collection, Iterable

from sqlalchemy.orm import Session

from riskreveal.domain.findings.risk_scorer import score as score_risk
from riskreveal.domain.findings.schemas import FindingRead, RiskScoreRead, VulnerabilityContext
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
    """Fill ``vulnerability`` and ``risk_score`` on every item with a ``cve_id``.

    Asset criticality isn't modeled yet (``Asset`` has no such field), so
    every finding here gets the scorer's neutral default (1.0) -- a future
    pass through this function supplies the asset's real criticality once
    that field exists, rather than this module guessing at one.
    """
    listed = list(items)
    contexts = vulnerability_contexts(db, {i.cve_id for i in listed if i.cve_id})
    for item in listed:
        if not item.cve_id:
            continue
        context = contexts.get(item.cve_id)
        item.vulnerability = context
        if context is not None:
            risk = score_risk(context)
            if risk is not None:
                item.risk_score = RiskScoreRead(
                    value=risk.value,
                    band=risk.band.value,
                    severity_component=risk.severity_component,
                    threat_component=risk.threat_component,
                    asset_criticality=risk.asset_criticality,
                    reasons=risk.reasons,
                )
    return listed
