"""Compare a finished scan's detected services with stored CVE data.

For each Nmap finding that carries a CPE with a concrete version:

1. make sure the NVD's data for that CPE is stored (``cve_service``);
2. run the verified matcher (``match_cves``), telling it the host platform;
3. store one ``version_match`` finding per *strong* match.

Weak matches (``needs_review``: "all versions" or platform-conditional) are
counted, not stored: the matcher's own documentation says they must not become
findings automatically.

Safety properties
-----------------
* **Idempotent.** A re-run replaces the scan's previous ``version_match``
  findings in one transaction; it never duplicates them.
* **No data is not "safe".** A CPE the NVD has no answer for, or that could not
  be fetched, is reported in the summary; it is never treated as clean.
* **A failing NVD does not fail the scan.** The scan stays ``completed``.
* **No network call while a transaction is open.**
* **Bounded.** At most ``MAX_VERSION_MATCH_FINDINGS`` are stored per scan,
  highest severity first; the summary says if anything was cut.

Findings are always ``confidence="inferred"``.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from riskreveal.domain.assets.models import Asset
from riskreveal.domain.findings.enums import Confidence, FindingSource, FindingStatus
from riskreveal.domain.findings.models import Finding
from riskreveal.domain.intelligence import cve_repository, cve_service
from riskreveal.domain.intelligence.cpe import Cpe, full_version, parse_cpe
from riskreveal.domain.intelligence.cve_service import DataStatus
from riskreveal.domain.intelligence.errors import FeedError
from riskreveal.domain.intelligence.host_platform import detect_host_platform
from riskreveal.domain.intelligence.matcher import CveMatch, match_cves
from riskreveal.domain.intelligence.records import CveRecord
from riskreveal.domain.intelligence.sources.nvd_client import NvdClient
from riskreveal.domain.intelligence.vuln_findings import (
    CveInfo,
    DetectedService,
    VersionMatchDraft,
    build_draft,
    severity_rank,
)
from riskreveal.domain.scanning.models import Scan

logger = logging.getLogger("riskreveal.intelligence.matching")

MAX_VERSION_MATCH_FINDINGS = 5000
_COMPLETED = "completed"


@dataclass(frozen=True)
class MatchSummary:
    findings_created: int = 0
    services_checked: int = 0
    services_skipped: int = 0
    """Services whose CPE is missing, unparseable, versionless or not software/OS."""
    cpes_fetched: int = 0
    sync_errors: int = 0
    weak_matches: int = 0
    """Matches stored nowhere because they need a human (all-versions / conditional)."""
    no_data: tuple[str, ...] = field(default_factory=tuple)
    """CPEs we have no CVE data for. NOT a statement that they are safe."""
    truncated: bool = False


@dataclass(frozen=True)
class _Candidate:
    service: DetectedService
    cpe: Cpe


def match_scan(
    db: Session,
    scan_id: uuid.UUID,
    *,
    client: NvdClient | None,
    cache_max_age: timedelta = cve_service.DEFAULT_CACHE_MAX_AGE,
    now: datetime | None = None,
) -> MatchSummary:
    """Create ``version_match`` findings for a completed scan.

    ``client=None`` means "use only the CVE data already stored" (no network).
    """
    candidates, skipped = _load_candidates(db, scan_id)
    db.rollback()  # end the read transaction before any slow network call
    if not candidates:
        return MatchSummary(services_skipped=skipped)

    fetched = errors = 0
    statuses: dict[Cpe, DataStatus] = {}
    for cpe in sorted({c.cpe for c in candidates}, key=_cpe_sort_key):
        try:
            status = cve_service.ensure_cpe_data(
                db, cpe, client, max_age=cache_max_age, now=now
            )
        except FeedError as exc:
            errors += 1
            logger.warning("NVD data for %s:%s unavailable: %s", cpe.vendor, cpe.product, exc)
            # Fall back to whatever is stored, and say honestly if that is nothing.
            status = cve_service.ensure_cpe_data(db, cpe, None, max_age=cache_max_age, now=now)
        if status is DataStatus.FETCHED:
            fetched += 1
        statuses[cpe] = status

    matched: list[tuple[_Candidate, CveMatch]] = []
    records_by_product: dict[tuple[str, str, str], list[CveRecord]] = {}
    no_data: set[str] = set()
    weak = 0
    for candidate in candidates:
        cpe = candidate.cpe
        key = (cpe.part, cpe.vendor, cpe.product)
        if key not in records_by_product:
            records_by_product[key] = cve_repository.records_for_product(db, *key)
        if _lacks_data(statuses[cpe], records_by_product[key]):
            no_data.add(f"{cpe.vendor}:{cpe.product} {full_version(cpe)}")
        host = detect_host_platform(
            candidate.service.extra_info, candidate.service.version, candidate.service.os_name
        )
        for match in match_cves(cpe, records_by_product[key], host=host):
            if match.needs_review:
                weak += 1
            else:
                matched.append((candidate, match))

    cves = cve_repository.get_cves(db, [match.cve_id for _, match in matched])
    drafts: list[VersionMatchDraft] = []
    for candidate, match in matched:
        cve = cves.get(match.cve_id)
        if cve is None:  # cannot happen (foreign key); never crash a whole scan on it
            continue
        info = CveInfo(
            cve_id=match.cve_id, description=cve.description, cvss_score=cve.cvss_score
        )
        drafts.append(build_draft(candidate.service, info, match, candidate.cpe))
    db.rollback()

    drafts.sort(key=lambda d: (-severity_rank(d.severity), d.cve_id, d.asset_id, d.port or 0))
    truncated = len(drafts) > MAX_VERSION_MATCH_FINDINGS
    if truncated:
        logger.warning(
            "scan %s: keeping %d of %d matches", scan_id, MAX_VERSION_MATCH_FINDINGS, len(drafts)
        )
        drafts = drafts[:MAX_VERSION_MATCH_FINDINGS]

    _replace_findings(db, scan_id, drafts)
    return MatchSummary(
        findings_created=len(drafts),
        services_checked=len(candidates),
        services_skipped=skipped,
        cpes_fetched=fetched,
        sync_errors=errors,
        weak_matches=weak,
        no_data=tuple(sorted(no_data)),
        truncated=truncated,
    )


# ---------------------------------------------------------------------------


def _lacks_data(status: DataStatus, records: list[CveRecord]) -> bool:
    """True when we have no usable answer for this CPE (not the same as "safe").

    The NVD not knowing the name, or the name being unusable, is always "no
    data". "Not stored" counts only if nothing at all is stored for the product,
    so CVE data loaded some other way is still used.
    """
    if status in (DataStatus.UNKNOWN_CPE, DataStatus.NO_NAME):
        return True
    return status is DataStatus.NOT_STORED and not records


def _cpe_sort_key(cpe: Cpe) -> tuple[str, str, str, str, str]:
    return (cpe.part, cpe.vendor, cpe.product, cpe.version, cpe.update)


def _load_candidates(db: Session, scan_id: uuid.UUID) -> tuple[list[_Candidate], int]:
    scan = db.get(Scan, scan_id)
    if scan is None or scan.status != _COMPLETED:
        logger.warning("scan %s is missing or not completed; nothing to match", scan_id)
        return [], 0

    rows = db.execute(
        select(Finding, Asset.os_name)
        .join(Asset, Asset.id == Finding.asset_id)
        .where(
            Finding.scan_id == scan_id,
            Finding.source == FindingSource.NMAP.value,
            Finding.cpe.is_not(None),
        )
    ).all()

    candidates: list[_Candidate] = []
    skipped = 0
    for finding, os_name in rows:
        cpe = parse_cpe(finding.cpe)
        if cpe is None or cpe.part not in ("a", "o") or full_version(cpe) is None:
            skipped += 1
            continue
        candidates.append(
            _Candidate(
                service=DetectedService(
                    asset_id=str(finding.asset_id),
                    port=finding.port,
                    protocol=finding.protocol,
                    service=finding.service,
                    product=finding.product,
                    version=finding.version,
                    extra_info=finding.extra_info,
                    os_name=os_name,
                    cpe_text=finding.cpe or "",
                ),
                cpe=cpe,
            )
        )
    return candidates, skipped


def _replace_findings(db: Session, scan_id: uuid.UUID, drafts: list[VersionMatchDraft]) -> None:
    """Swap the scan's version_match findings for ``drafts`` in one transaction."""
    try:
        db.execute(
            delete(Finding).where(
                Finding.scan_id == scan_id,
                Finding.source == FindingSource.VERSION_MATCH.value,
            )
        )
        db.add_all(
            [
                Finding(
                    scan_id=scan_id,
                    asset_id=uuid.UUID(d.asset_id),
                    source=FindingSource.VERSION_MATCH.value,
                    confidence=Confidence.INFERRED.value,
                    severity=d.severity,
                    status=FindingStatus.OPEN.value,
                    title=d.title,
                    description=d.description,
                    port=d.port,
                    protocol=d.protocol,
                    service=d.service,
                    product=d.product,
                    version=d.version,
                    extra_info=d.extra_info,
                    distro=d.distro,
                    cpe=d.cpe,
                    cve_id=d.cve_id,
                    raw_evidence=d.raw_evidence,
                )
                for d in drafts
            ]
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
