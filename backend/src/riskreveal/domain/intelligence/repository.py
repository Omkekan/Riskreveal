"""Data access for the threat-intelligence tables. Nothing here commits;
``service.py`` does.

Large imports are written in batches: PostgreSQL accepts at most 65,535
bound parameters per statement, so rows-per-statement x columns must stay
below that. Every statement is an upsert, so re-running an import is safe.
"""

from __future__ import annotations

from collections.abc import Collection, Iterator, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from riskreveal.domain.intelligence.cve_id import normalize_cve_id
from riskreveal.domain.intelligence.models import EpssScore, FeedSync, KevEntry
from riskreveal.domain.intelligence.sources.cisa_kev import KevRecord
from riskreveal.domain.intelligence.sources.first_epss import EpssRecord

KEV_BATCH_SIZE = 500  # x 11 columns
EPSS_BATCH_SIZE = 5000  # x 5 columns
_LOOKUP_BATCH_SIZE = 1000


@dataclass(frozen=True, slots=True)
class ThreatSignal:
    """Everything we know about a CVE from the threat feeds. ``None`` = unknown."""

    cve_id: str
    kev: bool
    kev_date_added: date | None
    kev_ransomware_use: bool
    epss: float | None
    epss_percentile: float | None
    epss_date: date | None


def _chunks[T](items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def upsert_kev(db: Session, records: Sequence[KevRecord]) -> int:
    """Insert or refresh KEV entries; return how many were written."""
    for chunk in _chunks(records, KEV_BATCH_SIZE):
        stmt = pg_insert(KevEntry).values(
            [
                {
                    "cve_id": r.cve_id,
                    "vendor_project": r.vendor_project,
                    "product": r.product,
                    "vulnerability_name": r.vulnerability_name,
                    "date_added": r.date_added,
                    "short_description": r.short_description,
                    "required_action": r.required_action,
                    "due_date": r.due_date,
                    "known_ransomware_use": r.known_ransomware_use,
                    "notes": r.notes,
                    "cwes": list(r.cwes),
                }
                for r in chunk
            ]
        )
        set_: dict[str, Any] = {
            name: stmt.excluded[name]
            for name in (
                "vendor_project",
                "product",
                "vulnerability_name",
                "date_added",
                "short_description",
                "required_action",
                "due_date",
                "known_ransomware_use",
                "notes",
                "cwes",
            )
        }
        set_["updated_at"] = func.now()
        db.execute(stmt.on_conflict_do_update(index_elements=[KevEntry.cve_id], set_=set_))
    return len(records)


def upsert_epss(
    db: Session, records: Sequence[EpssRecord], *, score_date: date, model_version: str
) -> None:
    """Insert or refresh EPSS scores.

    ``records`` must not contain the same CVE twice (PostgreSQL refuses to
    update one row twice in a single statement); the service de-duplicates.
    A row is only overwritten when the incoming ``score_date`` is the same or
    newer, so replaying an old file cannot roll scores back.
    """
    for chunk in _chunks(records, EPSS_BATCH_SIZE):
        stmt = pg_insert(EpssScore).values(
            [
                {
                    "cve_id": r.cve_id,
                    "score": r.score,
                    "percentile": r.percentile,
                    "score_date": score_date,
                    "model_version": model_version,
                }
                for r in chunk
            ]
        )
        db.execute(
            stmt.on_conflict_do_update(
                index_elements=[EpssScore.cve_id],
                set_={
                    "score": stmt.excluded.score,
                    "percentile": stmt.excluded.percentile,
                    "score_date": stmt.excluded.score_date,
                    "model_version": stmt.excluded.model_version,
                    "updated_at": func.now(),
                },
                where=EpssScore.score_date <= stmt.excluded.score_date,
            )
        )


def record_sync(db: Session, *, source: str, version: str | None, record_count: int) -> None:
    stmt = pg_insert(FeedSync).values(
        source=source, last_success_at=func.now(), version=version, record_count=record_count
    )
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=[FeedSync.source],
            set_={
                "last_success_at": func.now(),
                "version": stmt.excluded.version,
                "record_count": stmt.excluded.record_count,
            },
        )
    )


def list_syncs(db: Session) -> list[FeedSync]:
    return list(db.scalars(select(FeedSync).order_by(FeedSync.source)).all())


def get_threat_signals(db: Session, cve_ids: Collection[str]) -> dict[str, ThreatSignal]:
    """Look up KEV / EPSS data for the given CVE ids.

    Invalid ids are ignored. Only CVEs with at least one signal appear in the
    result; a missing key means "no information", which is not the same as an
    EPSS of zero.
    """
    wanted = sorted({c for c in map(normalize_cve_id, cve_ids) if c is not None})
    kev_rows: dict[str, KevEntry] = {}
    epss_rows: dict[str, EpssScore] = {}
    for chunk in _chunks(wanted, _LOOKUP_BATCH_SIZE):
        for kev in db.scalars(select(KevEntry).where(KevEntry.cve_id.in_(chunk))):
            kev_rows[kev.cve_id] = kev
        for epss in db.scalars(select(EpssScore).where(EpssScore.cve_id.in_(chunk))):
            epss_rows[epss.cve_id] = epss

    signals: dict[str, ThreatSignal] = {}
    for cve_id in sorted(kev_rows.keys() | epss_rows.keys()):
        kev_entry = kev_rows.get(cve_id)
        epss_entry = epss_rows.get(cve_id)
        signals[cve_id] = ThreatSignal(
            cve_id=cve_id,
            kev=kev_entry is not None,
            kev_date_added=kev_entry.date_added if kev_entry else None,
            kev_ransomware_use=bool(kev_entry and kev_entry.known_ransomware_use),
            epss=epss_entry.score if epss_entry else None,
            epss_percentile=epss_entry.percentile if epss_entry else None,
            epss_date=epss_entry.score_date if epss_entry else None,
        )
    return signals
