"""Data access for NVD CVE records. Nothing here commits; the services do.

Every write is an upsert or a replace of exactly the rows being imported, so
importing the same CVE twice leaves one copy and a CVE whose affected versions
changed upstream ends up with the new list, not a mixture.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from datetime import datetime

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from riskreveal.domain.intelligence.models import Cve, CveRange, CveSync
from riskreveal.domain.intelligence.records import CpeRange, CveRecord

logger = logging.getLogger("riskreveal.intelligence.cve")

CVE_BATCH_SIZE = 200
RANGE_BATCH_SIZE = 1500  # 13 columns per row: well under PostgreSQL's parameter limit

# Column widths (see models.py). A range wider than these is junk and is skipped.
_MAX_NAME = 128
_MAX_VERSION = 64


def _chunks[T](items: Sequence[T], size: int) -> Iterator[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def upsert_records(db: Session, records: Sequence[CveRecord]) -> int:
    """Store CVEs and replace their affected-version rows. Returns the CVE count."""
    unique = list({record.cve_id: record for record in records}.values())  # last one wins
    for batch in _chunks(unique, CVE_BATCH_SIZE):
        _write_cves(db, batch)
        _replace_ranges(db, batch)
    return len(unique)


def _write_cves(db: Session, batch: Sequence[CveRecord]) -> None:
    rows = [
        {
            "cve_id": r.cve_id,
            "description": r.description,
            "cvss_score": r.cvss_score,
            "cvss_severity": r.cvss_severity,
            "cvss_version": r.cvss_version,
            "cvss_vector": r.cvss_vector,
            "published_at": r.published,
            "last_modified_at": r.last_modified,
        }
        for r in batch
    ]
    stmt = pg_insert(Cve).values(rows)
    changed = [column for column in rows[0] if column != "cve_id"]
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                **{column: getattr(stmt.excluded, column) for column in changed},
                "updated_at": func.now(),
            },
        )
    )


def _replace_ranges(db: Session, batch: Sequence[CveRecord]) -> None:
    db.execute(delete(CveRange).where(CveRange.cve_id.in_([r.cve_id for r in batch])))
    rows: list[dict[str, object]] = []
    skipped = 0
    for record in batch:
        for position, rng in enumerate(record.ranges):
            row = _range_row(record.cve_id, position, rng)
            if row is None:
                skipped += 1
            else:
                rows.append(row)
    if skipped:
        logger.warning("skipped %d affected-version entries that did not fit the columns", skipped)
    for chunk in _chunks(rows, RANGE_BATCH_SIZE):
        db.execute(pg_insert(CveRange).values(list(chunk)))


def _range_row(cve_id: str, position: int, rng: CpeRange) -> dict[str, object] | None:
    if (
        len(rng.vendor) > _MAX_NAME
        or len(rng.product) > _MAX_NAME
        or len(rng.version) > _MAX_VERSION
        or len(rng.update) > _MAX_VERSION
    ):
        return None
    return {
        "cve_id": cve_id,
        "position": position,
        "part": rng.part,
        "vendor": rng.vendor,
        "product": rng.product,
        "cpe_version": rng.version,
        "cpe_update": rng.update,
        "start_including": rng.start_including,
        "start_excluding": rng.start_excluding,
        "end_including": rng.end_including,
        "end_excluding": rng.end_excluding,
        "conditional": rng.conditional,
        "requires": list(rng.requires),
    }


# --- cache bookkeeping --------------------------------------------------------


def record_sync(db: Session, name: str, *, found: bool, count: int, now: datetime) -> None:
    stmt = pg_insert(CveSync).values(
        cpe_name=name, last_success_at=now, found=found, cve_count=count
    )
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=["cpe_name"],
            set_={
                "last_success_at": stmt.excluded.last_success_at,
                "found": stmt.excluded.found,
                "cve_count": stmt.excluded.cve_count,
            },
        )
    )


def get_sync(db: Session, name: str) -> CveSync | None:
    # populate_existing: the upserts above bypass the session's identity map, so a
    # cached object could otherwise show an older timestamp than the database.
    return db.scalar(
        select(CveSync).where(CveSync.cpe_name == name).execution_options(populate_existing=True)
    )


# --- reading for the matcher -----------------------------------------------------


def records_for_product(db: Session, part: str, vendor: str, product: str) -> list[CveRecord]:
    """Minimal records (id + this product's ranges) for ``match_cves``.

    Only the ranges that name this product are loaded: the matcher ignores the
    others, and descriptions are fetched later for the CVEs that actually match.
    """
    statement = (
        select(CveRange)
        .where(CveRange.part == part, CveRange.vendor == vendor, CveRange.product == product)
        .order_by(CveRange.cve_id, CveRange.position)
    )
    by_cve: dict[str, list[CpeRange]] = {}
    for row in db.scalars(statement):
        by_cve.setdefault(row.cve_id, []).append(
            CpeRange(
                part=row.part,
                vendor=row.vendor,
                product=row.product,
                version=row.cpe_version,
                update=row.cpe_update,
                start_including=row.start_including,
                start_excluding=row.start_excluding,
                end_including=row.end_including,
                end_excluding=row.end_excluding,
                conditional=row.conditional,
                requires=tuple(
                    item for item in (row.requires or []) if isinstance(item, str)
                ),
            )
        )
    return [
        CveRecord(
            cve_id=cve_id,
            description="",
            published=None,
            last_modified=None,
            cvss_score=None,
            cvss_severity=None,
            cvss_version=None,
            cvss_vector=None,
            ranges=tuple(ranges),
        )
        for cve_id, ranges in by_cve.items()
    ]


def get_cves(db: Session, cve_ids: Sequence[str]) -> dict[str, Cve]:
    """CVE rows by id (unknown ids are absent)."""
    found: dict[str, Cve] = {}
    unique = sorted(set(cve_ids))
    for chunk in _chunks(unique, 1000):
        for cve in db.scalars(select(Cve).where(Cve.cve_id.in_(chunk))):
            found[cve.cve_id] = cve
    return found
