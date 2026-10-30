"""Importing threat-intelligence feeds into the database.

One import = one transaction, committed once at the end. If anything fails
(including a mostly-invalid file) the transaction is rolled back and nothing
from that import is saved: the previous good data stays in place. This is the
opposite of the old codebase's ``finally: commit()`` (01_... #18, #23).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.orm import Session

from riskreveal.domain.intelligence import repository
from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.sources.cisa_kev import KevCatalog
from riskreveal.domain.intelligence.sources.first_epss import (
    DEFAULT_MAX_INVALID_FRACTION,
    EpssReader,
    EpssRecord,
)

logger = logging.getLogger("riskreveal.intelligence")

SOURCE_KEV = "cisa_kev"
SOURCE_EPSS = "first_epss"


@dataclass(frozen=True, slots=True)
class ImportResult:
    source: str
    version: str | None
    imported: int
    skipped: int


def import_kev(db: Session, catalog: KevCatalog) -> ImportResult:
    """Save a parsed KEV catalog. Commits on success, rolls back on any error."""
    try:
        written = repository.upsert_kev(db, catalog.records)
        repository.record_sync(
            db, source=SOURCE_KEV, version=catalog.version, record_count=written
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    logger.info("KEV import finished: %d entries, %d skipped", written, catalog.skipped)
    return ImportResult(SOURCE_KEV, catalog.version, written, catalog.skipped)


def import_epss(
    db: Session,
    reader: EpssReader,
    *,
    max_invalid_fraction: float = DEFAULT_MAX_INVALID_FRACTION,
) -> ImportResult:
    """Stream an EPSS file into the database in batches, in ONE transaction.

    If the file turns out to be empty or has too many bad rows, everything
    written so far is rolled back.
    """
    try:
        imported = 0
        batch: dict[str, EpssRecord] = {}  # de-duplicates a CVE repeated within a batch
        for record in reader:
            batch[record.cve_id] = record
            if len(batch) >= repository.EPSS_BATCH_SIZE:
                repository.upsert_epss(
                    db,
                    list(batch.values()),
                    score_date=reader.score_date,
                    model_version=reader.model_version,
                )
                imported += len(batch)
                batch.clear()
        if batch:
            repository.upsert_epss(
                db,
                list(batch.values()),
                score_date=reader.score_date,
                model_version=reader.model_version,
            )
            imported += len(batch)

        if reader.rows_read == 0 or imported == 0:
            raise FeedParseError("The EPSS file contains no valid scores.")
        if reader.skipped / reader.rows_read > max_invalid_fraction:
            raise FeedParseError(
                f"The EPSS file has too many invalid rows ({reader.skipped} of {reader.rows_read})."
            )

        repository.record_sync(
            db,
            source=SOURCE_EPSS,
            version=f"{reader.model_version} / {reader.score_date.isoformat()}",
            record_count=imported,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    logger.info("EPSS import finished: %d scores, %d skipped", imported, reader.skipped)
    return ImportResult(
        SOURCE_EPSS,
        f"{reader.model_version} / {reader.score_date.isoformat()}",
        imported,
        reader.skipped,
    )
