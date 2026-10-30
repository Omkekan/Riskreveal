"""Data access for scans. Nothing here commits; the service layer does.

State changes are single conditional ``UPDATE ... WHERE status IN (...)``
statements, so they are atomic: two workers can never both claim the same
queued scan, and a cancel cannot be overwritten by a late "completed".
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from riskreveal.domain.scanning.enums import ScanStatus
from riskreveal.domain.scanning.models import Scan

ACTIVE_STATUSES = (ScanStatus.QUEUED, ScanStatus.RUNNING)


def get(db: Session, scan_id: uuid.UUID) -> Scan | None:
    """Fetch a scan, bypassing any stale copy in the session's identity map."""
    return db.scalar(
        select(Scan).where(Scan.id == scan_id).execution_options(populate_existing=True)
    )


def get_for_owner(db: Session, scan_id: uuid.UUID, owner_id: uuid.UUID) -> Scan | None:
    return db.scalar(
        select(Scan)
        .where(Scan.id == scan_id, Scan.owner_id == owner_id)
        .execution_options(populate_existing=True)
    )


def list_for_owner(
    db: Session, owner_id: uuid.UUID, *, limit: int, offset: int
) -> tuple[list[Scan], int]:
    total = db.scalar(select(func.count()).select_from(Scan).where(Scan.owner_id == owner_id))
    rows = db.scalars(
        select(Scan)
        .where(Scan.owner_id == owner_id)
        .order_by(Scan.created_at.desc(), Scan.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), total or 0


def count_active(db: Session, owner_id: uuid.UUID) -> int:
    count = db.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.owner_id == owner_id, Scan.status.in_([s.value for s in ACTIVE_STATUSES]))
    )
    return count or 0


def claim_queued(db: Session, scan_id: uuid.UUID) -> bool:
    """queued -> running, atomically. False if it was not queued (cancelled,
    already running, already finished): the caller must then do nothing."""
    stmt = (
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == ScanStatus.QUEUED.value)
        .values(status=ScanStatus.RUNNING.value, started_at=func.now())
        .returning(Scan.id)
        .execution_options(synchronize_session=False)
    )
    return db.execute(stmt).first() is not None


def transition(
    db: Session,
    scan_id: uuid.UUID,
    *,
    expected: Iterable[ScanStatus],
    new: ScanStatus,
    error: str | None = None,
) -> bool:
    """Move a scan to a final state only if it is currently in one of
    ``expected``. Returns whether a row was changed."""
    stmt = (
        update(Scan)
        .where(Scan.id == scan_id, Scan.status.in_([s.value for s in expected]))
        .values(status=new.value, finished_at=func.now(), error=error)
        .returning(Scan.id)
        .execution_options(synchronize_session=False)
    )
    return db.execute(stmt).first() is not None


def set_scanned_addresses(db: Session, scan_id: uuid.UUID, addresses: list[str]) -> None:
    db.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(scanned_addresses=addresses)
        .execution_options(synchronize_session=False)
    )


def fail_stale(
    db: Session,
    *,
    running_before: datetime,
    queued_before: datetime,
    running_message: str,
    queued_message: str,
) -> int:
    """Fail scans stuck in ``running`` (worker died) or ``queued`` (never picked
    up). Returns how many were failed."""
    failed = 0
    for expected, condition, message in (
        (ScanStatus.RUNNING, Scan.started_at < running_before, running_message),
        (ScanStatus.QUEUED, Scan.created_at < queued_before, queued_message),
    ):
        stmt = (
            update(Scan)
            .where(Scan.status == expected.value, condition)
            .values(status=ScanStatus.FAILED.value, finished_at=func.now(), error=message)
            .returning(Scan.id)
            .execution_options(synchronize_session=False)
        )
        failed += len(db.execute(stmt).all())
    return failed
