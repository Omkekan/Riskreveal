"""Read queries for findings, always scoped to the owning user.

Findings have no ``owner_id`` of their own: ownership comes from the scan that
produced them, so every query joins ``scans`` and filters on its owner. A
finding that belongs to someone else is indistinguishable from one that does
not exist.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from riskreveal.domain.findings.models import Finding
from riskreveal.domain.scanning.models import Scan


def get_for_owner(db: Session, finding_id: uuid.UUID, owner_id: uuid.UUID) -> Finding | None:
    return db.scalar(
        select(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .where(Finding.id == finding_id, Scan.owner_id == owner_id)
    )


def list_for_owner(
    db: Session,
    owner_id: uuid.UUID,
    *,
    scan_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    severity: str | None,
    limit: int,
    offset: int,
) -> tuple[list[Finding], int]:
    base = select(Finding).join(Scan, Scan.id == Finding.scan_id).where(Scan.owner_id == owner_id)
    if scan_id is not None:
        base = base.where(Finding.scan_id == scan_id)
    if asset_id is not None:
        base = base.where(Finding.asset_id == asset_id)
    if severity is not None:
        base = base.where(Finding.severity == severity)

    total = db.scalar(select(func.count()).select_from(base.subquery()))
    rows = db.scalars(
        base.order_by(Finding.created_at.desc(), Finding.id).limit(limit).offset(offset)
    ).all()
    return list(rows), total or 0
