"""Data access for assets. Nothing here commits; the service layer does."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from riskreveal.domain.assets.models import Asset


def upsert(
    db: Session,
    *,
    owner_id: uuid.UUID,
    address: str,
    hostname: str | None,
    os_name: str | None,
) -> uuid.UUID:
    """Insert the asset or update the existing (owner, address) row; return its id.

    Re-scanning a host refreshes ``last_scanned_at`` and fills in a hostname /
    OS name when the new scan knows one, but never blanks out a known value.
    """
    insert_stmt = pg_insert(Asset).values(
        owner_id=owner_id,
        address=address,
        hostname=hostname,
        os_name=os_name,
        last_scanned_at=func.now(),
    )
    stmt = insert_stmt.on_conflict_do_update(
        constraint="uq_assets_owner_id_address",
        set_={
            "hostname": func.coalesce(insert_stmt.excluded.hostname, Asset.hostname),
            "os_name": func.coalesce(insert_stmt.excluded.os_name, Asset.os_name),
            "last_scanned_at": func.now(),
            "updated_at": func.now(),
        },
    ).returning(Asset.id)
    return db.execute(stmt).scalar_one()


def get_for_owner(db: Session, asset_id: uuid.UUID, owner_id: uuid.UUID) -> Asset | None:
    return db.scalar(select(Asset).where(Asset.id == asset_id, Asset.owner_id == owner_id))


def list_for_owner(
    db: Session, owner_id: uuid.UUID, *, limit: int, offset: int
) -> tuple[list[Asset], int]:
    total = db.scalar(select(func.count()).select_from(Asset).where(Asset.owner_id == owner_id))
    rows = db.scalars(
        select(Asset)
        .where(Asset.owner_id == owner_id)
        .order_by(Asset.address, Asset.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return list(rows), total or 0
