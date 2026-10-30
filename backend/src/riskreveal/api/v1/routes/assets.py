"""Asset routes (read-only), scoped to the authenticated user.

No ``from __future__ import annotations``, matching the other route modules.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from riskreveal.core.pagination import Pagination
from riskreveal.db.session import get_db
from riskreveal.dependencies import CurrentUser
from riskreveal.domain.assets import repository
from riskreveal.domain.assets.schemas import AssetPage, AssetRead

router = APIRouter(prefix="/assets", tags=["assets"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=AssetPage)
def list_assets(current_user: CurrentUser, db: DbSession, page: Pagination) -> AssetPage:
    assets, total = repository.list_for_owner(
        db, current_user.id, limit=page.limit, offset=page.offset
    )
    return AssetPage(
        items=[AssetRead.model_validate(a) for a in assets],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{asset_id}", response_model=AssetRead)
def read_asset(asset_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> AssetRead:
    asset = repository.get_for_owner(db, asset_id, current_user.id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found.")
    return AssetRead.model_validate(asset)
