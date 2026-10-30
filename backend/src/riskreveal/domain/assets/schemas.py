"""Response schemas for assets."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    address: str
    hostname: str | None
    os_name: str | None
    last_scanned_at: datetime | None
    created_at: datetime
    updated_at: datetime


class AssetPage(BaseModel):
    items: list[AssetRead]
    total: int
    limit: int
    offset: int
