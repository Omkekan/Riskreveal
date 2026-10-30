"""Response schemas for findings.

``raw_evidence`` is attacker-controlled text (banners and script output from
the scanned host). It is only returned by the detail endpoint, and clients
must display it as plain text, never as HTML.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    source: str
    confidence: str
    severity: str
    status: str
    title: str
    description: str | None
    port: int | None
    protocol: str | None
    service: str | None
    product: str | None
    version: str | None
    cpe: str | None
    created_at: datetime
    updated_at: datetime


class FindingDetail(FindingRead):
    raw_evidence: str | None


class FindingPage(BaseModel):
    items: list[FindingRead]
    total: int
    limit: int
    offset: int
