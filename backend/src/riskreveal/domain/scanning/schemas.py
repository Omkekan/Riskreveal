"""Request/response schemas for scans.

``target`` is only checked for shape here (length, not blank). Whether it may
actually be scanned is the scope policy's job, in the service layer.
Profiles are checked against the fixed profile table, so a client can choose
a *name* but can never supply Nmap flags.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from riskreveal.domain.scanning.profiles import DEFAULT_PROFILE, PROFILES
from riskreveal.domain.scanning.scope_policy import MAX_TARGET_LENGTH


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=MAX_TARGET_LENGTH)
    profile: str = Field(default=DEFAULT_PROFILE, min_length=1, max_length=32)

    @field_validator("target")
    @classmethod
    def _strip_target(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("A target is required.")
        return cleaned

    @field_validator("profile")
    @classmethod
    def _known_profile(cls, v: str) -> str:
        if v not in PROFILES:
            raise ValueError(f"Unknown scan profile. Available: {', '.join(sorted(PROFILES))}.")
        return v


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target: str
    profile: str
    status: str
    scanned_addresses: list[str]
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime
    updated_at: datetime


class ScanPage(BaseModel):
    items: list[ScanRead]
    total: int
    limit: int
    offset: int
