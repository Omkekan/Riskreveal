"""The Asset model: one row per machine a user has scanned.

Minimal on purpose. Per the revised build order there is no organization,
criticality, tags, MAC-based identity resolution or service inventory yet;
those arrive after the first scan -> findings loop works end to end.

``address`` is the IP the scanner actually reached. For a hostname target the
scope policy resolves the name first and scans the resolved IP, so the
hostname is kept separately as a label.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from riskreveal.db.base import Base, TimestampMixin


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (
        # One row per (owner, IP): re-scanning the same host updates it
        # instead of creating a duplicate.
        UniqueConstraint("owner_id", "address", name="uq_assets_owner_id_address"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    # IPv4 or IPv6 text form. 45 chars is the longest IPv6 text form.
    address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"Asset(id={self.id!r}, address={self.address!r}, hostname={self.hostname!r})"
