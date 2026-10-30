"""The Scan model: one scan job.

``target`` is exactly what the user typed. ``scanned_addresses`` records what
the scope policy actually resolved and handed to Nmap, so there is always an
audit answer to "what did this scan really touch?".

Status is a plain string column guarded by a CHECK constraint rather than a
native PostgreSQL ENUM: adding a state later is a simple constraint change
instead of an ``ALTER TYPE`` migration.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from riskreveal.db.base import Base, TimestampMixin
from riskreveal.domain.scanning.enums import ScanStatus

_STATUS_VALUES = ", ".join(f"'{s.value}'" for s in ScanStatus)


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"
    __table_args__ = (
        # The naming convention turns this into ck_scans_status_valid.
        CheckConstraint(f"status IN ({_STATUS_VALUES})", name="status_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ScanStatus.QUEUED.value
    )
    scanned_addresses: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Short, user-safe failure reason. Never raw tracebacks or subprocess output.
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"Scan(id={self.id!r}, target={self.target!r}, status={self.status!r})"
