"""Threat-intelligence tables: CISA KEV, FIRST EPSS and feed bookkeeping.

``cve_id`` is plain text, not a foreign key to a CVE table: a feed may list
CVEs we have not ingested yet, and they must still be stored (02_... §4.2).
A CHECK constraint enforces the CVE-id format at the database level too.

These tables are refreshed from the internet, so each is a straight upsert
keyed by CVE id; nothing here is owned by a user.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, CheckConstraint, Date, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from riskreveal.db.base import Base, TimestampMixin
from riskreveal.domain.intelligence.cve_id import CVE_ID_SQL_REGEX


class KevEntry(Base, TimestampMixin):
    """A CVE that CISA lists as known to be exploited in the wild."""

    __tablename__ = "kev_entries"
    __table_args__ = (
        # Named ck_kev_entries_cve_id_format by the naming convention.
        CheckConstraint(f"cve_id ~ '{CVE_ID_SQL_REGEX}'", name="cve_id_format"),
    )

    cve_id: Mapped[str] = mapped_column(String(19), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_name: Mapped[str] = mapped_column(String(512), nullable=False)
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    short_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    known_ransomware_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    def __repr__(self) -> str:
        return f"KevEntry(cve_id={self.cve_id!r})"


class EpssScore(Base, TimestampMixin):
    """The latest EPSS probability (0..1) and percentile for a CVE."""

    __tablename__ = "epss_scores"
    __table_args__ = (
        CheckConstraint(f"cve_id ~ '{CVE_ID_SQL_REGEX}'", name="cve_id_format"),
        CheckConstraint("score >= 0 AND score <= 1", name="score_range"),
        CheckConstraint("percentile >= 0 AND percentile <= 1", name="percentile_range"),
    )

    cve_id: Mapped[str] = mapped_column(String(19), primary_key=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    # The date the score was computed (from the file header), NOT the import
    # date. An older file never overwrites a newer score.
    score_date: Mapped[date] = mapped_column(Date, nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)

    def __repr__(self) -> str:
        return f"EpssScore(cve_id={self.cve_id!r}, score={self.score!r})"


class FeedSync(Base):
    """When each feed was last imported successfully (feed health, 02_... Phase 2)."""

    __tablename__ = "feed_syncs"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_success_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Catalog version (KEV) or "model_version / score_date" (EPSS).
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)

    def __repr__(self) -> str:
        return f"FeedSync(source={self.source!r})"
