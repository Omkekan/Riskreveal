"""Threat-intelligence tables: CISA KEV, FIRST EPSS, NVD CVE records and bookkeeping.

``cve_id`` is plain text, not a foreign key to a CVE table: a feed may list
CVEs we have not ingested yet, and they must still be stored (02_... §4.2).
A CHECK constraint enforces the CVE-id format at the database level too.

These tables are refreshed from the internet, so each is a straight upsert
keyed by CVE id; nothing here is owned by a user.
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
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


class Cve(Base, TimestampMixin):
    """One CVE as published by the NVD (everything except its affected versions)."""

    __tablename__ = "cves"
    __table_args__ = (
        CheckConstraint(f"cve_id ~ '{CVE_ID_SQL_REGEX}'", name="cve_id_format"),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)", name="cvss_score_range"
        ),
    )

    cve_id: Mapped[str] = mapped_column(String(19), primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # The NVD's own label, lower-case (none, low, medium, high, critical).
    cvss_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_modified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"Cve(cve_id={self.cve_id!r})"


class CveRange(Base):
    """One "vulnerable" CPE entry of a CVE: a product and the versions it covers.

    ``position`` is the entry's index within its CVE, so re-importing a CVE can
    replace its rows deterministically. ``cpe_version``/``cpe_update`` are
    spelled out because ``version`` and ``update`` read badly in SQL.
    """

    __tablename__ = "cve_ranges"
    __table_args__ = (Index("ix_cve_ranges_product_key", "part", "vendor", "product"),)

    cve_id: Mapped[str] = mapped_column(
        String(19), ForeignKey("cves.cve_id", ondelete="CASCADE"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, primary_key=True)
    part: Mapped[str] = mapped_column(String(1), nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    cpe_version: Mapped[str] = mapped_column(String(64), nullable=False)
    cpe_update: Mapped[str] = mapped_column(String(64), nullable=False)
    start_including: Mapped[str | None] = mapped_column(String(64), nullable=True)
    start_excluding: Mapped[str | None] = mapped_column(String(64), nullable=True)
    end_including: Mapped[str | None] = mapped_column(String(64), nullable=True)
    end_excluding: Mapped[str | None] = mapped_column(String(64), nullable=True)
    conditional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # vendor:product of the platform(s) a conditional entry needs.
    requires: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)


class CveSync(Base):
    """When we asked the NVD about one exact CPE name, and what it said.

    The cache key is the *CPE name sent to the NVD*, because the NVD answers per
    name. ``found = False`` means the NVD does not know that name (HTTP 404):
    that is "no data", never "no vulnerabilities".
    """

    __tablename__ = "cve_syncs"

    cpe_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    last_success_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    found: Mapped[bool] = mapped_column(Boolean, nullable=False)
    cve_count: Mapped[int] = mapped_column(Integer, nullable=False)

    def __repr__(self) -> str:
        return f"CveSync(cpe_name={self.cpe_name!r})"
