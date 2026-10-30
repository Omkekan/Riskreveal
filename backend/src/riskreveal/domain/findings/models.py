"""The Finding model: one thing a scan found on one asset.

For now every finding comes from Nmap and is informational ("port 22/tcp is
open, running OpenSSH 6.6.1"). Vulnerability findings (CVE matches, Nuclei,
NSE vuln scripts) arrive with the intelligence pipeline and reuse this table.

Deliberately NOT here yet, to keep the migration small: cross-scan
de-duplication (``first_seen``/``last_seen``), ``cve_id``, CVSS / EPSS / KEV,
``risk_score``, ``verification``. Adding columns later is an additive
migration.
"""

from __future__ import annotations

import uuid
from enum import StrEnum

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from riskreveal.db.base import Base, TimestampMixin
from riskreveal.domain.findings.enums import Confidence, FindingSource, FindingStatus, Severity


def _in_list(column: str, enum_cls: type[StrEnum]) -> str:
    values = ", ".join(f"'{member.value}'" for member in enum_cls)
    return f"{column} IN ({values})"


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        # The naming convention prefixes these: ck_findings_severity_valid, ...
        CheckConstraint(_in_list("severity", Severity), name="severity_valid"),
        CheckConstraint(_in_list("confidence", Confidence), name="confidence_valid"),
        CheckConstraint(_in_list("status", FindingStatus), name="status_valid"),
        CheckConstraint(_in_list("source", FindingSource), name="source_valid"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    # Findings attach to the asset (the IP), never to "port 80 of whatever
    # host" -- that was the wrong-host bug in the old codebase (01_... #8).
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(32), nullable=False, default=FindingSource.NMAP.value
    )
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidence.DETECTED.value
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.INFO.value
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=FindingStatus.OPEN.value
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(8), nullable=True)
    service: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cpe: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Raw tool output kept as evidence. Treat as attacker-controlled DATA:
    # banners come from the scanned host. Never render it as HTML, and never
    # put it into an AI prompt as if it were instructions.
    raw_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"Finding(id={self.id!r}, title={self.title!r}, severity={self.severity!r})"
