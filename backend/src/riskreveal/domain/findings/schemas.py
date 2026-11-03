"""Response schemas for findings.

``raw_evidence`` is attacker-controlled text (banners and script output from
the scanned host). It is only returned by the detail endpoint, and clients
must display it as plain text, never as HTML.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class VulnerabilityContext(BaseModel):
    """What is known about a finding's CVE *right now*.

    Looked up when the finding is read, not stored on it. ``None`` means
    unknown, which is not zero: a CVE with no EPSS score has ``epss = None``.
    """

    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_vector: str | None = None
    published_at: datetime | None = None
    in_kev: bool = False
    kev_date_added: date | None = None
    kev_ransomware_use: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    epss_date: date | None = None


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
    extra_info: str | None
    cve_id: str | None
    vulnerability: VulnerabilityContext | None = None
    created_at: datetime
    updated_at: datetime


class FindingDetail(FindingRead):
    raw_evidence: str | None


class FindingPage(BaseModel):
    items: list[FindingRead]
    total: int
    limit: int
    offset: int
