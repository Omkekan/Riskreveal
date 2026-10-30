"""CISA Known Exploited Vulnerabilities (KEV) catalog: parser only.

Pure: no network and no database, so it can be tested with plain files. The
official JSON feed is at ``KEV_URL`` and looks like::

    {"title": "...", "catalogVersion": "2026.10.28", "dateReleased": "...",
     "count": 1234, "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
         "vulnerabilityName": "...", "dateAdded": "2021-12-10",
         "shortDescription": "...", "requiredAction": "...", "dueDate": "2021-12-24",
         "knownRansomwareCampaignUse": "Known", "notes": "...", "cwes": ["CWE-20"]}]}

Rules (from the plan: one bad record never discards a batch, but a mostly
broken file must not be accepted either):

* An entry without a valid CVE id or a valid ``dateAdded`` is skipped and counted.
* If more than ``max_invalid_fraction`` of the entries are skipped, or none are
  valid, the whole catalog is refused.
* A duplicate CVE id keeps the later entry.
* Every string is cleaned and clipped to its column size.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date

from riskreveal.domain.intelligence.cve_id import normalize_cve_id
from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.sources.textutil import clean_text

logger = logging.getLogger("riskreveal.intelligence.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_BYTES = 20 * 1024 * 1024
DEFAULT_MAX_INVALID_FRACTION = 0.02

_MAX_CWES = 50


@dataclass(frozen=True, slots=True)
class KevRecord:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    short_description: str | None
    required_action: str | None
    due_date: date | None
    known_ransomware_use: bool
    notes: str | None
    cwes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KevCatalog:
    version: str | None
    records: tuple[KevRecord, ...]
    skipped: int


def _parse_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


def _parse_entry(entry: object) -> KevRecord | None:
    if not isinstance(entry, dict):
        return None
    cve_id = normalize_cve_id(entry.get("cveID"))
    date_added = _parse_date(entry.get("dateAdded"))
    if cve_id is None or date_added is None:
        return None

    raw_cwes = entry.get("cwes")
    cwes: tuple[str, ...] = ()
    if isinstance(raw_cwes, list):
        cleaned = (clean_text(item, 32) for item in raw_cwes[:_MAX_CWES])
        cwes = tuple(item for item in cleaned if item)

    ransomware = str(entry.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"
    return KevRecord(
        cve_id=cve_id,
        vendor_project=clean_text(entry.get("vendorProject"), 255) or "Unknown",
        product=clean_text(entry.get("product"), 255) or "Unknown",
        vulnerability_name=clean_text(entry.get("vulnerabilityName"), 512) or cve_id,
        date_added=date_added,
        short_description=clean_text(entry.get("shortDescription"), 8000),
        required_action=clean_text(entry.get("requiredAction"), 8000),
        # A missing or unreadable due date must not lose a known-exploited CVE.
        due_date=_parse_date(entry.get("dueDate")),
        known_ransomware_use=ransomware,
        notes=clean_text(entry.get("notes"), 8000),
        cwes=cwes,
    )


def parse_kev(
    raw: bytes | str, *, max_invalid_fraction: float = DEFAULT_MAX_INVALID_FRACTION
) -> KevCatalog:
    """Parse the KEV JSON catalog. Raises :class:`FeedParseError` if unusable."""
    if len(raw) > KEV_MAX_BYTES:
        raise FeedParseError("The KEV catalog is larger than the allowed maximum size.")
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise FeedParseError("The KEV catalog is not valid JSON.") from exc
    if not isinstance(document, dict):
        raise FeedParseError("The KEV catalog has an unexpected shape.")
    entries = document.get("vulnerabilities")
    if not isinstance(entries, list):
        raise FeedParseError("The KEV catalog has no 'vulnerabilities' list.")

    records: dict[str, KevRecord] = {}
    skipped = 0
    for entry in entries:
        record = _parse_entry(entry)
        if record is None:
            skipped += 1
            continue
        records[record.cve_id] = record  # a later duplicate replaces an earlier one

    if not records:
        raise FeedParseError("The KEV catalog contains no valid entries.")
    if skipped / len(entries) > max_invalid_fraction:
        raise FeedParseError(
            f"The KEV catalog has too many invalid entries ({skipped} of {len(entries)})."
        )
    if skipped:
        logger.warning("KEV catalog: skipped %d invalid entries out of %d", skipped, len(entries))

    version = clean_text(document.get("catalogVersion"), 64) or clean_text(
        document.get("dateReleased"), 64
    )
    return KevCatalog(version=version, records=tuple(records.values()), skipped=skipped)
