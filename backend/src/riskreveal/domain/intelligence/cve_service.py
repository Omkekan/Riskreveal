"""Make sure the CVE data for one detected CPE is stored, fetching it if needed.

* The network fetch happens BEFORE any database write, and never while a
  transaction is open, so a slow or failing NVD cannot hold a connection and a
  failed fetch leaves the previous data untouched.
* A name the NVD does not know (HTTP 404) is remembered for a short time, so it
  is not re-asked on every scan, but only briefly: a rejected API key can look
  the same, and that must not silence a product for a day.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy.orm import Session

from riskreveal.domain.intelligence import cve_repository
from riskreveal.domain.intelligence.cpe import Cpe
from riskreveal.domain.intelligence.errors import FeedFetchError
from riskreveal.domain.intelligence.sources.nvd_client import NvdClient, nvd_cpe_names

logger = logging.getLogger("riskreveal.intelligence.cve")

DEFAULT_CACHE_MAX_AGE = timedelta(hours=24)
NEGATIVE_CACHE_MAX_AGE = timedelta(hours=1)


class DataStatus(StrEnum):
    CACHED = "cached"
    """Fresh data for this CPE was already stored."""
    FETCHED = "fetched"
    """Downloaded from the NVD now."""
    STALE = "stale"
    """Only older stored data is available (no client given)."""
    UNKNOWN_CPE = "unknown_cpe"
    """The NVD does not know any spelling of this CPE."""
    NO_NAME = "no_name"
    """The CPE cannot be turned into a safe NVD name (no version, odd characters)."""
    NOT_STORED = "not_stored"
    """Nothing stored and no client to ask."""


def ensure_cpe_data(
    db: Session,
    cpe: Cpe,
    client: NvdClient | None,
    *,
    max_age: timedelta = DEFAULT_CACHE_MAX_AGE,
    now: datetime | None = None,
    ignore_negative_cache: bool = False,
) -> DataStatus:
    """Return how the data for ``cpe`` stands, fetching it if stale and allowed.

    Raises ``FeedError`` (writing nothing) if the NVD cannot be read.
    """
    names = nvd_cpe_names(cpe)
    if not names:
        return DataStatus.NO_NAME
    current = now if now is not None else datetime.now(UTC)

    syncs = {name: cve_repository.get_sync(db, name) for name in names}

    def fresh_data(name: str) -> bool:
        sync = syncs[name]
        return sync is not None and sync.found and current - sync.last_success_at <= max_age

    def fresh_negative(name: str) -> bool:
        if ignore_negative_cache:  # a manual retry (for example after fixing an API key)
            return False
        sync = syncs[name]
        return (
            sync is not None
            and not sync.found
            and current - sync.last_success_at <= NEGATIVE_CACHE_MAX_AGE
        )

    if any(fresh_data(name) for name in names):
        return DataStatus.CACHED
    if client is None:
        had_old_data = any(s is not None and s.found for s in syncs.values())
        return DataStatus.STALE if had_old_data else DataStatus.NOT_STORED
    askable = [name for name in names if not fresh_negative(name)]
    if not askable:
        return DataStatus.UNKNOWN_CPE

    db.rollback()  # end the read transaction: no connection held during the network call
    missing: list[str] = []
    for name in askable:
        try:
            records = client.fetch_cves(name)
        except FeedFetchError as exc:
            if exc.status_code == 404:
                logger.warning("the NVD does not know the CPE name %s", name)
                missing.append(name)
                continue
            raise
        try:
            count = cve_repository.upsert_records(db, records)
            cve_repository.record_sync(db, name, found=True, count=count, now=current)
            for unknown in missing:  # remember the spellings that did not work
                cve_repository.record_sync(db, unknown, found=False, count=0, now=current)
            db.commit()
        except Exception:
            db.rollback()
            raise
        logger.info("stored %d CVEs for %s", count, name)
        return DataStatus.FETCHED

    for name in missing:
        cve_repository.record_sync(db, name, found=False, count=0, now=current)
    db.commit()
    return DataStatus.UNKNOWN_CPE
