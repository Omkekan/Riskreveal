"""Keeping the CISA KEV and FIRST EPSS feeds fresh, without waste.

Findings read KEV and EPSS live, so these two tables are only as good as the last
import. This module is the "refresh if stale" step used by the scheduled worker
tasks and by ``riskreveal.cli refresh-feeds``. It has no Celery in it, so it can
be tested directly.

How it avoids waste (the tasks may run often, and a laptop may be off at the
"right" hour, so they are built to be cheap and to catch up):

1. **Fresh** - if the feed was imported successfully less than ``min_age`` ago,
   nothing is downloaded.
2. **Unchanged** - otherwise the file is downloaded and its version (KEV) or score
   date (EPSS) is compared with what is stored; if it is not newer, nothing is
   written. (EPSS is published once a day, so most checks end here.)
3. Only a genuinely newer file is imported, through the same atomic, validated
   import the CLI uses.

A failed download or an invalid file never raises and never changes the stored
data; it is reported as ``FAILED`` so the caller can log it. Database errors are
not hidden: they propagate.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy.orm import Session

from riskreveal.domain.intelligence import repository, service
from riskreveal.domain.intelligence.errors import FeedError
from riskreveal.domain.intelligence.models import FeedSync
from riskreveal.domain.intelligence.sources.cisa_kev import KEV_MAX_BYTES, KEV_URL, parse_kev
from riskreveal.domain.intelligence.sources.first_epss import (
    EPSS_MAX_BYTES,
    EPSS_URL,
    EpssReader,
)

logger = logging.getLogger("riskreveal.intelligence.refresh")

Downloader = Callable[[str, int], bytes]
"""``download(url, max_bytes) -> body``. Injectable so tests need no network."""


class RefreshStatus(StrEnum):
    IMPORTED = "imported"  # a newer file was downloaded and stored
    FRESH = "fresh"  # updated recently; nothing downloaded
    UNCHANGED = "unchanged"  # downloaded, but not newer than what is stored
    FAILED = "failed"  # download or validation failed; stored data untouched


@dataclass(frozen=True, slots=True)
class RefreshOutcome:
    status: RefreshStatus
    detail: str
    imported: int = 0
    skipped: int = 0


@dataclass(frozen=True, slots=True)
class FeedPolicy:
    min_age: timedelta
    """Younger than this: do not even download."""
    stale_after: timedelta
    """Older than this: ``feed-status`` flags the feed as STALE."""


POLICIES: dict[str, FeedPolicy] = {
    # CISA adds entries on working days, at irregular times: check a few times a day.
    service.SOURCE_KEV: FeedPolicy(min_age=timedelta(hours=5), stale_after=timedelta(hours=48)),
    # EPSS publishes one file per day: re-check about daily; STALE after missing two days.
    service.SOURCE_EPSS: FeedPolicy(min_age=timedelta(hours=20), stale_after=timedelta(hours=72)),
}


def _default_download(url: str, max_bytes: int) -> bytes:
    # Imported here so this module stays importable without the HTTP library.
    from riskreveal.domain.intelligence.sources.fetch import download

    return download(url, max_bytes=max_bytes)


def _is_fresh(sync: FeedSync | None, policy: FeedPolicy, now: datetime) -> bool:
    return sync is not None and (now - sync.last_success_at) < policy.min_age


def refresh_kev(
    db: Session,
    *,
    download: Downloader | None = None,
    now: datetime | None = None,
    force: bool = False,
) -> RefreshOutcome:
    """Refresh the KEV catalog if it is stale. ``force`` skips the freshness checks."""
    current = now or datetime.now(UTC)
    sync = repository.get_sync(db, service.SOURCE_KEV)
    if not force and _is_fresh(sync, POLICIES[service.SOURCE_KEV], current):
        return RefreshOutcome(RefreshStatus.FRESH, "KEV was updated recently; nothing to do.")

    fetch = download or _default_download
    try:
        catalog = parse_kev(fetch(KEV_URL, KEV_MAX_BYTES))
    except FeedError as exc:
        return RefreshOutcome(RefreshStatus.FAILED, f"KEV download or validation failed: {exc}")

    if (
        not force
        and sync is not None
        and sync.version is not None
        and sync.version == catalog.version
    ):
        return RefreshOutcome(
            RefreshStatus.UNCHANGED, f"KEV catalog {catalog.version} is already stored."
        )

    result = service.import_kev(db, catalog)
    return RefreshOutcome(
        RefreshStatus.IMPORTED,
        f"KEV catalog {result.version or 'unknown'} stored.",
        imported=result.imported,
        skipped=result.skipped,
    )


def refresh_epss(
    db: Session,
    *,
    download: Downloader | None = None,
    now: datetime | None = None,
    force: bool = False,
) -> RefreshOutcome:
    """Refresh the EPSS scores if they are stale. ``force`` skips the freshness checks."""
    current = now or datetime.now(UTC)
    sync = repository.get_sync(db, service.SOURCE_EPSS)
    if not force and _is_fresh(sync, POLICIES[service.SOURCE_EPSS], current):
        return RefreshOutcome(RefreshStatus.FRESH, "EPSS was updated recently; nothing to do.")

    fetch = download or _default_download
    try:
        reader = EpssReader.from_bytes(fetch(EPSS_URL, EPSS_MAX_BYTES))
    except FeedError as exc:
        return RefreshOutcome(RefreshStatus.FAILED, f"EPSS download or validation failed: {exc}")

    latest = repository.latest_epss_date(db)
    if not force and latest is not None and reader.score_date <= latest:
        return RefreshOutcome(
            RefreshStatus.UNCHANGED,
            f"EPSS scores for {latest.isoformat()} are already stored; no newer file yet.",
        )

    try:
        result = service.import_epss(db, reader)
    except FeedError as exc:  # too many invalid rows: the import rolled everything back
        return RefreshOutcome(RefreshStatus.FAILED, f"EPSS import refused: {exc}")
    return RefreshOutcome(
        RefreshStatus.IMPORTED,
        f"EPSS scores for {reader.score_date.isoformat()} stored.",
        imported=result.imported,
        skipped=result.skipped,
    )


def describe_age(moment: datetime, now: datetime) -> str:
    """Human-friendly age: ``just now``, ``5 minutes ago``, ``3 hours ago``, ``2 days ago``."""
    seconds = (now - moment).total_seconds()
    if seconds < 60:  # includes a timestamp slightly in the future (clock skew)
        return "just now"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    return f"{days} days ago"


def is_stale(source: str, last_success_at: datetime, now: datetime) -> bool:
    """True if the feed is older than its ``stale_after`` (unknown sources: never)."""
    policy = POLICIES.get(source)
    return policy is not None and (now - last_success_at) > policy.stale_after
