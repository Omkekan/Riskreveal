"""Scheduled refresh of the KEV and EPSS feeds.

``findings/repository.py`` reads KEV live (a correlated EXISTS against
``kev_entries`` by ``cve_id``) and EPSS the same way elsewhere, rather than
storing either on the finding -- so a finding's KEV/EPSS status is only ever
as fresh as the last successful import. Without ``beat`` running, that import
only happens when someone runs ``load-kev`` / ``load-epss`` by hand (see
``cli/commands.py``). These tasks do the same download-parse-import as those
CLI commands, on a schedule (``tasks/beat_schedule.py``), so a deployment
without an operator running the CLI daily does not silently go stale.

Each task is independent and safe to run on its own cadence or to skip a run
entirely: every import is idempotent (``service.import_kev``/``import_epss``
upsert and commit in one transaction, same as the CLI path), so a failed or
skipped run just leaves yesterday's data in place until the next one
succeeds -- never a partial or corrupt import. Like every other task in this
module, there is no result backend and no retry policy here: a feed that is
briefly unreachable is retried next schedule tick, not by Celery itself.
"""

from __future__ import annotations

import logging

from riskreveal.config import get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.intelligence import service
from riskreveal.domain.intelligence.errors import FeedError
from riskreveal.domain.intelligence.sources import fetch
from riskreveal.domain.intelligence.sources.cisa_kev import KEV_MAX_BYTES, KEV_URL, parse_kev
from riskreveal.domain.intelligence.sources.first_epss import EPSS_MAX_BYTES, EPSS_URL, EpssReader
from riskreveal.tasks.celery_app import celery_app

logger = logging.getLogger("riskreveal.tasks.feeds")


@celery_app.task(name="riskreveal.feeds.sync_kev", ignore_result=True)
def sync_kev_task() -> None:
    """Download and import the CISA KEV catalog. Mirrors ``cli load-kev``.

    A no-op (with a debug log line, not a warning -- this is an expected,
    deliberate configuration, not a problem) when ``feed_sync_enabled`` is
    off; ``cli load-kev`` ignores this setting and always runs.
    """
    if not get_settings().feed_sync_enabled:
        logger.debug("scheduled KEV sync skipped: feed_sync_enabled is false")
        return
    try:
        raw = fetch.download(KEV_URL, max_bytes=KEV_MAX_BYTES)
        catalog = parse_kev(raw)
        with get_sessionmaker()() as db:
            result = service.import_kev(db, catalog)
    except FeedError:
        logger.exception("scheduled KEV sync failed")
        return
    logger.info(
        "scheduled KEV sync: stored %d entries (catalog %s); skipped %d invalid",
        result.imported,
        result.version or "unknown",
        result.skipped,
    )


@celery_app.task(name="riskreveal.feeds.sync_epss", ignore_result=True)
def sync_epss_task() -> None:
    """Download and import the daily FIRST EPSS scores. Mirrors ``cli load-epss``.

    About 300,000 rows; this one call can take noticeably longer than the KEV
    sync, which is why the two are staggered in ``beat_schedule.py`` rather
    than scheduled to start at the same moment. Same ``feed_sync_enabled``
    no-op behaviour as ``sync_kev_task``.
    """
    if not get_settings().feed_sync_enabled:
        logger.debug("scheduled EPSS sync skipped: feed_sync_enabled is false")
        return
    try:
        raw = fetch.download(EPSS_URL, max_bytes=EPSS_MAX_BYTES)
        reader = EpssReader.from_bytes(raw)
        with get_sessionmaker()() as db:
            result = service.import_epss(db, reader)
    except FeedError:
        logger.exception("scheduled EPSS sync failed")
        return
    logger.info(
        "scheduled EPSS sync: stored %d scores (model/date %s); skipped %d invalid rows",
        result.imported,
        result.version,
        result.skipped,
    )
