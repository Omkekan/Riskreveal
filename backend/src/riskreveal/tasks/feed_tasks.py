"""Celery tasks that keep the threat-intelligence feeds fresh.

Thin on purpose, like ``scan_tasks``: open a session, call
``domain/intelligence/feed_refresh``, log the outcome. The rules (when to
download, when to skip, what counts as valid) live in that module.

Worth knowing: the Windows ``solo`` worker runs one task at a time, so the daily
EPSS import (about 400,000 rows) delays queued scans by roughly a minute or two.
Set ``FEED_REFRESH_ENABLED=false`` to turn all of this off.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from celery.signals import worker_ready
from sqlalchemy.orm import Session

from riskreveal.config import get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.intelligence import feed_refresh
from riskreveal.domain.intelligence.feed_refresh import RefreshOutcome, RefreshStatus
from riskreveal.tasks.celery_app import celery_app

logger = logging.getLogger("riskreveal.tasks.feeds")


def _run(label: str, refresh: Callable[[Session], RefreshOutcome]) -> None:
    if not get_settings().feed_refresh_enabled:
        logger.info("%s refresh skipped: FEED_REFRESH_ENABLED is false", label)
        return
    try:
        with get_sessionmaker()() as db:
            outcome = refresh(db)
    except Exception:
        # A scheduled job must not crash the scheduler or the worker; the next run retries.
        logger.exception("%s refresh failed unexpectedly", label)
        return
    if outcome.status is RefreshStatus.FAILED:
        logger.error("%s refresh failed: %s", label, outcome.detail)
    else:
        logger.info(
            "%s refresh %s: %s (%d stored, %d skipped)",
            label,
            outcome.status.value,
            outcome.detail,
            outcome.imported,
            outcome.skipped,
        )


@celery_app.task(name="riskreveal.feeds.refresh_kev", ignore_result=True)
def refresh_kev_task() -> None:
    _run("KEV", feed_refresh.refresh_kev)


@celery_app.task(name="riskreveal.feeds.refresh_epss", ignore_result=True)
def refresh_epss_task() -> None:
    _run("EPSS", feed_refresh.refresh_epss)


@worker_ready.connect
def _refresh_feeds_on_worker_start(**_kwargs: object) -> None:
    """Check the feeds when a worker starts, so a laptop that was off at the
    scheduled time catches up without needing the scheduler. The tasks are
    "refresh if stale", so this is cheap when the data is already fresh."""
    if not get_settings().feed_refresh_enabled:
        return
    for task in (refresh_kev_task, refresh_epss_task):
        try:
            task.apply_async()
        except Exception:
            logger.exception("could not queue %s at worker start", task.name)
