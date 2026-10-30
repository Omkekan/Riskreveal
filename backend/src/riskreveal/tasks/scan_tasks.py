"""Celery tasks for scanning.

The tasks are thin: open a database session, call the service, close it. All
logic (and all safety rules) live in ``domain/scanning/service.py``.
"""

from __future__ import annotations

import logging
import uuid

from celery.signals import worker_ready

from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.scanning import service
from riskreveal.tasks.celery_app import celery_app

logger = logging.getLogger("riskreveal.tasks.scan")


@celery_app.task(name="riskreveal.scan.run", ignore_result=True)
def run_scan_task(scan_id: str) -> None:
    try:
        parsed = uuid.UUID(scan_id)
    except ValueError:
        logger.error("run_scan_task received an invalid scan id")
        return
    with get_sessionmaker()() as db:
        service.run_scan(db, parsed)


@celery_app.task(name="riskreveal.scan.reap_stale", ignore_result=True)
def reap_stale_scans_task() -> None:
    with get_sessionmaker()() as db:
        service.fail_stale_scans(db)


def dispatch_scan(scan_id: uuid.UUID) -> None:
    """Put a scan on the queue. Raises if the broker is unreachable."""
    run_scan_task.apply_async(
        args=[str(scan_id)],
        retry=True,
        retry_policy={
            "max_retries": 2,
            "interval_start": 0,
            "interval_step": 0.2,
            "interval_max": 0.5,
        },
    )


@worker_ready.connect
def _reap_on_worker_start(**_kwargs: object) -> None:
    """A scan left ``running`` by a crashed worker would otherwise stay that
    way forever. Clean up when a worker starts."""
    try:
        reap_stale_scans_task()
    except Exception:
        logger.exception("could not reap stale scans at worker start")
