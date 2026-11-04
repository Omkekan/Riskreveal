"""Periodic Celery tasks.

Run the scheduler as its own process, next to the worker (Windows is fine)::

    uv run celery -A riskreveal.tasks.celery_app:celery_app beat --loglevel=INFO

Without ``beat`` nothing here runs; the worker still cleans up stuck scans once
at start-up (``scan_tasks._reap_on_worker_start``). Run only ONE beat process.

A schedule entry is either a plain number of seconds (``fail-stale-scans``,
below) or a ``crontab(...)`` for a fixed time of day (the feed syncs): KEV and
EPSS are once-a-day upstream feeds, so a fixed daily time is more honest than
"every N seconds", and makes the two staggered on purpose (EPSS is a much
bigger file -- see ``tasks/feed_tasks.py`` -- so it starts after KEV, not at
the same moment).
"""

from __future__ import annotations

from typing import Any

from celery.schedules import crontab

# Task names are the ``name=`` given in the task modules.
BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "fail-stale-scans": {
        "task": "riskreveal.scan.reap_stale",
        "schedule": 300.0,  # seconds
    },
    "sync-kev": {
        "task": "riskreveal.feeds.sync_kev",
        "schedule": crontab(hour=3, minute=0),  # UTC
    },
    "sync-epss": {
        "task": "riskreveal.feeds.sync_epss",
        "schedule": crontab(hour=3, minute=20),  # UTC; after KEV, see the module docstring
    },
}
