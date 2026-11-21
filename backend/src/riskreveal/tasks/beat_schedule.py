"""Periodic Celery tasks.

Run the scheduler as its own process, next to the worker (Windows is fine)::

    uv run celery -A riskreveal.tasks.celery_app:celery_app beat --loglevel=INFO

Without ``beat`` nothing here runs; the worker still cleans up stuck scans once
at start-up (``scan_tasks._reap_on_worker_start``) and checks the threat feeds
once at start-up (``feed_tasks._refresh_feeds_on_worker_start``). Run only ONE
beat process.

The feed tasks are "refresh if stale": each one first checks when its feed last
succeeded and does nothing if that was recent, so running them every few hours
is cheap, and a machine that was off at the "right" time simply catches up.
"""

from __future__ import annotations

from typing import Any

# Task names are the ``name=`` given in the task modules.
BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "fail-stale-scans": {
        "task": "riskreveal.scan.reap_stale",
        "schedule": 300.0,  # seconds
    },
    "refresh-kev": {
        "task": "riskreveal.feeds.refresh_kev",
        "schedule": 6 * 3600.0,  # seconds; skips unless the last import is 5+ hours old
    },
    "refresh-epss": {
        "task": "riskreveal.feeds.refresh_epss",
        "schedule": 6 * 3600.0,  # seconds; skips unless the last import is 20+ hours old
    },
}
