"""Periodic Celery tasks.

Run the scheduler as its own process, next to the worker (Windows is fine)::

    uv run celery -A riskreveal.tasks.celery_app:celery_app beat --loglevel=INFO

Without ``beat`` nothing here runs; the worker still cleans up stuck scans once
at start-up (``scan_tasks._reap_on_worker_start``). Run only ONE beat process.
"""

from __future__ import annotations

from typing import Any

# Task names are the ``name=`` given in the task modules.
BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "fail-stale-scans": {
        "task": "riskreveal.scan.reap_stale",
        "schedule": 300.0,  # seconds
    },
}
