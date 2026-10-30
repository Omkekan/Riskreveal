"""Celery application.

Run a worker from ``backend/`` (Windows needs the solo pool)::

    uv run celery -A riskreveal.tasks.celery_app:celery_app worker --pool=solo --loglevel=INFO

Design choices:

* **JSON only.** ``accept_content=["json"]``: Celery's pickle serializer would
  let anyone who can write to Redis run code in the worker.
* **No result backend.** Scan state lives in the database; tasks return nothing.
* **Late ack + one task at a time.** A task is acknowledged only after it
  finishes, and the worker reserves just one. A redelivered task is harmless
  because ``run_scan`` claims the scan with a conditional UPDATE.
* **Time limits.** Celery's soft/hard time limits need signals that the Windows
  solo pool does not have; the real limit is the Nmap subprocess timeout set by
  the scan profile.
"""

from __future__ import annotations

from celery import Celery

from riskreveal.config import get_settings


def create_celery_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "riskreveal",
        broker=settings.redis_url,
        include=["riskreveal.tasks.scan_tasks"],
    )
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        task_ignore_result=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True,
        broker_connection_timeout=3,
        # Longer than the longest scan, so Redis does not redeliver a task
        # that is simply still running.
        broker_transport_options={"visibility_timeout": 3600},
        timezone="UTC",
        enable_utc=True,
    )
    return app


celery_app = create_celery_app()
