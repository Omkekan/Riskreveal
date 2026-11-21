"""The beat schedule must only name tasks that exist, and check the feeds often enough.

A typo in a task name is silent in production: the scheduler just logs an error and
the job never runs. These tests make that mistake loud.
"""

from __future__ import annotations

import subprocess
import sys
from datetime import timedelta

from riskreveal.domain.intelligence import service
from riskreveal.domain.intelligence.feed_refresh import POLICIES
from riskreveal.tasks.beat_schedule import BEAT_SCHEDULE
from riskreveal.tasks.celery_app import celery_app

FEED_ENTRIES = {
    "refresh-kev": service.SOURCE_KEV,
    "refresh-epss": service.SOURCE_EPSS,
}


def test_every_scheduled_task_is_a_registered_task() -> None:
    celery_app.loader.import_default_modules()  # loads the modules named in ``include``
    registered = set(celery_app.tasks)
    for name, entry in BEAT_SCHEDULE.items():
        assert entry["task"] in registered, f"{name!r} schedules unknown task {entry['task']!r}"


def test_celery_loads_the_task_modules_on_its_own() -> None:
    """In a fresh interpreter, where no test has imported ``feed_tasks`` already.

    The check above cannot catch a module missing from ``include``: other tests import
    the module directly, which registers its tasks anyway. A real worker only has
    ``include`` to go on, so ask a clean process what Celery registers by itself.
    """
    code = (
        "from riskreveal.tasks.celery_app import celery_app\n"
        "celery_app.loader.import_default_modules()\n"
        "print('\\n'.join(sorted(celery_app.tasks)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=False
    )
    assert result.returncode == 0, result.stderr
    names = set(result.stdout.split())
    assert {"riskreveal.scan.run", "riskreveal.scan.reap_stale"} <= names
    assert {"riskreveal.feeds.refresh_kev", "riskreveal.feeds.refresh_epss"} <= names


def test_the_feed_entries_and_the_reaper_are_all_present() -> None:
    assert {"fail-stale-scans", *FEED_ENTRIES} <= set(BEAT_SCHEDULE)


def test_every_schedule_is_a_positive_number_of_seconds() -> None:
    for name, entry in BEAT_SCHEDULE.items():
        schedule = entry["schedule"]
        assert isinstance(schedule, int | float) and schedule > 0, name


def test_no_task_is_scheduled_twice() -> None:
    tasks = [entry["task"] for entry in BEAT_SCHEDULE.values()]
    assert len(tasks) == len(set(tasks))


def test_feeds_are_checked_several_times_before_they_would_count_as_stale() -> None:
    for entry_name, source in FEED_ENTRIES.items():
        interval = timedelta(seconds=BEAT_SCHEDULE[entry_name]["schedule"])
        assert interval <= POLICIES[source].stale_after / 4, entry_name


def test_a_failed_attempt_still_leaves_time_to_recover_before_the_feed_is_stale() -> None:
    # Worst case before a refresh is attempted: it was just refreshed (min_age), then the
    # next scheduled check (interval). Staying within half the stale threshold means one
    # failed attempt (a network blip) can happen without the feed being flagged STALE.
    for entry_name, source in FEED_ENTRIES.items():
        interval = timedelta(seconds=BEAT_SCHEDULE[entry_name]["schedule"])
        policy = POLICIES[source]
        assert interval + policy.min_age <= policy.stale_after / 2, entry_name
