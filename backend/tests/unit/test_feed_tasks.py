"""Unit tests for the Celery feed tasks (settings, session and refresh are replaced)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from riskreveal.domain.intelligence import feed_refresh
from riskreveal.domain.intelligence.feed_refresh import RefreshOutcome, RefreshStatus
from riskreveal.tasks import feed_tasks


def _settings(enabled: bool) -> SimpleNamespace:
    return SimpleNamespace(feed_refresh_enabled=enabled)


def _session_factory() -> mock.MagicMock:
    """A stand-in for ``get_sessionmaker()``: calling it yields a session context."""
    factory = mock.MagicMock()
    factory.return_value.__enter__.return_value = mock.sentinel.db
    return factory


def test_task_names_are_the_ones_the_schedule_uses() -> None:
    assert feed_tasks.refresh_kev_task.name == "riskreveal.feeds.refresh_kev"
    assert feed_tasks.refresh_epss_task.name == "riskreveal.feeds.refresh_epss"


def test_a_disabled_feed_refresh_does_nothing_at_all() -> None:
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(False)),
        mock.patch.object(feed_tasks, "get_sessionmaker") as sessionmaker,
        mock.patch.object(feed_refresh, "refresh_kev") as refresh,
    ):
        feed_tasks.refresh_kev_task()
    assert sessionmaker.call_count == 0 and refresh.call_count == 0


def test_the_kev_task_runs_the_refresh_with_a_database_session() -> None:
    outcome = RefreshOutcome(RefreshStatus.IMPORTED, "stored", imported=5)
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(True)),
        mock.patch.object(feed_tasks, "get_sessionmaker", return_value=_session_factory()),
        mock.patch.object(feed_refresh, "refresh_kev", return_value=outcome) as refresh,
        mock.patch.object(feed_tasks, "logger") as log,
    ):
        feed_tasks.refresh_kev_task()
    refresh.assert_called_once_with(mock.sentinel.db)
    assert log.info.call_count == 1 and log.error.call_count == 0


def test_the_epss_task_runs_the_epss_refresh() -> None:
    outcome = RefreshOutcome(RefreshStatus.FRESH, "recent")
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(True)),
        mock.patch.object(feed_tasks, "get_sessionmaker", return_value=_session_factory()),
        mock.patch.object(feed_refresh, "refresh_epss", return_value=outcome) as refresh,
        mock.patch.object(feed_refresh, "refresh_kev") as other,
    ):
        feed_tasks.refresh_epss_task()
    refresh.assert_called_once_with(mock.sentinel.db)
    assert other.call_count == 0


def test_a_failed_refresh_is_logged_as_an_error_and_does_not_raise() -> None:
    outcome = RefreshOutcome(RefreshStatus.FAILED, "EPSS download or validation failed: x")
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(True)),
        mock.patch.object(feed_tasks, "get_sessionmaker", return_value=_session_factory()),
        mock.patch.object(feed_refresh, "refresh_epss", return_value=outcome),
        mock.patch.object(feed_tasks, "logger") as log,
    ):
        feed_tasks.refresh_epss_task()  # must not raise
    assert log.error.call_count == 1 and log.info.call_count == 0


def test_an_unexpected_error_is_logged_and_swallowed_so_the_worker_survives() -> None:
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(True)),
        mock.patch.object(feed_tasks, "get_sessionmaker", return_value=_session_factory()),
        mock.patch.object(feed_refresh, "refresh_kev", side_effect=RuntimeError("db is down")),
        mock.patch.object(feed_tasks, "logger") as log,
    ):
        feed_tasks.refresh_kev_task()  # must not raise
    assert log.exception.call_count == 1


# --- the worker-start hook -----------------------------------------------------


def test_worker_start_queues_both_refreshes_when_enabled() -> None:
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(True)),
        mock.patch.object(feed_tasks, "refresh_kev_task") as kev,
        mock.patch.object(feed_tasks, "refresh_epss_task") as epss,
    ):
        feed_tasks._refresh_feeds_on_worker_start()
    kev.apply_async.assert_called_once_with()
    epss.apply_async.assert_called_once_with()


def test_worker_start_queues_nothing_when_disabled() -> None:
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(False)),
        mock.patch.object(feed_tasks, "refresh_kev_task") as kev,
        mock.patch.object(feed_tasks, "refresh_epss_task") as epss,
    ):
        feed_tasks._refresh_feeds_on_worker_start()
    assert kev.apply_async.call_count == 0 and epss.apply_async.call_count == 0


def test_a_broker_problem_while_queueing_never_stops_the_worker_or_the_other_feed() -> None:
    with (
        mock.patch.object(feed_tasks, "get_settings", return_value=_settings(True)),
        mock.patch.object(feed_tasks, "refresh_kev_task") as kev,
        mock.patch.object(feed_tasks, "refresh_epss_task") as epss,
        mock.patch.object(feed_tasks, "logger") as log,
    ):
        kev.apply_async.side_effect = ConnectionError("broker unreachable")
        feed_tasks._refresh_feeds_on_worker_start()  # must not raise
    epss.apply_async.assert_called_once_with()
    assert log.exception.call_count == 1
