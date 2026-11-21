"""Integration tests: "refresh if stale" against a real (throwaway) PostgreSQL.

Needs Docker Desktop. Uses the shared ``api_app`` fixture (a testcontainers database
named ``riskreveal_test``); the development database is never touched. The network
is replaced by a fake downloader. The fixtures are SYNTHETIC (CVE-2099-xxxx).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from riskreveal.domain.intelligence import feed_refresh, repository, service
from riskreveal.domain.intelligence.errors import FeedFetchError
from riskreveal.domain.intelligence.feed_refresh import RefreshStatus
from riskreveal.domain.intelligence.models import EpssScore, KevEntry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
KEV_BYTES = (FIXTURES / "kev_sample.json").read_bytes()  # catalog version 2026.10.28


class Downloader:
    def __init__(self, answer: bytes | Exception) -> None:
        self.answer = answer
        self.calls = 0

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.calls += 1
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def db(api_app: FastAPI) -> Iterator[Session]:
    from riskreveal.db.session import get_engine, get_sessionmaker

    # These tables are TRUNCATEd below: refuse anything but the throwaway database.
    assert get_engine().url.database == "riskreveal_test"
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE TABLE kev_entries, epss_scores, feed_syncs"))
    with get_sessionmaker()() as session:
        yield session


def _later(hours: int) -> datetime:
    return datetime.now(UTC) + timedelta(hours=hours)


def _epss_file(score_date: str, *rows: str) -> bytes:
    header = f"#model_version:v2025.03.14,score_date:{score_date}T00:00:00Z"
    return "\n".join([header, "cve,epss,percentile", *rows]).encode()


def _score(db: Session, cve_id: str) -> float | None:
    db.expire_all()
    row = db.get(EpssScore, cve_id)
    return None if row is None else row.score


def _count(db: Session, model: type[KevEntry] | type[EpssScore]) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0


# --- KEV -------------------------------------------------------------------------


def test_kev_is_imported_when_nothing_is_stored(db: Session) -> None:
    downloader = Downloader(KEV_BYTES)
    outcome = feed_refresh.refresh_kev(db, download=downloader)
    assert outcome.status is RefreshStatus.IMPORTED and outcome.imported == 3
    assert downloader.calls == 1 and _count(db, KevEntry) == 3
    sync = repository.get_sync(db, service.SOURCE_KEV)
    assert sync is not None and sync.version == "2026.10.28"


def test_a_second_refresh_straight_after_downloads_nothing(db: Session) -> None:
    feed_refresh.refresh_kev(db, download=Downloader(KEV_BYTES))
    downloader = Downloader(KEV_BYTES)
    outcome = feed_refresh.refresh_kev(db, download=downloader)
    assert outcome.status is RefreshStatus.FRESH and downloader.calls == 0


def test_a_stale_check_with_the_same_catalog_writes_nothing(db: Session) -> None:
    feed_refresh.refresh_kev(db, download=Downloader(KEV_BYTES))
    before = repository.get_sync(db, service.SOURCE_KEV)
    assert before is not None
    stamp = before.last_success_at

    downloader = Downloader(KEV_BYTES)
    outcome = feed_refresh.refresh_kev(db, download=downloader, now=_later(6))
    assert outcome.status is RefreshStatus.UNCHANGED and downloader.calls == 1
    db.expire_all()
    after = repository.get_sync(db, service.SOURCE_KEV)
    assert after is not None and after.last_success_at == stamp


def test_a_newer_catalog_updates_the_stored_entries(db: Session) -> None:
    feed_refresh.refresh_kev(db, download=Downloader(KEV_BYTES))
    newer = KEV_BYTES.replace(b"2026.10.28", b"2026.10.30").replace(
        b"ExampleServer Remote Code Execution", b"ExampleServer RCE (renamed)"
    )
    assert newer != KEV_BYTES

    outcome = feed_refresh.refresh_kev(db, download=Downloader(newer), now=_later(6))
    assert outcome.status is RefreshStatus.IMPORTED
    db.expire_all()
    entry = db.get(KevEntry, "CVE-2099-0001")
    assert entry is not None and "renamed" in entry.vulnerability_name
    sync = repository.get_sync(db, service.SOURCE_KEV)
    assert sync is not None and sync.version == "2026.10.30"


def test_a_failed_kev_download_leaves_the_stored_data_alone(db: Session) -> None:
    feed_refresh.refresh_kev(db, download=Downloader(KEV_BYTES))
    outage = Downloader(FeedFetchError("The feed server answered HTTP 503.", status_code=503))
    outcome = feed_refresh.refresh_kev(db, download=outage, now=_later(6))
    assert outcome.status is RefreshStatus.FAILED
    assert _count(db, KevEntry) == 3
    sync = repository.get_sync(db, service.SOURCE_KEV)
    assert sync is not None and sync.version == "2026.10.28"


def test_force_refreshes_even_when_recent_and_unchanged(db: Session) -> None:
    feed_refresh.refresh_kev(db, download=Downloader(KEV_BYTES))
    downloader = Downloader(KEV_BYTES)
    outcome = feed_refresh.refresh_kev(db, download=downloader, force=True)
    assert outcome.status is RefreshStatus.IMPORTED and downloader.calls == 1


# --- EPSS ------------------------------------------------------------------------


def test_epss_is_imported_when_nothing_is_stored(db: Session) -> None:
    assert repository.latest_epss_date(db) is None
    file = _epss_file("2026-10-28", "CVE-2099-0001,0.50,0.50", "CVE-2099-0002,0.10,0.10")
    outcome = feed_refresh.refresh_epss(db, download=Downloader(file))
    assert outcome.status is RefreshStatus.IMPORTED and outcome.imported == 2
    assert repository.latest_epss_date(db) == date(2026, 10, 28)


def test_a_stale_check_with_the_same_score_date_changes_nothing(db: Session) -> None:
    file = _epss_file("2026-10-28", "CVE-2099-0001,0.50,0.50")
    feed_refresh.refresh_epss(db, download=Downloader(file))
    outcome = feed_refresh.refresh_epss(db, download=Downloader(file), now=_later(21))
    assert outcome.status is RefreshStatus.UNCHANGED
    assert _score(db, "CVE-2099-0001") == pytest.approx(0.50)


def test_a_newer_epss_file_updates_the_scores(db: Session) -> None:
    first = _epss_file("2026-10-28", "CVE-2099-0001,0.5,0.5")
    feed_refresh.refresh_epss(db, download=Downloader(first))
    newer = _epss_file("2026-10-29", "CVE-2099-0001,0.10,0.20", "CVE-2099-0003,0.30,0.40")
    outcome = feed_refresh.refresh_epss(db, download=Downloader(newer), now=_later(21))
    assert outcome.status is RefreshStatus.IMPORTED
    assert _score(db, "CVE-2099-0001") == pytest.approx(0.10)
    assert _score(db, "CVE-2099-0003") == pytest.approx(0.30)
    assert repository.latest_epss_date(db) == date(2026, 10, 29)


def test_an_older_epss_file_never_rolls_the_scores_back(db: Session) -> None:
    first = _epss_file("2026-10-28", "CVE-2099-0001,0.5,0.5")
    feed_refresh.refresh_epss(db, download=Downloader(first))
    older = _epss_file("2026-10-20", "CVE-2099-0001,0.99,0.99")
    outcome = feed_refresh.refresh_epss(db, download=Downloader(older), now=_later(21))
    assert outcome.status is RefreshStatus.UNCHANGED
    assert _score(db, "CVE-2099-0001") == pytest.approx(0.5)


def test_a_mostly_invalid_epss_file_is_refused_and_changes_nothing(db: Session) -> None:
    first = _epss_file("2026-10-28", "CVE-2099-0001,0.5,0.5")
    feed_refresh.refresh_epss(db, download=Downloader(first))
    garbage = _epss_file("2026-10-30", "CVE-2099-0001,0.9,0.9", *["garbage"] * 5)
    outcome = feed_refresh.refresh_epss(db, download=Downloader(garbage), now=_later(21))
    assert outcome.status is RefreshStatus.FAILED and "too many invalid" in outcome.detail
    assert _score(db, "CVE-2099-0001") == pytest.approx(0.5)  # the good row was rolled back too
    assert repository.latest_epss_date(db) == date(2026, 10, 28)


def test_a_failed_epss_download_leaves_the_stored_data_alone(db: Session) -> None:
    first = _epss_file("2026-10-28", "CVE-2099-0001,0.5,0.5")
    feed_refresh.refresh_epss(db, download=Downloader(first))
    outage = Downloader(FeedFetchError("The feed download took too long."))
    outcome = feed_refresh.refresh_epss(db, download=outage, now=_later(21))
    assert outcome.status is RefreshStatus.FAILED
    assert _score(db, "CVE-2099-0001") == pytest.approx(0.5)
