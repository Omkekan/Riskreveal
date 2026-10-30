"""Integration tests: import KEV / EPSS into a real (throwaway) PostgreSQL.

Needs Docker Desktop. Uses the shared ``api_app`` fixture, which creates every
table from the models in a testcontainers database named ``riskreveal_test``;
the development database is never touched. The fixtures are SYNTHETIC.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date
from pathlib import Path

import pytest
from fastapi import FastAPI
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from riskreveal.domain.intelligence import repository, service
from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.models import EpssScore, FeedSync, KevEntry
from riskreveal.domain.intelligence.sources.cisa_kev import parse_kev
from riskreveal.domain.intelligence.sources.first_epss import EpssReader

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture
def db(api_app: FastAPI) -> Iterator[Session]:
    from riskreveal.db.session import get_engine, get_sessionmaker

    # These tables are TRUNCATEd below: refuse anything but the throwaway database.
    assert get_engine().url.database == "riskreveal_test"
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE TABLE kev_entries, epss_scores, feed_syncs"))
    with get_sessionmaker()() as session:
        yield session


def _epss(score_date: str, *rows: str) -> EpssReader:
    header = f"#model_version:v2025.03.14,score_date:{score_date}T00:00:00Z"
    return EpssReader([header, "cve,epss,percentile", *rows])


def _count(db: Session, model: type[KevEntry] | type[EpssScore] | type[FeedSync]) -> int:
    return db.scalar(select(func.count()).select_from(model)) or 0


# --- KEV ---------------------------------------------------------------


def test_kev_import_stores_entries_and_records_the_sync(db: Session) -> None:
    catalog = parse_kev((FIXTURES / "kev_sample.json").read_bytes())
    result = service.import_kev(db, catalog)

    assert (result.imported, result.skipped, result.version) == (3, 0, "2026.10.28")
    assert _count(db, KevEntry) == 3
    first = db.get(KevEntry, "CVE-2099-0001")
    assert first is not None
    assert first.known_ransomware_use is True
    assert first.date_added == date(2026, 10, 1)
    assert first.due_date == date(2026, 10, 22)
    assert first.cwes == ["CWE-78", "CWE-20"]
    sync = db.get(FeedSync, "cisa_kev")
    assert sync is not None and sync.record_count == 3 and sync.version == "2026.10.28"


def test_kev_import_is_idempotent_and_refreshes_changed_entries(db: Session) -> None:
    raw = (FIXTURES / "kev_sample.json").read_bytes()
    service.import_kev(db, parse_kev(raw))
    changed = raw.replace(b"ExampleServer Remote Code Execution", b"ExampleServer RCE (renamed)")
    assert changed != raw
    service.import_kev(db, parse_kev(changed))

    assert _count(db, KevEntry) == 3
    assert _count(db, FeedSync) == 1
    db.expire_all()
    entry = db.get(KevEntry, "CVE-2099-0001")
    assert entry is not None and "renamed" in entry.vulnerability_name


def test_cve_id_check_constraint_is_enforced_by_the_database(db: Session) -> None:
    with pytest.raises(IntegrityError):
        db.execute(
            text(
                "INSERT INTO kev_entries (cve_id, vendor_project, product, vulnerability_name, "
                "date_added, known_ransomware_use, cwes) "
                "VALUES ('NOT-A-CVE', 'v', 'p', 'n', '2026-01-01', false, '[]')"
            )
        )
    db.rollback()
    assert _count(db, KevEntry) == 0


# --- EPSS --------------------------------------------------------------


def test_epss_import_stores_scores(db: Session) -> None:
    reader = EpssReader.from_bytes((FIXTURES / "epss_sample.csv").read_bytes())
    result = service.import_epss(db, reader)

    assert (result.imported, result.skipped) == (3, 0)
    assert _count(db, EpssScore) == 3
    score = db.get(EpssScore, "CVE-2099-0001")
    assert score is not None
    assert score.score == pytest.approx(0.97331)
    assert score.percentile == pytest.approx(0.99988)
    assert score.score_date == date(2026, 10, 28)
    assert score.model_version == "v2025.03.14"
    sync = db.get(FeedSync, "first_epss")
    assert sync is not None and sync.record_count == 3
    assert sync.version == "v2025.03.14 / 2026-10-28"


def test_a_newer_epss_file_updates_but_an_older_one_never_rolls_back(db: Session) -> None:
    service.import_epss(db, _epss("2026-10-20", "CVE-2099-0001,0.10,0.10"))
    service.import_epss(db, _epss("2026-10-28", "CVE-2099-0001,0.90,0.95"))
    service.import_epss(db, _epss("2026-10-10", "CVE-2099-0001,0.05,0.05"))  # old file replayed

    db.expire_all()
    score = db.get(EpssScore, "CVE-2099-0001")
    assert score is not None
    assert (score.score, score.score_date) == (pytest.approx(0.90), date(2026, 10, 28))


def test_same_day_reimport_is_allowed(db: Session) -> None:
    service.import_epss(db, _epss("2026-10-28", "CVE-2099-0001,0.10,0.10"))
    service.import_epss(db, _epss("2026-10-28", "CVE-2099-0001,0.20,0.20"))
    db.expire_all()
    score = db.get(EpssScore, "CVE-2099-0001")
    assert score is not None and score.score == pytest.approx(0.20)


def test_duplicate_cve_inside_one_file_does_not_crash_the_import(db: Session) -> None:
    result = service.import_epss(
        db, _epss("2026-10-28", "CVE-2099-0001,0.10,0.10", "CVE-2099-0001,0.30,0.30")
    )
    assert result.imported == 1
    score = db.get(EpssScore, "CVE-2099-0001")
    assert score is not None and score.score == pytest.approx(0.30)  # later row wins


def test_mostly_invalid_epss_file_is_rolled_back_completely(db: Session) -> None:
    good = [f"CVE-2099-{n:04d},0.5,0.5" for n in range(1, 6)]
    bad = ["garbage"] * 5
    with pytest.raises(FeedParseError, match="too many invalid"):
        service.import_epss(db, _epss("2026-10-28", *good, *bad))
    assert _count(db, EpssScore) == 0  # the 5 good rows were rolled back too
    assert _count(db, FeedSync) == 0


def test_empty_epss_file_is_refused(db: Session) -> None:
    with pytest.raises(FeedParseError, match="no valid scores"):
        service.import_epss(db, _epss("2026-10-28"))
    assert _count(db, FeedSync) == 0


def test_a_failed_import_keeps_the_previous_good_data(db: Session) -> None:
    service.import_epss(db, _epss("2026-10-20", "CVE-2099-0001,0.10,0.10"))
    with pytest.raises(FeedParseError):
        bad_file = _epss("2026-10-28", "CVE-2099-0001,0.99,0.99", "garbage", "garbage")
        service.import_epss(db, bad_file)
    db.expire_all()
    score = db.get(EpssScore, "CVE-2099-0001")
    assert score is not None and score.score == pytest.approx(0.10)


def test_epss_import_spanning_several_batches(db: Session) -> None:
    n = repository.EPSS_BATCH_SIZE * 2 + 17
    rows = [f"CVE-2099-{i:05d},0.5,0.5" for i in range(1, n + 1)]
    result = service.import_epss(db, _epss("2026-10-28", *rows))
    assert result.imported == n
    assert _count(db, EpssScore) == n


# --- threat signals ----------------------------------------------------


def test_threat_signals_combine_kev_and_epss(db: Session) -> None:
    service.import_kev(db, parse_kev((FIXTURES / "kev_sample.json").read_bytes()))
    service.import_epss(db, EpssReader.from_bytes((FIXTURES / "epss_sample.csv").read_bytes()))

    signals = repository.get_threat_signals(
        db,
        ["cve-2099-0001", "CVE-2099-0003", "CVE-2099-0004", "CVE-2099-9999", "not a cve", ""],
    )
    assert sorted(signals) == ["CVE-2099-0001", "CVE-2099-0003", "CVE-2099-0004"]

    both = signals["CVE-2099-0001"]
    assert both.kev is True and both.kev_ransomware_use is True
    assert both.kev_date_added == date(2026, 10, 1)
    assert both.epss == pytest.approx(0.97331) and both.epss_date == date(2026, 10, 28)

    kev_only = signals["CVE-2099-0003"]
    assert kev_only.kev is True and kev_only.epss is None and kev_only.epss_percentile is None

    epss_only = signals["CVE-2099-0004"]
    assert epss_only.kev is False and epss_only.kev_date_added is None
    assert epss_only.epss == pytest.approx(0.015)


def test_threat_signals_for_nothing_is_empty(db: Session) -> None:
    assert repository.get_threat_signals(db, []) == {}
    assert repository.get_threat_signals(db, ["CVE-2099-0001"]) == {}
