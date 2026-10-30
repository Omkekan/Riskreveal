"""Unit tests for the EPSS reader and the gzip safety helpers (pure).

``epss_sample.csv`` is SYNTHETIC (made-up scores for made-up CVE-2099-xxxx ids).
"""

from __future__ import annotations

import gzip
import tracemalloc
from datetime import date
from pathlib import Path

import pytest

from riskreveal.domain.intelligence.errors import FeedFetchError, FeedParseError
from riskreveal.domain.intelligence.sources.first_epss import EpssReader
from riskreveal.domain.intelligence.sources.payload import (
    gunzip_limited,
    maybe_gunzip,
    read_local,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "epss_sample.csv"
HEADER = "#model_version:v2025.03.14,score_date:2026-10-28T12:55:00Z"
COLUMNS = "cve,epss,percentile"


def _reader(*rows: str, header: str = HEADER) -> EpssReader:
    return EpssReader([header, COLUMNS, *rows])


def test_reads_the_sample_file() -> None:
    reader = EpssReader.from_bytes(FIXTURE.read_bytes())
    assert reader.model_version == "v2025.03.14"
    assert reader.score_date == date(2026, 10, 28)
    records = list(reader)
    assert [r.cve_id for r in records] == ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0004"]
    assert records[0].score == 0.97331 and records[0].percentile == 0.99988
    assert reader.rows_read == 3 and reader.skipped == 0


def test_gzip_and_plain_inputs_give_the_same_result() -> None:
    plain = FIXTURE.read_bytes()
    compressed = gzip.compress(plain)
    assert [r.cve_id for r in EpssReader.from_bytes(compressed)] == [
        r.cve_id for r in EpssReader.from_bytes(plain)
    ]


@pytest.mark.parametrize(
    "header",
    [
        "#model_version:v2023.03.01,score_date:2024-02-22T00:00:00+0000",
        "#model_version:v2025.03.14,score_date:2025-08-02T12:55:00Z",
        "#model_version:v1,score_date:2025-08-02",
    ],
)
def test_both_known_score_date_formats_are_accepted(header: str) -> None:
    reader = _reader("CVE-2099-0001,0.5,0.5", header=header)
    assert reader.score_date.year in (2024, 2025)
    assert len(list(reader)) == 1


def test_utf8_bom_and_windows_line_endings_are_tolerated() -> None:
    text = "\ufeff" + HEADER + "\r\n" + COLUMNS + "\r\nCVE-2099-0001,0.5,0.5\r\n\r\n"
    reader = EpssReader.from_bytes(text.encode("utf-8"))
    assert [r.cve_id for r in reader] == ["CVE-2099-0001"]


@pytest.mark.parametrize(
    "row",
    [
        "CVE-2099-0001,nan,0.5",
        "CVE-2099-0001,0.5,inf",
        "CVE-2099-0001,-0.1,0.5",
        "CVE-2099-0001,1.5,0.5",
        "CVE-2099-0001,0.5,2",
        "CVE-2099-0001,abc,0.5",
        "CVE-2099-0001,0.5",
        "CVE-2099-0001,0.5,0.5,extra",
        "NOT-A-CVE,0.5,0.5",
        ",0.5,0.5",
        "CVE-2099-0001,\u0660.\u0665,0.5",  # Arabic-Indic digits: float() would accept them
    ],
)
def test_bad_rows_are_skipped_and_counted(row: str) -> None:
    reader = _reader("CVE-2099-0002,0.25,0.75", row)
    records = list(reader)
    assert [r.cve_id for r in records] == ["CVE-2099-0002"]
    assert reader.rows_read == 2 and reader.skipped == 1


def test_boundary_values_are_valid() -> None:
    records = list(_reader("CVE-2099-0001,0,0", "CVE-2099-0002,1,1"))
    assert [(r.score, r.percentile) for r in records] == [(0.0, 0.0), (1.0, 1.0)]


@pytest.mark.parametrize(
    "lines",
    [
        [],
        [""],
        [COLUMNS, "CVE-2099-0001,0.5,0.5"],  # no comment header
        [HEADER],  # no column header
        [HEADER, "cve,score,percentile"],  # wrong columns
        ["#model_version:v1", COLUMNS],  # no score_date
        ["#score_date:2026-10-28", COLUMNS],  # no model_version
        ["#model_version:v1,score_date:not-a-date", COLUMNS],
    ],
)
def test_bad_headers_are_refused(lines: list[str]) -> None:
    with pytest.raises(FeedParseError):
        EpssReader(lines)


def test_reader_can_only_be_iterated_once() -> None:
    reader = _reader("CVE-2099-0001,0.5,0.5")
    assert len(list(reader)) == 1
    with pytest.raises(RuntimeError):
        list(reader)


def test_invalid_utf8_is_refused() -> None:
    with pytest.raises(FeedParseError, match="UTF-8"):
        EpssReader.from_bytes(b"\xff\xfe\xfa")


# --- gzip safety ---------------------------------------------------------


def test_gunzip_limited_round_trip() -> None:
    assert gunzip_limited(gzip.compress(b"hello"), 100) == b"hello"


def test_decompression_bomb_is_refused() -> None:
    bomb = gzip.compress(b"\x00" * 5_000_000)  # a few KB that expands to 5 MB
    assert len(bomb) < 10_000
    with pytest.raises(FeedParseError, match="more than the allowed"):
        gunzip_limited(bomb, 1_000_000)


def test_decompression_memory_stays_bounded() -> None:
    """The limit must stop the expansion itself, not just reject the result.

    Without ``max_length`` the 50 MB bomb below is fully expanded in memory
    before the size check runs, which is the attack the limit exists to stop.
    """
    bomb = gzip.compress(b"\x00" * 50_000_000)
    tracemalloc.start()
    try:
        with pytest.raises(FeedParseError):
            gunzip_limited(bomb, 1_000_000)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 10_000_000, f"peak allocation {peak} bytes: decompression was not bounded"


def test_output_exactly_at_the_limit_is_allowed() -> None:
    assert len(gunzip_limited(gzip.compress(b"a" * 1000), 1000)) == 1000
    with pytest.raises(FeedParseError):
        gunzip_limited(gzip.compress(b"a" * 1001), 1000)


def test_corrupt_and_truncated_gzip_are_refused() -> None:
    good = gzip.compress(b"some content " * 100)
    with pytest.raises(FeedParseError):
        gunzip_limited(b"\x1f\x8b" + b"garbage-not-gzip", 1000)
    with pytest.raises(FeedParseError, match="truncated"):
        gunzip_limited(good[: len(good) // 2], 10_000)


def test_maybe_gunzip_passes_plain_data_and_enforces_the_limit() -> None:
    assert maybe_gunzip(b"plain", 10) == b"plain"
    with pytest.raises(FeedParseError):
        maybe_gunzip(b"x" * 11, 10)


def test_read_local_enforces_size_and_reports_missing_files(tmp_path: Path) -> None:
    small = tmp_path / "small.bin"
    small.write_bytes(b"abc")
    assert read_local(small, 10) == b"abc"
    with pytest.raises(FeedFetchError, match="larger than"):
        read_local(small, 2)
    with pytest.raises(FeedFetchError, match="Cannot read"):
        read_local(tmp_path / "missing.bin", 10)
