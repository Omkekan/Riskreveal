"""CVEs are always written in CVE-id order (pure: the two writers are replaced).

Why it matters: each write locks the CVE rows it touches. Two matching tasks that
lock overlapping CVEs in different orders can deadlock, and PostgreSQL then aborts
one of them. One global order makes that impossible.
"""

from __future__ import annotations

from collections.abc import Sequence
from unittest import mock

from riskreveal.domain.intelligence import cve_repository
from riskreveal.domain.intelligence.records import CveRecord


def _record(cve_id: str, description: str = "") -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        description=description,
        published=None,
        last_modified=None,
        cvss_score=None,
        cvss_severity=None,
        cvss_version=None,
        cvss_vector=None,
        ranges=(),
    )


def _run(records: Sequence[CveRecord]) -> tuple[int, list[list[CveRecord]], list[list[str]]]:
    """Call upsert_records with both writers replaced by recorders."""
    cve_batches: list[list[CveRecord]] = []
    range_batches: list[list[str]] = []
    with (
        mock.patch.object(
            cve_repository,
            "_write_cves",
            side_effect=lambda db, batch: cve_batches.append(list(batch)),
        ),
        mock.patch.object(
            cve_repository,
            "_replace_ranges",
            side_effect=lambda db, batch: range_batches.append([r.cve_id for r in batch]),
        ),
    ):
        count = cve_repository.upsert_records(mock.sentinel.db, records)
    return count, cve_batches, range_batches


def _ids(batches: list[list[CveRecord]]) -> list[list[str]]:
    return [[record.cve_id for record in batch] for batch in batches]


def test_cves_are_written_in_id_order_whatever_order_the_nvd_returned_them() -> None:
    expected = [["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"]]
    for order in ((1, 2, 3), (3, 2, 1), (2, 3, 1)):
        _, batches, _ = _run([_record(f"CVE-2099-{n:04d}") for n in order])
        assert _ids(batches) == expected, order


def test_the_global_order_holds_across_batches() -> None:
    count = cve_repository.CVE_BATCH_SIZE * 2 + 37
    reversed_ids = [f"CVE-2099-{n:05d}" for n in range(count, 0, -1)]
    _, batches, range_batches = _run([_record(i) for i in reversed_ids])
    flat = [cve_id for batch in _ids(batches) for cve_id in batch]
    assert flat == sorted(reversed_ids)
    assert len(batches) == 3
    assert range_batches == _ids(batches)  # ranges follow the same batches, same order


def test_a_repeated_cve_is_written_once_and_the_last_copy_wins() -> None:
    count, batches, _ = _run(
        [_record("CVE-2099-0002", "old"), _record("CVE-2099-0001"), _record("CVE-2099-0002", "new")]
    )
    written = [(r.cve_id, r.description) for batch in batches for r in batch]
    assert count == 2
    assert written == [("CVE-2099-0001", ""), ("CVE-2099-0002", "new")]


def test_nothing_to_write_writes_nothing() -> None:
    assert _run([]) == (0, [], [])
