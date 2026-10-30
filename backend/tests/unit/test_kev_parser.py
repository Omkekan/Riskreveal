"""Unit tests for the CISA KEV parser (pure: no network, no database).

The fixture ``kev_sample.json`` is SYNTHETIC (shaped like CISA's feed, with
made-up CVE-2099-xxxx ids). It is not a copy of the real catalog.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.sources.cisa_kev import parse_kev

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "kev_sample.json"


def _entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "cveID": "CVE-2099-1000",
        "vendorProject": "V",
        "product": "P",
        "vulnerabilityName": "N",
        "dateAdded": "2026-01-02",
    }
    base.update(overrides)
    return base


def _catalog(*entries: object) -> bytes:
    return json.dumps({"catalogVersion": "t", "vulnerabilities": list(entries)}).encode()


def test_parses_the_sample_catalog() -> None:
    catalog = parse_kev(FIXTURE.read_bytes())
    assert catalog.version == "2026.10.28"
    assert catalog.skipped == 0
    assert [r.cve_id for r in catalog.records] == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "CVE-2099-0003",
    ]
    first, second, third = catalog.records
    assert first.date_added == date(2026, 10, 1)
    assert first.due_date == date(2026, 10, 22)
    assert first.known_ransomware_use is True
    assert first.cwes == ("CWE-78", "CWE-20")
    assert second.due_date is None  # empty string
    assert second.known_ransomware_use is False
    assert second.notes is None
    assert second.cwes == ()
    assert third.product == "OtherApp"


def test_accepts_text_as_well_as_bytes() -> None:
    assert len(parse_kev(FIXTURE.read_text(encoding="utf-8")).records) == 3


@pytest.mark.parametrize(
    "bad_id",
    [
        "",
        "CVE-2099",
        "CVE-99-1000",
        "cve-2099-1000; DROP TABLE users",
        "CVE-\uff12\uff10\uff19\uff19-1000",  # full-width digits must be rejected
        "CVE-2099-12345678901",  # more than 10 digits
        None,
        12345,
    ],
)
def test_entries_with_bad_cve_ids_are_skipped_individually(bad_id: object) -> None:
    good = _entry(cveID="CVE-2099-0007")
    raw = _catalog(good, _entry(cveID=bad_id))
    catalog = parse_kev(raw, max_invalid_fraction=1.0)
    ids = {r.cve_id for r in catalog.records}
    assert ids == {"CVE-2099-0007"}
    assert catalog.skipped == 1


def test_surrounding_whitespace_in_a_cve_id_is_stripped() -> None:
    catalog = parse_kev(_catalog(_entry(cveID="  CVE-2099-0043 ")))
    assert catalog.records[0].cve_id == "CVE-2099-0043"


def test_lowercase_cve_ids_are_normalised() -> None:
    catalog = parse_kev(_catalog(_entry(cveID="cve-2099-0042")))
    assert catalog.records[0].cve_id == "CVE-2099-0042"


@pytest.mark.parametrize("bad_date", [None, "", "yesterday", "2026-13-40", 20261001, []])
def test_entry_without_a_valid_date_added_is_skipped(bad_date: object) -> None:
    raw = _catalog(_entry(cveID="CVE-2099-0008"), _entry(dateAdded=bad_date))
    catalog = parse_kev(raw, max_invalid_fraction=1.0)
    assert [r.cve_id for r in catalog.records] == ["CVE-2099-0008"]
    assert catalog.skipped == 1


def test_non_object_entries_are_skipped() -> None:
    raw = _catalog(_entry(), "nonsense", 5, None, ["list"])
    catalog = parse_kev(raw, max_invalid_fraction=1.0)
    assert len(catalog.records) == 1 and catalog.skipped == 4


def test_unreadable_due_date_does_not_lose_the_entry() -> None:
    catalog = parse_kev(_catalog(_entry(dueDate="soon")))
    assert catalog.records[0].due_date is None


def test_duplicate_cve_keeps_the_later_entry() -> None:
    raw = _catalog(_entry(product="old"), _entry(product="new"))
    catalog = parse_kev(raw)
    assert len(catalog.records) == 1
    assert catalog.records[0].product == "new"
    assert catalog.skipped == 0


def test_strings_are_cleaned_and_clipped() -> None:
    raw = _catalog(
        _entry(
            vendorProject="Ven\x00dor",
            product="p" * 1000,
            vulnerabilityName="n" * 5000,
            shortDescription="d" * 20000,
            cwes=["CWE-1", 5, None, "", "w" * 100],
        )
    )
    record = parse_kev(raw).records[0]
    assert record.vendor_project == "Vendor"  # NUL removed
    assert len(record.product) == 255
    assert len(record.vulnerability_name) == 512
    assert record.short_description is not None and len(record.short_description) == 8000
    assert record.cwes == ("CWE-1", "w" * 32)


def test_missing_text_fields_get_safe_defaults() -> None:
    raw = json.dumps(
        {"vulnerabilities": [{"cveID": "CVE-2099-0009", "dateAdded": "2026-01-01"}]}
    ).encode()
    record = parse_kev(raw).records[0]
    assert (record.vendor_project, record.product) == ("Unknown", "Unknown")
    assert record.vulnerability_name == "CVE-2099-0009"


def test_version_falls_back_to_the_release_date() -> None:
    raw = json.dumps(
        {"dateReleased": "2026-10-28T14:23:46.5Z", "vulnerabilities": [_entry()]}
    ).encode()
    assert parse_kev(raw).version == "2026-10-28T14:23:46.5Z"


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"\xff\xfe\x00", b"[]", b"42", b'"text"', b"{}", b'{"vulnerabilities": 5}'],
)
def test_unusable_documents_are_refused(raw: bytes) -> None:
    with pytest.raises(FeedParseError):
        parse_kev(raw)


def test_deeply_nested_json_is_refused_not_crashed() -> None:
    with pytest.raises(FeedParseError):
        parse_kev(b"[" * 100000)


def test_empty_catalog_is_refused() -> None:
    with pytest.raises(FeedParseError, match="no valid entries"):
        parse_kev(_catalog())


def test_mostly_invalid_catalog_is_refused() -> None:
    raw = _catalog(_entry(), *[{"cveID": "bad"} for _ in range(10)])
    with pytest.raises(FeedParseError, match="too many invalid"):
        parse_kev(raw)  # default threshold is 2 %


def test_one_bad_entry_in_a_large_catalog_is_tolerated() -> None:
    entries = [_entry(cveID=f"CVE-2099-{n:04d}") for n in range(1, 101)]
    entries.append({"cveID": "bad"})
    catalog = parse_kev(_catalog(*entries))  # 1 of 101 is under the 2 % default
    assert len(catalog.records) == 100 and catalog.skipped == 1
