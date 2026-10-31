"""How the matcher treats versions that carry an update (OpenSSH 8.2p1).

Regression for a real miss found by ``scripts/nvd_match_demo.py --compare-with``:
the NVD lists CVE-2020-12062 as ``cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*``
(version 8.2, any update) and returns it for ``8.2:p1``, but the matcher joined
Nmap's ``8.2p1`` into one string and found it different from ``8.2``.

The records here are built by hand to isolate one rule at a time (the NVD
parser has its own tests).
"""

from __future__ import annotations

from typing import Any

import pytest

from riskreveal.domain.intelligence.cpe import parse_cpe
from riskreveal.domain.intelligence.matcher import match_cves
from riskreveal.domain.intelligence.records import CpeRange, CveRecord


def _record(**range_fields: Any) -> CveRecord:
    rng = CpeRange(part="a", vendor="openbsd", product="openssh", **range_fields)
    return CveRecord(
        cve_id="CVE-2099-0001",
        description="test",
        published=None,
        last_modified=None,
        cvss_score=None,
        cvss_severity=None,
        cvss_version=None,
        cvss_vector=None,
        ranges=(rng,),
    )


def _reason(record: CveRecord, version: str) -> str | None:
    cpe = parse_cpe(f"cpe:/a:openbsd:openssh:{version}")
    assert cpe is not None
    matches = match_cves(cpe, [record])
    return matches[0].reason if matches else None


# --- an exact entry --------------------------------------------------------


@pytest.mark.parametrize("version", ["8.2", "8.2p1", "8.2p2"])
def test_exact_entry_with_wildcard_update_covers_every_update(version: str) -> None:
    # The real CVE-2020-12062 entry: version 8.2, update "*".
    assert _reason(_record(version="8.2", update="*"), version) == "exact_version"


@pytest.mark.parametrize("version", ["8.1", "8.1p1", "8.3", "8.3p1", "8.2.1", "8.2.1p1", "82"])
def test_exact_entry_with_wildcard_update_does_not_cover_other_versions(version: str) -> None:
    assert _reason(_record(version="8.2", update="*"), version) is None


def test_the_nvd_spelling_of_the_host_version_matches_too() -> None:
    cpe = parse_cpe("cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*")
    assert cpe is not None
    assert match_cves(cpe, [_record(version="8.2", update="*")])[0].reason == "exact_version"


@pytest.mark.parametrize(
    ("version", "expected"),
    [("8.2p1", "exact_version"), ("8.2p2", None), ("8.2", None), ("8.3p1", None)],
)
def test_exact_entry_with_a_specific_update_is_unchanged(
    version: str, expected: str | None
) -> None:
    assert _reason(_record(version="8.2", update="p1"), version) == expected


@pytest.mark.parametrize(("version", "expected"), [("8.2", "exact_version"), ("8.2p1", None)])
def test_exact_entry_with_update_not_applicable_is_unchanged(
    version: str, expected: str | None
) -> None:
    assert _reason(_record(version="8.2", update="-"), version) == expected


def test_entry_written_with_the_suffix_in_the_version_still_matches() -> None:
    assert _reason(_record(version="6.6.1p1", update="*"), "6.6.1p1") == "exact_version"


# --- plain bounds are compared with the version part only ------------------


@pytest.mark.parametrize(
    ("version", "inside"),
    [
        ("8.1p9", True),
        ("8.2", True),
        ("8.2p1", True),
        ("8.2p2", True),
        ("8.3", False),
        ("8.3p1", False),
    ],
)
def test_end_including_a_plain_version(version: str, inside: bool) -> None:
    record = _record(end_including="8.2")
    assert (_reason(record, version) == "version_range") is inside


@pytest.mark.parametrize(
    ("version", "inside"),
    [("8.1p9", True), ("8.2", False), ("8.2p1", False), ("8.2p2", False), ("8.3", False)],
)
def test_end_excluding_a_plain_version(version: str, inside: bool) -> None:
    record = _record(end_excluding="8.2")
    assert (_reason(record, version) == "version_range") is inside


@pytest.mark.parametrize(
    ("version", "inside"),
    [("8.1p9", False), ("8.2", True), ("8.2p1", True), ("8.3p1", True)],
)
def test_start_including_a_plain_version(version: str, inside: bool) -> None:
    record = _record(start_including="8.2")
    assert (_reason(record, version) == "version_range") is inside


@pytest.mark.parametrize(
    ("version", "inside"),
    [("8.1p9", False), ("8.2", False), ("8.2p1", False), ("8.2.1", True), ("8.3p1", True)],
)
def test_start_excluding_a_plain_version(version: str, inside: bool) -> None:
    record = _record(start_excluding="8.2")
    assert (_reason(record, version) == "version_range") is inside


# --- a bound that names the update is compared with the full version -------


@pytest.mark.parametrize(
    ("version", "inside"),
    [("8.1p5", True), ("8.2", True), ("8.2p1", True), ("8.2p2", False), ("8.3", False)],
)
def test_end_including_a_bound_with_an_update(version: str, inside: bool) -> None:
    record = _record(end_including="8.2p1")
    assert (_reason(record, version) == "version_range") is inside


@pytest.mark.parametrize(
    ("version", "inside"),
    [("8.1p5", True), ("8.2", True), ("8.2p1", False), ("8.2p2", False)],
)
def test_end_excluding_a_bound_with_an_update(version: str, inside: bool) -> None:
    record = _record(end_excluding="8.2p1")
    assert (_reason(record, version) == "version_range") is inside


@pytest.mark.parametrize(
    ("version", "inside"),
    [("7.9", False), ("7.9p1", False), ("7.9p2", True), ("8.0", True)],
)
def test_start_excluding_a_bound_with_an_update(version: str, inside: bool) -> None:
    record = _record(start_excluding="7.9p1")
    assert (_reason(record, version) == "version_range") is inside


# --- things that must not change ------------------------------------------


@pytest.mark.parametrize(("version", "inside"), [("1.0.2", True), ("1.0.2k", False)])
def test_other_letter_suffixes_are_ordinary_version_text(version: str, inside: bool) -> None:
    # OpenSSL-style "1.0.2k" is NOT split: it sorts after 1.0.2, as before.
    record = CveRecord(
        cve_id="CVE-2099-0002",
        description="test",
        published=None,
        last_modified=None,
        cvss_score=None,
        cvss_severity=None,
        cvss_version=None,
        cvss_vector=None,
        ranges=(CpeRange(part="a", vendor="openssl", product="openssl", end_including="1.0.2"),),
    )
    cpe = parse_cpe(f"cpe:/a:openssl:openssl:{version}")
    assert cpe is not None
    assert bool(match_cves(cpe, [record])) is inside


def test_a_different_product_never_matches() -> None:
    cpe = parse_cpe("cpe:/a:openbsd:otherssh:8.2p1")
    assert cpe is not None
    assert match_cves(cpe, [_record(version="8.2", update="*")]) == []


def test_all_versions_and_conditional_entries_are_unchanged() -> None:
    assert _reason(_record(version="*", update="*"), "8.2p1") == "all_versions"
    conditional = _record(version="8.2", update="*", conditional=True)
    cpe = parse_cpe("cpe:/a:openbsd:openssh:8.2p1")
    assert cpe is not None
    (match,) = match_cves(cpe, [conditional])
    assert match.conditional and match.needs_review
