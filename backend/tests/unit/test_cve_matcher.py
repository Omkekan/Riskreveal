"""CVE matching, run against the synthetic NVD fixture. Pure Python."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from riskreveal.domain.intelligence.cpe import Cpe, parse_cpe
from riskreveal.domain.intelligence.matcher import CveMatch, match_cves
from riskreveal.domain.intelligence.records import CpeRange, CveRecord
from riskreveal.domain.intelligence.sources.nvd import parse_nvd_response

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nvd_sample.json"
RECORDS = parse_nvd_response(json.loads(FIXTURE.read_text(encoding="utf-8"))).records


def _match(cpe_text: str) -> dict[str, CveMatch]:
    cpe = parse_cpe(cpe_text)
    assert cpe is not None, cpe_text
    return {m.cve_id: m for m in match_cves(cpe, RECORDS)}


def test_range_and_exact_matches_for_an_nmap_style_cpe() -> None:
    matches = _match("cpe:/a:examplecorp:examplessh:6.6.1p1")
    assert set(matches) == {"CVE-2099-0001", "CVE-2099-0002"}
    assert matches["CVE-2099-0001"].reason == "version_range"  # 6.6.1p1 is before 7.2
    assert matches["CVE-2099-0002"].reason == "exact_version"  # NVD "6.6.1" + "p1"
    assert matches["CVE-2099-0001"].conditional is False


@pytest.mark.parametrize("version", ["6.6.1", "7.1p2", "7.2", "7.3"])
def test_exact_entry_applies_only_to_that_exact_release(version: str) -> None:
    # CVE-2099-0002 lists exactly 6.6.1p1; no neighbouring version may match it.
    assert "CVE-2099-0002" not in _match(f"cpe:/a:examplecorp:examplessh:{version}")


@pytest.mark.parametrize(
    ("version", "in_range"),
    [
        ("6.6.1", True),
        ("7.1p2", True),
        ("7.1", True),
        ("7.2", False),
        ("7.2p1", False),
        ("8.0", False),
    ],
)
def test_end_excluding_bound(version: str, in_range: bool) -> None:
    assert ("CVE-2099-0001" in _match(f"cpe:/a:examplecorp:examplessh:{version}")) is in_range


@pytest.mark.parametrize(
    ("version", "in_range"),
    [
        ("2.3.9", False),
        ("2.4.0", True),
        ("2.4.7", True),
        ("2.4.49", True),
        ("2.4.50", False),
        ("2.5", False),
    ],
)
def test_start_including_and_end_excluding_bounds_and_conditional_flag(
    version: str, in_range: bool
) -> None:
    matches = _match(f"cpe:/a:examplecorp:examplehttpd:{version}")
    assert ("CVE-2099-0004" in matches) is in_range
    if in_range:
        assert matches["CVE-2099-0004"].conditional is True


@pytest.mark.parametrize(
    "cpe_text",
    [
        "cpe:/a:examplecorp:examplessh",  # no version at all
        "cpe:/a:examplecorp:examplessh:7.2-fips",  # a version we can't order safely
        "cpe:/a:examplecorp:examplessh:latest",
        "cpe:/a:othervendor:examplessh:6.6.1p1",  # vendor differs
        "cpe:/a:examplecorp:otherproduct:6.6.1p1",  # product differs
        "cpe:/o:examplecorp:examplessh:6.6.1p1",  # part differs
        "cpe:/h:examplecorp:examplessh:6.6.1p1",  # hardware is never matched
    ],
)
def test_no_claim_when_unsure(cpe_text: str) -> None:
    assert _match(cpe_text) == {}


def test_a_cve_with_several_ranges_reports_its_strongest_reason_once() -> None:
    record = CveRecord(
        cve_id="CVE-2099-0200",
        description="",
        published=None,
        last_modified=None,
        cvss_score=None,
        cvss_severity=None,
        cvss_version=None,
        cvss_vector=None,
        ranges=(
            CpeRange("a", "v", "p", version="*", update="*", conditional=False),  # all versions
            CpeRange("a", "v", "p", version="1.0", update="*", conditional=True),  # exact
            CpeRange("a", "v", "p", version="*", end_excluding="2.0", conditional=False),  # range
        ),
    )
    (match,) = match_cves(Cpe("a", "v", "p", "1.0", "*"), [record])
    assert match == CveMatch("CVE-2099-0200", "exact_version", True)


def test_all_versions_entry_and_not_applicable_entry() -> None:
    def record(version: str) -> CveRecord:
        return CveRecord("CVE-2099-0300", "", None, None, None, None, None, None,
                         (CpeRange("a", "v", "p", version=version),))

    assert match_cves(Cpe("a", "v", "p", "9.9", "*"), [record("*")])[0].reason == "all_versions"
    assert match_cves(Cpe("a", "v", "p", "9.9", "*"), [record("-")]) == []


def test_an_unparseable_range_bound_makes_no_claim() -> None:
    bad = CveRecord("CVE-2099-0301", "", None, None, None, None, None, None,
                    (CpeRange("a", "v", "p", end_excluding="1.0-fips"),))
    assert match_cves(Cpe("a", "v", "p", "0.5", "*"), [bad]) == []


def test_results_are_sorted_by_cve_number_not_text() -> None:
    def record(cve_id: str) -> CveRecord:
        return CveRecord(cve_id, "", None, None, None, None, None, None,
                         (CpeRange("a", "v", "p", version="*"),))

    result = match_cves(
        Cpe("a", "v", "p", "1.0", "*"),
        [record("CVE-2099-10000"), record("CVE-2099-0999"), record("CVE-2098-50000")],
    )
    assert [m.cve_id for m in result] == ["CVE-2098-50000", "CVE-2099-0999", "CVE-2099-10000"]


def test_empty_input() -> None:
    assert match_cves(Cpe("a", "v", "p", "1.0", "*"), []) == []


@pytest.mark.parametrize(
    ("bounds", "version", "affected"),
    [
        # start_excluding < v <= end_including
        ({"start_excluding": "2.0", "end_including": "3.0"}, "2.0", False),
        ({"start_excluding": "2.0", "end_including": "3.0"}, "2.0.1", True),
        ({"start_excluding": "2.0", "end_including": "3.0"}, "3.0", True),
        ({"start_excluding": "2.0", "end_including": "3.0"}, "3.0.1", False),
        # start_including <= v < end_excluding
        ({"start_including": "2.0", "end_excluding": "3.0"}, "1.9", False),
        ({"start_including": "2.0", "end_excluding": "3.0"}, "2.0", True),
        ({"start_including": "2.0", "end_excluding": "3.0"}, "2.9.9", True),
        ({"start_including": "2.0", "end_excluding": "3.0"}, "3.0", False),
        # a lone lower bound
        ({"start_excluding": "2.0"}, "2.0", False),
        ({"start_excluding": "2.0"}, "99", True),
    ],
)
def test_each_kind_of_version_bound(bounds: dict[str, str], version: str, affected: bool) -> None:
    record = CveRecord("CVE-2099-0400", "", None, None, None, None, None, None,
                       (CpeRange("a", "v", "p", **bounds),))
    assert bool(match_cves(Cpe("a", "v", "p", version, "*"), [record])) is affected
