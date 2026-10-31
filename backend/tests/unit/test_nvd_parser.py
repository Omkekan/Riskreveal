"""NVD CVE API 2.0 parser, run against a SYNTHETIC fixture.

The fixture follows the documented shape of the NVD response but uses made-up
identifiers (CVE-2099-*, vendor "examplecorp") so no real CVE is ever given
invented details. Behaviour on the real feed is checked by
``scripts/nvd_match_demo.py``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from riskreveal.domain.findings.enums import Severity
from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.records import CveRecord, severity_from_cvss
from riskreveal.domain.intelligence.sources.nvd import parse_nvd_response

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "nvd_sample.json"
_CPE_OK = "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"


def _fixture() -> object:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_page_counts_and_skips() -> None:
    page = parse_nvd_response(_fixture())
    assert [r.cve_id for r in page.records] == ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0004"]
    assert page.skipped == 3  # the rejected CVE, the bad id, and the "junk" string
    assert page.total_results == 6
    assert page.start_index == 0
    assert page.results_per_page == 6


def test_range_cve_fields() -> None:
    record = parse_nvd_response(_fixture()).records[0]
    assert record.cve_id == "CVE-2099-0001"
    assert record.description == "Synthetic flaw in ExampleSSH before 7.2."  # English, not Spanish
    assert record.cvss_score == 9.8
    assert record.cvss_severity == "critical"
    assert record.cvss_version == "3.1"
    assert record.cvss_vector is not None
    assert record.cvss_vector.startswith("CVSS:3.1/")
    assert record.published == datetime(2099, 1, 1, 10, 0, tzinfo=UTC)  # naive input -> UTC
    assert len(record.ranges) == 1
    rng = record.ranges[0]
    assert (rng.part, rng.vendor, rng.product) == ("a", "examplecorp", "examplessh")
    assert rng.version == "*"
    assert rng.end_excluding == "7.2"
    assert rng.start_including is None
    assert rng.conditional is False


def test_exact_version_cve() -> None:
    record = parse_nvd_response(_fixture()).records[1]
    assert record.cve_id == "CVE-2099-0002"
    assert record.cvss_version == "3.0"
    assert record.cvss_severity == "medium"
    assert (record.ranges[0].version, record.ranges[0].update) == ("6.6.1", "p1")


def test_and_configuration_keeps_only_the_vulnerable_entry_and_flags_it_conditional() -> None:
    record = parse_nvd_response(_fixture()).records[2]
    assert record.cve_id == "CVE-2099-0004"
    assert len(record.ranges) == 1  # the non-vulnerable platform entry is dropped
    rng = record.ranges[0]
    assert rng.product == "examplehttpd"
    assert (rng.start_including, rng.end_excluding) == ("2.4.0", "2.4.50")
    assert rng.conditional is True
    # Only a CVSS v2 score exists, so v2 is used.
    assert (record.cvss_score, record.cvss_severity, record.cvss_version) == (5.0, "medium", "2.0")
    assert record.published == datetime(2099, 1, 2, 9, 0, tzinfo=UTC)  # a "Z" suffix is accepted


@pytest.mark.parametrize("payload", [None, [], "text", 5, {}, {"vulnerabilities": "no"}])
def test_documents_of_the_wrong_shape_are_refused(payload: object) -> None:
    with pytest.raises(FeedParseError):
        parse_nvd_response(payload)


def test_empty_page_is_fine() -> None:
    page = parse_nvd_response({"vulnerabilities": []})
    assert page.records == ()
    assert page.skipped == 0
    assert page.total_results == 0


@pytest.mark.parametrize(
    "cve",
    [
        {"vulnStatus": "Rejected", "descriptions": [{"lang": "en", "value": "Looks normal."}]},
        {"vulnStatus": " rejected ", "descriptions": [{"lang": "en", "value": "Looks normal."}]},
        {
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "** REJECT ** Unused."}],
        },
    ],
)
def test_each_rejection_signal_works_on_its_own(cve: dict[str, object]) -> None:
    page = parse_nvd_response({"vulnerabilities": [{"cve": {"id": "CVE-2099-0500", **cve}}]})
    assert page.records == ()
    assert page.skipped == 1


@pytest.mark.parametrize(
    ("raw_id", "kept_as"),
    [
        ("cve-2099-0600", "CVE-2099-0600"),  # normalized to upper case
        (" CVE-2099-0601 ", "CVE-2099-0601"),
        ("CVE-2099-0602\u0000", None),  # NUL inside the id
        ("CVE-\uff12\uff10\uff19\uff19-0603", None),  # full-width digits are look-alikes
        ("CVE-2099-12", None),  # too few digits
        ("CVE-2099-12345678901", None),  # too many digits
        (None, None),
        (12345, None),
    ],
)
def test_cve_ids_use_the_shared_strict_validation(raw_id: object, kept_as: str | None) -> None:
    page = parse_nvd_response({"vulnerabilities": [{"cve": {"id": raw_id, "descriptions": []}}]})
    assert [r.cve_id for r in page.records] == ([kept_as] if kept_as else [])


def test_hostile_values_are_neutralised() -> None:
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0100",
                    "published": "not a date",
                    "descriptions": [{"lang": "en", "value": "x" * 100_000}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 99, "version": "3.1"}}]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"vulnerable": True, "criteria": "garbage"},
                                        {"vulnerable": True, "criteria": 5},
                                        {"vulnerable": "yes", "criteria": _CPE_OK},
                                        "junk",
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                                            "versionEndExcluding": "9" * 500,
                                        },
                                    ]
                                }
                            ]
                        },
                        "junk",
                    ],
                }
            }
        ]
    }
    (record,) = parse_nvd_response(payload).records
    assert record.published is None  # an unparseable date is not an error
    assert len(record.description) == 20_000  # clipped
    assert record.cvss_score is None  # 99 is out of range, so it is ignored
    assert len(record.ranges) == 1  # only the one well-formed, vulnerable entry
    assert record.ranges[0].end_excluding is not None
    assert len(record.ranges[0].end_excluding) == 64  # clipped


def test_nul_bytes_are_removed_from_text_fields() -> None:
    # PostgreSQL refuses NUL in text columns; one hostile record must not break an import.
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0700",
                    "descriptions": [{"lang": "en", "value": "bad\u0000 text"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 5.0, "vectorString": "CVSS:3.1/\u0000AV:N"}}
                        ]
                    },
                }
            }
        ]
    }
    (record,) = parse_nvd_response(payload).records
    assert "\u0000" not in record.description
    assert record.description == "bad text"
    assert record.cvss_vector == "CVSS:3.1/AV:N"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss(score: float, expected: Severity) -> None:
    assert severity_from_cvss(score) == expected


@pytest.mark.parametrize("bad", [-0.1, 10.1, float("nan"), float("inf")])
def test_severity_from_cvss_rejects_out_of_range(bad: float) -> None:
    with pytest.raises(ValueError, match="between 0 and 10"):
        severity_from_cvss(bad)


# --- platform requirements ("this only applies on Windows") ---------------------


def _one_cve(configurations: list[object]) -> CveRecord:
    page = parse_nvd_response(
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-0800", "configurations": configurations}}]}
    )
    return page.records[0]


def _vulnerable(criteria: str) -> dict[str, object]:
    return {"vulnerable": True, "criteria": criteria}


def _platform(criteria: str) -> dict[str, object]:
    return {"vulnerable": False, "criteria": criteria}


_APP = "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"


def test_fixture_platform_requirements() -> None:
    records = {r.cve_id: r for r in parse_nvd_response(_fixture()).records}
    assert records["CVE-2099-0004"].ranges[0].requires == ("examplecorp:examplelinux",)
    assert records["CVE-2099-0001"].ranges[0].requires == ()
    assert records["CVE-2099-0002"].ranges[0].requires == ()


def test_platforms_are_collected_sorted_and_deduplicated() -> None:
    # Eight platforms listed in reverse order, plus duplicates and a garbage entry. With
    # this many, an unsorted result would almost never match the sorted one by luck.
    platforms = [_platform(f"cpe:2.3:o:vendor{i}:os:-:*:*:*:*:*:*:*") for i in range(8, 0, -1)]
    platforms += [_platform("cpe:2.3:o:vendor3:os:1809:*:*:*:*:*:*:*"), _platform("garbage")]
    record = _one_cve(
        [
            {
                "operator": "AND",
                "nodes": [{"cpeMatch": [_vulnerable(_APP)]}, {"cpeMatch": platforms}],
            }
        ]
    )
    (rng,) = record.ranges
    assert rng.conditional is True
    assert rng.requires == tuple(f"vendor{i}:os" for i in range(1, 9))


def test_platform_entries_in_a_plain_configuration_are_not_requirements() -> None:
    record = _one_cve(
        [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            _vulnerable(_APP),
                            _platform("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"),
                        ],
                    }
                ]
            }
        ]
    )
    (rng,) = record.ranges
    assert rng.conditional is False
    assert rng.requires == ()


def test_an_and_of_two_vulnerable_products_is_conditional_with_no_known_platform() -> None:
    record = _one_cve(
        [
            {
                "operator": "AND",
                "nodes": [
                    {"cpeMatch": [_vulnerable(_APP)]},
                    {"cpeMatch": [_vulnerable("cpe:2.3:a:other:plugin:*:*:*:*:*:*:*:*")]},
                ],
            }
        ]
    )
    assert len(record.ranges) == 2
    assert all(r.conditional and r.requires == () for r in record.ranges)


def test_platforms_of_a_negated_node_are_ignored() -> None:
    record = _one_cve(
        [
            {
                "operator": "AND",
                "nodes": [
                    {"cpeMatch": [_vulnerable(_APP)]},
                    {
                        "negate": True,
                        "cpeMatch": [_platform("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*")],
                    },
                ],
            }
        ]
    )
    (rng,) = record.ranges
    assert rng.requires == ()
