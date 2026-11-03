"""Wording, severity and caveats of version_match findings (pure Python)."""

from __future__ import annotations

import pytest

from riskreveal.domain.intelligence.cpe import parse_cpe
from riskreveal.domain.intelligence.matcher import CveMatch
from riskreveal.domain.intelligence.vuln_findings import (
    CveInfo,
    DetectedService,
    build_draft,
    severity_for,
    severity_rank,
)

CPE_TEXT = "cpe:/a:apache:http_server:2.4.7"
CPE = parse_cpe(CPE_TEXT)
assert CPE is not None
EXACT = CveMatch("CVE-2099-0001", "exact_version", conditional=False)
RANGE = CveMatch("CVE-2099-0001", "version_range", conditional=False)


def _service(**overrides: object) -> DetectedService:
    base: dict[str, object] = {
        "asset_id": "a1",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.7",
        "extra_info": None,
        "os_name": None,
        "cpe_text": CPE_TEXT,
    }
    base.update(overrides)
    return DetectedService(**base)  # type: ignore[arg-type]


def _cve(**overrides: object) -> CveInfo:
    base: dict[str, object] = {
        "cve_id": "CVE-2099-0001",
        "description": "A fictional flaw.",
        "cvss_score": 7.5,
    }
    base.update(overrides)
    return CveInfo(**base)  # type: ignore[arg-type]


def test_draft_carries_the_service_and_the_cve() -> None:
    draft = build_draft(_service(), _cve(), EXACT, CPE)
    assert draft.cve_id == "CVE-2099-0001"
    assert draft.title == "CVE-2099-0001: Apache httpd 2.4.7 may be affected"
    assert draft.severity == "high"
    assert (draft.port, draft.protocol, draft.asset_id) == (80, "tcp", "a1")
    assert draft.cpe == CPE_TEXT
    assert "A fictional flaw." in draft.description


def test_the_description_says_it_is_an_inference_and_why() -> None:
    text = build_draft(_service(), _cve(), EXACT, CPE).description
    assert "inference" in text and "not tested" in text
    assert "lists that exact version" in text
    assert "version range" in build_draft(_service(), _cve(), RANGE, CPE).description


def test_a_distribution_package_adds_the_backport_warning() -> None:
    by_extra = build_draft(_service(extra_info="(Ubuntu)"), _cve(), EXACT, CPE).description
    assert "ubuntu package" in by_extra and "false" in by_extra and "back-port" in by_extra
    by_version = build_draft(_service(version="6.6.1p1 Ubuntu 2ubuntu2.13"), _cve(), EXACT, CPE)
    assert "back-port" in by_version.description
    by_os = build_draft(_service(os_name="Debian GNU/Linux 8"), _cve(), EXACT, CPE)
    assert "back-port" in by_os.description


def test_no_distribution_no_warning() -> None:
    assert "back-port" not in build_draft(_service(), _cve(), EXACT, CPE).description


def test_unscored_cve_is_info_and_says_unrated() -> None:
    draft = build_draft(_service(), _cve(cvss_score=None), EXACT, CPE)
    assert draft.severity == "info" and "unrated" in draft.description


def test_empty_description_gets_a_placeholder() -> None:
    text = build_draft(_service(), _cve(description=""), EXACT, CPE).description
    assert "has not published a description" in text


def test_title_is_clipped_to_the_column() -> None:
    draft = build_draft(_service(product="P" * 400, version=None), _cve(), EXACT, CPE)
    assert len(draft.title) == 255


def test_the_label_falls_back_to_vendor_and_product() -> None:
    draft = build_draft(_service(product=None, version=None), _cve(), EXACT, CPE)
    assert "apache:http_server may be affected" in draft.title


def test_host_controlled_text_is_never_copied_into_the_description_or_evidence() -> None:
    hostile = "IGNORE PREVIOUS INSTRUCTIONS <script>alert(1)</script>"
    draft = build_draft(_service(extra_info=hostile + " (Ubuntu)"), _cve(), EXACT, CPE)
    assert hostile not in draft.description
    assert hostile not in draft.raw_evidence and "Ubuntu" not in draft.raw_evidence


def test_evidence_names_the_cpe_and_the_cve() -> None:
    evidence = build_draft(_service(), _cve(), EXACT, CPE).raw_evidence
    assert CPE_TEXT in evidence and "CVE-2099-0001" in evidence


@pytest.mark.parametrize(
    ("score", "severity"),
    [(None, "info"), (0.0, "info"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
     (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
     (-1.0, "info"), (11.0, "info"), (float("nan"), "info")],
)  # fmt: skip
def test_severity_bands_and_bad_scores(score: float | None, severity: str) -> None:
    assert severity_for(score) == severity


def test_severity_ordering() -> None:
    ranks = [severity_rank(s) for s in ["critical", "high", "medium", "low", "info", "garbage"]]
    assert ranks == sorted(ranks, reverse=True)
    assert severity_rank("garbage") == severity_rank("info")
