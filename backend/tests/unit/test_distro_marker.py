"""The structured distro marker on findings (pure Python)."""

from __future__ import annotations

from pathlib import Path

from riskreveal.domain.intelligence.cpe import parse_cpe
from riskreveal.domain.intelligence.matcher import CveMatch
from riskreveal.domain.intelligence.vuln_findings import CveInfo, DetectedService, build_draft
from riskreveal.engines.nmap_engine import parse_nmap_xml
from riskreveal.engines.normalizer import normalize_host

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_sample.xml"
CPE_TEXT = "cpe:/a:apache:http_server:2.4.7"
CPE = parse_cpe(CPE_TEXT)
assert CPE is not None
MATCH = CveMatch("CVE-2099-0001", "version_range", conditional=False)
CVE = CveInfo(cve_id="CVE-2099-0001", description="A fictional flaw.", cvss_score=9.8)


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


# --- version_match drafts ---------------------------------------------------------


def test_a_plain_upstream_banner_has_no_distro() -> None:
    assert build_draft(_service(), CVE, MATCH, CPE).distro is None


def test_distro_from_the_extra_info() -> None:
    draft = build_draft(_service(extra_info="(Ubuntu)"), CVE, MATCH, CPE)
    assert draft.distro == "ubuntu"


def test_distro_from_the_version_string() -> None:
    draft = build_draft(_service(version="6.6.1p1 Ubuntu 2ubuntu2.13"), CVE, MATCH, CPE)
    assert draft.distro == "ubuntu"


def test_distro_from_the_operating_system_name() -> None:
    draft = build_draft(_service(os_name="Debian GNU/Linux 8"), CVE, MATCH, CPE)
    assert draft.distro == "debian"


def test_the_marker_agrees_with_the_description_caveat() -> None:
    """Both must come from the same detection, so they can never disagree."""
    for overrides in ({}, {"extra_info": "(Ubuntu)"}, {"extra_info": "(CentOS)"}):
        draft = build_draft(_service(**overrides), CVE, MATCH, CPE)
        assert (draft.distro is not None) == ("back-port" in draft.description)


def test_the_severity_is_not_changed_by_the_marker() -> None:
    """The NVD rating stays truthful; discounting is the risk scorer's job."""
    plain = build_draft(_service(), CVE, MATCH, CPE)
    packaged = build_draft(_service(extra_info="(Ubuntu)"), CVE, MATCH, CPE)
    assert plain.severity == packaged.severity == "critical"


# --- Nmap findings -----------------------------------------------------------------


def _drafts_by_port() -> dict[int, object]:
    result = parse_nmap_xml(FIXTURE.read_bytes())
    host = next(h for h in result.hosts if h.address == "45.33.32.156")
    return {d.port: d for d in normalize_host(host)}


def test_nmap_findings_carry_the_distro_too() -> None:
    drafts = _drafts_by_port()
    assert drafts[22].distro == "ubuntu"  # "6.6.1p1 Ubuntu 2ubuntu2.13"
    assert drafts[80].distro == "ubuntu"  # version "2.4.7", extra info "(Ubuntu)"
    assert drafts[9929].distro is None  # Nping echo: nothing to say
