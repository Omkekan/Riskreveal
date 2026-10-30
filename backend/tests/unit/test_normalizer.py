"""Normalizer tests: parsed Nmap data -> informational finding drafts."""

from __future__ import annotations

from pathlib import Path

from riskreveal.engines.base import ParsedHost, ParsedPort, ParsedScript
from riskreveal.engines.nmap_engine import parse_nmap_xml
from riskreveal.engines.normalizer import normalize_host

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_sample.xml"


def _hosts():
    return parse_nmap_xml(FIXTURE.read_bytes()).hosts


def test_only_open_ports_of_up_hosts_become_findings() -> None:
    drafts = normalize_host(_hosts()[0])
    assert sorted(d.port for d in drafts) == [22, 80, 9929]  # not 8080 (filtered) or 23 (closed)


def test_down_host_produces_nothing() -> None:
    assert normalize_host(_hosts()[1]) == []


def test_drafts_are_attributed_to_their_own_host() -> None:
    v6 = normalize_host(_hosts()[2])
    assert [(d.address, d.port) for d in v6] == [("2606:4700:4700::1111", 443)]


def test_ssh_draft_content() -> None:
    ssh = next(d for d in normalize_host(_hosts()[0]) if d.port == 22)
    assert ssh.title == "Open port 22/tcp: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13"
    assert ssh.severity == "info"
    assert ssh.confidence == "detected"
    assert ssh.product == "OpenSSH"
    assert ssh.cpe == "cpe:/a:openbsd:openssh:6.6.1p1"
    assert ssh.raw_evidence is None


def test_script_output_is_evidence_not_a_separate_finding() -> None:
    drafts = normalize_host(_hosts()[0])
    assert len(drafts) == 3  # http-title did NOT add a fourth finding
    http = next(d for d in drafts if d.port == 80)
    assert http.raw_evidence is not None
    assert "[http-title]" in http.raw_evidence
    assert "Go ahead and ScanMe!" in http.raw_evidence


def test_title_falls_back_to_service_name_then_to_bare_port() -> None:
    host = ParsedHost(
        address="8.8.8.8",
        address_type="ipv4",
        status="up",
        ports=(
            ParsedPort(port=25, protocol="tcp", state="open", service="smtp"),
            ParsedPort(port=26, protocol="tcp", state="open"),
        ),
    )
    titles = [d.title for d in normalize_host(host)]
    assert titles == ["Open port 25/tcp: smtp", "Open port 26/tcp"]


def test_evidence_is_truncated() -> None:
    port = ParsedPort(
        port=80,
        protocol="tcp",
        state="open",
        scripts=(ParsedScript("big", "B" * 30_000),),
    )
    host = ParsedHost(address="8.8.8.8", address_type="ipv4", status="up", ports=(port,))
    evidence = normalize_host(host)[0].raw_evidence
    assert evidence is not None
    assert evidence.endswith("[truncated]")
    assert len(evidence) < 21_000
