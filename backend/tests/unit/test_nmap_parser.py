"""Nmap XML parser tests, against a synthetic fixture. No Nmap needed."""

from __future__ import annotations

from pathlib import Path

import pytest

from riskreveal.engines.base import NmapParseError
from riskreveal.engines.nmap_engine import MAX_SCRIPT_OUTPUT_CHARS, parse_nmap_xml

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "nmap_sample.xml"


def _parse():
    return parse_nmap_xml(FIXTURE.read_bytes())


def test_parses_hosts_and_skips_mac_only_entries() -> None:
    result = _parse()
    assert result.nmap_version == "7.97"
    # 4 <host> elements; the MAC-only one has no IP to attribute findings to.
    assert [h.address for h in result.hosts] == [
        "45.33.32.156",
        "45.33.32.157",
        "2606:4700:4700::1111",
    ]


def test_host_fields() -> None:
    host = _parse().hosts[0]
    assert host.status == "up"
    assert host.address_type == "ipv4"
    assert host.hostnames == ("scanme.nmap.org",)
    assert host.os_name == "Linux 3.2 - 4.9"  # best (first) match
    assert host.os_accuracy == 96


def test_down_host_is_kept_with_its_status() -> None:
    down = _parse().hosts[1]
    assert down.status == "down"


def test_ipv6_host_uses_the_ip_not_the_mac() -> None:
    host = _parse().hosts[2]
    assert host.address_type == "ipv6"
    assert host.address == "2606:4700:4700::1111"


def test_ports_keep_state_and_unparseable_ports_are_dropped() -> None:
    ports = {p.port: p for p in _parse().hosts[0].ports}
    assert set(ports) == {22, 80, 9929, 8080, 23}  # "bogus" port id dropped
    assert ports[22].state == "open"
    assert ports[8080].state == "filtered"
    assert ports[23].state == "closed"


def test_service_details_and_cpes() -> None:
    ssh = next(p for p in _parse().hosts[0].ports if p.port == 22)
    assert ssh.protocol == "tcp"
    assert ssh.service == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "6.6.1p1 Ubuntu 2ubuntu2.13"
    assert ssh.extrainfo == "Ubuntu Linux; protocol 2.0"
    assert ssh.service_confidence == 10
    assert ssh.cpes == ("cpe:/a:openbsd:openssh:6.6.1p1", "cpe:/o:linux:linux_kernel")


def test_tunnel_is_captured() -> None:
    https = _parse().hosts[2].ports[0]
    assert https.tunnel == "ssl"


def test_port_scripts_and_host_scripts_are_both_parsed() -> None:
    host = _parse().hosts[0]
    http = next(p for p in host.ports if p.port == 80)
    assert [(s.script_id, s.output) for s in http.scripts] == [
        ("http-title", "Go ahead and ScanMe!")
    ]
    assert [s.script_id for s in host.host_scripts] == ["clock-skew"]


def test_real_nmap_doctype_is_accepted() -> None:
    xml = '<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun version="7.97"></nmaprun>'
    assert parse_nmap_xml(xml).hosts == ()


def test_long_script_output_is_truncated() -> None:
    big = "A" * (MAX_SCRIPT_OUTPUT_CHARS + 500)
    xml = (
        '<nmaprun><host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        f'<script id="big" output="{big}"/></port></ports></host></nmaprun>'
    )
    script = parse_nmap_xml(xml).hosts[0].ports[0].scripts[0]
    assert len(script.output) < len(big)
    assert script.output.endswith("[truncated]")


@pytest.mark.parametrize(
    "bad_xml",
    [
        "",
        "not xml at all",
        "<nmaprun><host></nmaprun>",
        "<html><body>hi</body></html>",
    ],
)
def test_malformed_or_non_nmap_xml_raises(bad_xml: str) -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(bad_xml)


def test_entity_expansion_is_rejected() -> None:
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>'
        '<nmaprun version="&a;"></nmaprun>'
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(bomb)


def test_external_entity_is_rejected() -> None:
    xxe = (
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        '<nmaprun version="&x;"></nmaprun>'
    )
    with pytest.raises(NmapParseError):
        parse_nmap_xml(xxe)
