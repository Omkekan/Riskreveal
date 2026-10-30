"""The operator allowlist for public targets (pure Python, no DNS)."""

from __future__ import annotations

import pytest

from riskreveal.domain.scanning.authorization import check_authorized, parse_allowlist
from riskreveal.domain.scanning.scope_policy import ScopeError, validate_target


def _target(raw: str, resolved: tuple[str, ...] = (), *, allow_private: bool = False):
    return validate_target(raw, allow_private=allow_private, resolver=lambda _h: list(resolved))


def test_public_target_is_refused_when_allowlist_is_empty() -> None:
    with pytest.raises(ScopeError):
        check_authorized(_target("8.8.8.8"), allowlist=parse_allowlist([]))


def test_public_ip_on_allowlist_is_accepted() -> None:
    check_authorized(_target("8.8.8.8"), allowlist=parse_allowlist(["8.8.8.8"]))


def test_public_ip_inside_allowlisted_network_is_accepted() -> None:
    check_authorized(_target("203.0.114.9"), allowlist=parse_allowlist(["203.0.114.0/24"]))


def test_public_ip_outside_allowlisted_network_is_refused() -> None:
    with pytest.raises(ScopeError):
        check_authorized(_target("203.0.115.9"), allowlist=parse_allowlist(["203.0.114.0/24"]))


def test_hostname_on_allowlist_is_accepted() -> None:
    target = _target("scanme.nmap.org", ("45.33.32.156",))
    check_authorized(target, allowlist=parse_allowlist(["ScanMe.Nmap.org"]))


def test_hostname_allowlist_matches_exact_name_not_subdomains() -> None:
    target = _target("evil.scanme.nmap.org", ("45.33.32.157",))
    with pytest.raises(ScopeError):
        check_authorized(target, allowlist=parse_allowlist(["scanme.nmap.org"]))


def test_hostname_resolving_into_allowlisted_network_is_accepted() -> None:
    target = _target("host.example.com", ("203.0.114.5",))
    check_authorized(target, allowlist=parse_allowlist(["203.0.114.0/24"]))


def test_hostname_resolving_partly_outside_the_allowlist_is_refused() -> None:
    target = _target("host.example.com", ("203.0.114.5", "8.8.8.8"))
    with pytest.raises(ScopeError):
        check_authorized(target, allowlist=parse_allowlist(["203.0.114.0/24"]))


def test_cidr_must_sit_inside_an_allowlisted_network() -> None:
    allow = parse_allowlist(["203.0.114.0/24"])
    check_authorized(_target("203.0.114.0/28"), allowlist=allow)
    with pytest.raises(ScopeError):
        check_authorized(_target("203.0.115.0/28"), allowlist=allow)


def test_cidr_wider_than_the_allowlisted_network_is_refused() -> None:
    with pytest.raises(ScopeError):
        check_authorized(_target("203.0.114.0/24"), allowlist=parse_allowlist(["203.0.114.0/28"]))


def test_private_target_needs_no_allowlist_once_policy_allowed_it() -> None:
    check_authorized(_target("192.168.1.10", allow_private=True), allowlist=parse_allowlist([]))
    check_authorized(_target("127.0.0.1", allow_private=True), allowlist=parse_allowlist([]))
    check_authorized(_target("10.0.0.0/30", allow_private=True), allowlist=parse_allowlist([]))


def test_hostname_with_one_public_and_one_private_address_needs_the_allowlist() -> None:
    target = _target("mixed.example.com", ("8.8.8.8", "10.0.0.5"), allow_private=True)
    with pytest.raises(ScopeError):
        check_authorized(target, allowlist=parse_allowlist([]))


def test_ipv6_allowlist() -> None:
    allow = parse_allowlist(["2606:4700:4700::/48"])
    check_authorized(_target("2606:4700:4700::1111"), allowlist=allow)
    with pytest.raises(ScopeError):
        check_authorized(_target("2606:4700:4701::1111"), allowlist=parse_allowlist([]))


def test_blank_entries_are_ignored() -> None:
    allow = parse_allowlist(["", "  ", "8.8.8.8"])
    assert len(allow.networks) == 1
    assert not allow.hostnames


@pytest.mark.parametrize(
    "entry",
    [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "8.8.0.0/15",
        "2000::/3",
        "2606:4700::/32",
        "203.0.114.5/24",  # host bits set
        "-sV",
        "a b",
        "http://example.com",
        "exa_mple.com",
        "2130706433",
        "x" * 64 + ".com",
    ],
)
def test_bad_allowlist_entries_are_rejected(entry: str) -> None:
    with pytest.raises(ValueError):
        parse_allowlist([entry])


def test_ipv4_mapped_entry_is_stored_as_the_ipv4_address() -> None:
    allow = parse_allowlist(["::ffff:8.8.8.8"])
    check_authorized(_target("8.8.8.8"), allowlist=allow)
