"""Scope policy tests. Pure Python: no database, no network (DNS is faked)."""

from __future__ import annotations

import pytest

from riskreveal.domain.scanning.scope_policy import ScopeError, validate_target


def _fake_resolver(*addresses: str):
    def resolve(_hostname: str) -> list[str]:
        return list(addresses)

    return resolve


def _no_dns(hostname: str) -> list[str]:
    raise AssertionError(f"resolver must not be called for {hostname!r}")


# --- accepted ---------------------------------------------------------------


def test_public_ipv4_is_accepted() -> None:
    t = validate_target("8.8.8.8", allow_private=False, resolver=_no_dns)
    assert t.kind == "ip"
    assert t.scan_args == ("8.8.8.8",)
    assert t.addresses == ("8.8.8.8",)
    assert t.host_count == 1
    assert t.ipv6 is False


def test_public_ipv6_is_accepted_and_flagged() -> None:
    t = validate_target("2606:4700:4700::1111", allow_private=False, resolver=_no_dns)
    assert t.ipv6 is True
    assert t.scan_args == ("2606:4700:4700::1111",)


def test_surrounding_whitespace_is_trimmed() -> None:
    t = validate_target("  8.8.8.8\n", allow_private=False, resolver=_no_dns)
    assert t.scan_args == ("8.8.8.8",)


def test_public_cidr_is_accepted() -> None:
    t = validate_target("8.8.8.0/24", allow_private=False, resolver=_no_dns)
    assert t.kind == "cidr"
    assert t.scan_args == ("8.8.8.0/24",)
    assert t.addresses == ()
    assert t.host_count == 256


def test_cidr_with_host_bits_is_normalized() -> None:
    t = validate_target("8.8.8.5/24", allow_private=False, resolver=_no_dns)
    assert t.scan_args == ("8.8.8.0/24",)


def test_hostname_is_resolved_and_the_ip_is_what_gets_scanned() -> None:
    t = validate_target(
        "ScanMe.Nmap.Org.",
        allow_private=False,
        resolver=_fake_resolver("45.33.32.156"),
    )
    assert t.kind == "hostname"
    assert t.hostname == "scanme.nmap.org"
    assert t.scan_args == ("45.33.32.156",)  # an IP, never the name
    assert t.addresses == ("45.33.32.156",)


def test_dual_stack_hostname_scans_ipv4_only() -> None:
    t = validate_target(
        "example.org",
        allow_private=False,
        resolver=_fake_resolver("2606:4700:4700::1111", "8.8.8.8"),
    )
    assert t.scan_args == ("8.8.8.8",)
    assert t.ipv6 is False


def test_ipv6_only_hostname_is_flagged_ipv6() -> None:
    t = validate_target(
        "example.org", allow_private=False, resolver=_fake_resolver("2606:4700:4700::1111")
    )
    assert t.ipv6 is True


# --- private ranges: opt-in only -------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["10.0.0.1", "192.168.1.1", "172.16.5.4", "127.0.0.1", "::1", "100.64.0.1", "10.0.0.0/24"],
)
def test_private_and_loopback_rejected_by_default(target: str) -> None:
    with pytest.raises(ScopeError):
        validate_target(target, allow_private=False, resolver=_no_dns)


@pytest.mark.parametrize("target", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "10.0.0.0/24"])
def test_private_and_loopback_allowed_when_enabled(target: str) -> None:
    assert validate_target(target, allow_private=True, resolver=_no_dns).scan_args


def test_ipv4_mapped_loopback_cannot_bypass_the_check() -> None:
    with pytest.raises(ScopeError):
        validate_target("::ffff:127.0.0.1", allow_private=False, resolver=_no_dns)


# --- never allowed, even with allow_private ---------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "169.254.169.254",  # cloud metadata
        "169.254.0.0/24",
        "fe80::1",
        "0.0.0.0",  # noqa: S104
        "::",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "240.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_special_ranges_rejected_even_when_private_allowed(target: str) -> None:
    with pytest.raises(ScopeError):
        validate_target(target, allow_private=True, resolver=_no_dns)


# --- size limits ------------------------------------------------------------


def test_oversized_range_rejected() -> None:
    with pytest.raises(ScopeError):
        validate_target("8.8.0.0/16", allow_private=False, resolver=_no_dns)


def test_ipv6_range_rejected_when_too_large() -> None:
    with pytest.raises(ScopeError):
        validate_target("2606:4700::/64", allow_private=False, resolver=_no_dns)


def test_max_hosts_is_configurable() -> None:
    with pytest.raises(ScopeError):
        validate_target("8.8.8.0/24", allow_private=False, max_hosts=64, resolver=_no_dns)
    assert validate_target("8.8.8.0/26", allow_private=False, max_hosts=64, resolver=_no_dns)


# --- hostname resolution rules ----------------------------------------------


def test_hostname_resolving_to_private_is_rejected_without_echoing_the_ip() -> None:
    with pytest.raises(ScopeError) as excinfo:
        validate_target(
            "internal.example.org", allow_private=False, resolver=_fake_resolver("10.1.2.3")
        )
    assert "10.1.2.3" not in str(excinfo.value)


def test_hostname_with_any_disallowed_address_is_rejected() -> None:
    with pytest.raises(ScopeError):
        validate_target(
            "mixed.example.org",
            allow_private=False,
            resolver=_fake_resolver("8.8.8.8", "10.1.2.3"),
        )


def test_hostname_resolving_to_metadata_rejected_even_when_private_allowed() -> None:
    with pytest.raises(ScopeError):
        validate_target(
            "meta.example.org", allow_private=True, resolver=_fake_resolver("169.254.169.254")
        )


def test_localhost_allowed_only_when_private_allowed() -> None:
    resolver = _fake_resolver("127.0.0.1")
    with pytest.raises(ScopeError):
        validate_target("localhost", allow_private=False, resolver=resolver)
    assert validate_target("localhost", allow_private=True, resolver=resolver).scan_args == (
        "127.0.0.1",
    )


def test_unresolvable_hostname_rejected() -> None:
    with pytest.raises(ScopeError):
        validate_target("nope.example.org", allow_private=False, resolver=_fake_resolver())


def test_resolver_error_is_passed_through() -> None:
    def failing(_hostname: str) -> list[str]:
        raise ScopeError("The hostname could not be resolved.")

    with pytest.raises(ScopeError):
        validate_target("nope.example.org", allow_private=False, resolver=failing)


def test_too_many_resolved_addresses_rejected() -> None:
    many = [f"8.8.{i}.1" for i in range(17)]
    with pytest.raises(ScopeError):
        validate_target("big.example.org", allow_private=False, resolver=_fake_resolver(*many))


# --- malformed / hostile input: never reaches the resolver ------------------


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "-sV",
        "--script=vuln",
        "-oN",
        "8.8.8.8 -p-",
        "8.8.8.8,8.8.4.4",
        "8.8.8.8;id",
        "a b.example.org",
        "http://example.org",
        "example.org/path",
        "fe80::1%eth0",
        "127.1",
        "2130706433",
        "0x7f.0.0.1",
        "a..b",
        "-bad.example.org",
        "bad-.example.org",
        "ünïcode.example.org",
        "x" * 300,
        ("a" * 64) + ".example.org",
    ],
)
def test_malformed_targets_rejected_before_any_dns(target: str) -> None:
    with pytest.raises(ScopeError):
        validate_target(target, allow_private=True, resolver=_no_dns)
