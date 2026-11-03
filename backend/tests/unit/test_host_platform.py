"""Host platform detection and the "can this platform-specific CVE apply?" rule. Pure Python."""

from __future__ import annotations

import pytest

from riskreveal.domain.intelligence.host_platform import (
    HostPlatform,
    detect_host_platform,
    requirement_platform,
    requirements_possible,
)

LINUX = HostPlatform("linux")
UBUNTU = HostPlatform("linux", "ubuntu")
WINDOWS = HostPlatform("windows")


@pytest.mark.parametrize(
    ("texts", "expected"),
    [
        (("2.4.7", "(Ubuntu)"), UBUNTU),
        (("6.6.1p1 Ubuntu 2ubuntu2.13", "protocol 2.0"), UBUNTU),
        ((None, "(Win32)"), WINDOWS),
        (("Microsoft IIS httpd",), WINDOWS),
        (("2.4.58", "(Win64) OpenSSL/3.1"), WINDOWS),
        (("Linux",), LINUX),
        (("2.4.6", "(CentOS)"), HostPlatform("linux", "centos")),
        (("8.9 FreeBSD 20200214",), HostPlatform("bsd", "freebsd")),
        (("Darwin",), HostPlatform("macos")),
        # not recognised, or contradictory: no claim
        (("2.4.7", "(Unix)"), None),
        ((None, None), None),
        ((), None),
        (("Windows", "Ubuntu"), None),
        (("(Win32) running on Debian",), None),
    ],
)
def test_detect_host_platform(texts: tuple[str | None, ...], expected: HostPlatform | None) -> None:
    assert detect_host_platform(*texts) == expected


def test_detect_host_platform_survives_huge_input() -> None:
    assert detect_host_platform("x" * 1_000_000) is None


@pytest.mark.parametrize(
    ("requirement", "expected"),
    [
        # the values seen in the real NVD feed
        ("microsoft:windows", WINDOWS),
        ("redhat:enterprise_linux", HostPlatform("linux", "rhel")),
        ("redhat:enterprise_linux_desktop", HostPlatform("linux", "rhel")),
        # other common ones
        ("microsoft:windows_server_2019", WINDOWS),
        ("linux:linux_kernel", LINUX),
        ("canonical:ubuntu_linux", UBUNTU),
        ("debian:debian_linux", HostPlatform("linux", "debian")),
        ("apple:mac_os_x", HostPlatform("macos")),
        ("freebsd:freebsd", HostPlatform("bsd", "freebsd")),
        ("openbsd:openbsd", HostPlatform("bsd")),
        ("oracle:solaris", HostPlatform("solaris")),
        ("opensuse:leap", HostPlatform("linux", "suse")),
        # unrecognised: None, never a guess
        ("cisco:ios", None),
        ("something", None),
        ("", None),
        (":", None),
    ],
)
def test_requirement_platform(requirement: str, expected: HostPlatform | None) -> None:
    assert requirement_platform(requirement) == expected


@pytest.mark.parametrize(
    ("host", "requires", "possible"),
    [
        # known host, requirement known to be different: ruled out
        (UBUNTU, ("microsoft:windows",), False),
        (LINUX, ("microsoft:windows",), False),
        (WINDOWS, ("redhat:enterprise_linux",), False),
        (UBUNTU, ("redhat:enterprise_linux", "redhat:enterprise_linux_desktop"), False),
        # compatible
        (WINDOWS, ("microsoft:windows",), True),
        (UBUNTU, ("linux:linux_kernel",), True),
        (UBUNTU, ("canonical:ubuntu_linux",), True),
        # cannot rule it out, so it stays
        (LINUX, ("redhat:enterprise_linux",), True),  # a Linux of unknown distribution
        (UBUNTU, ("microsoft:windows", "cisco:ios"), True),  # one requirement unrecognised
        (UBUNTU, ("microsoft:windows", "canonical:ubuntu_linux"), True),  # any one is enough
        (None, ("microsoft:windows",), True),  # unknown host
        (UBUNTU, (), True),  # no requirements recorded
        (HostPlatform(), ("microsoft:windows",), True),  # a host about which nothing is known
    ],
)
def test_requirements_possible(
    host: HostPlatform | None, requires: tuple[str, ...], possible: bool
) -> None:
    assert requirements_possible(host, requires) is possible
