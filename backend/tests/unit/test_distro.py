"""Distribution detection. Pure Python."""

from __future__ import annotations

import pytest

from riskreveal.domain.intelligence.distro import detect_distro


@pytest.mark.parametrize(
    ("texts", "expected"),
    [
        (("6.6.1p1 Ubuntu 2ubuntu2.13", None), "ubuntu"),
        (("2.4.7", "(Ubuntu)"), "ubuntu"),
        (("1:8.4p1-5+deb11u1", None), "debian"),
        (("8.4p1 Debian 5+deb11u1", "protocol 2.0"), "debian"),
        ((None, "(CentOS)"), "centos"),
        (("2.4.6", "(Red Hat Enterprise Linux)"), "rhel"),
        (("7.4p1-22.el7_9", None), "rhel"),
        (("9.3p1-1.fc39", None), "fedora"),
        (("8.9 FreeBSD 20200214", None), "freebsd"),
        (("6.6.1p1", "protocol 2.0"), None),
        (("2.4.7", "(Unix)"), None),
        ((None, None), None),
        ((), None),
        (("",), None),
    ],
)
def test_detect_distro(texts: tuple[str | None, ...], expected: str | None) -> None:
    assert detect_distro(*texts) == expected


def test_very_long_input_is_handled_quickly_and_safely() -> None:
    assert detect_distro("a" * 1_000_000) is None
