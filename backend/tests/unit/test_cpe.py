"""CPE parsing. Pure Python."""

from __future__ import annotations

import pytest

from riskreveal.domain.intelligence.cpe import Cpe, full_version, join_version, parse_cpe


def test_parses_an_nmap_style_cpe_22_uri() -> None:
    cpe = parse_cpe("cpe:/a:openbsd:openssh:6.6.1p1")
    assert cpe == Cpe("a", "openbsd", "openssh", "6.6.1p1", "*")


def test_cpe_22_without_a_version_has_a_wildcard_version() -> None:
    assert parse_cpe("cpe:/o:linux:linux_kernel") == Cpe("o", "linux", "linux_kernel", "*", "*")


def test_parses_a_nvd_style_cpe_23_string() -> None:
    cpe = parse_cpe("cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*")
    assert cpe == Cpe("a", "openbsd", "openssh", "6.6.1", "p1")


def test_parsing_is_case_insensitive_and_trims() -> None:
    assert parse_cpe("  CPE:/A:Apache:HTTP_Server:2.4.7 ") == Cpe(
        "a", "apache", "http_server", "2.4.7", "*"
    )


def test_cpe_22_percent_encoding_is_decoded() -> None:
    cpe = parse_cpe("cpe:/a:vendor:prod%2fx:1.0")
    assert cpe is not None
    assert cpe.product == "prod/x"


def test_cpe_23_backslash_escapes_are_honored() -> None:
    cpe = parse_cpe(r"cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.product == "pro:duct"
    assert cpe.version == "1.0"


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "   ",
        "nonsense",
        "cpe:/",
        "cpe:/a",
        "cpe:/a:onlyvendor",
        "cpe:/x:vendor:product:1",  # unknown part
        "cpe:/a::product:1",  # empty vendor
        "cpe:2.3:a:vendor:product",  # too few fields
        "cpe:2.3:a:*:*:1:*:*:*:*:*:*:*",  # wildcard vendor/product
        "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*:extra",  # too many fields
        "cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:\\",  # dangling backslash
        "cpe:/a:vend\x00or:product:1",
        "cpe:/a:vendor:" + "p" * 600,  # too long
    ],
)
def test_malformed_cpes_return_none(bad: str | None) -> None:
    assert parse_cpe(bad) is None


@pytest.mark.parametrize(
    ("version", "update", "expected"),
    [
        ("6.6.1", "p1", "6.6.1p1"),
        ("6.6.1p1", "*", "6.6.1p1"),
        ("2.4.7", "-", "2.4.7"),
        ("2.4.7", "", "2.4.7"),
        ("*", "*", None),
        ("-", "*", None),
        ("", "p1", None),
    ],
)
def test_join_version(version: str, update: str, expected: str | None) -> None:
    assert join_version(version, update) == expected


def test_full_version_uses_version_and_update() -> None:
    cpe = parse_cpe("cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*")
    assert cpe is not None
    assert full_version(cpe) == "6.6.1p1"
