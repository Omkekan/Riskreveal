"""Version parsing and ordering. Pure Python."""

from __future__ import annotations

import pytest

from riskreveal.domain.intelligence.versions import compare_versions, parse_version


def _cmp(a: str, b: str) -> int:
    left, right = parse_version(a), parse_version(b)
    assert left is not None, f"{a!r} should parse"
    assert right is not None, f"{b!r} should parse"
    return compare_versions(left, right)


@pytest.mark.parametrize(
    ("older", "newer"),
    [
        ("6.6.1", "6.6.1p1"),
        ("6.6.1p1", "6.6.2"),
        ("6.6.1p1", "6.6.1p2"),
        ("7.1p2", "7.2"),
        ("2.4.7", "2.4.10"),
        ("1.9", "1.10"),
        ("9", "10"),
        ("0.9.8", "1.0"),
        ("1.0rc1", "1.0"),
        ("1.0-rc1", "1.0"),
        ("1.0alpha", "1.0beta"),
        ("1.0beta1", "1.0rc1"),
        ("1.0rc1", "1.0rc2"),
        ("1.0.2", "1.0.2k"),
        ("1.0.2j", "1.0.2k"),
        ("1.0.2k", "1.0.3"),
        ("1.0a", "1.0.1"),
        ("1.0", "1.0.0.1"),
        ("1.0.0", "1.0.1"),
        ("2.0-sp1", "2.0-sp2"),
        ("2.0", "2.0sp1"),
    ],
)
def test_ordering(older: str, newer: str) -> None:
    assert _cmp(older, newer) == -1
    assert _cmp(newer, older) == 1


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1.0", "1.0.0"),
        ("2.4.7", "2.4.7.0"),
        ("6.6.1p1", "6.6.1p1"),
        ("1.2", "v1.2"),
        ("1.2", "1_2"),
        ("1.2", "1-2"),
        ("1.0RC1", "1.0rc1"),
        ("007", "7"),
    ],
)
def test_equality(a: str, b: str) -> None:
    assert _cmp(a, b) == 0


@pytest.mark.parametrize(
    "unparseable",
    [
        None,
        "",
        "   ",
        "abc",
        "latest",
        "v",
        "1.0 beta",  # a space
        "1:2.3",  # an epoch colon
        "1.0.2k-fips",  # unknown word
        "2.4.7ubuntu",  # unknown word
        "1." + "9" * 70,  # too long
        ".".join(["1"] * 30),  # too many parts
        "1" + "9" * 30,  # a number with too many digits
        "1.0\x00",
        "1.0;rm",
    ],
)
def test_unparseable_versions_return_none(unparseable: str | None) -> None:
    assert parse_version(unparseable) is None
