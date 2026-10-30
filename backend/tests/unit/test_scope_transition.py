"""IPv6 transition ranges embed an IPv4 address and are never scannable."""

from __future__ import annotations

import pytest

from riskreveal.domain.scanning.scope_policy import ScopeError, validate_target


def _validate(raw: str, *, allow_private: bool):
    return validate_target(raw, allow_private=allow_private, resolver=lambda _h: [])


@pytest.mark.parametrize(
    "address",
    [
        "64:ff9b::7f00:1",  # NAT64 -> 127.0.0.1
        "64:ff9b::a00:1",  # NAT64 -> 10.0.0.1
        "64:ff9b:1::1",
        "2002:7f00:1::1",  # 6to4 -> 127.0.0.1
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    ],
)
@pytest.mark.parametrize("allow_private", [False, True])
def test_transition_addresses_are_never_allowed(address: str, allow_private: bool) -> None:
    with pytest.raises(ScopeError):
        _validate(address, allow_private=allow_private)


def test_ordinary_public_ipv6_is_still_allowed() -> None:
    assert _validate("2606:4700:4700::1111", allow_private=False).ipv6
    assert _validate("2001:4860:4860::8888", allow_private=False).ipv6
