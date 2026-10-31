"""system_resolver: timeout and error handling. No real DNS is used.

``socket.getaddrinfo`` is swapped for a fake and always restored.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from riskreveal.domain.scanning.scope_policy import ScopeError, system_resolver


@contextmanager
def _fake_getaddrinfo(fake: Callable[..., Any]) -> Iterator[None]:
    original = socket.getaddrinfo
    socket.getaddrinfo = fake  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original


def _info(address: str) -> tuple[int, int, int, str, tuple[str, int]]:
    return (2, 1, 6, "", (address, 0))


def test_returns_sorted_unique_addresses() -> None:
    def fake(*_a: object, **_k: object) -> list[object]:
        return [_info("93.184.216.35"), _info("93.184.216.34"), _info("93.184.216.34")]

    with _fake_getaddrinfo(fake):
        assert system_resolver("example.org") == ["93.184.216.34", "93.184.216.35"]


def test_slow_lookup_times_out_quickly() -> None:
    release = threading.Event()

    def slow(*_a: object, **_k: object) -> list[object]:
        release.wait(5)
        return [_info("93.184.216.34")]

    started = time.monotonic()
    try:
        with _fake_getaddrinfo(slow), pytest.raises(ScopeError, match="timed out"):
            system_resolver("slow.example.org", timeout=0.2)
        assert time.monotonic() - started < 2.0
    finally:
        release.set()  # let the abandoned lookup thread finish


@pytest.mark.parametrize(
    "error",
    [
        socket.gaierror(-2, "Name or service not known"),
        UnicodeError("label too long"),
        OSError("boom"),
    ],
)
def test_lookup_failures_become_a_fixed_scope_error(error: Exception) -> None:
    def failing(*_a: object, **_k: object) -> list[object]:
        raise error

    with (
        _fake_getaddrinfo(failing),
        pytest.raises(ScopeError, match="could not be resolved") as info,
    ):
        system_resolver("bad.example.org")
    # The user-facing message must not leak resolver internals.
    assert "Name or service" not in str(info.value)
    assert "boom" not in str(info.value)
