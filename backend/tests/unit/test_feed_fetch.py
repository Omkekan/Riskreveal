"""Tests for the feed downloader using a fake network (no real HTTP)."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from riskreveal.domain.intelligence.errors import FeedFetchError
from riskreveal.domain.intelligence.sources.fetch import download

URL = "https://feeds.example.test/data.json"


def _transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def test_returns_the_body() -> None:
    transport = _transport(lambda request: httpx.Response(200, content=b"hello"))
    assert download(URL, max_bytes=100, transport=transport) == b"hello"


def test_refuses_plain_http_before_any_request() -> None:
    called = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(request)
        return httpx.Response(200, content=b"x")

    with pytest.raises(FeedFetchError, match="HTTPS"):
        download("http://feeds.example.test/x", max_bytes=100, transport=_transport(handler))
    assert not called


@pytest.mark.parametrize("status", [301, 403, 404, 500, 503])
def test_non_200_answers_are_errors(status: int) -> None:
    transport = _transport(lambda request: httpx.Response(status))
    with pytest.raises(FeedFetchError, match=f"HTTP {status}"):
        download(URL, max_bytes=100, transport=transport)


def test_oversized_body_is_refused() -> None:
    transport = _transport(lambda request: httpx.Response(200, content=b"x" * 101))
    with pytest.raises(FeedFetchError, match="larger than"):
        download(URL, max_bytes=100, transport=transport)


def test_body_exactly_at_the_limit_is_allowed() -> None:
    transport = _transport(lambda request: httpx.Response(200, content=b"x" * 100))
    assert len(download(URL, max_bytes=100, transport=transport)) == 100


def test_network_failures_become_feed_errors_without_leaking_details() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret-internal-detail")

    with pytest.raises(FeedFetchError) as info:
        download(URL, max_bytes=100, transport=_transport(handler))
    assert "ConnectError" in str(info.value)
    assert "secret-internal-detail" not in str(info.value)


def test_redirect_to_plain_http_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "https":
            return httpx.Response(302, headers={"location": "http://feeds.example.test/data"})
        return httpx.Response(200, content=b"downgraded")

    with pytest.raises(FeedFetchError, match="non-HTTPS"):
        download(URL, max_bytes=100, transport=_transport(handler))


def test_slow_download_hits_the_overall_deadline() -> None:
    transport = _transport(lambda request: httpx.Response(200, content=b"x" * 10))
    with pytest.raises(FeedFetchError, match="too long"):
        download(URL, max_bytes=100, max_seconds=-1.0, transport=transport)
