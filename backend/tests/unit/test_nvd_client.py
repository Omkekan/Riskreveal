"""NVD name candidates and the client, against a fake network (no real HTTP)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from riskreveal.domain.intelligence.cpe import Cpe, parse_cpe
from riskreveal.domain.intelligence.errors import FeedFetchError, FeedParseError
from riskreveal.domain.intelligence.sources.nvd_client import (
    DELAY_WITH_KEY_SECONDS,
    DELAY_WITHOUT_KEY_SECONDS,
    NvdClient,
    nvd_cpe_names,
)

APACHE = "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"


def _names(text: str) -> list[str]:
    cpe = parse_cpe(text)
    assert cpe is not None
    return nvd_cpe_names(cpe)


# --- which names do we ask the NVD about? ---------------------------------------


def test_a_plain_version_is_asked_as_written() -> None:
    assert _names("cpe:/a:apache:http_server:2.4.7") == [APACHE]


def test_a_patch_level_is_tried_the_way_the_nvd_stores_it_first() -> None:
    assert _names("cpe:/a:openbsd:openssh:6.6.1p1") == [
        "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*",  # version + update (verified)
        "cpe:2.3:a:openbsd:openssh:6.6.1p1:*:*:*:*:*:*:*",  # as Nmap wrote it
    ]


@pytest.mark.parametrize(
    ("text", "base", "update"),
    [
        ("cpe:/a:vendor:thing:8.2p1", "8.2", "p1"),
        ("cpe:/a:vendor:thing:1.0rc2", "1.0", "rc2"),
        ("cpe:/a:vendor:thing:3.1sp1", "3.1", "sp1"),
    ],
)
def test_update_suffixes_are_split(text: str, base: str, update: str) -> None:
    assert _names(text)[0] == f"cpe:2.3:a:vendor:thing:{base}:{update}:*:*:*:*:*:*"


@pytest.mark.parametrize("version", ["1.0.2k", "2.4.7-1", "8.20", "1.0a"])
def test_other_versions_are_not_split(version: str) -> None:
    names = _names(f"cpe:/a:vendor:thing:{version}")
    assert names == [f"cpe:2.3:a:vendor:thing:{version}:*:*:*:*:*:*:*"]


def test_an_explicit_update_is_kept() -> None:
    assert _names("cpe:/a:openbsd:openssh:6.6.1:p1") == [
        "cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "cpe:/a:apache:http_server",  # no version
        "cpe:/h:vendor:thing:1.0",  # hardware
        "cpe:/a:vendor:thing:-",  # version not applicable
    ],
)
def test_cpes_that_cannot_be_asked_about_give_no_names(text: str) -> None:
    assert _names(text) == []


@pytest.mark.parametrize(
    "cpe",
    [
        Cpe("a", "ven dor", "thing", "1.0"),
        Cpe("a", "vendor", "thi;ng", "1.0"),
        Cpe("a", "vendor", "thing", "1.0&x=1"),
        Cpe("a", "vendor", "thing", "1.0", "a b"),
        Cpe("a", "v" * 101, "thing", "1.0"),
        Cpe("a", "vendor", "thing", "1" * 70),
        Cpe("a", "ünï", "thing", "1.0"),
    ],
)
def test_hostile_components_never_reach_a_request(cpe: Cpe) -> None:
    assert nvd_cpe_names(cpe) == []


# --- the client -----------------------------------------------------------------


def _page(ids: list[str], *, total: int, start: int = 0) -> dict[str, Any]:
    return {
        "resultsPerPage": len(ids),
        "startIndex": start,
        "totalResults": total,
        "vulnerabilities": [
            {"cve": {"id": i, "descriptions": [{"lang": "en", "value": f"{i} text"}]}}
            for i in ids
        ],
    }


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    key: str | None = None,
    page_size: int = 2000,
    retries: int = 3,
) -> tuple[NvdClient, list[float]]:
    sleeps: list[float] = []
    client = NvdClient(
        api_key=key,
        sleep=sleeps.append,
        page_size=page_size,
        max_retries=retries,
        transport=httpx.MockTransport(handler),
    )
    return client, sleeps


def test_it_asks_for_the_exact_name_and_only_vulnerable_entries() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_page(["CVE-2099-0001"], total=1))

    client, sleeps = _client(handler)
    records = client.fetch_cves(APACHE)
    assert [r.cve_id for r in records] == ["CVE-2099-0001"]
    assert seen[0].url.params["cpeName"] == APACHE
    assert "isVulnerable" in str(seen[0].url)
    assert sleeps == []  # the first request is not delayed


def test_several_pages_are_followed_with_a_polite_delay() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["startIndex"])
        ids = ["CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"][start : start + 2]
        return httpx.Response(200, json=_page(ids, total=3, start=start))

    client, sleeps = _client(handler, page_size=2)
    assert [r.cve_id for r in client.fetch_cves(APACHE)] == [
        "CVE-2099-0001",
        "CVE-2099-0002",
        "CVE-2099-0003",
    ]
    assert sleeps == [DELAY_WITHOUT_KEY_SECONDS]


def test_every_request_after_the_first_is_paced_even_across_calls() -> None:
    client, sleeps = _client(lambda request: httpx.Response(200, json=_page([], total=0)))
    client.fetch_cves(APACHE)
    client.fetch_cves(APACHE)
    client.fetch_cves(APACHE)
    assert sleeps == [DELAY_WITHOUT_KEY_SECONDS, DELAY_WITHOUT_KEY_SECONDS]


def test_an_api_key_is_a_header_never_in_the_url_and_it_speeds_things_up() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        start = int(request.url.params["startIndex"])
        ids = ["CVE-2099-0001", "CVE-2099-0002"][start : start + 1]
        return httpx.Response(200, json=_page(ids, total=2, start=start))

    client, sleeps = _client(handler, key="  secret-key  ", page_size=1)
    client.fetch_cves(APACHE)
    assert all(r.headers["apiKey"] == "secret-key" for r in seen)
    assert "secret-key" not in str(seen[0].url)
    assert sleeps == [DELAY_WITH_KEY_SECONDS]


def test_no_key_means_no_header() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_page([], total=0))

    client, _ = _client(handler, key="   ")
    client.fetch_cves(APACHE)
    assert "apikey" not in seen[0].headers


def test_a_rate_limit_answer_is_retried_with_growing_back_off() -> None:
    answers = [
        httpx.Response(403),
        httpx.Response(503),
        httpx.Response(200, json=_page([], total=0)),
    ]
    client, sleeps = _client(lambda request: answers.pop(0))
    assert client.fetch_cves(APACHE) == []
    backoffs = [s for s in sleeps if s > DELAY_WITHOUT_KEY_SECONDS]
    assert len(backoffs) == 2 and backoffs[1] > backoffs[0]


def test_it_gives_up_after_the_retry_budget() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(403)

    client, _ = _client(handler, retries=2)
    with pytest.raises(FeedFetchError) as info:
        client.fetch_cves(APACHE)
    assert len(calls) == 3 and info.value.status_code == 403


def test_an_unknown_cpe_name_is_a_404_that_is_not_retried() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(404)

    client, _ = _client(handler)
    with pytest.raises(FeedFetchError) as info:
        client.fetch_cves(APACHE)
    assert len(calls) == 1 and info.value.status_code == 404


def test_an_error_message_never_contains_the_api_key() -> None:
    client, _ = _client(lambda request: httpx.Response(404), key="super-secret-key")
    with pytest.raises(FeedFetchError) as info:
        client.fetch_cves(APACHE)
    assert "super-secret-key" not in str(info.value)


def test_a_non_json_answer_is_a_parse_error() -> None:
    client, _ = _client(lambda request: httpx.Response(200, content=b"<html>maintenance</html>"))
    with pytest.raises(FeedParseError):
        client.fetch_cves(APACHE)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "apache",
        "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*&x=1",
        "cpe:2.3:a:apa che:http_server:1:*:*:*:*:*:*:*",
        "cpe:2.3:a:ünï:http_server:1:*:*:*:*:*:*:*",
        "cpe:/a:apache:http_server:2.4.7",
    ],
)
def test_a_name_not_built_by_us_is_refused_before_any_request(name: str) -> None:
    called: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        called.append(1)
        return httpx.Response(200, json=_page([], total=0))

    client, _ = _client(handler)
    with pytest.raises(FeedParseError):
        client.fetch_cves(name)
    assert not called


def test_an_endless_listing_is_stopped() -> None:
    client, _ = _client(
        lambda request: httpx.Response(200, json=_page(["CVE-2099-0001"], total=10**9)),
        page_size=1,
    )
    with pytest.raises(FeedParseError, match="too many"):
        client.fetch_cves(APACHE)
