"""Downloading feeds over HTTPS, with hard limits.

The URLs are constants in the source modules (never user input), but the
response is still untrusted: it is size-capped while streaming, has an overall
time limit, and must stay on HTTPS across redirects.
"""

from __future__ import annotations

import time

import httpx

from riskreveal.domain.intelligence.errors import FeedFetchError

_USER_AGENT = "RiskReveal/0.1 (+https://github.com/Omkekan/Riskreveal)"
_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
_MAX_REDIRECTS = 3
DEFAULT_MAX_SECONDS = 120.0


def download(
    url: str,
    *,
    max_bytes: int,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    transport: httpx.BaseTransport | None = None,
) -> bytes:
    """GET ``url`` and return the body, refusing anything over ``max_bytes``.

    ``transport`` exists only so tests can supply a fake network; production
    code leaves it ``None``.
    """
    if not url.startswith("https://"):
        raise FeedFetchError("Feeds must be downloaded over HTTPS.")

    deadline = time.monotonic() + max_seconds
    chunks: list[bytes] = []
    total = 0
    try:
        with (
            httpx.Client(
                timeout=_TIMEOUT,
                follow_redirects=True,
                max_redirects=_MAX_REDIRECTS,
                headers={"User-Agent": _USER_AGENT},
                transport=transport,
            ) as client,
            client.stream("GET", url) as response,
        ):
            if response.url.scheme != "https":
                raise FeedFetchError("The feed server redirected to a non-HTTPS address.")
            if response.status_code != 200:
                raise FeedFetchError(f"The feed server answered HTTP {response.status_code}.")
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise FeedFetchError("The feed is larger than the allowed maximum size.")
                if time.monotonic() > deadline:
                    raise FeedFetchError("The feed download took too long.")
                chunks.append(chunk)
    except httpx.HTTPError as exc:
        raise FeedFetchError(f"Could not download the feed ({type(exc).__name__}).") from exc
    return b"".join(chunks)
