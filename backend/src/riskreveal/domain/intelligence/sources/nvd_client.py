"""Ask the NVD which CVEs list one exact CPE as vulnerable.

This is the same query ``scripts/nvd_match_demo.py`` uses (and that was checked
against real data): ``cpeName=<CPE 2.3 name>&isVulnerable``. Parsing is done by
``sources/nvd.py``; this module only builds requests, pages, retries and paces
itself.

Two things make it more than a thin wrapper:

* **Dictionary names.** The NVD only answers for names that exist in its CPE
  dictionary (HTTP 404 otherwise), and it spells some versions differently from
  Nmap: OpenSSH ``6.6.1p1`` is version ``6.6.1`` + update ``p1``.
  :func:`nvd_cpe_names` returns the names to try, most likely first.
* **Politeness.** Without an API key the NVD allows about 5 requests per 30 s.
  The client waits between requests and retries rate-limit answers (HTTP 403
  and 429) with back-off. An API key is sent as a header and never appears in
  an error message.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from urllib.parse import quote

import httpx

from riskreveal.domain.intelligence.cpe import Cpe, full_version
from riskreveal.domain.intelligence.errors import FeedFetchError, FeedParseError
from riskreveal.domain.intelligence.records import CveRecord
from riskreveal.domain.intelligence.sources.fetch import download
from riskreveal.domain.intelligence.sources.nvd import parse_nvd_response

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # the NVD's maximum
MAX_PAGES = 25
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
DELAY_WITHOUT_KEY_SECONDS = 6.5
DELAY_WITH_KEY_SECONDS = 0.7
RETRY_STATUSES = frozenset({403, 429, 500, 502, 503, 504})  # the NVD answers 403 when throttled
MAX_NAME_LENGTH = 255  # width of cve_syncs.cpe_name

_NAME_PART = re.compile(r"^[a-z0-9_.\-]{1,100}$")
_VERSION_PART = re.compile(r"^[a-z0-9_.\-]{1,64}$")
# "6.6.1p1" -> base "6.6.1" + update "p1". Same suffixes the matcher treats as updates.
_PATCH_LEVEL = re.compile(
    r"(?P<base>\d[0-9.]*?)(?P<update>(?:p|sp|rc|beta|alpha|patch|update|pre)\d*)"
)


def nvd_cpe_names(cpe: Cpe) -> list[str]:
    """CPE 2.3 names to ask the NVD about, most likely spelling first.

    Empty if the CPE cannot be turned into a safe name (no version, or a part
    that is not application/OS, or characters outside ``[a-z0-9_.-]``). Every
    component is validated, so a hostile banner cannot shape the request.
    """
    version = full_version(cpe)
    if (
        version is None
        or cpe.part not in ("a", "o")
        or not _NAME_PART.match(cpe.vendor)
        or not _NAME_PART.match(cpe.product)
    ):
        return []

    spellings: list[tuple[str, str]] = []
    if cpe.update in ("*", ""):
        split = _PATCH_LEVEL.fullmatch(cpe.version)
        if split is not None:
            spellings.append((split.group("base"), split.group("update")))
    spellings.append((cpe.version, cpe.update))

    names: list[str] = []
    for ver, update in spellings:
        if not _VERSION_PART.match(ver) or not (update == "*" or _VERSION_PART.match(update)):
            continue
        name = f"cpe:2.3:{cpe.part}:{cpe.vendor}:{cpe.product}:{ver}:{update}:*:*:*:*:*:*"
        if len(name) <= MAX_NAME_LENGTH and name not in names:
            names.append(name)
    return names


class NvdClient:
    """Fetch CVE records for one CPE name at a time."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
        page_size: int = PAGE_SIZE,
        max_retries: int = 3,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._api_key = api_key.strip() if api_key and api_key.strip() else None
        self._sleep = sleep
        self._page_size = max(1, min(page_size, PAGE_SIZE))
        self._max_retries = max_retries
        self._transport = transport  # tests only
        self._delay = DELAY_WITH_KEY_SECONDS if self._api_key else DELAY_WITHOUT_KEY_SECONDS
        self._requests = 0

    def fetch_cves(self, nvd_cpe_name: str) -> list[CveRecord]:
        """Every CVE the NVD lists as vulnerable for ``nvd_cpe_name``.

        Raises ``FeedFetchError`` (``status_code == 404`` when the NVD does not
        know the name) or ``FeedParseError``. The name must come from
        :func:`nvd_cpe_names`; anything else is refused.
        """
        if not nvd_cpe_name.startswith("cpe:2.3:") or not re.fullmatch(
            r"[a-z0-9_.:*\-]{1,255}", nvd_cpe_name
        ):
            raise FeedParseError("NVD: refusing a CPE name with unexpected characters.")

        records: list[CveRecord] = []
        start = 0
        for _ in range(MAX_PAGES):
            query = (
                f"cpeName={quote(nvd_cpe_name, safe=':*')}&isVulnerable"
                f"&resultsPerPage={self._page_size}&startIndex={start}"
            )
            try:
                payload = json.loads(self._get(f"{NVD_URL}?{query}"))
            except (ValueError, RecursionError) as exc:
                raise FeedParseError("NVD: the response was not valid JSON.") from exc
            page = parse_nvd_response(payload)
            records.extend(page.records)
            start += page.results_per_page
            if page.results_per_page == 0 or start >= page.total_results:
                return records
        raise FeedParseError("NVD: too many result pages; stopping.")

    def _get(self, url: str) -> bytes:
        headers = {"apiKey": self._api_key} if self._api_key else None
        for attempt in range(self._max_retries + 1):
            if self._requests:
                self._sleep(self._delay)  # pace every request after the first
            self._requests += 1
            try:
                return download(
                    url,
                    max_bytes=MAX_RESPONSE_BYTES,
                    headers=headers,
                    transport=self._transport,
                )
            except FeedFetchError as exc:
                if exc.status_code not in RETRY_STATUSES or attempt == self._max_retries:
                    raise
                self._sleep(self._delay * 2 * (2**attempt))
        raise AssertionError("unreachable")  # the loop always returns or raises
