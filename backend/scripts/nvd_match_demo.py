"""Compare the NVD's answer with our own matcher for one CPE. Needs internet.

    uv run python scripts/nvd_match_demo.py "cpe:/a:apache:http_server:2.4.7"
    uv run python scripts/nvd_match_demo.py "cpe:/a:apache:http_server:2.4.7" --kev

What it does, in order:

1. Parses the CPE (the form Nmap reports) and asks the NVD, over HTTPS, which
   CVEs list that CPE as vulnerable. ONE request; nothing is stored.
2. Parses the NVD's reply with our parser (``sources/nvd.py``).
3. Runs our matcher (``matcher.py``) over those same CVEs and prints, for each,
   whether OUR logic agrees that the version is affected.
4. With ``--kev``: also downloads CISA's Known Exploited Vulnerabilities list
   (one request, about 1 MB, through the same hardened downloader the importer
   uses) and marks the CVEs that appear in it.

Rows marked NOT MATCHED are the interesting ones: the NVD says the CVE applies
but our matcher disagrees. That means a version format or a product/vendor name
we don't handle yet, or a difference in how the NVD treats the "update" field.
Send those lines back so the matcher can be fixed with real examples.

No API key is needed. If you have one, set NVD_API_KEY in your terminal (it is
only sent to the NVD and never printed); without a key the NVD allows about
5 requests per 30 seconds, which is plenty for this script. Run it sparingly.

A match is NOT proof that a host is vulnerable: it only says the advertised
version is in a vulnerable range (distribution back-ports, disabled features
and false banners all exist). Only scan systems you are allowed to scan.
"""

from __future__ import annotations

import argparse
import os
import sys
from urllib.parse import quote

import httpx

from riskreveal.domain.intelligence.cpe import Cpe, full_version, parse_cpe
from riskreveal.domain.intelligence.errors import FeedError
from riskreveal.domain.intelligence.matcher import match_cves
from riskreveal.domain.intelligence.records import CveRecord
from riskreveal.domain.intelligence.sources.cisa_kev import KEV_MAX_BYTES, KEV_URL, parse_kev
from riskreveal.domain.intelligence.sources.fetch import download
from riskreveal.domain.intelligence.sources.nvd import parse_nvd_response

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESPONSE_BYTES = 50 * 1024 * 1024
TIMEOUT_SECONDS = 30.0


def default_nvd_name(cpe: Cpe) -> str:
    """The CPE 2.3 name sent to the NVD when --nvd-cpe-name isn't given."""
    return (
        f"cpe:2.3:{cpe.part}:{cpe.vendor}:{cpe.product}:{cpe.version}:{cpe.update}"
        ":*:*:*:*:*:*"
    )


def _get_nvd_json(url: str, api_key: str | None) -> object:
    headers = {"User-Agent": "riskreveal-dev-demo/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    response = httpx.get(url, headers=headers, timeout=TIMEOUT_SECONDS, follow_redirects=False)
    if response.status_code != 200:
        hint = ""
        if response.status_code in (403, 429):
            hint = " (rate limited? wait a minute, or set NVD_API_KEY)"
        elif response.status_code == 404:
            hint = " (the NVD does not know that CPE name; try --nvd-cpe-name)"
        raise RuntimeError(f"HTTP {response.status_code}{hint}")
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise RuntimeError("the response was unexpectedly large")
    return response.json()


def _cve_order(record: CveRecord) -> tuple[int, int]:
    _, year, number = record.cve_id.split("-")
    return (int(year), int(number))


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the NVD with our CVE matcher.")
    parser.add_argument("cpe", help='a CPE, e.g. "cpe:/a:apache:http_server:2.4.7"')
    parser.add_argument("--nvd-cpe-name", help="CPE 2.3 name to send to the NVD instead")
    parser.add_argument("--results", type=int, default=500, help="most CVEs to request (1-2000)")
    parser.add_argument("--kev", action="store_true", help="also mark CVEs in CISA's KEV list")
    args = parser.parse_args()

    subject = parse_cpe(args.cpe)
    if subject is None:
        print("That is not a valid CPE.")
        return 2
    if full_version(subject) is None:
        print("The CPE needs a version (e.g. cpe:/a:apache:http_server:2.4.7).")
        return 2

    nvd_name = args.nvd_cpe_name or default_nvd_name(subject)
    results = max(1, min(args.results, 2000))
    url = f"{NVD_URL}?cpeName={quote(nvd_name, safe=':*')}&isVulnerable&resultsPerPage={results}"

    print(f"Asking the NVD about: {nvd_name}")
    try:
        page = parse_nvd_response(_get_nvd_json(url, os.environ.get("NVD_API_KEY")))
    except (httpx.HTTPError, RuntimeError, ValueError, FeedError) as exc:
        print(f"Could not get or read the NVD answer: {type(exc).__name__}: {exc}")
        return 1

    kev_ids: set[str] = set()
    if args.kev:
        try:
            catalog = parse_kev(download(KEV_URL, max_bytes=KEV_MAX_BYTES))
            kev_ids = {record.cve_id for record in catalog.records}
            print(f"KEV list: {len(catalog.records)} entries, {catalog.skipped} skipped.")
        except FeedError as exc:
            print(f"Could not get or read the KEV list: {type(exc).__name__}: {exc}")

    local = {m.cve_id: m for m in match_cves(subject, page.records)}
    print(
        f"NVD returned {len(page.records)} CVEs "
        f"(NVD total: {page.total_results}; skipped while parsing: {page.skipped})."
    )
    if page.total_results > len(page.records) + page.skipped:
        print("NOTE: the NVD has more results than were requested; raise --results.")
    print()
    print(f"{'CVE':<17} {'CVSS':>5}  {'Severity':<9} {'KEV':<4} Our matcher")
    for record in sorted(page.records, key=_cve_order):
        match = local.get(record.cve_id)
        score = f"{record.cvss_score:.1f}" if record.cvss_score is not None else "-"
        verdict = "NOT MATCHED"
        if match is not None:
            verdict = match.reason + (" (conditional)" if match.conditional else "")
        in_kev = "yes" if record.cve_id in kev_ids else "-"
        severity = record.cvss_severity or "-"
        print(f"{record.cve_id:<17} {score:>5}  {severity:<9} {in_kev:<4} {verdict}")

    missed = sum(1 for r in page.records if r.cve_id not in local)
    print()
    agreed = len(page.records) - missed
    print(f"Our matcher agrees with the NVD on {agreed} of {len(page.records)}.")
    if missed:
        print("Please send back the NOT MATCHED lines (and the command you ran).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
