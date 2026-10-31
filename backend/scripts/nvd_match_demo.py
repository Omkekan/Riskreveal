"""Compare the NVD's answer with our own matcher for one CPE. Needs internet.

    uv run python scripts/nvd_match_demo.py "cpe:/a:apache:http_server:2.4.7" --kev
    uv run python scripts/nvd_match_demo.py "cpe:/a:apache:http_server:2.4.7" \\
        --compare-with "cpe:/a:apache:http_server:2.4.41" --show-review

What it does:

1. Parses the CPE (the form Nmap reports) and asks the NVD, over HTTPS, which
   CVEs list that CPE as vulnerable. Nothing is stored.
2. Parses the reply with our parser and runs our matcher over the same CVEs.
   Rows marked NOT MATCHED mean the NVD says a CVE applies but we disagree
   (a gap in the matcher). This checks that we MISS nothing.
3. Rows marked REVIEW are matches too weak to report automatically: the NVD
   lists the product for every version ("all_versions"), or only on another
   platform ("conditional", e.g. Windows only). The platform is listed.
4. With --compare-with OTHER_CPE (a second version of the same product) it also
   runs a PRECISION check: using the NVD's own answers for both versions as the
   reference, it lists CVEs our matcher claims for one version that the NVD did
   NOT list for it. A strong match in that list is a bug in the matcher; REVIEW
   rows there are expected. This checks that we do not raise FALSE ALARMS.
5. With --kev it also marks CVEs in CISA's Known Exploited list.
6. With --show-review it prints a short description for every REVIEW row.

Costs one NVD request per CPE (two with --compare-with) and one 1 MB KEV
download with --kev. No API key is needed; if you have one, set NVD_API_KEY in
your terminal (it is only sent to the NVD and never printed). Without a key the
NVD allows about 5 requests per 30 seconds. Run it sparingly.

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
from riskreveal.domain.intelligence.matcher import CveMatch, match_cves
from riskreveal.domain.intelligence.records import CveRecord
from riskreveal.domain.intelligence.sources.cisa_kev import KEV_MAX_BYTES, KEV_URL, parse_kev
from riskreveal.domain.intelligence.sources.fetch import download
from riskreveal.domain.intelligence.sources.nvd import NvdPage, parse_nvd_response

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESPONSE_BYTES = 50 * 1024 * 1024
TIMEOUT_SECONDS = 30.0
SNIPPET_CHARS = 110


def default_nvd_name(cpe: Cpe) -> str:
    """The CPE 2.3 name sent to the NVD when no explicit name is given."""
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


def _fetch_page(nvd_name: str, results: int) -> NvdPage:
    url = f"{NVD_URL}?cpeName={quote(nvd_name, safe=':*')}&isVulnerable&resultsPerPage={results}"
    print(f"Asking the NVD about: {nvd_name}")
    return parse_nvd_response(_get_nvd_json(url, os.environ.get("NVD_API_KEY")))


def _cve_order(cve_id: str) -> tuple[int, int]:
    _, year, number = cve_id.split("-")
    return (int(year), int(number))


def _verdict(match: CveMatch | None) -> str:
    if match is None:
        return "NOT MATCHED"
    return match.reason + ("  REVIEW" if match.needs_review else "")


def _safe(text: str) -> str:
    """One printable line: NVD text is external input, so no control characters."""
    return "".join(ch if ch.isprintable() else " " for ch in text)[:SNIPPET_CHARS]


def _require_version_cpe(text: str) -> Cpe | None:
    cpe = parse_cpe(text)
    if cpe is None:
        print(f"Not a valid CPE: {text[:80]!r}")
        return None
    if full_version(cpe) is None:
        print(f"The CPE needs a version (e.g. cpe:/a:apache:http_server:2.4.7): {text[:80]!r}")
        return None
    return cpe


def _precision_check(
    label: str,
    cpe: Cpe,
    expected: set[str],
    universe: dict[str, CveRecord],
) -> int:
    """Compare our matches for ``cpe`` with the NVD's list; return the number of problems.

    EXTRA = we claim a CVE the NVD did not list for this CPE (a false alarm, unless
    the row is a REVIEW one). MISSED = the NVD listed a CVE and we did not match it.
    """
    claimed = {m.cve_id: m for m in match_cves(cpe, universe.values())}
    extra = sorted(set(claimed) - expected, key=_cve_order)
    missed = sorted(expected - set(claimed), key=_cve_order)
    print(f"  {label}: we match {len(claimed)} CVEs; the NVD listed {len(expected)}.")
    if not extra and not missed:
        print("    agrees with the NVD: good.")
        return 0
    problems = 0
    for cve_id in extra:
        match = claimed[cve_id]
        problems += 0 if match.needs_review else 1
        print(f"    EXTRA  {cve_id:<16} {_verdict(match)}")
    for cve_id in missed:
        problems += 1
        print(f"    MISSED {cve_id:<16} the NVD lists it, we do not match it")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare the NVD with our CVE matcher.")
    parser.add_argument("cpe", help='a CPE, e.g. "cpe:/a:apache:http_server:2.4.7"')
    parser.add_argument("--nvd-cpe-name", help="CPE 2.3 name to send to the NVD instead")
    parser.add_argument("--compare-with", help="a second version of the product (precision check)")
    parser.add_argument("--compare-nvd-cpe-name", help="CPE 2.3 name for --compare-with")
    parser.add_argument("--results", type=int, default=500, help="most CVEs to request (1-2000)")
    parser.add_argument("--kev", action="store_true", help="mark CVEs in CISA's KEV list")
    parser.add_argument("--show-review", action="store_true", help="describe REVIEW rows")
    args = parser.parse_args()

    subject = _require_version_cpe(args.cpe)
    other = _require_version_cpe(args.compare_with) if args.compare_with else None
    if subject is None or (args.compare_with and other is None):
        return 2
    results = max(1, min(args.results, 2000))

    try:
        page = _fetch_page(args.nvd_cpe_name or default_nvd_name(subject), results)
        other_page = None
        if other is not None:
            other_page = _fetch_page(args.compare_nvd_cpe_name or default_nvd_name(other), results)
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
    records = {r.cve_id: r for r in page.records}
    for cve_id in sorted(records, key=_cve_order):
        record = records[cve_id]
        score = f"{record.cvss_score:.1f}" if record.cvss_score is not None else "-"
        severity = record.cvss_severity or "-"
        in_kev = "yes" if cve_id in kev_ids else "-"
        print(f"{cve_id:<17} {score:>5}  {severity:<9} {in_kev:<4} {_verdict(local.get(cve_id))}")

    missed = [cve_id for cve_id in records if cve_id not in local]
    review = [m for m in local.values() if m.needs_review]
    print()
    print(f"Agreement: we match {len(local)} of the NVD's {len(records)} (missed: {len(missed)}).")
    print(f"Strong matches: {len(local) - len(review)}.  Needing review: {len(review)}.")
    if missed:
        print("Please send back the NOT MATCHED lines (and the command you ran).")

    if review:
        print()
        print("REVIEW rows (weak matches; do not report these automatically):")
        for match in sorted(review, key=lambda m: _cve_order(m.cve_id)):
            platform = f"  requires: {', '.join(match.requires)}" if match.requires else ""
            print(f"  {match.cve_id:<16} {match.reason}{platform}")
            if args.show_review:
                print(f"      {_safe(records[match.cve_id].description)}")

    problems = 0
    if other is not None and other_page is not None:
        print()
        print("Precision check (the NVD's own answers are the reference):")
        universe = {**{r.cve_id: r for r in other_page.records}, **records}
        problems += _precision_check("first CPE ", subject, set(records), universe)
        problems += _precision_check(
            "second CPE", other, {r.cve_id for r in other_page.records}, universe
        )
        print()
        if problems:
            print(f"{problems} problem line(s) (EXTRA without REVIEW, or MISSED): send them back.")
        else:
            print("No problems found for these two versions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
