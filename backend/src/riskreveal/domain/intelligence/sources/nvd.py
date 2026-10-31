"""Parser for NVD CVE API 2.0 responses.

Endpoint: ``https://services.nvd.nist.gov/rest/json/cves/2.0``. This module
only turns an already-downloaded, already-JSON-decoded response into
:class:`CveRecord` objects; it does no I/O. It is defensive on purpose: the
document is external input, so every access checks the type, and an item that
doesn't look right is skipped (and counted) instead of aborting the page.

Decisions worth knowing:

* **Rejected CVEs are skipped** (``vulnStatus == "Rejected"`` or a
  ``** REJECT **`` description).
* **Only "vulnerable" CPE entries become ranges.** In an NVD configuration the
  entries marked ``vulnerable: false`` describe the platform the software runs
  on, not something that is affected. A configuration joined with AND is
  flagged ``conditional`` (the CVE needs that extra platform too), and the
  platform entries of that configuration are recorded as ``requires``
  (``vendor:product`` strings) so callers can tell, for example, a
  Windows-only Apache bug from one that affects Linux.
* **CVSS preference:** v4.0, then v3.1, v3.0, v2; within a version the
  "Primary" (NVD) score is preferred.
* A CVE with no CVSS yet (not analyzed) has ``cvss_score = None``.
* Text fields go through ``clean_text`` (NUL bytes removed: PostgreSQL rejects
  them; values clipped), and CVE ids through ``normalize_cve_id``, exactly like
  the KEV and EPSS importers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from riskreveal.domain.intelligence.cpe import parse_cpe
from riskreveal.domain.intelligence.cve_id import normalize_cve_id
from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.records import CpeRange, CveRecord
from riskreveal.domain.intelligence.sources.textutil import clean_text

MAX_RANGES_PER_CVE = 20_000
MAX_REQUIRES_PER_RANGE = 50
MAX_DESCRIPTION_CHARS = 20_000
MAX_BOUND_LENGTH = 64

_CVSS_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_SEVERITY_LABELS = frozenset({"none", "low", "medium", "high", "critical"})


@dataclass(frozen=True)
class NvdPage:
    records: tuple[CveRecord, ...]
    total_results: int
    start_index: int
    results_per_page: int
    skipped: int
    """Items that were rejected, malformed, or had an invalid CVE id."""


def parse_nvd_response(payload: object) -> NvdPage:
    root = _as_dict(payload)
    if root is None:
        raise FeedParseError("NVD response is not a JSON object.")
    items = root.get("vulnerabilities")
    if not isinstance(items, list):
        raise FeedParseError("NVD response has no 'vulnerabilities' list.")

    records: list[CveRecord] = []
    skipped = 0
    for item in items:
        record = _parse_item(item)
        if record is None:
            skipped += 1
        else:
            records.append(record)

    return NvdPage(
        records=tuple(records),
        total_results=_as_int(root.get("totalResults"), len(items)),
        start_index=_as_int(root.get("startIndex"), 0),
        results_per_page=_as_int(root.get("resultsPerPage"), len(items)),
        skipped=skipped,
    )


def _parse_item(item: object) -> CveRecord | None:
    item_dict = _as_dict(item)
    cve = _as_dict(item_dict.get("cve")) if item_dict is not None else None
    if cve is None:
        return None

    cve_id = normalize_cve_id(cve.get("id"))
    if cve_id is None:
        return None

    status = cve.get("vulnStatus")
    if isinstance(status, str) and status.strip().lower() == "rejected":
        return None

    description = _english_description(cve)
    if description.startswith("** REJECT **"):
        return None

    score, severity, version, vector = _best_cvss(cve.get("metrics"))
    return CveRecord(
        cve_id=cve_id,
        description=description,
        published=_parse_datetime(cve.get("published")),
        last_modified=_parse_datetime(cve.get("lastModified")),
        cvss_score=score,
        cvss_severity=severity,
        cvss_version=version,
        cvss_vector=clean_text(vector, 128),
        ranges=_collect_ranges(cve),
    )


def _collect_ranges(cve: dict[str, Any]) -> tuple[CpeRange, ...]:
    ranges: list[CpeRange] = []
    for config in _as_list(cve.get("configurations")):
        config_dict = _as_dict(config)
        if config_dict is None:
            continue
        config_is_and = _is_and(config_dict.get("operator"))
        nodes = [
            node
            for node in (_as_dict(item) for item in _as_list(config_dict.get("nodes")))
            if node is not None and node.get("negate") is not True  # negated: not "affected"
        ]
        requires = _platform_requirements(nodes)
        for node in nodes:
            conditional = config_is_and or _is_and(node.get("operator"))
            for match in _as_list(node.get("cpeMatch")):
                rng = _parse_cpe_match(match, conditional, requires if conditional else ())
                if rng is None:
                    continue
                ranges.append(rng)
                if len(ranges) >= MAX_RANGES_PER_CVE:
                    return tuple(ranges)
    return tuple(ranges)


def _platform_requirements(nodes: list[dict[str, Any]]) -> tuple[str, ...]:
    """``vendor:product`` of the non-vulnerable (platform) entries of a configuration."""
    found: set[str] = set()
    for node in nodes:
        for match in _as_list(node.get("cpeMatch")):
            data = _as_dict(match)
            if data is None or data.get("vulnerable") is not False:
                continue
            criteria = data.get("criteria")
            cpe = parse_cpe(criteria if isinstance(criteria, str) else None)
            if cpe is not None:
                found.add(f"{cpe.vendor}:{cpe.product}")
    return tuple(sorted(found))[:MAX_REQUIRES_PER_RANGE]


def _parse_cpe_match(
    match: object, conditional: bool, requires: tuple[str, ...] = ()
) -> CpeRange | None:
    data = _as_dict(match)
    if data is None or data.get("vulnerable") is not True:
        return None
    criteria = data.get("criteria")
    cpe = parse_cpe(criteria if isinstance(criteria, str) else None)
    if cpe is None:
        return None
    return CpeRange(
        part=cpe.part,
        vendor=cpe.vendor,
        product=cpe.product,
        version=cpe.version,
        update=cpe.update,
        start_including=_bound(data.get("versionStartIncluding")),
        start_excluding=_bound(data.get("versionStartExcluding")),
        end_including=_bound(data.get("versionEndIncluding")),
        end_excluding=_bound(data.get("versionEndExcluding")),
        conditional=conditional,
        requires=requires,
    )


def _best_cvss(metrics: object) -> tuple[float | None, str | None, str | None, str | None]:
    data = _as_dict(metrics)
    if data is None:
        return None, None, None, None
    for key, default_version in _CVSS_KEYS:
        entries = [e for e in (_as_dict(x) for x in _as_list(data.get(key))) if e is not None]
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cvss = _as_dict(entry.get("cvssData"))
        if cvss is None:
            continue
        score = _as_score(cvss.get("baseScore"))
        if score is None:
            continue
        label = cvss.get("baseSeverity") or entry.get("baseSeverity")
        severity = label.strip().lower() if isinstance(label, str) else None
        if severity not in _SEVERITY_LABELS:
            severity = None
        version = cvss.get("version")
        vector = cvss.get("vectorString")
        return (
            score,
            severity,
            clean_text(version, 8) or default_version,
            vector if isinstance(vector, str) else None,
        )
    return None, None, None, None


def _english_description(cve: dict[str, Any]) -> str:
    for entry in _as_list(cve.get("descriptions")):
        item = _as_dict(entry)
        if item is not None and item.get("lang") == "en":
            return clean_text(item.get("value"), MAX_DESCRIPTION_CHARS) or ""
    return ""


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _as_dict(value: object) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _as_list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_int(value: object, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return default


def _as_score(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    score = float(value)
    return score if 0.0 <= score <= 10.0 else None  # NaN fails this too


def _is_and(value: object) -> bool:
    return isinstance(value, str) and value.strip().upper() == "AND"


def _bound(value: object) -> str | None:
    return clean_text(value, MAX_BOUND_LENGTH)
