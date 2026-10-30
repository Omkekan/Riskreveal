"""FIRST EPSS scores: parser only.

Pure: no network and no database. The daily file (``EPSS_URL``, gzip-compressed
CSV) looks like::

    #model_version:v2025.03.14,score_date:2025-08-02T12:55:00Z
    cve,epss,percentile
    CVE-1999-0001,0.0142,0.79836

The ``score_date`` is written in more than one format over time
(``...+0000`` and ``...Z``), so only its leading ``YYYY-MM-DD`` is used.

The file has roughly 300,000 rows, so rows are streamed: :class:`EpssReader`
reads and checks the header immediately, then yields rows one by one while
counting the ones it had to skip (malformed, out of range, NaN/inf, wrong
column count, invalid CVE id).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import date

from riskreveal.domain.intelligence.cve_id import normalize_cve_id
from riskreveal.domain.intelligence.errors import FeedParseError
from riskreveal.domain.intelligence.sources.payload import maybe_gunzip
from riskreveal.domain.intelligence.sources.textutil import clean_text

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_INVALID_FRACTION = 0.01

_EXPECTED_COLUMNS = ["cve", "epss", "percentile"]


@dataclass(frozen=True, slots=True)
class EpssRecord:
    cve_id: str
    score: float
    percentile: float


def _probability(text: str) -> float | None:
    """Parse a number in [0, 1]; ``None`` for anything else (NaN, inf, words)."""
    if not text.isascii():
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return value


def _parse_row(line: str) -> EpssRecord | None:
    parts = line.split(",")
    if len(parts) != 3:
        return None
    cve_id = normalize_cve_id(parts[0])
    score = _probability(parts[1].strip())
    percentile = _probability(parts[2].strip())
    if cve_id is None or score is None or percentile is None:
        return None
    return EpssRecord(cve_id=cve_id, score=score, percentile=percentile)


class EpssReader:
    """Header-checked, single-pass stream of :class:`EpssRecord`."""

    def __init__(self, lines: Iterable[str]) -> None:
        self._lines = iter(lines)
        self._started = False
        self.rows_read = 0
        self.skipped = 0
        self.model_version, self.score_date = self._read_header()

    @classmethod
    def from_bytes(cls, raw: bytes, *, max_bytes: int = EPSS_MAX_BYTES) -> EpssReader:
        """Build a reader from the downloaded/loaded bytes (gzip or plain CSV)."""
        data = maybe_gunzip(raw, max_bytes)
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise FeedParseError("The EPSS file is not valid UTF-8 text.") from exc
        return cls(text.split("\n"))

    def _next_nonblank(self) -> str | None:
        for line in self._lines:
            stripped = line.lstrip("\ufeff").strip()
            if stripped:
                return stripped
        return None

    def _read_header(self) -> tuple[str, date]:
        comment = self._next_nonblank()
        if comment is None or not comment.startswith("#"):
            raise FeedParseError("The EPSS file is missing its '#model_version' header line.")
        meta: dict[str, str] = {}
        for part in comment[1:].split(","):
            key, _, value = part.partition(":")
            meta[key.strip()] = value.strip()

        model_version = clean_text(meta.get("model_version"), 32)
        score_date: date | None = None
        try:
            score_date = date.fromisoformat(meta.get("score_date", "")[:10])
        except ValueError:
            score_date = None
        if model_version is None or score_date is None:
            raise FeedParseError("The EPSS header has no usable model_version / score_date.")

        columns = self._next_nonblank()
        if columns is None or [c.strip().lower() for c in columns.split(",")] != _EXPECTED_COLUMNS:
            raise FeedParseError("The EPSS file does not have the 'cve,epss,percentile' columns.")
        return model_version, score_date

    def __iter__(self) -> Iterator[EpssRecord]:
        if self._started:
            raise RuntimeError("An EpssReader can only be iterated once.")
        self._started = True
        for line in self._lines:
            stripped = line.strip()
            if not stripped:
                continue
            self.rows_read += 1
            record = _parse_row(stripped)
            if record is None:
                self.skipped += 1
                continue
            yield record
