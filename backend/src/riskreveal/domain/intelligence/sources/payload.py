"""Reading feed bytes safely: size limits, gzip handling, local files.

Feeds are untrusted input. A tiny gzip file can expand to gigabytes (a
"decompression bomb"), so decompression always has a hard output limit.
Standard library only.
"""

from __future__ import annotations

import zlib
from pathlib import Path

from riskreveal.domain.intelligence.errors import FeedFetchError, FeedParseError

GZIP_MAGIC = b"\x1f\x8b"


def gunzip_limited(data: bytes, max_bytes: int) -> bytes:
    """Decompress a gzip payload, refusing to produce more than ``max_bytes``."""
    decompressor = zlib.decompressobj(wbits=31)  # 31 = gzip container
    try:
        out = decompressor.decompress(data, max_bytes + 1)
        if len(out) > max_bytes or decompressor.unconsumed_tail:
            raise FeedParseError("The feed expands to more than the allowed maximum size.")
        out += decompressor.flush()
    except zlib.error as exc:
        raise FeedParseError("The feed is not a valid gzip file.") from exc
    if len(out) > max_bytes:
        raise FeedParseError("The feed expands to more than the allowed maximum size.")
    if not decompressor.eof:
        raise FeedParseError("The gzip feed is truncated.")
    return out


def maybe_gunzip(data: bytes, max_bytes: int) -> bytes:
    """Return the plain bytes whether ``data`` is gzip-compressed or not."""
    if data.startswith(GZIP_MAGIC):
        return gunzip_limited(data, max_bytes)
    if len(data) > max_bytes:
        raise FeedParseError("The feed is larger than the allowed maximum size.")
    return data


def read_local(path: Path, max_bytes: int) -> bytes:
    """Read a feed file the operator supplied, enforcing the size limit."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FeedFetchError("Cannot read the file you supplied.") from exc
    if size > max_bytes:
        raise FeedFetchError("The file you supplied is larger than the allowed maximum size.")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FeedFetchError("Cannot read the file you supplied.") from exc
