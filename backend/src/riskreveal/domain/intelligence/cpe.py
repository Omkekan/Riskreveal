"""CPE (Common Platform Enumeration) parsing.

Nmap reports CPE **2.2 URIs** (``cpe:/a:openbsd:openssh:6.6.1p1``). The NVD
uses CPE **2.3 formatted strings**
(``cpe:2.3:a:openbsd:openssh:6.6.1:p1:*:*:*:*:*:*``). Both parse to the same
:class:`Cpe`. Only the first five components matter for matching software
against CVEs: part, vendor, product, version and update.

Parsing is strict and total: anything malformed returns ``None``. It never
raises, because CPE strings come from scanned hosts and external feeds.

Known simplification: after un-escaping, an escaped literal ``\\*`` is
indistinguishable from the ``*`` wildcard. No real vendor or product name
contains one.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote

MAX_CPE_LENGTH = 512

_PARTS = frozenset({"a", "o", "h"})
_NOT_A_VALUE = frozenset({"", "*", "-"})
_CPE23_FIELD_COUNT = 13


@dataclass(frozen=True)
class Cpe:
    part: str
    """``a`` application, ``o`` operating system, ``h`` hardware."""
    vendor: str
    product: str
    version: str = "*"
    update: str = "*"


def parse_cpe(text: str | None) -> Cpe | None:
    """Parse a CPE 2.2 URI or CPE 2.3 formatted string, or return ``None``."""
    if text is None:
        return None
    value = text.strip()
    if not value or len(value) > MAX_CPE_LENGTH:
        return None
    if any(ch < " " or ch == "\x7f" for ch in value):
        return None

    prefix = value[:8].lower()
    if prefix.startswith("cpe:2.3:"):
        return _parse_23(value)
    if prefix.startswith("cpe:/"):
        return _parse_22(value)
    return None


def join_version(version: str, update: str) -> str | None:
    """Combine a CPE version and update into one comparable version string.

    NVD splits some versions across two fields (OpenSSH ``6.6.1p1`` is
    version ``6.6.1`` + update ``p1``); Nmap keeps them together. Joining
    makes both spellings equal. Returns ``None`` if there is no version.
    """
    if version in _NOT_A_VALUE:
        return None
    if update in _NOT_A_VALUE:
        return version
    return version + update


def full_version(cpe: Cpe) -> str | None:
    return join_version(cpe.version, cpe.update)


def _parse_22(value: str) -> Cpe | None:
    components = [unquote(item) for item in value[5:].split(":")]
    if len(components) < 3:
        return None
    version = components[3] if len(components) > 3 else "*"
    update = components[4] if len(components) > 4 else "*"
    return _build(components[0], components[1], components[2], version, update)


def _parse_23(value: str) -> Cpe | None:
    fields = _split_unescaped(value)
    if fields is None or len(fields) != _CPE23_FIELD_COUNT:
        return None
    return _build(fields[2], fields[3], fields[4], fields[5], fields[6])


def _split_unescaped(text: str) -> list[str] | None:
    """Split on ``:`` honoring backslash escapes; drop the backslashes."""
    fields: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            if index + 1 >= len(text):
                return None  # dangling backslash
            current.append(text[index + 1])
            index += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    fields.append("".join(current))
    return fields


def _build(part: str, vendor: str, product: str, version: str, update: str) -> Cpe | None:
    part = part.strip().lower()
    vendor = vendor.strip().lower() or "*"
    product = product.strip().lower() or "*"
    version = version.strip().lower() or "*"
    update = update.strip().lower() or "*"
    if part not in _PARTS:
        return None
    if vendor in ("*", "-") or product in ("*", "-"):
        return None
    return Cpe(part=part, vendor=vendor, product=product, version=version, update=update)
