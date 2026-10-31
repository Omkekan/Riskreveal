"""Software version parsing and ordering, built for CVE range matching.

Real-world versions are messy (``6.6.1p1``, ``1.0.2k``, ``2.4.7``,
``1.0rc1``). The rules, chosen so that *a wrong answer is never silently
produced*:

* A version is split into numbers and letter groups; ``. - _ + ~`` are
  separators. Numbers compare numerically (``2.4.10 > 2.4.7``).
* Trailing zeros don't matter: ``1.0 == 1.0.0``.
* Known pre-release words (``dev snapshot alpha beta pre preview rc cr``)
  sort **before** the plain release: ``1.0rc1 < 1.0``.
* Known post-release words (``sp pl patch update hotfix``) and **single
  letters** sort **after** it: ``6.6.1 < 6.6.1p1 < 6.6.2`` and OpenSSL's
  ``1.0.2 < 1.0.2k``. A single letter always counts as post-release, so
  Python-style ``1.0b1`` (beta) is ordered wrongly; the case is rare in the
  software Nmap reports and is the one known ambiguity.
* Anything else (an unknown word, a space, a colon, text longer than 64
  characters, more than 24 parts) is **unparseable**: ``parse_version``
  returns ``None`` and the matcher makes no claim. "Don't know" is the
  honest answer for ``1.0.2k-fips`` or ``2:8.4p1``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_VERSION_LENGTH = 64
MAX_VERSION_TOKENS = 24
MAX_NUMBER_DIGITS = 18

_ALLOWED = re.compile(r"^[0-9a-z.\-_+~]+$")
_TOKEN = re.compile(r"\d+|[a-z]+")

# Sort keys: (kind, number, text). kind orders pre-release < end of version <
# post-release letter < number, which makes "1.0a" sort before "1.0.1".
_PRE_RELEASE = {
    "dev": 0,
    "snapshot": 0,
    "alpha": 1,
    "beta": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
    "cr": 4,
}
_POST_WORDS = frozenset({"sp", "pl", "patch", "update", "hotfix"})

_Key = tuple[float, int, str]
_END: _Key = (0.0, 0, "")
_ZERO: _Key = (1.0, 0, "")


@dataclass(frozen=True)
class ParsedVersion:
    raw: str
    keys: tuple[_Key, ...]


def parse_version(text: str | None) -> ParsedVersion | None:
    """Parse a version string, or return ``None`` if it can't be ordered safely."""
    if text is None:
        return None
    value = text.strip().lower()
    if len(value) > 1 and value.startswith("v") and value[1].isdigit():
        value = value[1:]
    if not value or len(value) > MAX_VERSION_LENGTH or not _ALLOWED.match(value):
        return None

    tokens = _TOKEN.findall(value)
    if not tokens or len(tokens) > MAX_VERSION_TOKENS or not tokens[0].isdigit():
        return None

    keys: list[_Key] = []
    for token in tokens:
        if token.isdigit():
            if len(token) > MAX_NUMBER_DIGITS:
                return None
            keys.append((1.0, int(token), ""))
        elif len(token) == 1 or token in _POST_WORDS:
            keys.append((0.5, 0, token))
        elif token in _PRE_RELEASE:
            keys.append((-1.0, _PRE_RELEASE[token], ""))
        else:
            return None
    return ParsedVersion(raw=value, keys=tuple(keys))


def compare_versions(a: ParsedVersion, b: ParsedVersion) -> int:
    """Return -1, 0 or 1 as ``a`` is older than, equal to, or newer than ``b``."""
    for index in range(max(len(a.keys), len(b.keys))):
        left = a.keys[index] if index < len(a.keys) else _END
        right = b.keys[index] if index < len(b.keys) else _END
        if left == right:
            continue
        # "end of version" and a trailing zero are the same thing: 1.0 == 1.0.0
        if (left == _END and right == _ZERO) or (right == _END and left == _ZERO):
            continue
        return -1 if left < right else 1
    return 0
