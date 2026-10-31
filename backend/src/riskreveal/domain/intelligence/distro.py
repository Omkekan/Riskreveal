"""Spot distribution-packaged software from what Nmap reports.

Linux distributions and BSDs usually **back-port security fixes without
changing the upstream version number**: Ubuntu's ``OpenSSH 6.6.1p1
2ubuntu2.13`` contains fixes that the upstream version ``6.6.1p1`` does not.
An upstream-version match against a CVE is therefore only a *hint* on such a
host. This module just recognises the situation, so findings can say
"verify the package version" instead of claiming the host is vulnerable.

Strings come from the scanned host (attacker-controlled): they are only ever
matched against fixed patterns and are length-limited first.
"""

from __future__ import annotations

import re

_MAX_TEXT = 512

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ubuntu", re.compile(r"\bubuntu\b|\d+ubuntu\d")),
    ("debian", re.compile(r"\bdebian\b|\bdeb\d+u\d+")),
    ("centos", re.compile(r"\bcentos\b")),
    ("rhel", re.compile(r"\bred hat\b|\brhel\b|\.el\d+")),
    ("fedora", re.compile(r"\bfedora\b|\.fc\d+")),
    ("suse", re.compile(r"\bsuse\b|\bopensuse\b")),
    ("alpine", re.compile(r"\balpine\b")),
    ("amazon", re.compile(r"\bamazon\b")),
    ("freebsd", re.compile(r"\bfreebsd\b")),
)


def detect_distro(*texts: str | None) -> str | None:
    """Return the distribution named in any of the strings, or ``None``."""
    for text in texts:
        if not text:
            continue
        lowered = text[:_MAX_TEXT].lower()
        for name, pattern in _PATTERNS:
            if pattern.search(lowered):
                return name
    return None
