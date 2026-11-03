"""What operating system a scanned host runs, and whether a CVE can apply to it.

Some CVEs only exist on one platform: the NVD records them as a product
"running on" an operating system (for example Apache HTTP Server "on
Windows"). The parser keeps those platform requirements as ``vendor:product``
strings (``CpeRange.requires``); real feed data shows entries such as
``microsoft:windows`` and ``redhat:enterprise_linux``.

This module answers one narrow question: given what we know about the host,
is it *impossible* for a platform-specific CVE to apply? It only ever rules a
match OUT when the host's platform is known and every requirement is known to
be different. Anything uncertain stays in: an unknown host, an unrecognised
requirement, or a host whose distribution is not known all keep the match, so
a CVE is never hidden on a guess.

Host strings come from the scanned machine (attacker-controlled) and are only
matched against fixed patterns after a length limit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from riskreveal.domain.intelligence.distro import detect_distro

_MAX_TEXT = 512


@dataclass(frozen=True)
class HostPlatform:
    family: str | None = None
    """``linux``, ``windows``, ``bsd``, ``macos`` or ``solaris``."""
    distro: str | None = None
    """``ubuntu``, ``debian``, ``rhel`` ... when known (see ``distro.py``)."""


_DISTRO_FAMILY = {
    "ubuntu": "linux",
    "debian": "linux",
    "centos": "linux",
    "rhel": "linux",
    "fedora": "linux",
    "suse": "linux",
    "alpine": "linux",
    "amazon": "linux",
    "freebsd": "bsd",
}

_FAMILY_WORDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("windows", re.compile(r"\bwin32\b|\bwin64\b|\bwindows\b|\bmicrosoft\b")),
    ("linux", re.compile(r"\blinux\b")),
    ("macos", re.compile(r"\bdarwin\b|\bmac os x\b|\bmacos\b")),
    ("bsd", re.compile(r"\bfreebsd\b|\bopenbsd\b|\bnetbsd\b")),
    ("solaris", re.compile(r"\bsolaris\b|\bsunos\b")),
)


def detect_host_platform(*texts: str | None) -> HostPlatform | None:
    """Work out the platform from Nmap strings (version, extra info, OS type).

    Returns ``None`` if nothing is recognised or the strings contradict each
    other (for example both "Windows" and "Ubuntu").
    """
    cleaned = [text[:_MAX_TEXT].lower() for text in texts if text]
    if not cleaned:
        return None
    distro = detect_distro(*cleaned)
    families = {name for name, pattern in _FAMILY_WORDS if any(pattern.search(t) for t in cleaned)}
    if distro is not None:
        families.add(_DISTRO_FAMILY[distro])
    if len(families) != 1:
        return None
    (family,) = families
    return HostPlatform(family=family, distro=distro)


def requirement_platform(requirement: str) -> HostPlatform | None:
    """Platform named by a ``vendor:product`` requirement, or ``None`` if unrecognised."""
    vendor, _, product = requirement.strip().lower().partition(":")
    if vendor == "microsoft" and "windows" in product:
        return HostPlatform("windows")
    if vendor == "apple" and (product.startswith("mac") or "os_x" in product):
        return HostPlatform("macos")
    if (vendor, product) == ("linux", "linux_kernel"):
        return HostPlatform("linux")
    if (vendor, product) == ("canonical", "ubuntu_linux"):
        return HostPlatform("linux", "ubuntu")
    if (vendor, product) == ("debian", "debian_linux"):
        return HostPlatform("linux", "debian")
    if vendor == "redhat" and (product.startswith("enterprise_linux") or product == "linux"):
        return HostPlatform("linux", "rhel")
    if (vendor, product) == ("centos", "centos"):
        return HostPlatform("linux", "centos")
    if (vendor, product) == ("fedoraproject", "fedora"):
        return HostPlatform("linux", "fedora")
    if vendor in ("suse", "opensuse"):
        return HostPlatform("linux", "suse")
    if (vendor, product) == ("alpinelinux", "alpine_linux"):
        return HostPlatform("linux", "alpine")
    if vendor == "amazon" and "linux" in product:
        return HostPlatform("linux", "amazon")
    if (vendor, product) == ("freebsd", "freebsd"):
        return HostPlatform("bsd", "freebsd")
    if (vendor, product) in (("openbsd", "openbsd"), ("netbsd", "netbsd")):
        return HostPlatform("bsd")
    if vendor in ("oracle", "sun") and product in ("solaris", "sunos"):
        return HostPlatform("solaris")
    return None


def requirements_possible(host: HostPlatform | None, requires: tuple[str, ...]) -> bool:
    """False only if the host is known and every requirement is known to be different."""
    if host is None or not requires:
        return True
    for requirement in requires:
        required = requirement_platform(requirement)
        if required is None or _compatible(host, required):
            return True
    return False


def _compatible(host: HostPlatform, required: HostPlatform) -> bool:
    if host.family and required.family and host.family != required.family:
        return False
    return not (host.distro and required.distro and host.distro != required.distro)
