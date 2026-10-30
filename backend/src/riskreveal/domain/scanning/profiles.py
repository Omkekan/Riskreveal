"""Named scan profiles: the only Nmap options a scan can ever use.

A user picks a profile *name*. They never supply Nmap flags, so there is no
way to add ``--script``, ``-oN /some/path`` or ``--datadir`` through the API.
Every profile here is a fixed, reviewed tuple of arguments.

Shared by all profiles (added by ``engines.nmap_engine.build_command``):
``-oX -`` (XML to stdout), ``--no-stylesheet``, ``-n`` (no reverse DNS),
``--open`` (only list open ports), and ``-Pn`` for single hosts.

Not included yet, on purpose:

* ``-O`` (OS detection) needs administrator rights and raw sockets on
  Windows. The parser already reads OS matches if a profile ever enables it.
* ``-sC`` / ``--script`` -- script output is informational noise unless it is
  classified first (``engines/script_classifier.py``, a later step), and
  ``--script vuln`` should be an explicit, reviewed choice.
"""

from __future__ import annotations

from dataclasses import dataclass


class UnknownProfileError(ValueError):
    """The requested profile name does not exist."""


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    nmap_args: tuple[str, ...]
    timeout_seconds: int
    """Hard wall-clock limit for the whole Nmap process."""


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Top 100 TCP ports with light service-version detection.",
        nmap_args=(
            "-sV",
            "--version-light",
            "--top-ports",
            "100",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "3m",
        ),
        timeout_seconds=300,
    ),
    "standard": ScanProfile(
        name="standard",
        description="Top 1000 TCP ports with service-version detection.",
        nmap_args=(
            "-sV",
            "--top-ports",
            "1000",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "10m",
        ),
        timeout_seconds=900,
    ),
}

DEFAULT_PROFILE = "quick"


def get_profile(name: str) -> ScanProfile:
    try:
        return PROFILES[name]
    except KeyError:
        known = ", ".join(sorted(PROFILES))
        raise UnknownProfileError(f"Unknown scan profile. Available: {known}.") from None
