"""Engine-neutral result types and errors.

Every scanning engine (Nmap now; Nuclei, authenticated collectors later)
returns these plain, frozen dataclasses. They hold *data from the scanned
host*, which is attacker-controlled: banners, product strings and script
output may contain anything. Nothing downstream may treat them as trusted
markup, file paths or instructions.
"""

from __future__ import annotations

from dataclasses import dataclass


class EngineError(Exception):
    """A scan engine failed. The message is safe to log; don't show raw
    subprocess output to end users."""


class EngineNotFoundError(EngineError):
    """The scanner executable could not be found."""


class EngineTimeoutError(EngineError):
    """The scanner ran past its hard time limit and was killed."""


class NmapParseError(EngineError):
    """The scanner's XML output was malformed, unsafe, or not Nmap XML."""


@dataclass(frozen=True)
class ParsedScript:
    script_id: str
    output: str


@dataclass(frozen=True)
class ParsedPort:
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    tunnel: str | None = None
    service_confidence: int | None = None
    """Nmap's 0-10 confidence in its service identification, if reported."""
    cpes: tuple[str, ...] = ()
    scripts: tuple[ParsedScript, ...] = ()


@dataclass(frozen=True)
class ParsedHost:
    address: str
    address_type: str
    """``ipv4`` or ``ipv6``."""
    status: str
    """``up``, ``down`` or ``unknown``."""
    hostnames: tuple[str, ...] = ()
    os_name: str | None = None
    os_accuracy: int | None = None
    ports: tuple[ParsedPort, ...] = ()
    host_scripts: tuple[ParsedScript, ...] = ()


@dataclass(frozen=True)
class ScanResult:
    hosts: tuple[ParsedHost, ...]
    nmap_version: str | None = None
