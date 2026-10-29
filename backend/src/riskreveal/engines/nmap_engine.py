"""Nmap wrapper: build the command, run it safely, parse the XML.

Safety properties:

* **No shell.** The command is an argument *list* (``shell=False``). Targets
  come only from ``ValidatedTarget.scan_args`` (see the scope policy) and
  options only from a fixed :class:`ScanProfile`, so no user string reaches
  Nmap's command line unvalidated.
* **Hard timeout.** ``subprocess.run(timeout=...)`` kills Nmap if it hangs;
  the old codebase had no timeouts at all (01_... #17).
* **Safe XML parsing.** ``defusedxml`` rejects entity-expansion and external
  entity tricks. Real Nmap output contains ``<!DOCTYPE nmaprun>``, so DTDs
  themselves are allowed; entities are not.
* **Findings are attributed per host IP**, from each ``<host>`` element --
  never "port 80 of whatever host" (01_... #8) -- and ``hostscript`` results
  are parsed too (01_... #9).
* **Bounded data.** Script output is truncated: it is attacker-controlled and
  can be enormous.

Nothing here touches the database. Persisting results is the service
layer's job.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from riskreveal.domain.scanning.profiles import ScanProfile
from riskreveal.domain.scanning.scope_policy import ValidatedTarget
from riskreveal.engines.base import (
    EngineError,
    EngineNotFoundError,
    EngineTimeoutError,
    NmapParseError,
    ParsedHost,
    ParsedPort,
    ParsedScript,
    ScanResult,
)

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

logger = logging.getLogger("riskreveal.engines.nmap")

MAX_SCRIPT_OUTPUT_CHARS = 10_000
MAX_STDERR_CHARS = 500

# Injectable so tests can fake the subprocess; defaults to subprocess.run.
Runner = Callable[..., Any]


# ---------------------------------------------------------------------------
# Running Nmap
# ---------------------------------------------------------------------------


def find_nmap(
    path: str | None = None, *, which: Callable[[str], str | None] = shutil.which
) -> str:
    """Return the Nmap executable path, or raise :class:`EngineNotFoundError`."""
    found = path or which("nmap")
    if not found:
        raise EngineNotFoundError(
            "Nmap was not found. Install it (winget install Insecure.Nmap) and make sure "
            "`nmap --version` works in a new terminal."
        )
    return found


def build_command(nmap_path: str, profile: ScanProfile, target: ValidatedTarget) -> list[str]:
    """Build the exact Nmap argument list for a validated target."""
    command = [nmap_path, "-oX", "-", "--no-stylesheet", "-n", "--open", *profile.nmap_args]
    if target.ipv6:
        command.append("-6")
    if target.kind != "cidr":
        # Named hosts often drop ping probes, so a host that is up would be
        # skipped. For a whole range, skipping discovery would instead probe
        # every address, so ranges keep normal host discovery.
        command.append("-Pn")
    command.extend(target.scan_args)
    return command


def run_nmap(
    target: ValidatedTarget,
    profile: ScanProfile,
    *,
    nmap_path: str | None = None,
    runner: Runner = subprocess.run,
) -> ScanResult:
    """Run Nmap against an already-validated target and parse the result."""
    executable = find_nmap(nmap_path)
    command = build_command(executable, profile, target)
    logger.info(
        "Running nmap profile=%s kind=%s hosts=%d", profile.name, target.kind, target.host_count
    )
    try:
        completed = runner(
            command,
            capture_output=True,
            timeout=profile.timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise EngineTimeoutError(
            f"Nmap exceeded the {profile.timeout_seconds}s limit for profile '{profile.name}'."
        ) from exc
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__
        raise EngineError(f"Could not start Nmap: {reason}") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise EngineError(
            f"Nmap exited with status {completed.returncode}: {stderr[-MAX_STDERR_CHARS:]}"
        )
    return parse_nmap_xml(completed.stdout)


# ---------------------------------------------------------------------------
# Parsing Nmap XML
# ---------------------------------------------------------------------------


def parse_nmap_xml(xml: str | bytes) -> ScanResult:
    """Parse Nmap ``-oX`` output into engine-neutral dataclasses."""
    try:
        root = fromstring(xml)
    except (ParseError, DefusedXmlException) as exc:
        raise NmapParseError("Nmap output was not valid or safe XML.") from exc

    if root.tag != "nmaprun":
        raise NmapParseError("Output is not Nmap XML (missing <nmaprun> root).")

    hosts = tuple(
        host for host_el in root.findall("host") if (host := _parse_host(host_el)) is not None
    )
    return ScanResult(hosts=hosts, nmap_version=root.get("version"))


def _parse_host(host_el: Element) -> ParsedHost | None:
    address: str | None = None
    address_type = ""
    for addr_el in host_el.findall("address"):
        addr_type = addr_el.get("addrtype", "")
        if addr_type in ("ipv4", "ipv6"):
            address = addr_el.get("addr")
            address_type = addr_type
            break
    if not address:
        return None  # e.g. a MAC-only entry: nothing we can attribute findings to

    status_el = host_el.find("status")
    status = status_el.get("state", "unknown") if status_el is not None else "unknown"

    hostnames = tuple(
        name
        for hn in host_el.findall("hostnames/hostname")
        if (name := hn.get("name"))
    )

    os_name: str | None = None
    os_accuracy: int | None = None
    match_el = host_el.find("os/osmatch")  # Nmap lists the best match first
    if match_el is not None:
        os_name = match_el.get("name")
        os_accuracy = _to_int(match_el.get("accuracy"))

    ports = tuple(
        port for port_el in host_el.findall("ports/port") if (port := _parse_port(port_el))
    )
    host_scripts = tuple(_parse_scripts(host_el.findall("hostscript/script")))

    return ParsedHost(
        address=address,
        address_type=address_type,
        status=status,
        hostnames=hostnames,
        os_name=os_name,
        os_accuracy=os_accuracy,
        ports=ports,
        host_scripts=host_scripts,
    )


def _parse_port(port_el: Element) -> ParsedPort | None:
    number = _to_int(port_el.get("portid"))
    protocol = port_el.get("protocol")
    if number is None or not protocol:
        return None

    state_el = port_el.find("state")
    state = state_el.get("state", "unknown") if state_el is not None else "unknown"

    service_el = port_el.find("service")
    service = product = version = extrainfo = tunnel = None
    confidence: int | None = None
    cpes: tuple[str, ...] = ()
    if service_el is not None:
        service = service_el.get("name")
        product = service_el.get("product")
        version = service_el.get("version")
        extrainfo = service_el.get("extrainfo")
        tunnel = service_el.get("tunnel")
        confidence = _to_int(service_el.get("conf"))
        cpes = tuple(
            text for cpe in service_el.findall("cpe") if (text := (cpe.text or "").strip())
        )

    return ParsedPort(
        port=number,
        protocol=protocol,
        state=state,
        service=service,
        product=product,
        version=version,
        extrainfo=extrainfo,
        tunnel=tunnel,
        service_confidence=confidence,
        cpes=cpes,
        scripts=tuple(_parse_scripts(port_el.findall("script"))),
    )


def _parse_scripts(script_els: list[Element]) -> list[ParsedScript]:
    scripts: list[ParsedScript] = []
    for el in script_els:
        script_id = el.get("id")
        if not script_id:
            continue
        output = el.get("output", "")
        if len(output) > MAX_SCRIPT_OUTPUT_CHARS:
            output = output[:MAX_SCRIPT_OUTPUT_CHARS] + "\n[truncated]"
        scripts.append(ParsedScript(script_id=script_id, output=output))
    return scripts


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
