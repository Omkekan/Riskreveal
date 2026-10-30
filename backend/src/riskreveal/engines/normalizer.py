"""Turn parsed engine output into finding drafts.

First, deliberately small version: one **informational** draft per *open*
port on each host that is *up*. That is honest about what Nmap proved ("this
port is open and looks like X"); it does not claim a vulnerability.

What this does NOT do, on purpose (see 01_Conversation_Summary.md #7):
script output is attached to its port as evidence, but never becomes a
finding by itself. In the old codebase every script output -- ``http-title``,
``ssh-hostkey``, "NOT VULNERABLE" -- became a "finding", which buried the
real ones in noise. Promoting a script result to a finding needs the script
classifier (``engines/script_classifier.py``), which comes later.

Pure standard library; no database access.
"""

from __future__ import annotations

from dataclasses import dataclass

from riskreveal.domain.findings.enums import Confidence, Severity
from riskreveal.engines.base import ParsedHost, ParsedPort

MAX_EVIDENCE_CHARS = 20_000


@dataclass(frozen=True)
class FindingDraft:
    """A finding not yet saved. ``address`` says which host it belongs to."""

    address: str
    port: int
    protocol: str
    title: str
    description: str
    severity: str
    confidence: str
    service: str | None
    product: str | None
    version: str | None
    cpe: str | None
    raw_evidence: str | None


def normalize_host(host: ParsedHost) -> list[FindingDraft]:
    """Findings for one host. A host that isn't up produces none."""
    if host.status != "up":
        return []
    return [_port_to_draft(host.address, port) for port in host.ports if port.state == "open"]


def _port_to_draft(address: str, port: ParsedPort) -> FindingDraft:
    label = _service_label(port)
    title = f"Open port {port.port}/{port.protocol}"
    if label:
        title += f": {label}"

    description = f"Port {port.port}/{port.protocol} is open"
    description += f" and appears to be running {label}." if label else "."

    return FindingDraft(
        address=address,
        port=port.port,
        protocol=port.protocol,
        title=title[:255],
        description=description,
        severity=Severity.INFO.value,
        confidence=Confidence.DETECTED.value,
        service=port.service,
        product=port.product,
        version=port.version,
        cpe=port.cpes[0] if port.cpes else None,
        raw_evidence=_evidence(port),
    )


def _service_label(port: ParsedPort) -> str:
    """e.g. ``OpenSSH 6.6.1p1`` or ``http`` -- product+version if known."""
    if port.product:
        return f"{port.product} {port.version}".strip() if port.version else port.product
    return port.service or ""


def _evidence(port: ParsedPort) -> str | None:
    if not port.scripts:
        return None
    text = "\n\n".join(f"[{s.script_id}]\n{s.output}" for s in port.scripts)
    if len(text) > MAX_EVIDENCE_CHARS:
        text = text[:MAX_EVIDENCE_CHARS] + "\n[truncated]"
    return text
