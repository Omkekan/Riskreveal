"""Operator allowlist for scanning *public* targets.

The scope policy (``scope_policy.py``) decides whether an address is *safe to
reach* (no metadata endpoint, no internal ranges unless opted in). It cannot
decide whether the person asking is *allowed* to scan it. Until per-user
ownership verification exists (DNS TXT / HTTP token), this module is the
interim control and it **fails closed**:

* A target whose addresses are all private/loopback is accepted here. The
  scope policy has already refused those unless the operator enabled
  ``SCAN_PRIVATE_RANGES_ALLOWED``, so enabling that flag is the operator's
  explicit decision.
* Any target containing a public address is accepted only if the operator
  listed it in ``SCAN_PUBLIC_ALLOWLIST`` (comma separated): an exact
  hostname, a single IP, or a CIDR range. Hostname entries match the exact
  name only, never subdomains.
* Allowlisted ranges must be no wider than /16 (IPv4) or /48 (IPv6), so a
  typo such as ``0.0.0.0/0`` cannot silently open the whole internet.

Pure standard library: importable and testable without the web stack.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

from riskreveal.domain.scanning.scope_policy import ScopeError, ValidatedTarget

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 48

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class ScanAllowlist:
    """Parsed ``SCAN_PUBLIC_ALLOWLIST``."""

    hostnames: frozenset[str]
    networks: tuple[IPNetwork, ...]

    def permits(self, target: ValidatedTarget) -> bool:
        """True if the operator explicitly listed this target."""
        if target.kind == "hostname" and target.hostname in self.hostnames:
            return True
        if target.kind == "cidr":
            wanted = ipaddress.ip_network(target.scan_args[0], strict=False)
            return any(_network_within(wanted, allowed) for allowed in self.networks)
        addresses = [ipaddress.ip_address(text) for text in target.addresses]
        return bool(addresses) and all(
            any(address in network for network in self.networks) for address in addresses
        )


def parse_allowlist(entries: Iterable[str]) -> ScanAllowlist:
    """Parse and validate allowlist entries. Raises ``ValueError`` on a bad one."""
    hostnames: set[str] = set()
    networks: list[IPNetwork] = []
    for raw in entries:
        entry = raw.strip().lower()
        if not entry:
            continue
        parsed = _parse_entry(entry)
        if isinstance(parsed, str):
            hostnames.add(parsed)
        else:
            networks.append(parsed)
    return ScanAllowlist(hostnames=frozenset(hostnames), networks=tuple(networks))


def check_authorized(target: ValidatedTarget, *, allowlist: ScanAllowlist) -> None:
    """Raise :class:`ScopeError` unless the target may be scanned."""
    if _is_non_public(target):
        return  # the scope policy already required the operator's private-range opt-in
    if allowlist.permits(target):
        return
    raise ScopeError(
        "This target is public and is not on this server's list of scannable public "
        "targets. Only scan systems you own or have written permission to test; the "
        "server operator must add the target to SCAN_PUBLIC_ALLOWLIST first."
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _is_non_public(target: ValidatedTarget) -> bool:
    if target.kind == "cidr":
        network = ipaddress.ip_network(target.scan_args[0], strict=False)
        return not network.network_address.is_global and not network[-1].is_global
    addresses = [ipaddress.ip_address(text) for text in target.addresses]
    # An empty list must never count as "all private".
    return bool(addresses) and all(not address.is_global for address in addresses)


def _network_within(inner: IPNetwork, outer: IPNetwork) -> bool:
    if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return inner.subnet_of(outer)
    return False


def _parse_entry(entry: str) -> str | IPNetwork:
    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError as exc:
            raise ValueError(
                f"{entry!r} is not a valid network (use the network address, e.g. 203.0.113.0/24)"
            ) from exc
        minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
        if network.prefixlen < minimum:
            raise ValueError(f"{entry!r} is too wide; the smallest prefix allowed is /{minimum}")
        return network
    try:
        address = ipaddress.ip_address(entry)
    except ValueError:
        return _parse_hostname(entry)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return ipaddress.ip_network(f"{address}/{address.max_prefixlen}")


def _parse_hostname(entry: str) -> str:
    hostname = entry.rstrip(".")
    if not hostname.isascii() or len(hostname) > 253:
        raise ValueError(f"{entry!r} is not a valid hostname")
    labels = hostname.split(".")
    if not all(_LABEL_RE.match(label) for label in labels) or labels[-1].isdigit():
        raise ValueError(f"{entry!r} is not a valid IP address, network or hostname")
    return hostname
