"""Scan scope policy: decide whether a user-supplied target may be scanned.

This module is the gate in front of Nmap. Everything a user types as a scan
target goes through :func:`validate_target`, and only the *validated*
addresses it returns are ever passed to the scanner. Properties it enforces:

* **One target per scan**, in one of three shapes: a single IP, a CIDR
  range, or a hostname. Whitespace, commas, option-like strings such as
  ``-sV`` and URLs are rejected, so a target can never smuggle extra Nmap
  arguments (the argument-injection bug in the old codebase, 01_... #4).
* **No internal or special-purpose addresses by default.** Loopback, RFC 1918
  private, shared (CGNAT) and other non-global ranges are refused unless the
  operator sets ``SCAN_PRIVATE_RANGES_ALLOWED=true``. Link-local (which
  includes the cloud metadata address 169.254.169.254), multicast,
  unspecified and reserved ranges are refused **always**, flag or no flag.
* **Hostnames are resolved here, and the resolved IPs are what get
  scanned.** Every resolved address must pass the same checks, so a name
  pointing at an internal host is rejected. Scanning the pinned IPs (not the
  name) also stops Nmap re-resolving to something different a moment later.
* **Bounded size.** Ranges larger than ``max_hosts`` (default 256) are
  refused.

What this module cannot do: prove you are *authorized* to scan a target.
That is a human responsibility (scan only systems you own or have written
permission to test; ``scanme.nmap.org`` is Nmap's own public test host).
Error messages deliberately avoid echoing resolved IP addresses, so the
policy can't be used to probe what an internal DNS name resolves to.

Pure standard library: importable and testable without the web stack.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

DEFAULT_MAX_HOSTS = 256
MAX_TARGET_LENGTH = 255
MAX_RESOLVED_ADDRESSES = 16
# How long to wait for a hostname lookup. The OS resolver can take far longer
# (about 11 s on one network), and the caller may hold a database transaction
# open while it waits.
DNS_TIMEOUT_SECONDS = 5.0

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Sequence[str]]

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

# IPv6 transition ranges that embed an IPv4 address. Python calls some of them
# "global", but a gateway can translate them to an IPv4 address (possibly a
# private one) that this policy never got to judge. Never scanned.
_TRANSITION_NETWORKS = (
    ipaddress.IPv6Network("64:ff9b::/96"),  # NAT64
    ipaddress.IPv6Network("64:ff9b:1::/48"),  # local-use NAT64
    ipaddress.IPv6Network("2002::/16"),  # 6to4
    ipaddress.IPv6Network("2001::/32"),  # Teredo
)


class ScopeError(ValueError):
    """The target is not allowed. The message is safe to show to the user."""


@dataclass(frozen=True)
class ValidatedTarget:
    """A target that passed the policy. Pass ``scan_args`` -- and nothing
    else -- to the scanner."""

    original: str
    kind: Literal["ip", "cidr", "hostname"]
    scan_args: tuple[str, ...]
    """Exactly the addresses/ranges to hand to Nmap (IPs only, never a name)."""
    addresses: tuple[str, ...]
    """Concrete IPs known up front: the IP itself, or the resolved IPs for a
    hostname. Empty for a CIDR (hosts are only known after the scan)."""
    hostname: str | None
    """The (normalized) hostname the user typed, for hostname targets."""
    host_count: int
    ipv6: bool


def system_resolver(hostname: str, *, timeout: float = DNS_TIMEOUT_SECONDS) -> list[str]:
    """Resolve a hostname to a sorted, de-duplicated list of IP strings.

    ``socket.getaddrinfo`` cannot be interrupted, so the lookup runs in a
    daemon thread and we simply stop *waiting* after ``timeout`` seconds. An
    abandoned lookup finishes (or fails) on its own and its result is
    discarded; being a daemon thread, it never keeps the process alive.
    Every failure, whatever its type, becomes a :class:`ScopeError` with a
    fixed message, so resolver internals never reach the user.
    """
    outcome: list[Any] = []  # one item: the lookup result, or the exception it raised

    def lookup() -> None:
        try:
            outcome.append(socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM))
        except Exception as exc:
            outcome.append(exc)

    worker = threading.Thread(target=lookup, name="dns-lookup", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive() or not outcome:
        raise ScopeError("The hostname lookup timed out.")

    result = outcome[0]
    if isinstance(result, Exception):
        raise ScopeError("The hostname could not be resolved.") from result
    return sorted({str(info[4][0]) for info in result})


def validate_target(
    raw: str,
    *,
    allow_private: bool,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    resolver: Resolver = system_resolver,
) -> ValidatedTarget:
    """Validate one scan target, or raise :class:`ScopeError`.

    ``allow_private`` should come from ``settings.scan_private_ranges_allowed``.
    ``resolver`` is injectable so tests (and, later, a caching resolver) don't
    need real DNS.
    """
    target = raw.strip()
    if not target:
        raise ScopeError("A target is required.")
    if len(target) > MAX_TARGET_LENGTH:
        raise ScopeError("The target is too long.")
    if "%" in target:
        raise ScopeError("Scoped (zone-id) addresses are not supported.")

    if "/" in target:
        return _validate_cidr(target, allow_private=allow_private, max_hosts=max_hosts)

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return _validate_hostname(target, allow_private=allow_private, resolver=resolver)

    _check_address(ip, allow_private=allow_private)
    text = str(_unwrap(ip))
    return ValidatedTarget(
        original=target,
        kind="ip",
        scan_args=(text,),
        addresses=(text,),
        hostname=None,
        host_count=1,
        ipv6=_unwrap(ip).version == 6,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _unwrap(ip: IPAddress) -> IPAddress:
    """Treat an IPv4-mapped IPv6 address (``::ffff:127.0.0.1``) as the IPv4
    address it wraps, so it can't be used to sneak past the IPv4 checks."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _check_address(ip: IPAddress, *, allow_private: bool) -> None:
    ip = _unwrap(ip)
    if isinstance(ip, ipaddress.IPv6Address) and any(
        ip in network for network in _TRANSITION_NETWORKS
    ):
        raise ScopeError(
            "This address is in a range that can never be scanned "
            "(unspecified, multicast, link-local or reserved)."
        )
    # Never allowed, regardless of configuration.
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ScopeError(
            "This address is in a range that can never be scanned "
            "(unspecified, multicast, link-local or reserved)."
        )
    # Loopback is checked before "reserved" because Python classes IPv6 ::1 as
    # reserved (::/8); it should follow the private-range switch instead.
    if ip.is_loopback:
        if not allow_private:
            raise ScopeError(
                "Private, loopback and other non-public addresses are not allowed "
                "by this server's scan policy."
            )
        return
    if ip.is_reserved:
        raise ScopeError(
            "This address is in a range that can never be scanned "
            "(unspecified, multicast, link-local or reserved)."
        )
    # RFC 1918 private, CGNAT and other non-public ranges: opt-in only.
    if not ip.is_global and not allow_private:
        raise ScopeError(
            "Private, loopback and other non-public addresses are not allowed "
            "by this server's scan policy."
        )


def _validate_cidr(target: str, *, allow_private: bool, max_hosts: int) -> ValidatedTarget:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScopeError("That is not a valid IP range.") from exc

    if network.num_addresses > max_hosts:
        raise ScopeError(f"Ranges larger than {max_hosts} addresses are not allowed.")

    # Check both ends. Ranges are capped small, so this also covers the middle
    # for every allocation boundary that matters.
    _check_address(network.network_address, allow_private=allow_private)
    _check_address(network[-1], allow_private=allow_private)

    cidr = str(network)
    return ValidatedTarget(
        original=target,
        kind="cidr",
        scan_args=(cidr,),
        addresses=(),
        hostname=None,
        host_count=network.num_addresses,
        ipv6=network.version == 6,
    )


def _validate_hostname(
    target: str, *, allow_private: bool, resolver: Resolver
) -> ValidatedTarget:
    hostname = target.lower().rstrip(".")

    if not hostname.isascii():
        raise ScopeError("Use the ASCII (punycode) form of internationalized hostnames.")
    if len(hostname) > 253:
        raise ScopeError("The hostname is too long.")
    labels = hostname.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ScopeError("That is not a valid IP address, IP range or hostname.")
    # A final all-digit label ("127.1", "2130706433") is an old-style numeric
    # IP, not a real hostname. Refuse it rather than let the resolver guess.
    if labels[-1].isdigit():
        raise ScopeError("That is not a valid IP address, IP range or hostname.")

    resolved = resolver(hostname)
    if not resolved:
        raise ScopeError("The hostname did not resolve to any address.")
    if len(resolved) > MAX_RESOLVED_ADDRESSES:
        raise ScopeError("The hostname resolves to too many addresses.")

    addresses: list[str] = []
    for text in resolved:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError as exc:
            raise ScopeError("The hostname resolved to an invalid address.") from exc
        try:
            _check_address(ip, allow_private=allow_private)
        except ScopeError as exc:
            # Don't echo the address: that would leak internal DNS answers.
            raise ScopeError(
                "The hostname resolves to an address this server's scan policy does not allow."
            ) from exc
        addresses.append(str(_unwrap(ip)))

    # One Nmap run can't mix address families (IPv6 needs -6). If the name has
    # both A and AAAA records, scan the IPv4 ones; IPv6-only names scan IPv6.
    unique_all = sorted(set(addresses))
    ipv4_only = [a for a in unique_all if ":" not in a]
    unique = tuple(ipv4_only or unique_all)
    return ValidatedTarget(
        original=target,
        kind="hostname",
        scan_args=unique,
        addresses=unique,
        hostname=hostname,
        host_count=len(unique),
        ipv6=":" in unique[0],
    )
