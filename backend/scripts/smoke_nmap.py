"""Manual smoke test: validate -> run real Nmap -> parse -> normalize. No database.

Run from backend/:
    uv run python scripts/smoke_nmap.py                   # scans scanme.nmap.org
    uv run python scripts/smoke_nmap.py 192.168.1.10      # only works if
                                                          # SCAN_PRIVATE_RANGES_ALLOWED=true

ONLY scan systems you own or have written permission to test.
scanme.nmap.org is Nmap's public test host: one quick scan is fine, but don't
loop on it or hammer it.
"""

from __future__ import annotations

import sys

from riskreveal.config import get_settings
from riskreveal.domain.scanning.profiles import DEFAULT_PROFILE, get_profile
from riskreveal.domain.scanning.scope_policy import ScopeError, validate_target
from riskreveal.engines.base import EngineError
from riskreveal.engines.nmap_engine import run_nmap
from riskreveal.engines.normalizer import normalize_host


def main() -> int:
    raw = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    settings = get_settings()

    try:
        target = validate_target(raw, allow_private=settings.scan_private_ranges_allowed)
    except ScopeError as exc:
        print(f"Target rejected by scope policy: {exc}")
        return 2
    print(f"Target OK: kind={target.kind} scanning={', '.join(target.scan_args)}")

    profile = get_profile(DEFAULT_PROFILE)
    print(f"Running Nmap profile '{profile.name}' (timeout {profile.timeout_seconds}s)...")
    try:
        result = run_nmap(target, profile)
    except EngineError as exc:
        print(f"Scan failed: {exc}")
        return 1

    print(f"Nmap {result.nmap_version}: {len(result.hosts)} host(s) in the output")
    total = 0
    for host in result.hosts:
        drafts = normalize_host(host)
        total += len(drafts)
        print(f"\n{host.address} ({host.status}) {', '.join(host.hostnames)}")
        for draft in drafts:
            print(f"  [{draft.severity}/{draft.confidence}] {draft.title}")
    print(f"\n{total} informational finding draft(s). Nothing was saved to the database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
