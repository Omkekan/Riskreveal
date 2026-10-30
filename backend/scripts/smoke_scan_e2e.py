"""End-to-end check with the REAL database and the REAL Nmap, no API or Celery.

    uv run python scripts/smoke_scan_e2e.py you@example.com                  # scanme.nmap.org
    uv run python scripts/smoke_scan_e2e.py you@example.com 192.168.1.10

The user must already exist (register through the API first). The target goes
through exactly the same checks as an API request: the scope policy, and for a
public target the ``SCAN_PUBLIC_ALLOWLIST`` in backend/.env, e.g.::

    SCAN_PUBLIC_ALLOWLIST=scanme.nmap.org

Only scan systems you own or have written permission to test. scanme.nmap.org
is Nmap's public test host: one quick scan is fine, do not loop on it.
"""

from __future__ import annotations

import sys

from sqlalchemy import select

from riskreveal.config import get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.assets.models import Asset
from riskreveal.domain.findings.models import Finding
from riskreveal.domain.scanning import repository as scan_repository
from riskreveal.domain.scanning import service
from riskreveal.domain.scanning.profiles import DEFAULT_PROFILE
from riskreveal.domain.scanning.scope_policy import ScopeError
from riskreveal.domain.users import repository as user_repository


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    email = sys.argv[1].strip().lower()
    raw_target = sys.argv[2] if len(sys.argv) > 2 else "scanme.nmap.org"
    settings = get_settings()

    with get_sessionmaker()() as db:
        user = user_repository.get_by_email(db, email)
        if user is None:
            print(f"No user with email {email!r}. Register one through the API first.")
            return 2

        try:
            scan = service.create_scan(
                db, owner_id=user.id, raw_target=raw_target, profile_name=DEFAULT_PROFILE
            )
        except (ScopeError, service.ScanRejectedError) as exc:
            print(f"Target refused: {exc}")
            return 2
        print(f"Scan {scan.id} queued: target={scan.target} will scan {scan.scanned_addresses}")
        print(f"Running real Nmap (profile '{scan.profile}')... this can take a few minutes.")

        final = service.run_scan(db, scan.id, settings=settings)
        db.expire_all()
        result = scan_repository.get(db, scan.id)
        if result is None:
            print("The scan row disappeared.")
            return 1
        print(f"\nStatus: {final.value if final else 'not run'}  error: {result.error}")

        findings = db.scalars(
            select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.port)
        ).all()
        for finding in findings:
            asset = db.get(Asset, finding.asset_id)
            where = asset.address if asset else "?"
            print(f"  [{finding.severity}] {where}  {finding.title}")
        print(f"\n{len(findings)} finding(s) saved to the database.")
        return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
