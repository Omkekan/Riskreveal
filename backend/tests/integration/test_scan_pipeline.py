"""The scan pipeline against a real PostgreSQL (Docker Desktop required).

Two kinds of test:

* ``live_nmap`` -- runs the REAL Nmap binary against a throwaway TCP listener
  on 127.0.0.1 that the test itself opens, then checks the open port really
  shows up as an asset and a finding. Nothing about the scan result is faked.
  Skipped automatically if Nmap is not installed.
* failure-path tests -- inject a fake subprocess runner to force timeouts,
  garbage output and oversized banners, which cannot be produced on demand
  with real Nmap. These only test how the service reacts to bad scanner
  behaviour; they are not a stand-in for scanning.
"""

from __future__ import annotations

import contextlib
import shutil
import socket
import subprocess
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from riskreveal.config import Settings, get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.assets.models import Asset
from riskreveal.domain.findings.models import Finding
from riskreveal.domain.scanning import profiles, repository, service
from riskreveal.domain.scanning.enums import ScanStatus
from riskreveal.domain.scanning.models import Scan
from riskreveal.domain.scanning.profiles import ScanProfile
from riskreveal.domain.users import service as user_service
from riskreveal.domain.users.models import User

FIXTURE_XML = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_sample.xml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def db(client: TestClient) -> Iterator[Session]:  # `client` truncates the tables first
    with get_sessionmaker()() as session:
        yield session


def _user(db: Session, email: str = "scanner@example.com") -> User:
    return user_service.register_user(
        db, email=email, password="correct-horse-battery", full_name=None
    )


def _settings(**overrides: object) -> Settings:
    return get_settings().model_copy(update=overrides)


def _fake_runner(stdout: bytes = b"", returncode: int = 0, stderr: bytes = b""):
    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    return runner


def _raising_runner(exc: BaseException):
    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise exc

    return runner


def _queue(db: Session, owner: User, target: str, cfg: Settings, profile: str = "quick") -> Scan:
    return service.create_scan(
        db, owner_id=owner.id, raw_target=target, profile_name=profile, settings=cfg
    )


PUBLIC_CFG = {"scan_public_allowlist": ["8.8.8.8"]}


# ---------------------------------------------------------------------------
# REAL Nmap against a local listener
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _listener() -> Iterator[int]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    server.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            with contextlib.suppress(OSError):
                conn.sendall(b"220 riskreveal-test ESMTP ready\r\n")
            conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield int(server.getsockname()[1])
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()


@pytest.mark.live_nmap
@pytest.mark.skipif(shutil.which("nmap") is None, reason="Nmap is not installed")
def test_real_nmap_finds_the_open_port_and_stores_it(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _listener() as port:
        # A test-only profile that scans exactly the one port we opened.
        profile = ScanProfile(
            name="itest",
            description="integration test: one local port",
            nmap_args=("-sT", "-p", str(port), "-T4", "--max-retries", "1"),
            timeout_seconds=120,
        )
        monkeypatch.setitem(profiles.PROFILES, "itest", profile)
        cfg = _settings(scan_private_ranges_allowed=True)

        owner = _user(db)
        scan = _queue(db, owner, "127.0.0.1", cfg, profile="itest")
        assert scan.status == ScanStatus.QUEUED.value

        final = service.run_scan(db, scan.id, settings=cfg)  # real subprocess.run, real Nmap

    assert final is ScanStatus.COMPLETED
    done = db.get(Scan, scan.id, populate_existing=True)
    assert done is not None
    assert done.status == "completed"
    assert done.scanned_addresses == ["127.0.0.1"]
    assert done.error is None
    assert done.started_at is not None and done.finished_at is not None

    asset = db.scalar(select(Asset).where(Asset.owner_id == owner.id))
    assert asset is not None and asset.address == "127.0.0.1"
    assert asset.last_scanned_at is not None

    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    assert [f.port for f in findings] == [port]
    assert findings[0].asset_id == asset.id
    assert findings[0].severity == "info"
    assert findings[0].title.startswith(f"Open port {port}/tcp")


# ---------------------------------------------------------------------------
# Failure paths (fake runner = bad scanner behaviour only)
# ---------------------------------------------------------------------------


def test_scanner_timeout_fails_the_scan_with_a_safe_message(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    final = service.run_scan(
        db, scan.id, settings=cfg, runner=_raising_runner(subprocess.TimeoutExpired("nmap", 1))
    )
    assert final is ScanStatus.FAILED
    failed = db.get(Scan, scan.id, populate_existing=True)
    assert failed is not None
    assert failed.status == "failed"
    assert failed.error == "The scan exceeded its time limit and was stopped."
    assert db.scalar(select(func.count()).select_from(Finding)) == 0


def test_nmap_stderr_never_reaches_the_scan_row(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    service.run_scan(
        db,
        scan.id,
        settings=cfg,
        runner=_fake_runner(returncode=1, stderr=b"SECRET-PATH C:\\Users\\x\\boom"),
    )
    failed = db.get(Scan, scan.id, populate_existing=True)
    assert failed is not None and failed.status == "failed"
    assert failed.error == "The scanner failed to run."
    assert "SECRET" not in (failed.error or "")


def test_garbage_output_fails_the_scan_and_saves_nothing(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    service.run_scan(db, scan.id, settings=cfg, runner=_fake_runner(stdout=b"not xml at all"))
    failed = db.get(Scan, scan.id, populate_existing=True)
    assert failed is not None and failed.status == "failed"
    assert db.scalar(select(func.count()).select_from(Asset)) == 0


def test_unstartable_nmap_fails_the_scan_cleanly(db: Session) -> None:
    # A real subprocess.run on a path that does not exist: the OS refuses to start it.
    cfg = _settings(nmap_path=str(Path("definitely") / "not-nmap.exe"), **PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    final = service.run_scan(db, scan.id, settings=cfg)
    assert final is ScanStatus.FAILED
    failed = db.get(Scan, scan.id, populate_existing=True)
    assert failed is not None
    assert failed.error == "The scanner failed to run."


def test_oversized_banner_is_clipped_not_fatal(db: Session) -> None:
    long = "A" * 5000
    xml = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.97">
  <host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="53"><state state="open"/>
      <service name="{long}" product="{long}" version="{long}"><cpe>cpe:/a:{long}</cpe></service>
    </port></ports>
  </host>
</nmaprun>""".encode()
    cfg = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    final = service.run_scan(db, scan.id, settings=cfg, runner=_fake_runner(stdout=xml))
    assert final is ScanStatus.COMPLETED
    finding = db.scalar(select(Finding).where(Finding.scan_id == scan.id))
    assert finding is not None
    assert len(finding.service or "") == 64
    assert len(finding.product or "") == 128
    assert len(finding.version or "") == 128
    assert len(finding.cpe or "") == 255
    assert len(finding.title) == 255


def test_down_host_creates_no_asset_and_no_findings(db: Session) -> None:
    xml = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.97">
  <host><status state="down"/><address addr="8.8.8.8" addrtype="ipv4"/></host>
</nmaprun>"""
    cfg = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    final = service.run_scan(db, scan.id, settings=cfg, runner=_fake_runner(stdout=xml))
    assert final is ScanStatus.COMPLETED
    assert db.scalar(select(func.count()).select_from(Asset)) == 0
    assert db.scalar(select(func.count()).select_from(Finding)) == 0


def test_rescan_updates_the_same_asset(db: Session) -> None:
    xml = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.97">
  <host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="53"><state state="open"/>
      <service name="domain"/></port></ports></host>
</nmaprun>"""
    cfg = _settings(**PUBLIC_CFG)
    owner = _user(db)
    for _ in range(2):
        scan = _queue(db, owner, "8.8.8.8", cfg)
        service.run_scan(db, scan.id, settings=cfg, runner=_fake_runner(stdout=xml))
    assert db.scalar(select(func.count()).select_from(Asset)) == 1
    assert db.scalar(select(func.count()).select_from(Finding)) == 2  # one per scan


def test_a_scan_runs_at_most_once(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", cfg)
    xml = FIXTURE_XML.read_bytes()
    first = service.run_scan(db, scan.id, settings=cfg, runner=_fake_runner(stdout=xml))
    second = service.run_scan(db, scan.id, settings=cfg, runner=_fake_runner(stdout=xml))
    assert first is not None
    assert second is None


def test_cancelled_scan_is_not_run(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG)
    owner = _user(db)
    scan = _queue(db, owner, "8.8.8.8", cfg)
    cancelled = service.cancel_scan(db, scan_id=scan.id, owner_id=owner.id)
    assert cancelled is not None and cancelled.status == "cancelled"
    assert service.run_scan(db, scan.id, settings=cfg) is None
    with pytest.raises(service.ScanNotCancellableError):
        service.cancel_scan(db, scan_id=scan.id, owner_id=owner.id)


def test_scan_cancelled_while_running_discards_results(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG)
    owner = _user(db)
    scan = _queue(db, owner, "8.8.8.8", cfg)
    xml = FIXTURE_XML.read_bytes()

    def cancelling_runner(
        command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        # A second session cancels the scan while "Nmap" is running.
        with get_sessionmaker()() as other:
            service.cancel_scan(other, scan_id=scan.id, owner_id=owner.id)
        return subprocess.CompletedProcess(command, 0, xml, b"")

    final = service.run_scan(db, scan.id, settings=cfg, runner=cancelling_runner)
    assert final is ScanStatus.CANCELLED
    assert db.scalar(select(func.count()).select_from(Finding)) == 0
    assert db.scalar(select(func.count()).select_from(Asset)) == 0


def test_target_is_revalidated_when_the_scan_runs(db: Session) -> None:
    allowed = _settings(**PUBLIC_CFG)
    scan = _queue(db, _user(db), "8.8.8.8", allowed)
    # The operator removed the target from the allowlist while it was queued.
    final = service.run_scan(db, scan.id, settings=_settings(scan_public_allowlist=[]))
    assert final is ScanStatus.FAILED
    failed = db.get(Scan, scan.id, populate_existing=True)
    assert failed is not None and "SCAN_PUBLIC_ALLOWLIST" in (failed.error or "")


def test_stale_running_and_queued_scans_are_failed(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG, scan_max_active_per_user=10)
    owner = _user(db)
    running = _queue(db, owner, "8.8.8.8", cfg)
    queued = _queue(db, owner, "8.8.8.8", cfg)
    fresh = _queue(db, owner, "8.8.8.8", cfg)
    assert repository.claim_queued(db, running.id)
    db.commit()

    future = datetime.now(UTC) + service.STALE_QUEUED_AFTER + service.STALE_RUNNING_AFTER
    assert service.fail_stale_scans(db, now=future) == 3
    for scan_id in (running.id, queued.id, fresh.id):
        row = db.get(Scan, scan_id, populate_existing=True)
        assert row is not None and row.status == "failed"
    assert service.fail_stale_scans(db) == 0


def test_active_scan_cap_is_enforced(db: Session) -> None:
    cfg = _settings(**PUBLIC_CFG, scan_max_active_per_user=1)
    owner = _user(db)
    _queue(db, owner, "8.8.8.8", cfg)
    with pytest.raises(service.TooManyActiveScansError):
        _queue(db, owner, "8.8.8.8", cfg)
    other = _user(db, "other@example.com")
    _queue(db, other, "8.8.8.8", cfg)  # the cap is per user


def test_unknown_user_cannot_create_a_scan(db: Session) -> None:
    with pytest.raises(service.ScanRejectedError):
        service.create_scan(
            db,
            owner_id=uuid.uuid4(),
            raw_target="8.8.8.8",
            profile_name="quick",
            settings=_settings(**PUBLIC_CFG),
        )
