"""The distro marker end to end, and the findings filters (needs Docker Desktop).

CVEs are SYNTHETIC (CVE-2099-xxxx); nothing contacts the internet. Matching is
the owner's verified ``matching_service``; this file checks that the marker is
stored, exposed and filterable.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from datetime import UTC, date, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from riskreveal.config import Settings, get_settings
from riskreveal.db.session import get_engine, get_sessionmaker
from riskreveal.domain.assets.models import Asset
from riskreveal.domain.findings.models import Finding
from riskreveal.domain.intelligence import cve_repository, matching_service
from riskreveal.domain.intelligence.models import KevEntry
from riskreveal.domain.intelligence.records import CpeRange, CveRecord
from riskreveal.domain.scanning import service as scan_service
from riskreveal.domain.scanning.enums import ScanStatus
from riskreveal.domain.scanning.models import Scan
from riskreveal.domain.users import service as user_service
from riskreveal.domain.users.models import User

FIXTURE_XML = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_sample.xml"
FINDINGS = "/api/v1/findings"
PW = "correct-horse-battery"


@pytest.fixture
def db(client: TestClient) -> Iterator[Session]:  # `client` truncates users CASCADE first
    assert get_engine().url.database == "riskreveal_test"
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE TABLE cves, cve_syncs, kev_entries, epss_scores CASCADE"))
    with get_sessionmaker()() as session:
        yield session


# --- builders ------------------------------------------------------------------------


def _range(vendor: str, product: str, **fields: object) -> CpeRange:
    return CpeRange(part="a", vendor=vendor, product=product, **fields)  # type: ignore[arg-type]


def _record(cve_id: str, vendor: str, product: str, **range_fields: object) -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        description=f"{cve_id}: a fictional flaw.",
        published=datetime(2099, 1, 1, tzinfo=UTC),
        last_modified=datetime(2099, 2, 1, tzinfo=UTC),
        cvss_score=9.8,
        cvss_severity=None,
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N",
        ranges=(_range(vendor, product, **range_fields),),
    )


def _store_cves(db: Session) -> None:
    cve_repository.upsert_records(
        db,
        [
            _record("CVE-2099-0001", "apache", "http_server", end_excluding="2.4.52"),
            _record("CVE-2099-0002", "openbsd", "openssh", end_excluding="7.2"),
        ],
    )
    db.commit()


def _scan_with_services(
    db: Session, owner: User, *, ubuntu: bool, address: str = "203.0.113.10"
) -> Scan:
    """A completed scan with an Apache and an OpenSSH finding, packaged or plain.

    An asset is unique per (owner, address), so two scans for one owner need
    two different addresses.
    """
    asset = Asset(owner_id=owner.id, address=address)
    scan = Scan(
        owner_id=owner.id,
        target=address,
        profile="quick",
        status="completed",
        scanned_addresses=[address],
    )
    db.add_all([asset, scan])
    db.flush()
    common = {"scan_id": scan.id, "asset_id": asset.id, "source": "nmap", "protocol": "tcp",
              "confidence": "detected", "severity": "info", "status": "open"}  # fmt: skip
    db.add_all(
        [
            Finding(
                **common, title="Open port 80/tcp", port=80, service="http",
                product="Apache httpd", version="2.4.7",
                extra_info="(Ubuntu)" if ubuntu else None,
                cpe="cpe:/a:apache:http_server:2.4.7",
            ),
            Finding(
                **common, title="Open port 22/tcp", port=22, service="ssh", product="OpenSSH",
                version="6.6.1p1 Ubuntu 2ubuntu2.13" if ubuntu else "6.6.1p1",
                extra_info="Ubuntu Linux; protocol 2.0" if ubuntu else None,
                cpe="cpe:/a:openbsd:openssh:6.6.1p1",
            ),
        ]
    )  # fmt: skip
    db.commit()
    return scan


def _match(db: Session, scan: Scan) -> None:
    matching_service.match_scan(db, scan.id, client=None)  # type: ignore[arg-type]


def _version_matches(db: Session, scan: Scan) -> list[Finding]:
    db.expire_all()
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id, Finding.source == "version_match")
            .order_by(Finding.cve_id)
        )
    )


def _login(client: TestClient, email: str) -> dict[str, str]:
    client.post("/api/v1/auth/register", json={"email": email, "password": PW})
    tokens = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def _owner(db: Session, email: str) -> User:
    return db.scalars(select(User).where(User.email == email)).one()


# --- the marker is stored on version_match findings ----------------------------------


def test_cve_findings_on_a_distribution_package_record_the_distro(db: Session) -> None:
    owner = user_service.register_user(db, email="o1@example.com", password=PW, full_name=None)
    scan = _scan_with_services(db, owner, ubuntu=True)
    _store_cves(db)
    _match(db, scan)
    found = _version_matches(db, scan)
    assert [f.cve_id for f in found] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert {f.distro for f in found} == {"ubuntu"}
    assert all("back-port" in (f.description or "") for f in found)


def test_cve_findings_on_upstream_software_have_no_distro(db: Session) -> None:
    owner = user_service.register_user(db, email="o2@example.com", password=PW, full_name=None)
    scan = _scan_with_services(db, owner, ubuntu=False)
    _store_cves(db)
    _match(db, scan)
    found = _version_matches(db, scan)
    assert len(found) == 2
    assert {f.distro for f in found} == {None}


def test_the_marker_is_refreshed_when_a_scan_is_rematched(db: Session) -> None:
    owner = user_service.register_user(db, email="o3@example.com", password=PW, full_name=None)
    scan = _scan_with_services(db, owner, ubuntu=True)
    _store_cves(db)
    _match(db, scan)
    db.execute(text("UPDATE findings SET distro = NULL"))  # as if created before the column
    db.commit()
    _match(db, scan)
    assert {f.distro for f in _version_matches(db, scan)} == {"ubuntu"}


# --- the real pipeline stores it on the Nmap findings too ---------------------------


def test_nmap_findings_from_a_real_scan_run_record_the_distro(db: Session) -> None:
    cfg: Settings = get_settings().model_copy(
        update={"scan_public_allowlist": ["8.8.8.8"], "vuln_matching_enabled": False}
    )
    owner = user_service.register_user(db, email="o4@example.com", password=PW, full_name=None)
    scan = scan_service.create_scan(
        db, owner_id=owner.id, raw_target="8.8.8.8", profile_name="quick", settings=cfg
    )

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, FIXTURE_XML.read_bytes(), b"")

    assert scan_service.run_scan(db, scan.id, settings=cfg, runner=runner) is ScanStatus.COMPLETED
    rows = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    by_port = {f.port: f.distro for f in rows}
    assert by_port[22] == "ubuntu"
    assert by_port[80] == "ubuntu"
    assert by_port[9929] is None


# --- API: exposure and filters ---------------------------------------------------------


def _api_setup(client: TestClient, db: Session) -> tuple[dict[str, str], Scan, Scan]:
    headers = _login(client, "api@example.com")
    owner = _owner(db, "api@example.com")
    packaged = _scan_with_services(db, owner, ubuntu=True)
    upstream = _scan_with_services(db, owner, ubuntu=False, address="203.0.113.11")
    _store_cves(db)
    _match(db, packaged)
    _match(db, upstream)
    db.add(
        KevEntry(
            cve_id="CVE-2099-0001", vendor_project="Fictional", product="httpd",
            vulnerability_name="Fictional bug", date_added=date(2099, 1, 5),
            known_ransomware_use=False, cwes=[],
        )
    )  # fmt: skip
    db.commit()
    return headers, packaged, upstream


def _get(client: TestClient, headers: dict[str, str], **params: object) -> list[dict[str, object]]:
    response = client.get(FINDINGS, params={"limit": 100, **params}, headers=headers)
    assert response.status_code == 200, response.text
    return list(response.json()["items"])


def test_the_api_exposes_the_distro(client: TestClient, db: Session) -> None:
    headers, packaged, upstream = _api_setup(client, db)
    items = _get(client, headers, source="version_match", scan_id=str(packaged.id))
    assert {i["distro"] for i in items} == {"ubuntu"}
    items = _get(client, headers, source="version_match", scan_id=str(upstream.id))
    assert {i["distro"] for i in items} == {None}


def test_filter_distro_packaged(client: TestClient, db: Session) -> None:
    headers, packaged, upstream = _api_setup(client, db)
    only_packaged = _get(client, headers, source="version_match", distro_packaged="true")
    assert {i["scan_id"] for i in only_packaged} == {str(packaged.id)}
    not_packaged = _get(client, headers, source="version_match", distro_packaged="false")
    assert {i["scan_id"] for i in not_packaged} == {str(upstream.id)}
    assert len(only_packaged) == len(not_packaged) == 2


def test_filter_source(client: TestClient, db: Session) -> None:
    headers, _packaged, _upstream = _api_setup(client, db)
    assert {i["source"] for i in _get(client, headers, source="version_match")} == {"version_match"}
    assert {i["source"] for i in _get(client, headers, source="nmap")} == {"nmap"}


def test_filter_cve_id(client: TestClient, db: Session) -> None:
    headers, _packaged, _upstream = _api_setup(client, db)
    items = _get(client, headers, cve_id="CVE-2099-0002")
    assert len(items) == 2 and {i["cve_id"] for i in items} == {"CVE-2099-0002"}


def test_filter_kev_reads_the_live_catalog(client: TestClient, db: Session) -> None:
    headers, _packaged, _upstream = _api_setup(client, db)
    listed = _get(client, headers, kev="true")
    assert {i["cve_id"] for i in listed} == {"CVE-2099-0001"}
    assert len(listed) == 2  # one per scan
    unlisted = _get(client, headers, kev="false")
    assert "CVE-2099-0001" not in {i["cve_id"] for i in unlisted}
    assert "CVE-2099-0002" in {i["cve_id"] for i in unlisted}
    assert any(i["cve_id"] is None for i in unlisted)  # Nmap findings are not KEV-listed

    db.execute(text("DELETE FROM kev_entries"))  # the catalog changes: the answer follows
    db.commit()
    assert _get(client, headers, kev="true") == []


def test_filters_combine(client: TestClient, db: Session) -> None:
    headers, packaged, _upstream = _api_setup(client, db)
    items = _get(
        client, headers, source="version_match", distro_packaged="true", kev="true",
        scan_id=str(packaged.id),
    )  # fmt: skip
    assert [i["cve_id"] for i in items] == ["CVE-2099-0001"]


@pytest.mark.parametrize(
    "params",
    [
        {"cve_id": "not-a-cve"},
        {"cve_id": "CVE-2099-0001; DROP TABLE findings"},
        {"source": "bogus"},
        {"kev": "maybe"},
        {"distro_packaged": "perhaps"},
    ],
)
def test_bad_filter_values_are_rejected(client: TestClient, params: dict[str, str]) -> None:
    headers = _login(client, "bad@example.com")
    assert client.get(FINDINGS, params=params, headers=headers).status_code == 422


def test_filters_never_cross_users(client: TestClient, db: Session) -> None:
    _api_setup(client, db)
    other = _login(client, "other@example.com")
    for params in ({"source": "version_match"}, {"kev": "true"}, {"distro_packaged": "true"}):
        assert _get(client, other, **params) == []
