"""Scan, finding and asset HTTP routes (Docker Desktop required).

The task queue is replaced by a recorder, so no Redis or worker is needed
here. Running a scan end to end is covered in test_scan_pipeline.py.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from riskreveal.api.v1.routes.scans import get_scan_dispatcher
from riskreveal.config import Settings, get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.scanning import service

SCANS = "/api/v1/scans"
FINDINGS = "/api/v1/findings"
ASSETS = "/api/v1/assets"
PW = "correct-horse-battery"
FIXTURE_XML = Path(__file__).resolve().parents[1] / "fixtures" / "nmap_sample.xml"


class Recorder:
    def __init__(self) -> None:
        self.ids: list[uuid.UUID] = []
        self.fail = False

    def __call__(self, scan_id: uuid.UUID) -> None:
        if self.fail:
            raise ConnectionError("broker down")
        self.ids.append(scan_id)


@pytest.fixture
def queue(api_app: FastAPI) -> Iterator[Recorder]:
    recorder = Recorder()
    api_app.dependency_overrides[get_scan_dispatcher] = lambda: recorder
    yield recorder
    api_app.dependency_overrides.pop(get_scan_dispatcher, None)


@pytest.fixture
def settings_override(api_app: FastAPI) -> Iterator[dict[str, object]]:
    overrides: dict[str, object] = {"scan_public_allowlist": ["8.8.8.8"]}

    def provide() -> Settings:
        return get_settings().model_copy(update=overrides)

    api_app.dependency_overrides[get_settings] = provide
    yield overrides
    api_app.dependency_overrides.pop(get_settings, None)


def _login(client: TestClient, email: str) -> dict[str, str]:
    client.post("/api/v1/auth/register", json={"email": email, "password": PW})
    tokens = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_scan_routes_require_authentication(client: TestClient) -> None:
    assert client.get(SCANS).status_code == 401
    assert client.post(SCANS, json={"target": "8.8.8.8"}).status_code == 401
    assert client.get(FINDINGS).status_code == 401
    assert client.get(ASSETS).status_code == 401


def test_create_scan_queues_it_and_returns_it(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    headers = _login(client, "a@example.com")
    response = client.post(SCANS, json={"target": " 8.8.8.8 "}, headers=headers)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "queued"
    assert body["target"] == "8.8.8.8"
    assert body["profile"] == "quick"
    assert body["scanned_addresses"] == ["8.8.8.8"]
    assert queue.ids == [uuid.UUID(body["id"])]

    fetched = client.get(f"{SCANS}/{body['id']}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["id"] == body["id"]


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "-sV", "8.8.8.8 -sV", "http://8.8.8.8", "1.1.1.1"],
)
def test_refused_targets_are_422_and_never_queued(
    client: TestClient, queue: Recorder, settings_override: dict[str, object], target: str
) -> None:
    headers = _login(client, "a@example.com")
    response = client.post(SCANS, json={"target": target}, headers=headers)
    assert response.status_code == 422, response.text
    assert queue.ids == []
    assert client.get(SCANS, headers=headers).json()["total"] == 0


def test_public_target_not_on_allowlist_is_refused(client: TestClient, queue: Recorder) -> None:
    headers = _login(client, "a@example.com")  # default settings: empty allowlist
    response = client.post(SCANS, json={"target": "8.8.8.8"}, headers=headers)
    assert response.status_code == 422
    assert "SCAN_PUBLIC_ALLOWLIST" in response.json()["detail"]


def test_bad_profile_and_extra_fields_are_422(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    headers = _login(client, "a@example.com")
    bad_profile = client.post(SCANS, json={"target": "8.8.8.8", "profile": "-sV"}, headers=headers)
    assert bad_profile.status_code == 422
    extra = client.post(
        SCANS, json={"target": "8.8.8.8", "nmap_args": "--script vuln"}, headers=headers
    )
    assert extra.status_code == 422
    assert queue.ids == []


def test_queue_outage_fails_the_scan_and_returns_503(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    headers = _login(client, "a@example.com")
    queue.fail = True
    response = client.post(SCANS, json={"target": "8.8.8.8"}, headers=headers)
    assert response.status_code == 503
    scans = client.get(SCANS, headers=headers).json()
    assert scans["total"] == 1
    assert scans["items"][0]["status"] == "failed"
    assert "broker down" not in str(scans)


def test_active_scan_cap_returns_429(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    settings_override["scan_max_active_per_user"] = 1
    headers = _login(client, "a@example.com")
    assert client.post(SCANS, json={"target": "8.8.8.8"}, headers=headers).status_code == 201
    assert client.post(SCANS, json={"target": "8.8.8.8"}, headers=headers).status_code == 429


def test_users_cannot_see_or_cancel_each_others_scans(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    alice = _login(client, "alice@example.com")
    bob = _login(client, "bob@example.com")
    scan_id = client.post(SCANS, json={"target": "8.8.8.8"}, headers=alice).json()["id"]

    assert client.get(f"{SCANS}/{scan_id}", headers=bob).status_code == 404
    assert client.post(f"{SCANS}/{scan_id}/cancel", headers=bob).status_code == 404
    assert client.get(SCANS, headers=bob).json()["total"] == 0
    assert client.get(f"{SCANS}/{uuid.uuid4()}", headers=alice).status_code == 404
    assert client.get(f"{SCANS}/not-a-uuid", headers=alice).status_code == 422
    # still queued: Bob's cancel attempt did nothing
    assert client.get(f"{SCANS}/{scan_id}", headers=alice).json()["status"] == "queued"


def test_cancel_then_cancel_again(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    headers = _login(client, "a@example.com")
    scan_id = client.post(SCANS, json={"target": "8.8.8.8"}, headers=headers).json()["id"]
    first = client.post(f"{SCANS}/{scan_id}/cancel", headers=headers)
    assert first.status_code == 200 and first.json()["status"] == "cancelled"
    assert client.post(f"{SCANS}/{scan_id}/cancel", headers=headers).status_code == 409


def test_pagination_is_bounded(client: TestClient, queue: Recorder) -> None:
    headers = _login(client, "a@example.com")
    assert client.get(f"{SCANS}?limit=0", headers=headers).status_code == 422
    assert client.get(f"{SCANS}?limit=101", headers=headers).status_code == 422
    assert client.get(f"{SCANS}?offset=-1", headers=headers).status_code == 422
    assert client.get(f"{SCANS}?limit=100&offset=0", headers=headers).status_code == 200


def test_findings_and_assets_are_owner_scoped(
    client: TestClient, queue: Recorder, settings_override: dict[str, object]
) -> None:
    alice = _login(client, "alice@example.com")
    bob = _login(client, "bob@example.com")
    scan_id = client.post(SCANS, json={"target": "8.8.8.8"}, headers=alice).json()["id"]

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 0, FIXTURE_XML.read_bytes(), b"")

    cfg = get_settings().model_copy(update=settings_override)
    with get_sessionmaker()() as db:
        service.run_scan(db, uuid.UUID(scan_id), settings=cfg, runner=runner)

    mine = client.get(f"{FINDINGS}?scan_id={scan_id}", headers=alice).json()
    assert mine["total"] >= 1
    assert "raw_evidence" not in mine["items"][0]
    finding_id = mine["items"][0]["id"]

    detail = client.get(f"{FINDINGS}/{finding_id}", headers=alice)
    assert detail.status_code == 200 and "raw_evidence" in detail.json()
    assert client.get(f"{FINDINGS}/{finding_id}", headers=bob).status_code == 404
    assert client.get(FINDINGS, headers=bob).json()["total"] == 0
    assert client.get(f"{FINDINGS}?severity=nonsense", headers=alice).status_code == 422
    assert client.get(f"{FINDINGS}?severity=info", headers=alice).json()["total"] == mine["total"]
    assert client.get(f"{FINDINGS}?severity=critical", headers=alice).json()["total"] == 0

    assets = client.get(ASSETS, headers=alice).json()
    assert assets["total"] >= 1
    asset_id = assets["items"][0]["id"]
    assert client.get(f"{ASSETS}/{asset_id}", headers=alice).status_code == 200
    assert client.get(f"{ASSETS}/{asset_id}", headers=bob).status_code == 404
    assert client.get(ASSETS, headers=bob).json()["total"] == 0
