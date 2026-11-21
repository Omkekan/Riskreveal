"""Registration switch and response headers (needs PostgreSQL via the shared fixtures)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from riskreveal.config import Environment, get_settings
from riskreveal.db.session import get_sessionmaker
from riskreveal.domain.users.models import User
from riskreveal.main import create_app

PW = "correct-horse-battery"


@pytest.fixture
def db(client: TestClient) -> Iterator[Session]:  # `client` truncates users first
    with get_sessionmaker()() as session:
        yield session


def _register(client: TestClient, email: str) -> int:
    return client.post("/api/v1/auth/register", json={"email": email, "password": PW}).status_code


def test_registration_is_open_by_default(client: TestClient) -> None:
    assert get_settings().registration_enabled is True
    assert _register(client, "a@example.com") == 201


def test_closing_registration_blocks_new_accounts_but_not_existing_ones(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _register(client, "owner@example.com") == 201
    monkeypatch.setattr(get_settings(), "registration_enabled", False)

    blocked = client.post(
        "/api/v1/auth/register", json={"email": "new@example.com", "password": PW}
    )
    assert blocked.status_code == 403
    assert "disabled" in blocked.json()["detail"]
    assert db.scalar(select(func.count()).select_from(User)) == 1  # nothing was created

    login = client.post("/api/v1/auth/login", json={"email": "owner@example.com", "password": PW})
    assert login.status_code == 200  # people who already have an account are unaffected


def test_responses_carry_the_basic_hardening_headers(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "strict-transport-security" not in response.headers  # development: no HSTS


def test_api_responses_are_never_cacheable_even_errors(client: TestClient) -> None:
    bad_login = client.post("/api/v1/auth/login", json={"email": "x@example.com", "password": "y"})
    assert bad_login.status_code == 401
    assert bad_login.headers["cache-control"] == "no-store"
    assert _register(client, "a@example.com") == 201
    ok = client.post("/api/v1/auth/login", json={"email": "a@example.com", "password": PW})
    assert ok.status_code == 200 and ok.headers["cache-control"] == "no-store"  # carries tokens


def test_production_adds_hsts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "environment", Environment.PRODUCTION)
    response = TestClient(create_app()).get("/healthz")
    assert response.headers["strict-transport-security"].startswith("max-age=")
    assert TestClient(create_app()).get("/docs").status_code == 404  # docs hidden in production
