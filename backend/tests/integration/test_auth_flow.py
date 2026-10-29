"""End-to-end auth tests against a real PostgreSQL (see conftest.py).

Requires Docker Desktop to be running.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from riskreveal.core.rate_limit import limiter
from riskreveal.db.session import get_engine
from riskreveal.domain.users import service

REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
ME = "/api/v1/auth/me"

EMAIL = "alice@example.com"
GOOD_PW = "correct-horse-battery"


def _register(client: TestClient, email: str = EMAIL) -> None:
    response = client.post(REGISTER, json={"email": email, "password": GOOD_PW})
    assert response.status_code == 201, response.text


def _login(client: TestClient) -> dict[str, str]:
    response = client.post(LOGIN, json={"email": EMAIL, "password": GOOD_PW})
    assert response.status_code == 200, response.text
    tokens: dict[str, str] = response.json()
    return tokens


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_register_returns_user_without_password_hash(client: TestClient) -> None:
    response = client.post(
        REGISTER, json={"email": "Alice@Example.com", "password": GOOD_PW, "full_name": "Alice"}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == EMAIL
    assert body["full_name"] == "Alice"
    assert body["is_active"] is True
    assert "hashed_password" not in body
    assert "password" not in body


def test_duplicate_email_is_409_even_with_different_case(client: TestClient) -> None:
    _register(client)
    response = client.post(REGISTER, json={"email": "ALICE@example.com", "password": GOOD_PW})
    assert response.status_code == 409


def test_short_password_is_422(client: TestClient) -> None:
    response = client.post(REGISTER, json={"email": EMAIL, "password": "short"})
    assert response.status_code == 422


def test_login_then_me(client: TestClient) -> None:
    _register(client)
    tokens = _login(client)
    assert tokens["token_type"] == "bearer"

    response = client.get(ME, headers=_bearer(tokens["access_token"]))
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL


def test_wrong_password_and_unknown_email_look_identical(client: TestClient) -> None:
    _register(client)
    wrong_pw = client.post(LOGIN, json={"email": EMAIL, "password": "not-the-password"})
    unknown = client.post(LOGIN, json={"email": "nobody@example.com", "password": GOOD_PW})
    assert wrong_pw.status_code == unknown.status_code == 401
    assert wrong_pw.json() == unknown.json()


def test_unknown_email_still_runs_a_password_verification(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards the timing-oracle fix: unknown emails must still cost one hash check."""
    calls: list[str] = []
    real_verify = service.verify_password

    def spy(password: str, hashed_password: str) -> bool:
        calls.append(hashed_password)
        return real_verify(password, hashed_password)

    monkeypatch.setattr(service, "verify_password", spy)
    response = client.post(LOGIN, json={"email": "nobody@example.com", "password": GOOD_PW})
    assert response.status_code == 401
    assert len(calls) == 1


def test_me_requires_a_token(client: TestClient) -> None:
    assert client.get(ME).status_code == 401
    assert client.get(ME, headers=_bearer("not-a-jwt")).status_code == 401


def test_refresh_token_cannot_be_used_as_access_token(client: TestClient) -> None:
    _register(client)
    tokens = _login(client)
    assert client.get(ME, headers=_bearer(tokens["refresh_token"])).status_code == 401


def test_access_token_cannot_be_used_to_refresh(client: TestClient) -> None:
    _register(client)
    tokens = _login(client)
    response = client.post(REFRESH, json={"refresh_token": tokens["access_token"]})
    assert response.status_code == 401


def test_refresh_issues_a_working_new_pair(client: TestClient) -> None:
    _register(client)
    tokens = _login(client)
    response = client.post(REFRESH, json={"refresh_token": tokens["refresh_token"]})
    assert response.status_code == 200
    new_tokens = response.json()
    assert client.get(ME, headers=_bearer(new_tokens["access_token"])).status_code == 200


def test_disabled_user_cannot_login_and_old_token_stops_working(client: TestClient) -> None:
    _register(client)
    tokens = _login(client)

    with get_engine().begin() as conn:
        conn.execute(text("UPDATE users SET is_active = false WHERE email = :e"), {"e": EMAIL})

    assert client.get(ME, headers=_bearer(tokens["access_token"])).status_code == 401
    response = client.post(LOGIN, json={"email": EMAIL, "password": GOOD_PW})
    assert response.status_code == 401


def test_auth_endpoints_are_rate_limited(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "riskreveal.core.rate_limit.get_settings",
        lambda: SimpleNamespace(auth_rate_limit="2/minute"),
    )
    limiter.reset()
    payload = {"email": "nobody@example.com", "password": GOOD_PW}
    statuses = [client.post(LOGIN, json=payload).status_code for _ in range(3)]
    assert statuses == [401, 401, 429]
