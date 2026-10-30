"""Shared pytest configuration and fixtures.

The environment variables below are set at import time, BEFORE any riskreveal
module is imported, because ``riskreveal.config`` validates settings on first
use and ``riskreveal.main`` builds an app when imported. Real environment
variables take priority over ``backend/.env`` in pydantic-settings, so the
test run never picks up your development secrets or your development
database URL.

Integration tests start their OWN throwaway PostgreSQL container
(testcontainers), so they need Docker Desktop running but never touch the
``riskreveal-v2`` development database.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "development"
os.environ["DEBUG"] = "false"
# Placeholder only; the integration fixtures swap in the container's URL.
os.environ["DATABASE_URL"] = "postgresql+psycopg://test:test@localhost:1/placeholder"
os.environ["REDIS_URL"] = "redis://localhost:1/0"
os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()
os.environ["AUTH_RATE_LIMIT"] = "1000/minute"
os.environ["CORS_ORIGINS"] = "http://localhost:3000"
# Pin the scan policy so a developer's backend/.env can't change test outcomes.
os.environ["SCAN_PRIVATE_RANGES_ALLOWED"] = "false"
os.environ["SCAN_PUBLIC_ALLOWLIST"] = ""
os.environ["SCAN_RATE_LIMIT"] = "1000/minute"
os.environ["SCAN_MAX_ACTIVE_PER_USER"] = "3"
os.environ["NMAP_PATH"] = ""


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer(
        "postgres:17-alpine", driver="psycopg", dbname="riskreveal_test"
    ) as postgres:
        yield postgres.get_connection_url()


@pytest.fixture(scope="session")
def api_app(database_url: str) -> Iterator[FastAPI]:
    # Register every table on Base.metadata (an unimported model is never created).
    import riskreveal.domain.assets.models
    import riskreveal.domain.findings.models
    import riskreveal.domain.scanning.models
    import riskreveal.domain.users.models  # noqa: F401
    from riskreveal.config import get_settings
    from riskreveal.db.base import Base
    from riskreveal.db.session import get_engine, get_sessionmaker
    from riskreveal.main import create_app

    os.environ["DATABASE_URL"] = database_url
    get_settings.cache_clear()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()

    engine = get_engine()
    Base.metadata.create_all(engine)
    yield create_app()
    engine.dispose()


@pytest.fixture
def client(api_app: FastAPI) -> Iterator[TestClient]:
    from sqlalchemy import text

    from riskreveal.core.rate_limit import limiter
    from riskreveal.db.session import get_engine

    # CASCADE: assets/scans/findings now reference users, so a plain TRUNCATE fails.
    # Safety net: this fixture TRUNCATEs. Refuse to run against anything but the
    # throwaway container database.
    assert get_engine().url.database == "riskreveal_test"
    limiter.reset()
    with get_engine().begin() as conn:
        conn.execute(text("TRUNCATE TABLE users CASCADE"))  # cascades to scans/assets/findings
    with TestClient(api_app) as test_client:
        yield test_client
