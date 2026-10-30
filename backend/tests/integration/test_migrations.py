"""Run the real Alembic migrations against a throwaway PostgreSQL.

The other integration tests build tables with ``create_all``, which would hide
a broken or out-of-date migration. This test applies every migration to an
empty database, checks that the models and the migrated schema agree
(``alembic check``), then downgrades to nothing and upgrades again.

Alembic runs in a subprocess so its logging setup cannot affect other tests.
Requires Docker Desktop.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

BACKEND_DIR = Path(__file__).resolve().parents[2]
_EXPECTED_TABLES = {
    "users",
    "assets",
    "scans",
    "findings",
    "kev_entries",
    "epss_scores",
    "feed_syncs",
}


@pytest.fixture(scope="module")
def migration_db_url() -> Iterator[str]:
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer(
        "postgres:17-alpine", driver="psycopg", dbname="riskreveal_migration_test"
    ) as postgres:
        yield postgres.get_connection_url()


def _alembic(url: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "DATABASE_URL": url}
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _tables(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return set(inspect(engine).get_table_names())
    finally:
        engine.dispose()


def test_upgrade_check_downgrade_upgrade(migration_db_url: str) -> None:
    up = _alembic(migration_db_url, "upgrade", "head")
    assert up.returncode == 0, up.stderr
    assert _tables(migration_db_url) >= _EXPECTED_TABLES

    check = _alembic(migration_db_url, "check")
    assert check.returncode == 0, check.stdout + check.stderr

    down = _alembic(migration_db_url, "downgrade", "base")
    assert down.returncode == 0, down.stderr
    assert not (_EXPECTED_TABLES & _tables(migration_db_url))

    again = _alembic(migration_db_url, "upgrade", "head")
    assert again.returncode == 0, again.stderr
