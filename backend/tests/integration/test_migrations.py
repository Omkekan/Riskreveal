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
from sqlalchemy import create_engine, inspect, text

BACKEND_DIR = Path(__file__).resolve().parents[2]
_EXPECTED_TABLES = {
    "users",
    "assets",
    "scans",
    "findings",
    "kev_entries",
    "epss_scores",
    "feed_syncs",
    "cves",
    "cve_ranges",
    "cve_syncs",
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


def _constraint_definition(url: str, name: str) -> str:
    """The live CHECK text. ``alembic check`` cannot see CHECK constraints, so the
    hand-written part of the version_match migration is tested directly."""
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return str(
                conn.execute(
                    text("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = :n"),
                    {"n": name},
                ).scalar_one()
            )
    finally:
        engine.dispose()


def _finding_columns(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        return {c["name"] for c in inspect(engine).get_columns("findings")}
    finally:
        engine.dispose()


def test_upgrade_check_downgrade_upgrade(migration_db_url: str) -> None:
    up = _alembic(migration_db_url, "upgrade", "head")
    assert up.returncode == 0, up.stderr
    assert _tables(migration_db_url) >= _EXPECTED_TABLES

    check = _alembic(migration_db_url, "check")
    assert check.returncode == 0, check.stdout + check.stderr

    # The CVE migration, one step: version_match is allowed after it, refused before it.
    check_name = "ck_findings_source_valid"
    assert "version_match" in _constraint_definition(migration_db_url, check_name)
    assert {"cve_id", "extra_info"} <= _finding_columns(migration_db_url)
    step_down = _alembic(migration_db_url, "downgrade", "9c4e7e871afa")
    assert step_down.returncode == 0, step_down.stderr
    assert "version_match" not in _constraint_definition(migration_db_url, check_name)
    assert not {"cve_id", "extra_info"} & _finding_columns(migration_db_url)
    step_up = _alembic(migration_db_url, "upgrade", "head")
    assert step_up.returncode == 0, step_up.stderr

    down = _alembic(migration_db_url, "downgrade", "base")
    assert down.returncode == 0, down.stderr
    assert not (_EXPECTED_TABLES & _tables(migration_db_url))

    again = _alembic(migration_db_url, "upgrade", "head")
    assert again.returncode == 0, again.stderr
