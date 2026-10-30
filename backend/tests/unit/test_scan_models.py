"""Schema checks for the new tables. Needs SQLAlchemy but NOT a database.

Compiles the real PostgreSQL DDL and checks the constraint/index names the
naming convention in db/base.py should produce, so the Alembic migration
autogenerate creates is predictable.
"""

from __future__ import annotations

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from riskreveal.db.base import Base
from riskreveal.domain.assets.models import Asset
from riskreveal.domain.findings.models import Finding
from riskreveal.domain.scanning.models import Scan


def _ddl(model: type) -> str:
    table = model.__table__  # type: ignore[attr-defined]
    return str(CreateTable(table).compile(dialect=postgresql.dialect()))


def test_tables_are_registered_on_the_shared_metadata() -> None:
    assert {"users", "assets", "scans", "findings"} <= set(Base.metadata.tables)


def test_asset_schema() -> None:
    ddl = _ddl(Asset)
    assert "CREATE TABLE assets" in ddl
    assert "pk_assets" in ddl
    assert "uq_assets_owner_id_address" in ddl
    assert "fk_assets_owner_id_users" in ddl
    assert "ON DELETE CASCADE" in ddl


def test_scan_schema() -> None:
    ddl = _ddl(Scan)
    assert "CREATE TABLE scans" in ddl
    assert "ck_scans_status_valid" in ddl
    assert "'queued'" in ddl
    assert "JSONB" in ddl


def test_finding_schema() -> None:
    ddl = _ddl(Finding)
    assert "CREATE TABLE findings" in ddl
    for name in (
        "fk_findings_scan_id_scans",
        "fk_findings_asset_id_assets",
        "ck_findings_severity_valid",
        "ck_findings_confidence_valid",
        "ck_findings_status_valid",
        "ck_findings_source_valid",
    ):
        assert name in ddl


def test_foreign_key_columns_are_indexed() -> None:
    index_names = {ix.name for table in Base.metadata.tables.values() for ix in table.indexes}
    expected = {"ix_assets_owner_id", "ix_scans_owner_id", "ix_findings_scan_id"}
    assert expected | {"ix_findings_asset_id"} <= index_names


def test_repr_never_includes_raw_evidence() -> None:
    finding = Finding(title="Open port 80/tcp", severity="info", raw_evidence="SECRET-BANNER")
    assert "SECRET-BANNER" not in repr(finding)
