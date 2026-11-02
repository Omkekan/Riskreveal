"""add cve store and version match findings

Adds the NVD CVE store (``cves``, ``cve_ranges``, ``cve_syncs``), the findings
columns ``cve_id`` and ``extra_info``, and allows ``source = 'version_match'``.

Hand-written: autogenerate cannot see CHECK-constraint changes, so the two
CHECK edits at the end of ``upgrade`` are the part to review most carefully
(``test_migrations.py`` checks them against the live database).

Revision ID: 4f8a2c61d0b7
Revises: 9c4e7e871afa
Create Date: 2026-10-31 10:30:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '4f8a2c61d0b7'
down_revision: str | None = '9c4e7e871afa'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CVE_ID_REGEX = "^CVE-[0-9]{4}-[0-9]{4,10}$"


def upgrade() -> None:
    op.create_table('cves',
    sa.Column('cve_id', sa.String(length=19), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cvss_severity', sa.String(length=16), nullable=True),
    sa.Column('cvss_version', sa.String(length=8), nullable=True),
    sa.Column('cvss_vector', sa.String(length=128), nullable=True),
    sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_modified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("cve_id ~ '" + CVE_ID_REGEX + "'", name=op.f('ck_cves_cve_id_format')),
    sa.CheckConstraint('cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)', name=op.f('ck_cves_cvss_score_range')),
    sa.PrimaryKeyConstraint('cve_id', name=op.f('pk_cves'))
    )
    op.create_table('cve_syncs',
    sa.Column('cpe_name', sa.String(length=255), nullable=False),
    sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('found', sa.Boolean(), nullable=False),
    sa.Column('cve_count', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('cpe_name', name=op.f('pk_cve_syncs'))
    )
    op.create_table('cve_ranges',
    sa.Column('cve_id', sa.String(length=19), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('part', sa.String(length=1), nullable=False),
    sa.Column('vendor', sa.String(length=128), nullable=False),
    sa.Column('product', sa.String(length=128), nullable=False),
    sa.Column('cpe_version', sa.String(length=64), nullable=False),
    sa.Column('cpe_update', sa.String(length=64), nullable=False),
    sa.Column('start_including', sa.String(length=64), nullable=True),
    sa.Column('start_excluding', sa.String(length=64), nullable=True),
    sa.Column('end_including', sa.String(length=64), nullable=True),
    sa.Column('end_excluding', sa.String(length=64), nullable=True),
    sa.Column('conditional', sa.Boolean(), nullable=False),
    sa.Column('requires', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.ForeignKeyConstraint(['cve_id'], ['cves.cve_id'], name=op.f('fk_cve_ranges_cve_id_cves'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('cve_id', 'position', name=op.f('pk_cve_ranges'))
    )
    op.create_index('ix_cve_ranges_product_key', 'cve_ranges', ['part', 'vendor', 'product'], unique=False)

    op.add_column('findings', sa.Column('extra_info', sa.String(length=255), nullable=True))
    op.add_column('findings', sa.Column('cve_id', sa.String(length=19), nullable=True))
    op.create_index(op.f('ix_findings_cve_id'), 'findings', ['cve_id'], unique=False)
    op.create_check_constraint(
        op.f('ck_findings_cve_id_format'),
        'findings',
        "cve_id IS NULL OR cve_id ~ '" + CVE_ID_REGEX + "'",
    )
    op.drop_constraint(op.f('ck_findings_source_valid'), 'findings', type_='check')
    op.create_check_constraint(
        op.f('ck_findings_source_valid'), 'findings', "source IN ('nmap', 'version_match')"
    )


def downgrade() -> None:
    # The narrower CHECK would reject these rows, so they must go first.
    op.execute("DELETE FROM findings WHERE source = 'version_match'")
    op.drop_constraint(op.f('ck_findings_source_valid'), 'findings', type_='check')
    op.create_check_constraint(op.f('ck_findings_source_valid'), 'findings', "source IN ('nmap')")
    op.drop_constraint(op.f('ck_findings_cve_id_format'), 'findings', type_='check')
    op.drop_index(op.f('ix_findings_cve_id'), table_name='findings')
    op.drop_column('findings', 'cve_id')
    op.drop_column('findings', 'extra_info')

    op.drop_index('ix_cve_ranges_product_key', table_name='cve_ranges')
    op.drop_table('cve_ranges')
    op.drop_table('cve_syncs')
    op.drop_table('cves')
