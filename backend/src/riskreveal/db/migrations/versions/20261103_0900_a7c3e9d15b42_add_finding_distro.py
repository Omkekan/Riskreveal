"""add finding distro

Adds ``findings.distro``: the Linux distribution that packages the detected
software (ubuntu, debian, rhel ...), when the banner shows one. Distributions
back-port security fixes without changing the version number, so upstream CVE
matches against such a banner are likely false positives; a structured column
lets the API filter on it and a future risk scorer discount it.

Existing findings keep NULL ("none detected"). Re-run ``match-scan`` for a scan
to refresh its version_match findings with the marker.

Revision ID: a7c3e9d15b42
Revises: 4f8a2c61d0b7
Create Date: 2026-11-03 09:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a7c3e9d15b42'
down_revision: str | None = '4f8a2c61d0b7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('distro', sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column('findings', 'distro')
