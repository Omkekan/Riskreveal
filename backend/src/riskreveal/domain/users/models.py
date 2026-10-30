"""The User model.

Deliberately minimal for this stage of the build: no organization_id, no
roles. Per the revised build order, a full multi-tenant RBAC layer is
built later, once there's a real working vertical slice (register, log
in, scan, see a finding) to anchor those decisions against — adding
organizations now, before anything real exists yet, would mean
designing RBAC in the abstract. ``is_active`` is included anyway since
it costs nothing now and avoids an extra migration later for something
every auth system eventually needs (disabling an account without
deleting it).
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from riskreveal.db.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    """A RiskReveal account.

    Primary key is a UUID, not an auto-incrementing integer — generated
    in Python (``default=uuid.uuid4``) rather than by the database, so
    it's portable across any future database migration and doesn't
    depend on a Postgres-specific generation function. A UUID primary
    key also means user IDs aren't sequentially enumerable, which
    matters once API endpoints like ``GET /users/{id}`` exist: an
    integer ID invites a trivial "try id=1, id=2, ..." enumeration that
    a random UUID doesn't.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # unique=True + index=True together produce a single UNIQUE INDEX
    # (named ix_users_email by the naming convention in db/base.py) rather
    # than a separate UniqueConstraint plus a separate plain index — one
    # object does both jobs (fast lookup by email, and uniqueness) instead
    # of two redundant ones. Confirmed by compiling the actual DDL, not
    # assumed.
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        # Deliberately excludes hashed_password — a repr is the kind of
        # thing that ends up in a log line or an error message without
        # anyone intending it to.
        return f"User(id={self.id!r}, email={self.email!r}, is_active={self.is_active!r})"