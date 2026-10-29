"""Data access for users.

Only queries and ``add`` live here. Nothing in this module commits: the
service layer decides when a unit of work is complete (see ``db/session.py``
for why ``get_db`` deliberately does not auto-commit).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from riskreveal.domain.users.models import User


def get_by_id(db: Session, user_id: uuid.UUID) -> User | None:
    return db.get(User, user_id)


def get_by_email(db: Session, email: str) -> User | None:
    """Look up by already-normalized (trimmed, lower-case) email."""
    return db.scalar(select(User).where(User.email == email))


def add(db: Session, user: User) -> User:
    """Stage a new user and flush, so a unique-email violation raises here."""
    db.add(user)
    db.flush()
    return user
