"""Database engine and session management.

Uses synchronous SQLAlchemy sessions deliberately, not async. FastAPI runs
sync dependencies in a threadpool automatically, so this costs little for
the API — and it means the API and the Celery workers (which are
synchronous by nature) share exactly one data-access pattern instead of
maintaining both an async ORM layer for the API and a separate sync one
for the workers. Revisit this only if measured request latency under real
load makes it worth the added complexity, not before.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from riskreveal.config import get_settings

logger = logging.getLogger("riskreveal.db")


@lru_cache
def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine (created once, reused).

    `pool_pre_ping=True` makes the pool test a connection with a cheap
    `SELECT 1` before handing it out, so a connection that Postgres (or a
    firewall/NAT) silently dropped while idle gets transparently replaced
    instead of surfacing as a confusing mid-request error.
    """
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        # Only ever echo SQL in development, and only when DEBUG is also
        # true — this must never be on in production, since logged SQL can
        # include parameter values from sensitive queries.
        echo=settings.is_development and settings.debug,
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    """Return the process-wide session factory (created once, reused)."""
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a `Session`, guaranteed to be closed after.

    Deliberately does **not** auto-commit. Committing happens inside the
    service-layer function that did the work, as its last successful
    step — so a function that raises partway through a multi-step write
    leaves nothing committed, rather than this dependency's `finally`
    block committing whatever partial state exists. (The original
    codebase's scan task did exactly that — a bare `finally: commit()`
    around the whole task — which is how a failed scan could still end up
    with half its findings saved.) On any exception, this dependency rolls
    back explicitly before re-raising, so a forgotten rollback in the
    calling code can't leave the session in a broken, half-transacted
    state for whatever runs next on it.
    """
    session_factory = get_sessionmaker()
    db = session_factory()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_database_connection() -> bool:
    """Lightweight connectivity check for health endpoints.

    Returns `False` on any database error rather than raising, so a
    caller like `GET /healthz` can decide how to respond (a 503, a
    degraded-status payload) instead of the health check itself crashing
    with a 500 — which would be a strange way to report "the database is
    unreachable."
    """
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        logger.warning("Database connectivity check failed.", exc_info=True)
        return False