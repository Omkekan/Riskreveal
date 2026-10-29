"""Scan lifecycle states.

Kept in a module of its own (no SQLAlchemy import) so pure-Python code and
tests can use the enum without pulling in the ORM.
"""

from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
