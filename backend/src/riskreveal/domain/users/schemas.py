"""Request/response schemas for the users domain.

Validation lives here, at the edge, so the service layer can assume it is
handed clean values:

- Emails are trimmed and lower-cased, and capped at 254 characters to match
  the ``users.email`` column (``String(254)``). Without the cap, an overlong
  address would pass validation and then fail inside the database as a 500.
- Passwords are *not* trimmed or otherwise altered. The upper bound exists so
  a multi-megabyte "password" can't be used to burn CPU in Argon2.
- ``extra="forbid"`` on inputs: unknown fields (``is_active``, ``id`` ...)
  are rejected with a 422 rather than silently ignored.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MAX_EMAIL_LENGTH = 254


def normalize_email(value: str) -> str:
    """Canonical form used for storage and lookup."""
    return value.strip().lower()


def _clean_email(value: str) -> str:
    cleaned = normalize_email(value)
    if len(cleaned) > MAX_EMAIL_LENGTH:
        raise ValueError(f"Email must be at most {MAX_EMAIL_LENGTH} characters.")
    return cleaned


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return _clean_email(v)

    @field_validator("full_name")
    @classmethod
    def _blank_name_to_none(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    # No minimum length here on purpose: login should say "wrong credentials",
    # not leak the password policy. The maximum still bounds hashing cost.
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return _clean_email(v)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=4096)


class UserRead(BaseModel):
    """What the API returns about a user. Never includes the password hash."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    full_name: str | None
    is_active: bool
    created_at: datetime


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer" # noqa: S105
    expires_in: int
    """Access-token lifetime in seconds."""
