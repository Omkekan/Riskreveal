"""User service: registration, authentication, and token issuance.

Two security properties are enforced here rather than left to callers:

1. **No timing oracle on login.** ``authenticate`` always performs exactly
   one Argon2 verification, against a throwaway hash when the email doesn't
   exist. Skipping the hash for unknown emails would make "no such user"
   measurably faster than "wrong password" and let an attacker enumerate
   registered addresses (see the note in ``core/security.py``).
2. **One generic failure.** Unknown email, wrong password, and disabled
   account all raise the same ``InvalidCredentialsError``; the route turns
   it into one identical 401.

Known, accepted trade-off: ``register_user`` *does* reveal that an email is
taken (HTTP 409). Hiding that properly needs an email-verification flow, which
doesn't exist yet.
"""

from __future__ import annotations

import secrets
import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from riskreveal.config import get_settings
from riskreveal.core.security import (
    TokenError,
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from riskreveal.domain.users import repository as user_repository
from riskreveal.domain.users.models import User
from riskreveal.domain.users.schemas import TokenPair, normalize_email

# Verified against when the email doesn't exist, so both login paths cost the
# same. Random, never stored, never matches a real password. Computed once at
# import (a one-time ~tens-of-ms cost) so the first unknown-email login isn't
# slower than the rest.
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


class EmailAlreadyRegisteredError(Exception):
    """An account with this email already exists."""


class InvalidCredentialsError(Exception):
    """Wrong email/password, disabled account, or an unusable refresh token."""


def register_user(
    db: Session, *, email: str, password: str, full_name: str | None = None
) -> User:
    normalized = normalize_email(email)
    if user_repository.get_by_email(db, normalized) is not None:
        raise EmailAlreadyRegisteredError

    user = User(
        email=normalized,
        hashed_password=hash_password(password),
        full_name=full_name,
    )
    try:
        user_repository.add(db, user)
        db.commit()
    except IntegrityError as exc:
        # Two simultaneous registrations for the same email both pass the
        # lookup above; the unique index is what actually decides the winner.
        db.rollback()
        raise EmailAlreadyRegisteredError from exc
    return user


def authenticate(db: Session, *, email: str, password: str) -> User:
    user = user_repository.get_by_email(db, normalize_email(email))

    hash_to_check = user.hashed_password if user is not None else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(password, hash_to_check)

    if user is None or not password_ok or not user.is_active:
        raise InvalidCredentialsError

    # Transparently upgrade hashes made with weaker parameters than today's.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)
        db.commit()
    return user


def issue_token_pair(user_id: uuid.UUID) -> TokenPair:
    settings = get_settings()
    return TokenPair(
        access_token=create_access_token(user_id),
        refresh_token=create_refresh_token(user_id),
        expires_in=settings.access_token_expire_minutes * 60,
    )


def refresh_session(db: Session, *, refresh_token: str) -> TokenPair:
    """Exchange a valid refresh token for a new access + refresh pair.

    Note: tokens carry a ``jti`` but there is no revocation list yet, so an old
    refresh token stays usable until it expires. Add revocation/rotation
    tracking before this is exposed beyond development.
    """
    try:
        decoded = decode_token(refresh_token, expected_type=TokenType.REFRESH)
        user_id = uuid.UUID(decoded.subject)
    except (TokenError, ValueError) as exc:
        raise InvalidCredentialsError from exc

    user = user_repository.get_by_id(db, user_id)
    if user is None or not user.is_active:
        raise InvalidCredentialsError
    return issue_token_pair(user.id)
