"""Password hashing and JWT token issuance/verification.

Password hashing uses Argon2id (via argon2-cffi) — the current
OWASP-recommended default for new applications, and a deliberate
replacement for the original codebase's Bcrypt.

JWTs are used for both access and refresh tokens, distinguished by a
``type`` claim that's checked on decode — not just issued and trusted.
Without that check, a leaked refresh token could be replayed directly as
an access token, since both are signed with the same secret and would
otherwise look identical to the verifier.

Note for whoever builds the login route on top of this module: calling
``verify_password`` only when a user is found, and skipping it entirely
when the email doesn't exist, creates a timing difference (hashing is
deliberately slow; a failed DB lookup is fast) that lets an attacker
enumerate valid emails by measuring response time. The login flow should
call ``verify_password`` against a dummy hash even when no user was
found, so both paths take comparable time.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from riskreveal.config import get_settings

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage. Never store the plaintext."""
    return _password_hasher.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash.

    Returns False for any verification failure (wrong password, a
    corrupted hash, a hash from an unsupported algorithm) rather than
    raising — callers need to know whether the password matched, not
    why it didn't.
    """
    try:
        _password_hasher.verify(hashed_password, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return True


def needs_rehash(hashed_password: str) -> bool:
    """True if a stored hash used weaker-than-current cost parameters.

    Lets a login flow transparently upgrade a user's stored hash to the
    current cost parameters the next time they log in successfully,
    without forcing a password reset.
    """
    return bool(_password_hasher.check_needs_rehash(hashed_password))


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


class TokenError(Exception):
    """Raised for any invalid, expired, malformed, or wrong-type token."""


@dataclass(frozen=True)
class DecodedToken:
    subject: str
    """The user ID the token was issued for, as a string."""
    token_type: TokenType
    expires_at: datetime
    jti: str
    """Unique token ID — not used for revocation yet, but present now so
    a revocation list can be added later without reissuing every token
    format again."""


def create_access_token(user_id: uuid.UUID) -> str:
    settings = get_settings()
    return _create_token(
        user_id, TokenType.ACCESS, timedelta(minutes=settings.access_token_expire_minutes)
    )


def create_refresh_token(user_id: uuid.UUID) -> str:
    settings = get_settings()
    return _create_token(
        user_id, TokenType.REFRESH, timedelta(days=settings.refresh_token_expire_days)
    )


def _create_token(user_id: uuid.UUID, token_type: TokenType, expires_in: timedelta) -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "type": token_type.value,
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        payload, settings.jwt_secret_key.get_secret_value(), algorithm=settings.jwt_algorithm
    )


def decode_token(token: str, *, expected_type: TokenType) -> DecodedToken:
    """Decode and validate a JWT, enforcing the expected token type.

    Raises :class:`TokenError` for anything wrong with the token:
    expired, malformed, wrong signature, missing claims, or the wrong
    type presented (a refresh token where an access token was expected,
    or vice versa).
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError as exc:
        raise TokenError("Invalid or expired token.") from exc

    try:
        token_type = TokenType(payload["type"])
        subject: str = payload["sub"]
        jti: str = payload["jti"]
        expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)
    except (KeyError, ValueError) as exc:
        raise TokenError("Token is missing required claims.") from exc

    if token_type is not expected_type:
        raise TokenError(f"Expected a {expected_type.value} token, got a {token_type.value} token.")

    return DecodedToken(subject=subject, token_type=token_type, expires_at=expires_at, jti=jti)