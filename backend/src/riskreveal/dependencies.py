"""Shared FastAPI dependencies.

``CurrentUser`` is the one to use on any route that needs a logged-in user::

    @router.get("/something")
    def something(current_user: CurrentUser) -> ...: ...

Every failure mode (no header, bad/expired token, a refresh token presented
as an access token, deleted or disabled user) produces the same 401, so the
response never tells a caller *why* authentication failed.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from riskreveal.core.security import TokenError, TokenType, decode_token
from riskreveal.db.session import get_db
from riskreveal.domain.users import repository as user_repository
from riskreveal.domain.users.models import User

# auto_error=False so a missing header goes through our own 401 (with the
# WWW-Authenticate header) instead of FastAPI's default 403.
bearer_scheme = HTTPBearer(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None:
        raise _unauthorized()

    try:
        decoded = decode_token(credentials.credentials, expected_type=TokenType.ACCESS)
        user_id = uuid.UUID(decoded.subject)
    except (TokenError, ValueError) as exc:
        raise _unauthorized() from exc

    user = user_repository.get_by_id(db, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
