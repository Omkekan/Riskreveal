"""Authentication routes: register, login, refresh, and "who am I".

Deliberately NO ``from __future__ import annotations`` in this module.
slowapi's ``@limiter.limit`` wraps each endpoint in a function defined in
slowapi's own module, and FastAPI can resolve string annotations against the
wrapper's globals instead of this module's. Plain (non-postponed) annotations
avoid that whole class of start-up problem.

Error bodies here use FastAPI's default ``{"detail": ...}`` shape. The planned
``core/exceptions.py`` (RFC 9457 problem details) will unify this later.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from riskreveal.core.rate_limit import auth_limit, limiter
from riskreveal.db.session import get_db
from riskreveal.dependencies import CurrentUser
from riskreveal.domain.users import service
from riskreveal.domain.users.schemas import (
    LoginRequest,
    RefreshRequest,
    TokenPair,
    UserCreate,
    UserRead,
)

router = APIRouter(prefix="/auth", tags=["auth"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit(auth_limit)
def register(request: Request, payload: UserCreate, db: DbSession) -> UserRead:
    try:
        user = service.register_user(
            db,
            email=payload.email,
            password=payload.password,
            full_name=payload.full_name,
        )
    except service.EmailAlreadyRegisteredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        ) from exc
    return UserRead.model_validate(user)


@router.post("/login", response_model=TokenPair)
@limiter.limit(auth_limit)
def login(request: Request, payload: LoginRequest, db: DbSession) -> TokenPair:
    try:
        user = service.authenticate(db, email=payload.email, password=payload.password)
    except service.InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return service.issue_token_pair(user.id)


@router.post("/refresh", response_model=TokenPair)
@limiter.limit(auth_limit)
def refresh(request: Request, payload: RefreshRequest, db: DbSession) -> TokenPair:
    try:
        return service.refresh_session(db, refresh_token=payload.refresh_token)
    except service.InvalidCredentialsError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/me", response_model=UserRead)
def read_me(current_user: CurrentUser) -> UserRead:
    return UserRead.model_validate(current_user)
