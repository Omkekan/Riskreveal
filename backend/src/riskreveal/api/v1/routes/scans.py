"""Scan routes. Every query is scoped to the authenticated user.

Deliberately NO ``from __future__ import annotations`` (see routes/auth.py):
slowapi wraps endpoints, and FastAPI must resolve plain annotations.

A scan that belongs to someone else answers 404, the same as one that does
not exist, so ids cannot be probed.
"""

import uuid
from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from riskreveal.config import Settings, get_settings
from riskreveal.core.pagination import Pagination
from riskreveal.core.rate_limit import limiter, scan_limit
from riskreveal.db.session import get_db
from riskreveal.dependencies import CurrentUser
from riskreveal.domain.scanning import repository, service
from riskreveal.domain.scanning.schemas import ScanCreate, ScanPage, ScanRead
from riskreveal.domain.scanning.scope_policy import ScopeError
from riskreveal.tasks.scan_tasks import dispatch_scan

router = APIRouter(prefix="/scans", tags=["scans"])

DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings)]


def get_scan_dispatcher() -> Callable[[uuid.UUID], None]:
    """Dependency so tests can replace the queue with a recorder."""
    return dispatch_scan


Dispatcher = Annotated[Callable[[uuid.UUID], None], Depends(get_scan_dispatcher)]


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
@limiter.limit(scan_limit)
def create_scan(
    request: Request,
    payload: ScanCreate,
    current_user: CurrentUser,
    db: DbSession,
    settings: AppSettings,
    dispatch: Dispatcher,
) -> ScanRead:
    try:
        scan = service.create_scan(
            db,
            owner_id=current_user.id,
            raw_target=payload.target,
            profile_name=payload.profile,
            settings=settings,
        )
    except ScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    except service.TooManyActiveScansError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except service.ScanRejectedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    try:
        dispatch(scan.id)
    except Exception as exc:  # broker errors vary (kombu, redis, OS); all mean "not queued"
        service.mark_queue_failed(db, scan.id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The scan queue is unavailable. Please try again later.",
        ) from exc
    return ScanRead.model_validate(scan)


@router.get("", response_model=ScanPage)
def list_scans(current_user: CurrentUser, db: DbSession, page: Pagination) -> ScanPage:
    scans, total = repository.list_for_owner(
        db, current_user.id, limit=page.limit, offset=page.offset
    )
    return ScanPage(
        items=[ScanRead.model_validate(s) for s in scans],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{scan_id}", response_model=ScanRead)
def read_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> ScanRead:
    scan = repository.get_for_owner(db, scan_id, current_user.id)
    if scan is None:
        raise _not_found()
    return ScanRead.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanRead)
def cancel_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> ScanRead:
    try:
        scan = service.cancel_scan(db, scan_id=scan_id, owner_id=current_user.id)
    except service.ScanNotCancellableError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if scan is None:
        raise _not_found()
    return ScanRead.model_validate(scan)
