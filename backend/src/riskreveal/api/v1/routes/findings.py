"""Finding routes (read-only), scoped to the authenticated user.

No ``from __future__ import annotations``, matching the other route modules.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from riskreveal.core.pagination import Pagination
from riskreveal.db.session import get_db
from riskreveal.dependencies import CurrentUser
from riskreveal.domain.findings import repository
from riskreveal.domain.findings.enums import Severity
from riskreveal.domain.findings.schemas import FindingDetail, FindingPage, FindingRead

router = APIRouter(prefix="/findings", tags=["findings"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=FindingPage)
def list_findings(
    current_user: CurrentUser,
    db: DbSession,
    page: Pagination,
    scan_id: Annotated[uuid.UUID | None, Query()] = None,
    asset_id: Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[Severity | None, Query()] = None,
) -> FindingPage:
    findings, total = repository.list_for_owner(
        db,
        current_user.id,
        scan_id=scan_id,
        asset_id=asset_id,
        severity=severity.value if severity is not None else None,
        limit=page.limit,
        offset=page.offset,
    )
    return FindingPage(
        items=[FindingRead.model_validate(f) for f in findings],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def read_finding(finding_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> FindingDetail:
    finding = repository.get_for_owner(db, finding_id, current_user.id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return FindingDetail.model_validate(finding)
