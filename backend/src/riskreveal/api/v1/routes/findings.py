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
from riskreveal.domain.findings.enrichment import attach_context
from riskreveal.domain.findings.enums import FindingSource, Severity
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
    source: Annotated[FindingSource | None, Query()] = None,
    kev: Annotated[
        bool | None, Query(description="Only (true) or never (false) KEV-listed.")
    ] = None,
    cve_id: Annotated[
        str | None, Query(pattern=r"^CVE-[0-9]{4}-[0-9]{4,10}$", max_length=19)
    ] = None,
    distro_packaged: Annotated[
        bool | None,
        Query(description="True: banner shows a distribution package (back-ports likely)."),
    ] = None,
) -> FindingPage:
    findings, total = repository.list_for_owner(
        db,
        current_user.id,
        scan_id=scan_id,
        asset_id=asset_id,
        severity=severity.value if severity is not None else None,
        source=source.value if source is not None else None,
        kev=kev,
        cve_id=cve_id,
        distro_packaged=distro_packaged,
        limit=page.limit,
        offset=page.offset,
    )
    return FindingPage(
        items=attach_context(db, [FindingRead.model_validate(f) for f in findings]),
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def read_finding(finding_id: uuid.UUID, current_user: CurrentUser, db: DbSession) -> FindingDetail:
    finding = repository.get_for_owner(db, finding_id, current_user.id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")
    return attach_context(db, [FindingDetail.model_validate(finding)])[0]
