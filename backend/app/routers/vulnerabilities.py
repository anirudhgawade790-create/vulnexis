from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.vulnerability import VulnerabilityRead, VulnSyncResponse

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("/kev", response_model=List[VulnerabilityRead])
async def list_kev(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return all CISA Known Exploited Vulnerabilities."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.is_kev == True).order_by(  # noqa: E712
            Vulnerability.kev_date_added.desc()
        )
    )
    return result.scalars().all()


@router.get("/", response_model=List[VulnerabilityRead])
async def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    is_kev: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Vulnerability)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if is_kev is not None:
        query = query.where(Vulnerability.is_kev == is_kev)
    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{vuln_id}", response_model=VulnerabilityRead)
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return vuln


@router.post("/sync", response_model=VulnSyncResponse)
async def sync_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    """Trigger synchronization with NVD and CISA KEV (stub — real sync in worker)."""
    return VulnSyncResponse(
        synced_count=0,
        kev_count=0,
        message="Sync queued. Check worker logs for progress.",
    )
