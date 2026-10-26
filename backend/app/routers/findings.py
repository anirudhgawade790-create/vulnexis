from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingRead, FindingStatusUpdate, RemediationDetail

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/", response_model=List[FindingRead])
async def list_findings(
    severity: Optional[str] = Query(None),
    finding_type: Optional[str] = Query(None),
    finding_status: Optional[str] = Query(None, alias="status"),
    asset_id: Optional[str] = Query(None),
    scan_job_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Finding)
    if severity:
        query = query.where(Finding.severity == severity)
    if finding_type:
        query = query.where(Finding.finding_type == finding_type)
    if finding_status:
        query = query.where(Finding.status == finding_status)
    if asset_id:
        query = query.where(Finding.asset_id == asset_id)
    if scan_job_id:
        query = query.where(Finding.scan_job_id == scan_job_id)
    query = query.order_by(Finding.risk_score.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{finding_id}", response_model=FindingRead)
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding


@router.patch("/{finding_id}/status", response_model=FindingRead)
async def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.status = payload.status
    if payload.resolution_notes:
        finding.resolution_notes = payload.resolution_notes
    if payload.status == "remediated":
        finding.resolved_at = datetime.now(timezone.utc)
    await db.flush()
    return finding


@router.get("/{finding_id}/remediation", response_model=RemediationDetail)
async def get_remediation(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    steps = finding.remediation_steps or []
    ps_examples = [
        s.get("command", "") for s in steps if s.get("command") and "PowerShell" in s.get("command", "")
    ]

    return RemediationDetail(
        finding_id=finding.id,
        title=finding.title,
        plain_explanation=finding.business_impact or "Review the finding evidence for details.",
        technical_explanation=finding.evidence,
        potential_impact=finding.business_impact or "Impact not assessed.",
        recommended_fix=finding.recommended_action or "Refer to the remediation steps.",
        required_permissions="Administrator" if finding.severity in ("critical", "high") else "Standard",
        estimated_effort="high" if finding.severity == "critical" else "medium",
        verification_steps=[s.get("step", "") for s in steps],
        documentation_links=[],
        rollback_considerations="Review changes before applying. Test in non-production first.",
        powershell_examples=ps_examples,
    )


@router.post("/{finding_id}/assign", response_model=FindingRead)
async def assign_finding(
    finding_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.assigned_to = payload.get("user_id")
    await db.flush()
    return finding
