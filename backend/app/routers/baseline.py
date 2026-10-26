from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.models.baseline_policy import BaselinePolicy
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.baseline import (
    BaselinePolicyCreate,
    BaselinePolicyRead,
    BaselinePolicyUpdate,
    BaselineResultSummary,
    ControlResult,
)

router = APIRouter(prefix="/baseline", tags=["baseline"])


@router.get("/policies", response_model=List[BaselinePolicyRead])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(BaselinePolicy).order_by(BaselinePolicy.created_at.desc()))
    return result.scalars().all()


@router.post("/policies", response_model=BaselinePolicyRead, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: BaselinePolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    policy = BaselinePolicy(**payload.model_dump(), created_by=current_user.id)
    db.add(policy)
    await db.flush()
    return policy


@router.get("/policies/{policy_id}", response_model=BaselinePolicyRead)
async def get_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(BaselinePolicy).where(BaselinePolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    return policy


@router.put("/policies/{policy_id}", response_model=BaselinePolicyRead)
async def update_policy(
    policy_id: str,
    payload: BaselinePolicyUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    result = await db.execute(select(BaselinePolicy).where(BaselinePolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(policy, field, value)
    await db.flush()
    return policy


@router.get("/results", response_model=BaselineResultSummary)
async def get_baseline_results(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return the latest baseline assessment results (stub)."""
    policy_result = await db.execute(
        select(BaselinePolicy).where(BaselinePolicy.is_active == True).limit(1)  # noqa: E712
    )
    policy = policy_result.scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active baseline policy found",
        )

    # Stub result — real assessment via POST /assess/{scan_job_id}
    controls = policy.controls or []
    return BaselineResultSummary(
        policy_id=policy.id,
        policy_name=policy.name,
        scan_job_id="",
        total_controls=len(controls),
        passed=0,
        failed=0,
        unknown=len(controls),
        compliance_percentage=0.0,
        results=[
            ControlResult(
                control_id=c.get("id", str(i)),
                title=c.get("title", f"Control {i}"),
                result="unknown",
                evidence=None,
                last_checked=datetime.now(timezone.utc),
            )
            for i, c in enumerate(controls)
        ],
        assessed_at=datetime.now(timezone.utc),
    )


@router.post("/assess/{scan_job_id}", response_model=BaselineResultSummary)
async def assess_baseline(
    scan_job_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin", "analyst"])),
):
    """Run baseline assessment against a completed scan job (stub)."""
    scan_result = await db.execute(select(ScanJob).where(ScanJob.id == scan_job_id))
    scan_job = scan_result.scalar_one_or_none()
    if not scan_job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    policy_result = await db.execute(
        select(BaselinePolicy).where(BaselinePolicy.is_active == True).limit(1)  # noqa: E712
    )
    policy = policy_result.scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active baseline policy found",
        )

    controls = policy.controls or []
    return BaselineResultSummary(
        policy_id=policy.id,
        policy_name=policy.name,
        scan_job_id=scan_job_id,
        total_controls=len(controls),
        passed=0,
        failed=0,
        unknown=len(controls),
        compliance_percentage=0.0,
        results=[
            ControlResult(
                control_id=c.get("id", str(i)),
                title=c.get("title", f"Control {i}"),
                result="unknown",
                evidence="Requires Windows remote assessment to evaluate.",
                last_checked=datetime.now(timezone.utc),
            )
            for i, c in enumerate(controls)
        ],
        assessed_at=datetime.now(timezone.utc),
    )
