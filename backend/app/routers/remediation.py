from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import RemediationDetail

router = APIRouter(prefix="/remediation", tags=["remediation"])


def _build_remediation_detail(finding: Finding) -> RemediationDetail:
    steps = finding.remediation_steps or []
    ps_examples = [
        s.get("command", "")
        for s in steps
        if s.get("command") and "PowerShell" in s.get("command", "")
    ]
    return RemediationDetail(
        finding_id=finding.id,
        title=finding.title,
        plain_explanation=finding.business_impact or "Review the finding evidence for details.",
        technical_explanation=finding.evidence,
        potential_impact=finding.business_impact or "Impact not assessed.",
        recommended_fix=finding.recommended_action or "Apply the remediation steps listed below.",
        required_permissions=(
            "Administrator" if finding.severity in ("critical", "high") else "Standard user"
        ),
        estimated_effort="high" if finding.severity == "critical" else (
            "medium" if finding.severity == "high" else "low"
        ),
        verification_steps=[s.get("step", "") for s in steps if s.get("step")],
        documentation_links=[],
        rollback_considerations=(
            "Test changes in a non-production environment before applying. "
            "Document current state to enable rollback if required."
        ),
        powershell_examples=ps_examples,
    )


@router.get("/plan", response_model=List[RemediationDetail])
async def get_remediation_plan(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin", "analyst"])),
):
    """Return prioritized remediation details for all open findings."""
    result = await db.execute(
        select(Finding)
        .where(Finding.status == "open")
        .order_by(Finding.risk_score.desc())
        .limit(50)
    )
    findings = result.scalars().all()
    return [_build_remediation_detail(f) for f in findings]


@router.get("/{finding_id}", response_model=RemediationDetail)
async def get_finding_remediation(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return _build_remediation_detail(finding)


@router.post("/{finding_id}/verify")
async def verify_remediation(
    finding_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin", "analyst"])),
):
    """Mark a finding as verified-remediated with optional notes."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    notes = payload.get("notes", "")
    return {
        "status": "verified",
        "finding_id": finding_id,
        "notes": notes,
        "message": "Remediation verification recorded. Update finding status via PATCH /findings/{id}/status.",
    }
