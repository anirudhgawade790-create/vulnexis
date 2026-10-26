from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.models.scan_job import ScanJob
from app.models.user import User
from app.schemas.scan import ScanJobCreate, ScanJobRead, ScanResultsSummary

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/", response_model=List[ScanJobRead])
async def list_scans(
    scan_status: Optional[str] = Query(None, alias="status"),
    target_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(ScanJob)
    if scan_status:
        query = query.where(ScanJob.status == scan_status)
    if target_id:
        query = query.where(ScanJob.target_id == target_id)
    query = query.order_by(ScanJob.created_at.desc()).offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/", response_model=ScanJobRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    scan_job = ScanJob(
        target_id=payload.target_id,
        scan_type=payload.scan_type,
        options=payload.options,
        started_by=current_user.id,
        status="queued",
    )
    db.add(scan_job)
    await db.flush()
    # In full implementation, dispatch to Celery worker here
    return scan_job


@router.get("/{scan_id}", response_model=ScanJobRead)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    return scan


@router.delete("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin", "analyst"])),
):
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    if scan.status not in ("queued", "running"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel a scan with status '{scan.status}'",
        )
    scan.status = "cancelled"
    await db.flush()
    return {"message": "Scan cancelled"}


@router.get("/{scan_id}/progress")
async def scan_progress_sse(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Server-Sent Events stream for scan progress."""
    import asyncio
    import json

    import redis.asyncio as aioredis

    from app.config import get_settings

    settings = get_settings()

    async def event_generator():
        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        pubsub = redis_client.pubsub()
        channel = f"scan:{scan_id}:progress"
        await pubsub.subscribe(channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield f"data: {message['data']}\n\n"
                    data = json.loads(message["data"])
                    if data.get("progress") == 100 or data.get("phase") in ("completed", "failed"):
                        break
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()
            await redis_client.aclose()

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.get("/{scan_id}/results", response_model=ScanResultsSummary)
async def get_scan_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    from sqlalchemy import func

    from app.models.asset import Asset
    from app.models.finding import Finding

    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")

    assets_count = (
        await db.execute(select(func.count(Asset.id)).where(Asset.scan_job_id == scan_id))
    ).scalar_one()

    windows_count = (
        await db.execute(
            select(func.count(Asset.id)).where(
                Asset.scan_job_id == scan_id, Asset.is_windows == True  # noqa: E712
            )
        )
    ).scalar_one()

    findings_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_job_id == scan_id)
        .group_by(Finding.severity)
    )
    findings_by_severity = {row[0]: row[1] for row in findings_result}

    type_result = await db.execute(
        select(Finding.finding_type, func.count(Finding.id))
        .where(Finding.scan_job_id == scan_id)
        .group_by(Finding.finding_type)
    )
    findings_by_type = {row[0]: row[1] for row in type_result}

    duration = None
    if scan.started_at and scan.completed_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()

    return ScanResultsSummary(
        scan_job_id=scan_id,
        assets_found=assets_count,
        windows_assets=windows_count,
        total_open_ports=0,
        findings_by_severity=findings_by_severity,
        findings_by_type=findings_by_type,
        scan_duration_seconds=duration,
    )


@router.get("/{scan_id}/compare/{prev_id}")
async def compare_scans(
    scan_id: str,
    prev_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    from app.schemas.scan import ChangeDetectionReport

    for sid in (scan_id, prev_id):
        r = await db.execute(select(ScanJob).where(ScanJob.id == sid))
        if not r.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan job {sid} not found",
            )

    return ChangeDetectionReport(
        scan_job_id=scan_id,
        previous_scan_job_id=prev_id,
        new_findings=[],
        resolved_findings=[],
        new_assets=[],
        removed_assets=[],
        new_ports=[],
        closed_ports=[],
        risk_delta=0.0,
    )
