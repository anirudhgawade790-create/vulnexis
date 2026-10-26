import json
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
    from app.services.scan_service import ScanService

    service = ScanService()
    return await service.list_scans(
        {"status": scan_status, "target_id": target_id, "page": page, "size": size}, db
    )


@router.post("/", response_model=ScanJobRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanJobCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"])),
):
    from app.services.scan_service import ScanService

    service = ScanService()
    try:
        return await service.create_scan(payload, current_user, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


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

    from app.services.scan_service import ScanService

    service = ScanService()
    await service.cancel_scan(scan_id, db)
    return {"message": "Scan cancelled"}


@router.get("/{scan_id}/progress")
async def scan_progress_sse(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Server-Sent Events stream for scan progress via Redis pub/sub."""
    from app.config import get_settings

    settings = get_settings()

    async def event_generator():
        import redis.asyncio as aioredis

        redis_client = aioredis.from_url(settings.redis_url, decode_responses=True)
        pubsub = redis_client.pubsub()
        channel = f"scan:{scan_id}:progress"
        await pubsub.subscribe(channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    yield f"data: {message['data']}\n\n"
                    data = json.loads(message["data"])
                    if data.get("progress") == 100 or data.get("phase") in (
                        "completed",
                        "failed",
                    ):
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
    from app.services.scan_service import ScanService

    service = ScanService()
    results = await service.get_scan_results(scan_id, db)
    if not results:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan job not found")
    return results


@router.get("/{scan_id}/compare/{prev_id}")
async def compare_scans(
    scan_id: str,
    prev_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    from app.services.change_detection import ChangeDetectionService

    service = ChangeDetectionService()
    try:
        return await service.compare_scans(scan_id, prev_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
