from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.user import User
from app.schemas.asset import AssetRead, AssetUpdate
from app.schemas.finding import FindingRead

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/", response_model=List[AssetRead])
async def list_assets(
    scan_job_id: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    is_windows: Optional[bool] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Asset)
    if scan_job_id:
        query = query.where(Asset.scan_job_id == scan_job_id)
    if ip:
        query = query.where(Asset.ip_address.contains(ip))
    if is_windows is not None:
        query = query.where(Asset.is_windows == is_windows)
    query = query.offset((page - 1) * size).limit(size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{asset_id}", response_model=AssetRead)
async def get_asset(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetRead)
async def update_asset(
    asset_id: str,
    payload: AssetUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(asset, field, value)
    await db.flush()
    return asset


@router.get("/{asset_id}/findings", response_model=List[FindingRead])
async def get_asset_findings(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Finding).where(Finding.asset_id == asset_id))
    return result.scalars().all()


@router.get("/{asset_id}/history", response_model=List[AssetRead])
async def get_asset_history(
    asset_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    # Get the target asset to find its IP
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Find all assets with same IP across scan jobs
    history_result = await db.execute(
        select(Asset)
        .where(Asset.ip_address == asset.ip_address)
        .order_by(Asset.created_at.desc())
    )
    return history_result.scalars().all()
