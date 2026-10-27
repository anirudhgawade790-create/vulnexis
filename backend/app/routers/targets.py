from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.models.target import Target
from app.models.user import User
from app.schemas.target import TargetCreate, TargetRead, TargetUpdate

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/", response_model=List[TargetRead])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    target = Target(
        **payload.model_dump(),
        created_by=current_user.id,
    )
    db.add(target)
    await db.flush()
    return target


@router.get("/{target_id}", response_model=TargetRead)
async def get_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


@router.put("/{target_id}", response_model=TargetRead)
async def update_target(
    target_id: str,
    payload: TargetUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(target, field, value)
    await db.flush()
    return target


@router.delete("/{target_id}")
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    await db.delete(target)
    return {"message": "Target deleted"}
