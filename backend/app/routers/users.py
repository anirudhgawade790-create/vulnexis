from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_role
from app.models.user import User
from app.schemas.user import UserCreate, UserRead, UserUpdate
from app.services.audit_service import record_audit_event
from app.services.auth_service import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/", response_model=List[UserRead])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    # Check for duplicate username/email
    result = await db.execute(
        select(User).where((User.username == payload.username) | (User.email == payload.email))
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        full_name=payload.full_name,
    )
    db.add(user)
    await db.flush()
    record_audit_event(
        db, action="user_created", user=current_user, resource_type="user",
        resource_id=user.id, details={"role": user.role}, request=request,
    )
    return user


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Users can read their own profile; admins can read anyone's
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.put("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    changes = payload.model_dump(exclude_none=True)
    if current_user.id == user.id and (
        changes.get("role", user.role) != "admin"
        or changes.get("is_active", user.is_active) is False
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own administrator access",
        )
    removes_active_admin = (
        user.role == "admin"
        and user.is_active
        and (changes.get("role", user.role) != "admin" or changes.get("is_active") is False)
    )
    if removes_active_admin:
        admin_count = (
            await db.execute(
                select(func.count(User.id)).where(
                    User.role == "admin", User.is_active.is_(True)
                )
            )
        ).scalar_one()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot deactivate or demote the last active administrator",
            )
    for field, value in changes.items():
        setattr(user, field, value)
    await db.flush()
    record_audit_event(
        db,
        action="user_updated",
        user=current_user,
        resource_type="user",
        resource_id=user.id,
        details={"changed_fields": sorted(changes)},
        request=request,
    )
    return user


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(["admin"])),
):
    if current_user.id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete yourself")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role == "admin" and user.is_active:
        admin_count = (
            await db.execute(
                select(func.count(User.id)).where(
                    User.role == "admin", User.is_active.is_(True)
                )
            )
        ).scalar_one()
        if admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot delete the last active administrator",
            )
    record_audit_event(
        db, action="user_deleted", user=current_user, resource_type="user",
        resource_id=user.id, request=request,
    )
    await db.delete(user)
    return {"message": "User deleted"}


@router.patch("/{user_id}/password")
async def change_password(
    user_id: str,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    new_password = payload.get("new_password", "")
    if len(new_password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too short")
    user.hashed_password = hash_password(new_password)
    return {"message": "Password updated"}
