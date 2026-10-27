from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.user import UserRead
from app.services.auth_service import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.services.audit_service import record_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with username + password, return access and refresh tokens."""
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password):
        record_audit_event(db, action="login_failed", request=request)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive account")

    # Update last login timestamp
    user.last_login = datetime.now(timezone.utc)
    await db.flush()
    record_audit_event(
        db, action="login_succeeded", user=user, resource_type="user",
        resource_id=user.id, request=request,
    )

    token_data = {"sub": user.id, "role": user.role}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": UserRead.model_validate(user),
    }


@router.post("/refresh")
async def refresh_token(
    payload: dict,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a refresh token for a new access token."""
    from jose import JWTError

    token = payload.get("refresh_token", "")
    try:
        data = decode_token(token)
        if data.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
        user_id = data.get("sub")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    new_token = create_access_token({"sub": user.id, "role": user.role})
    return {"access_token": new_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Logout endpoint (client discards token; Redis blacklist optional)."""
    record_audit_event(
        db, action="logout", user=current_user, resource_type="user",
        resource_id=current_user.id, request=request,
    )
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserRead)
async def me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user."""
    return current_user
