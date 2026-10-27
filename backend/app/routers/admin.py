import asyncio
import socket
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
import shutil

from app.config import get_settings
from app.dependencies import get_db, require_role
from app.models.audit_log import AuditLog
from app.models.user import User

router = APIRouter(prefix="/admin", tags=["admin"])


def _service_reachable(url: str) -> bool:
    parsed = urlparse(url)
    if not parsed.hostname:
        return False
    port = parsed.port or (6380 if parsed.scheme == "rediss" else 6379)
    try:
        with socket.create_connection((parsed.hostname, port), timeout=0.35):
            return True
    except OSError:
        return False


@router.get("/overview")
async def admin_overview(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    settings = get_settings()
    total_users = (await db.execute(select(func.count(User.id)))).scalar_one()
    active_users = (
        await db.execute(select(func.count(User.id)).where(User.is_active.is_(True)))
    ).scalar_one()
    role_counts_result = await db.execute(
        select(User.role, func.count(User.id)).group_by(User.role)
    )
    role_counts = {role: count for role, count in role_counts_result}

    database_available = True
    try:
        await db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        database_available = False

    redis_available = await asyncio.to_thread(_service_reachable, settings.redis_url)
    broker_available = await asyncio.to_thread(
        _service_reachable, settings.celery_broker_url
    )
    recent_result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).limit(8)
    )
    recent_events = [
        {
            "id": event.id,
            "action": event.action,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "user_id": event.user_id,
            "created_at": event.created_at,
            "ip_address": event.ip_address,
        }
        for event in recent_result.scalars()
    ]

    return {
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "users_by_role": role_counts,
        "database_available": database_available,
        "redis_available": redis_available,
        "worker_status": "unknown" if not broker_available else "unverified",
        "scanner_available": bool(
            shutil.which(settings.nmap_path) or Path(settings.nmap_path).is_file()
        ),
        "version": "0.1.0",
        "recent_events": recent_events,
    }


@router.get("/audit-logs")
async def list_audit_logs(
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None, max_length=100),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(["admin"])),
):
    query = select(AuditLog)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action == action)
    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
    if end_date:
        query = query.where(AuditLog.created_at <= end_date)
    result = await db.execute(
        query.order_by(AuditLog.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    )
    return result.scalars().all()
