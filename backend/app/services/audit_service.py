from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User


def record_audit_event(
    db: AsyncSession,
    *,
    action: str,
    user: User | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    request: Request | None = None,
) -> None:
    client_host = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None
    db.add(
        AuditLog(
            user_id=user.id if user else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=client_host,
            user_agent=user_agent[:500] if user_agent else None,
        )
    )
