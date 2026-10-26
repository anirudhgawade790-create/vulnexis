import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum("admin", "analyst", "viewer", name="user_role"),
        nullable=False,
        default="viewer",
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        "AuditLog", back_populates="user", cascade="all, delete-orphan"
    )
    targets: Mapped[list["Target"]] = relationship(  # noqa: F821
        "Target", back_populates="creator", foreign_keys="Target.created_by"
    )
    scan_jobs: Mapped[list["ScanJob"]] = relationship(  # noqa: F821
        "ScanJob", back_populates="started_by_user", foreign_keys="ScanJob.started_by"
    )
    baseline_policies: Mapped[list["BaselinePolicy"]] = relationship(  # noqa: F821
        "BaselinePolicy", back_populates="creator"
    )
    assigned_findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="assignee", foreign_keys="Finding.assigned_to"
    )
