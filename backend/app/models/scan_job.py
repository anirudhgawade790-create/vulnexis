import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.types import JsonType


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(
        Enum("network", "windows", "full", name="scan_type"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        Enum("queued", "running", "completed", "failed", "cancelled", name="scan_status"),
        nullable=False,
        default="queued",
    )
    progress: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    celery_task_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    options: Mapped[dict | None] = mapped_column(JsonType, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    target: Mapped["Target"] = relationship(  # noqa: F821
        "Target", back_populates="scan_jobs"
    )
    started_by_user: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="scan_jobs", foreign_keys=[started_by]
    )
    assets: Mapped[list["Asset"]] = relationship(  # noqa: F821
        "Asset", back_populates="scan_job"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="scan_job"
    )
