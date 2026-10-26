import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope_type: Mapped[str] = mapped_column(
        Enum("ip", "cidr", "hostname", "range", name="scope_type"),
        nullable=False,
    )
    scope_value: Mapped[str] = mapped_column(String(500), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    business_criticality: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", name="business_criticality_target"),
        nullable=False,
        default="medium",
    )
    created_by: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )
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

    # Relationships
    creator: Mapped["User"] = relationship(  # noqa: F821
        "User", back_populates="targets", foreign_keys=[created_by]
    )
    scan_jobs: Mapped[list["ScanJob"]] = relationship(  # noqa: F821
        "ScanJob", back_populates="target"
    )
    assets: Mapped[list["Asset"]] = relationship(  # noqa: F821
        "Asset", back_populates="target"
    )
