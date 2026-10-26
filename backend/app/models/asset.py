import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.types import JsonType


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "ip_address", name="uq_asset_scan_ip"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id"), nullable=False
    )
    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.id"), nullable=False
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_build: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_arch: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_windows: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_supported_os: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    asset_type: Mapped[str] = mapped_column(
        Enum("server", "workstation", "network_device", "unknown", name="asset_type"),
        nullable=False,
        default="unknown",
    )
    business_criticality: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", name="business_criticality_asset"),
        nullable=False,
        default="medium",
    )
    open_ports: Mapped[list | None] = mapped_column(JsonType, nullable=True)
    windows_details: Mapped[dict | None] = mapped_column(JsonType, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
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
    scan_job: Mapped["ScanJob"] = relationship(  # noqa: F821
        "ScanJob", back_populates="assets"
    )
    target: Mapped["Target"] = relationship(  # noqa: F821
        "Target", back_populates="assets"
    )
    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        "Finding", back_populates="asset"
    )
