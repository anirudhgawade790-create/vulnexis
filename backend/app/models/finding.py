import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.models.types import JsonType


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_job_id", "asset_id", "check_name", name="uq_finding_scan_asset_check"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_job_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scan_jobs.id"), nullable=False
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id"), nullable=False
    )
    vulnerability_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("vulnerabilities.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    finding_type: Mapped[str] = mapped_column(
        Enum(
            "confirmed_vulnerability",
            "potential_vulnerability",
            "misconfiguration",
            "network_exposure",
            "informational",
            name="finding_type",
        ),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        Enum("critical", "high", "medium", "low", "info", name="finding_severity"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        Enum(
            "open",
            "acknowledged",
            "remediated",
            "false_positive",
            "wont_fix",
            name="finding_status",
        ),
        nullable=False,
        default="open",
    )
    check_name: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    detection_method: Mapped[str] = mapped_column(String(100), nullable=False)
    confidence: Mapped[str] = mapped_column(
        Enum("confirmed", "high", "medium", "low", name="finding_confidence"),
        nullable=False,
    )
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommended_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_steps: Mapped[list | None] = mapped_column(JsonType, nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=True
    )

    # Relationships
    scan_job: Mapped["ScanJob"] = relationship(  # noqa: F821
        "ScanJob", back_populates="findings"
    )
    asset: Mapped["Asset"] = relationship(  # noqa: F821
        "Asset", back_populates="findings"
    )
    vulnerability: Mapped["Vulnerability | None"] = relationship(  # noqa: F821
        "Vulnerability", back_populates="findings"
    )
    assignee: Mapped["User | None"] = relationship(  # noqa: F821
        "User", back_populates="assigned_findings", foreign_keys=[assigned_to]
    )
