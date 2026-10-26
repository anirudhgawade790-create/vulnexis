# Import all models so Alembic autodiscovery works
from app.models.types import JsonType  # noqa: F401 — register custom type first
from app.models.user import User
from app.models.target import Target
from app.models.scan_job import ScanJob
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.finding import Finding
from app.models.baseline_policy import BaselinePolicy
from app.models.audit_log import AuditLog

__all__ = [
    "JsonType",
    "User",
    "Target",
    "ScanJob",
    "Asset",
    "Vulnerability",
    "Finding",
    "BaselinePolicy",
    "AuditLog",
]
