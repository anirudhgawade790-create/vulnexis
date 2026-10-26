from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanJobCreate(BaseModel):
    target_id: str
    scan_type: Literal["network", "windows", "full"]
    options: Optional[Dict[str, Any]] = None


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_id: str
    scan_type: str
    status: str
    progress: int
    started_by: str
    celery_task_id: Optional[str]
    options: Optional[Dict[str, Any]]
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime


class ScanResultsSummary(BaseModel):
    scan_job_id: str
    assets_found: int
    windows_assets: int
    total_open_ports: int
    findings_by_severity: Dict[str, int]
    findings_by_type: Dict[str, int]
    scan_duration_seconds: Optional[float]
    errors: List[str] = []


class ChangeDetectionReport(BaseModel):
    scan_job_id: str
    previous_scan_job_id: str
    new_findings: List[str]
    resolved_findings: List[str]
    new_assets: List[str]
    removed_assets: List[str]
    new_ports: List[Dict[str, Any]]
    closed_ports: List[Dict[str, Any]]
    risk_delta: float


class ScanProgressEvent(BaseModel):
    scan_job_id: str
    progress: int = Field(..., ge=0, le=100)
    phase: str
    current_host: Optional[str] = None
    message: str
    timestamp: datetime
