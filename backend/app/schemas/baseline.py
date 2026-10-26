from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict


class BaselinePolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    framework: Literal["cis_windows", "nist_csf", "custom"] = "custom"
    version: str = "1.0"
    controls: List[Dict[str, Any]] = []
    is_active: bool = True


class BaselinePolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    framework: str
    version: str
    controls: List[Dict[str, Any]]
    is_active: bool
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class BaselinePolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    controls: Optional[List[Dict[str, Any]]] = None
    is_active: Optional[bool] = None


class ControlResult(BaseModel):
    control_id: str
    title: str
    result: Literal["pass", "fail", "unknown"]
    evidence: Optional[str]
    last_checked: datetime


class BaselineResultSummary(BaseModel):
    policy_id: str
    policy_name: str
    scan_job_id: str
    total_controls: int
    passed: int
    failed: int
    unknown: int
    compliance_percentage: float
    results: List[ControlResult]
    assessed_at: datetime
