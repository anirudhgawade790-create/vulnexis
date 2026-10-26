from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_job_id: str
    asset_id: str
    vulnerability_id: Optional[str]
    title: str
    finding_type: str
    severity: str
    status: str
    check_name: str
    evidence: str
    detection_method: str
    confidence: str
    risk_score: float
    risk_explanation: Optional[str]
    business_impact: Optional[str]
    recommended_action: Optional[str]
    remediation_steps: Optional[List[Dict[str, Any]]]
    resolution_notes: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime]
    assigned_to: Optional[str]


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "remediated", "false_positive", "wont_fix"]
    resolution_notes: Optional[str] = None


class RemediationDetail(BaseModel):
    finding_id: str
    title: str
    plain_explanation: str
    technical_explanation: str
    potential_impact: str
    recommended_fix: str
    required_permissions: str
    estimated_effort: Literal["low", "medium", "high", "critical"]
    verification_steps: List[str]
    documentation_links: List[str]
    rollback_considerations: str
    powershell_examples: List[str] = []
