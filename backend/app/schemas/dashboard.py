from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class DashboardSummary(BaseModel):
    total_assets: int
    windows_assets: int
    total_vulnerabilities: int
    findings_by_severity: Dict[str, int]
    overall_posture_score: float
    unpatched_systems: int
    critical_assets_at_risk: int
    open_findings: int
    remediated_findings: int
    last_scan_at: Optional[datetime]


class TrendDataPoint(BaseModel):
    date: str
    critical: int
    high: int
    medium: int
    low: int
    total: int


class TrendData(BaseModel):
    period_days: int
    data_points: List[TrendDataPoint]
    posture_trend: List[Dict[str, Any]]


class InsightItem(BaseModel):
    id: str
    title: str
    detail: str
    severity: str
    category: str
    evidence_tags: List[str]
    created_at: datetime


class ExposureNode(BaseModel):
    id: str
    ip_address: str
    hostname: Optional[str]
    risk_score: float
    asset_type: str
    open_port_count: int
    severity: str


class ExposureMapData(BaseModel):
    nodes: List[ExposureNode]
    total_exposed_ports: int
    high_risk_count: int
    generated_at: datetime
