from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_job_id: str
    target_id: str
    ip_address: str
    hostname: Optional[str]
    mac_address: Optional[str]
    os_name: Optional[str]
    os_version: Optional[str]
    os_build: Optional[str]
    os_arch: Optional[str]
    is_windows: bool
    is_supported_os: Optional[bool]
    asset_type: str
    business_criticality: str
    open_ports: Optional[List[Dict[str, Any]]]
    windows_details: Optional[Dict[str, Any]]
    risk_score: Optional[float]
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class AssetUpdate(BaseModel):
    business_criticality: Optional[Literal["critical", "high", "medium", "low"]] = None
    asset_type: Optional[Literal["server", "workstation", "network_device", "unknown"]] = None
