from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class TargetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scope_type: Literal["ip", "cidr", "hostname", "range"]
    scope_value: str = Field(..., max_length=500)
    business_criticality: Literal["critical", "high", "medium", "low"] = "medium"
    is_active: bool = True


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    scope_type: str
    scope_value: str
    is_active: bool
    business_criticality: str
    created_by: Optional[str]
    created_at: datetime
    updated_at: datetime


class TargetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    scope_value: Optional[str] = Field(None, max_length=500)
    business_criticality: Optional[Literal["critical", "high", "medium", "low"]] = None
    is_active: Optional[bool] = None
