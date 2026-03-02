"""Pydantic schemas for reporting, compliance, GDPR, and asset management endpoints."""

import uuid as _uuid
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# NIS2 compliance summary
# ---------------------------------------------------------------------------


class NIS2ComplianceSummary(BaseModel):
    patch_management_active: bool
    vulnerability_handling_evidence: dict
    open_incidents: list[dict]
    incident_reporting_compliance: dict


# ---------------------------------------------------------------------------
# GDPR deletion requests
# ---------------------------------------------------------------------------


class DeletionRequestCreate(BaseModel):
    request_type: str  # org_erasure | data_export


class DeletionRequestResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: _uuid.UUID
    org_id: _uuid.UUID
    request_type: str
    status: str
    requested_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Asset management
# ---------------------------------------------------------------------------


class DeviceCriticalityUpdate(BaseModel):
    criticality: str  # critical | high | standard | low


class DeviceTagsUpdate(BaseModel):
    tags: list[str]


class DepartmentCreate(BaseModel):
    name: str
    criticality: str = "standard"


class DepartmentResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: _uuid.UUID
    name: str
    criticality: str
    device_count: int = 0


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


class KEVHistoryRow(BaseModel):
    cve_id: str
    kev_added_date: Optional[date] = None
    affected_count: int = 0
    patched_count: int = 0
    avg_mttrem_hours: Optional[float] = None


class ComplianceReport(BaseModel):
    period_days: int
    patch_rate: float
    total_exposed: int
    total_patched: int
    mttrem_p50: Optional[float] = None
    top_unresolved: list[dict]


class ExposureTimelineEntry(BaseModel):
    timestamp: Optional[datetime] = None
    event: str
    details: Optional[dict] = None


# ---------------------------------------------------------------------------
# MTTRem executive report
# ---------------------------------------------------------------------------


class MTTRemGroupBreakdown(BaseModel):
    group: str
    p50: Optional[float] = None
    p90: Optional[float] = None
    avg_hours: Optional[float] = None
    sample_count: int = 0


class MTTRemExecutiveReport(BaseModel):
    period_days: int
    generated_at: datetime
    fleet_size: int
    total_exposed: int
    total_patched: int
    patch_rate: float
    overall_p50: Optional[float] = None
    overall_p90: Optional[float] = None
    overall_mean: Optional[float] = None
    kev_p50: Optional[float] = None
    kev_p90: Optional[float] = None
    by_ring: list[MTTRemGroupBreakdown]
    by_criticality: list[MTTRemGroupBreakdown]
    top_unresolved: list[dict]
    narrative: Optional[str] = None
    ai_generated: bool = False
