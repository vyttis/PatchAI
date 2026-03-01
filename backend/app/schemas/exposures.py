"""Pydantic schemas for exposure and dashboard endpoints."""

import uuid as _uuid
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, field_validator


# ---------------------------------------------------------------------------
# Exposure schemas
# ---------------------------------------------------------------------------


class ExposureListItem(BaseModel):
    model_config = {"from_attributes": True}

    id: _uuid.UUID
    vuln_id: _uuid.UUID
    cve_id: str
    cvss: Optional[float] = None
    epss: Optional[float] = None
    in_kev: bool = False
    affected_count: int = 0
    status: str
    mitigations: Optional[dict] = None
    created_at: Optional[datetime] = None
    last_checked_at: Optional[datetime] = None
    patched_at: Optional[datetime] = None


class ExposureDetail(ExposureListItem):
    title: Optional[str] = None
    description: Optional[str] = None
    kev_added_date: Optional[date] = None
    recheck_interval: Optional[str] = None
    next_recheck: Optional[datetime] = None
    deployment_recommendation: Optional[dict] = None


class AcceptRiskRequest(BaseModel):
    note: str

    @field_validator("note")
    @classmethod
    def note_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("note must not be empty")
        return v.strip()


class ExposureHistoryEntry(BaseModel):
    timestamp: Optional[datetime] = None
    event_type: Optional[str] = None
    result: Optional[str] = None
    changes: Optional[dict] = None


# ---------------------------------------------------------------------------
# Dashboard schemas
# ---------------------------------------------------------------------------


class DashboardResponse(BaseModel):
    kev_exposures: dict
    unpatched_exposures: dict
    top_20_urgent: list[dict]
    deployment_summary: dict
    mttrem: dict
    fleet_health: dict
