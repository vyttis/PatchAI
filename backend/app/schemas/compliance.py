"""Pydantic schemas for NIS2 compliance endpoints."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class NIS2IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str  # significant | major | critical
    affected_systems: Optional[dict] = None
    detected_at: datetime
    related_cve_ids: Optional[list[str]] = None


class NIS2IncidentResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: _uuid.UUID
    org_id: _uuid.UUID
    title: str
    description: Optional[str] = None
    severity: str
    affected_systems: Optional[dict] = None
    detected_at: datetime
    early_warning_due: Optional[datetime] = None
    notification_due: Optional[datetime] = None
    final_report_due: Optional[datetime] = None
    early_warning_sent_at: Optional[datetime] = None
    notification_sent_at: Optional[datetime] = None
    related_cve_ids: Optional[list[str]] = None
    status: str
    created_by: Optional[_uuid.UUID] = None
    is_early_warning_overdue: bool = False
    is_notification_overdue: bool = False
    is_final_report_overdue: bool = False
