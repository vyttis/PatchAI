"""Pydantic schemas for deployment endpoints."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class CreateDeploymentRequest(BaseModel):
    vuln_id: _uuid.UUID
    remediation_id: _uuid.UUID
    policy: dict  # {auto_deploy: bool, ring_delay_hours: {pilot: 4, broad: 24}}


class ApproveNextRingRequest(BaseModel):
    """Optional body for approve-next-ring — can carry override policy."""
    pass


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class DeploymentPlanSummary(BaseModel):
    deployment_id: _uuid.UUID
    remediation_id: _uuid.UUID
    canary_count: int
    pilot_count: int
    broad_count: int
    total_devices: int
    ring_dispatched: str = "canary"


class DeploymentJobStatus(BaseModel):
    model_config = {"from_attributes": True}

    id: _uuid.UUID
    device_id: _uuid.UUID
    ring: str
    state: str
    failure_reason: Optional[str] = None
    deferred_count: int = 0
    retry_count: int = 0
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class DeploymentProgressResponse(BaseModel):
    remediation_id: _uuid.UUID
    ring_status: dict  # {canary: {queued: N, complete: N, ...}, pilot: {...}, broad: {...}}
    anomaly_detected: bool = False
    anomaly_details: Optional[dict] = None
    jobs: list[DeploymentJobStatus] = []


class ApproveNextRingResponse(BaseModel):
    ring_dispatched: str
    devices_dispatched: int
