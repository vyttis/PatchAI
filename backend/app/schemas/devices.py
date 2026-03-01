"""Pydantic schemas for device command delivery and job status updates."""

import uuid as _uuid
from typing import Optional

from pydantic import BaseModel


class NextCommandResponse(BaseModel):
    """Response for GET /next-command.

    Always returns 200 with JSON. command=null on timeout (Invariant #12).
    """

    command: Optional[dict] = None


class JobStatusRequest(BaseModel):
    """Agent reports job execution status."""

    job_id: _uuid.UUID
    status: str  # downloading | installing | pending_reboot | verifying | complete | failed
    reason: Optional[str] = None
    telemetry: Optional[dict] = None


class JobStatusResponse(BaseModel):
    accepted: bool = True
