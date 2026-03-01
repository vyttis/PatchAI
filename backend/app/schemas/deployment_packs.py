"""Pydantic schemas for deployment packs, agent updates, and token management."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class DeploymentPackRequest(BaseModel):
    platform: str = "windows"
    dept_id: Optional[_uuid.UUID] = None
    label: str
    max_uses: int = 500
    expires_hours: int = 24


class AgentUpdateCheckResponse(BaseModel):
    update_available: bool
    version: Optional[str] = None
    download_url: Optional[str] = None
    sha256: Optional[str] = None
    release_notes: Optional[str] = None
    force_update: bool = False


class InternalReleaseRequest(BaseModel):
    platform: str
    version: str
    sha256: str
    msi_url: str
    sig_url: Optional[str] = None
    release_notes: Optional[str] = None


class EnrollmentTokenListItem(BaseModel):
    token_id: str
    org_id: _uuid.UUID
    dept_id: Optional[_uuid.UUID] = None
    label: Optional[str] = None
    expires_at: Optional[datetime] = None
    max_uses: int
    used_count: int
    created_at: datetime
