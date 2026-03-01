"""Pydantic schemas for device enrollment and check-in."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class EnrollmentTokenCreate(BaseModel):
    dept_id: Optional[_uuid.UUID] = None
    label: Optional[str] = None
    expires_at: Optional[datetime] = None
    max_uses: int = 100


class EnrollmentTokenResponse(BaseModel):
    token: str
    token_id: str
    org_id: _uuid.UUID
    expires_at: Optional[datetime] = None
    max_uses: int


class EnrollRequest(BaseModel):
    token: str
    csr_pem: str


class EnrollResponse(BaseModel):
    device_id: _uuid.UUID
    cert_pem: str
    ca_cert_pem: str
    server_url: str = "https://api.patchpilot.com"
    checkin_interval: int = 300


class DeviceCheckinRequest(BaseModel):
    hostname: str
    os_build: Optional[str] = None
    inventory_section_hashes: Optional[dict] = None


class DeviceCheckinResponse(BaseModel):
    commands_pending: bool = False
