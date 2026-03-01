"""Pydantic schemas for authentication and authorization."""

import uuid as _uuid
from dataclasses import dataclass


@dataclass
class CurrentUser:
    """Decoded JWT user identity."""

    id: _uuid.UUID
    org_id: _uuid.UUID
    role: str  # org_admin | admin | viewer


@dataclass
class OrgScope:
    """Tenant-scoped context for all org-level operations."""

    org_id: _uuid.UUID
    user: CurrentUser
