"""Audit log model — append-only by design (Security Invariant #5).

The patchpilot_app DB role has INSERT only on this table.
UPDATE and DELETE are revoked at the DB level.
NO updated_at column — this table is append-only.
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin


class AuditLog(TenantMixin, Base):
    __tablename__ = "audit_log"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    timestamp: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        default=None,
    )
    device_id: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        default=None,
    )
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(Text, default=None)
    changes: Mapped[Optional[dict]] = mapped_column(JSONB, default=None)
    ai_feature: Mapped[Optional[str]] = mapped_column(Text, default=None)
    ip_address: Mapped[Optional[str]] = mapped_column(Text, default=None)
    result: Mapped[Optional[str]] = mapped_column(Text, default=None)
