"""Deletion request model — GDPR right to erasure workflow."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin


class DeletionRequest(TenantMixin, Base):
    __tablename__ = "deletion_requests"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
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
    request_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="org_erasure | user_erasure | data_export",
    )
    requested_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="pending"
    )
    export_url: Mapped[Optional[str]] = mapped_column(Text, default=None)
