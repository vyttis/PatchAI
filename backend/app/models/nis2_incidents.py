"""NIS2 incident model — Article 21 compliance with auto-computed deadlines.

Generated columns:
  early_warning_due = detected_at + 24h
  notification_due  = detected_at + 72h
  final_report_due  = detected_at + 3 months
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Computed, ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin


class NIS2Incident(TenantMixin, Base):
    __tablename__ = "nis2_incidents"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    severity: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="significant | major | critical",
    )
    affected_systems: Mapped[Optional[dict]] = mapped_column(JSONB, default=None)
    detected_at: Mapped[datetime] = mapped_column(nullable=False)

    # Generated deadline columns (NIS2 Article 21)
    early_warning_due: Mapped[Optional[datetime]] = mapped_column(
        Computed("detected_at + interval '24 hours'"),
    )
    notification_due: Mapped[Optional[datetime]] = mapped_column(
        Computed("detected_at + interval '72 hours'"),
    )
    final_report_due: Mapped[Optional[datetime]] = mapped_column(
        Computed("detected_at + interval '3 months'"),
    )

    early_warning_sent_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    notification_sent_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    related_cve_ids: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(Text), default=None
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="open"
    )
    created_by: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
