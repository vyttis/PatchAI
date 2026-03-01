"""DeviceVulnerability model — per-device vulnerability status with MTTRem tracking.

Inherits TenantMixin (Invariant #16). The mttrem_hours column is a PostgreSQL
generated column: EXTRACT(EPOCH FROM (patched_at - signal_ingested_at)) / 3600.
SQLite tests skip this column via the conftest computed-column compiler.
"""

import uuid as _uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import Boolean, Computed, ForeignKey, Integer, Numeric, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin, TimestampMixin


class DeviceVulnerability(TenantMixin, TimestampMixin, Base):
    __tablename__ = "device_vulnerabilities"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vuln_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    remediation_id: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("remediations.id", ondelete="SET NULL"),
        default=None,
        comment="Nullable — zero-day exposures have no remediation yet",
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="exposed",
        comment="exposed | deploying | patched | accepted_risk",
    )
    urgency_score: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    signal_ingested_at: Mapped[Optional[datetime]] = mapped_column(
        default=None,
        comment="min(kev_added_date, published_at) — when system first knew",
    )
    patched_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    uncertain_baseline: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false",
    )

    # Generated column: MTTRem in hours (PostgreSQL only, skipped on SQLite)
    mttrem_hours: Mapped[Optional[Decimal]] = mapped_column(
        Numeric,
        Computed("EXTRACT(EPOCH FROM (patched_at - signal_ingested_at)) / 3600"),
        nullable=True,
    )
