"""DeploymentJob model — ring rollout job tracking with telemetry snapshots.

Inherits TenantMixin (Invariant #16). Full state machine implementation
comes in Phase 3A — this is the schema definition for the mttrem_by_ring view.
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin


class DeploymentJob(TenantMixin, Base):
    __tablename__ = "deployment_jobs"

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
    remediation_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("remediations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ring: Mapped[Optional[str]] = mapped_column(
        Text, default=None,
        comment="canary | pilot | broad",
    )
    state: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="queued",
        comment="queued|downloading|installing|pending_reboot|verifying|complete|failed|failed_final",
    )
    state_updated_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    playbook_snapshot: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=None,
        comment="Frozen copy of remediation playbook at dispatch time",
    )
    telemetry_before: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=None,
        comment="Per-job telemetry snapshot before install",
    )
    telemetry_after: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=None,
        comment="Per-job telemetry snapshot after install",
    )
    created_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
