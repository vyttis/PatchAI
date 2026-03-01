"""DeploymentJob model — ring rollout job tracking with telemetry snapshots.

Inherits TenantMixin (Invariant #16). State machine in services/state_machine.py.
Ring rollout logic in workers/ring_rollout.py.
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Integer, Text, func
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
    ring: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="canary | pilot | broad",
    )
    state: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="queued",
        comment="queued|downloading|installing|pending_reboot|user_deferred|"
                "forced_reboot|verifying|complete|failed|diagnosing|failed_final",
    )
    state_updated_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    playbook_snapshot: Mapped[dict] = mapped_column(
        JSONB, nullable=False,
        comment="Frozen copy of remediation playbook at dispatch time",
    )
    created_by_user_id: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, default=None)
    deferred_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0",
    )
    forced_reboot_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    retry_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0",
    )
    telemetry_before: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=None,
        comment="Per-job telemetry snapshot before install",
    )
    telemetry_after: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=None,
        comment="Per-job telemetry snapshot after install",
    )
