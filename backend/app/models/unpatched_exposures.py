"""UnpatchedExposure model — first-class entity for zero-day response workflow.

When no patch exists for a CVE, the loop creates an UnpatchedExposure instead of
leaving a NULL device_vulnerability. This entity has its own state machine and
recheck loop. Language: "zero-day response" — never "zero-day detection" (Invariant #14).

Inherits TenantMixin (Invariant #16).
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Integer, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import INTERVAL, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin


class UnpatchedExposure(TenantMixin, Base):
    __tablename__ = "unpatched_exposures"
    __table_args__ = (
        UniqueConstraint("org_id", "vuln_id", name="uq_unpatched_exposure_org_vuln"),
    )

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    vuln_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    affected_count: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0",
    )
    mitigations: Mapped[Optional[dict]] = mapped_column(
        JSONB, default=None,
        comment="Vendor-provided workarounds",
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="open",
        comment="open | mitigated | patched | accepted_risk",
    )
    created_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    patched_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    recheck_interval: Mapped[Optional[str]] = mapped_column(
        Text, default=None,
        server_default="1 hour",
        comment="INTERVAL on PostgreSQL, stored as text for SQLite compat",
    )
