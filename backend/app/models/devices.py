"""Device model — Windows endpoints managed by PatchPilot agents."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, ForeignKey, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin, TimestampMixin


class Device(TenantMixin, TimestampMixin, Base):
    __tablename__ = "devices"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dept_id: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("departments.id", ondelete="SET NULL"),
        default=None,
    )
    hostname: Mapped[str] = mapped_column(Text, nullable=False)
    os_build: Mapped[Optional[str]] = mapped_column(Text, default=None)
    cert_fingerprint: Mapped[Optional[str]] = mapped_column(
        Text, unique=True, default=None
    )
    cert_serial: Mapped[Optional[str]] = mapped_column(Text, default=None)
    cert_revoked_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    criticality: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="standard"
    )
    tags: Mapped[Optional[list[str]]] = mapped_column(
        ARRAY(Text), default=None
    )
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    inventory_section_hashes: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )
    winget_available: Mapped[Optional[bool]] = mapped_column(
        Boolean, default=None
    )
    relay_node_available: Mapped[Optional[bool]] = mapped_column(
        Boolean, default=None
    )
