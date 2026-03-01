"""Remediation model — fix artifacts (KB numbers, patches) with playbook and OS targets."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TimestampMixin


class Remediation(TimestampMixin, Base):
    __tablename__ = "remediations"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    source: Mapped[Optional[str]] = mapped_column(Text, default=None)
    external_id: Mapped[Optional[str]] = mapped_column(Text, default=None)
    title: Mapped[Optional[str]] = mapped_column(Text, default=None)
    playbook: Mapped[dict] = mapped_column(
        JSONB, nullable=False,
        comment="type: patch|config_mitigation, steps, KB number, etc.",
    )
    released_at: Mapped[Optional[datetime]] = mapped_column(default=None)


class RemediationVulnerability(Base):
    """Join table: remediation ↔ vulnerability (many-to-many)."""

    __tablename__ = "remediation_vulnerabilities"

    remediation_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("remediations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    vuln_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        primary_key=True,
    )


class RemediationOsTarget(Base):
    """OS build targets for a remediation — maps KB to specific Windows builds."""

    __tablename__ = "remediation_os_targets"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    remediation_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("remediations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    os_build: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="e.g. '19045' (Windows 10 22H2)",
    )
    min_build_revision: Mapped[Optional[int]] = mapped_column(
        Integer, default=None,
        comment="UBR below this = vulnerable",
    )
