"""Advisory model — MSRC and vendor bulletins linked to CVEs."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TimestampMixin


class Advisory(TimestampMixin, Base):
    __tablename__ = "advisories"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    source: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="msrc | vendor",
    )
    external_id: Mapped[str] = mapped_column(
        Text, unique=True, nullable=False,
        comment="e.g. ADV-2024-0001 or MS24-001",
    )
    title: Mapped[Optional[str]] = mapped_column(Text, default=None)
    published_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    severity: Mapped[Optional[str]] = mapped_column(Text, default=None)
    advisory_url: Mapped[Optional[str]] = mapped_column(Text, default=None)


class AdvisoryVulnerability(Base):
    """Join table: advisory ↔ vulnerability (many-to-many)."""

    __tablename__ = "advisory_vulnerabilities"

    advisory_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("advisories.id", ondelete="CASCADE"),
        primary_key=True,
    )
    vuln_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        primary_key=True,
    )
