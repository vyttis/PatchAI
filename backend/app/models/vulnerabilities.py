"""Vulnerability model — CVE records with CVSS, EPSS, and KEV status."""

import uuid as _uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import Boolean, Date, Numeric, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TimestampMixin


class Vulnerability(TimestampMixin, Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    cve_id: Mapped[str] = mapped_column(
        Text, unique=True, nullable=False,
        comment="e.g. CVE-2024-12345",
    )
    cvss_base_score: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(3, 1), default=None,
    )
    cvss_vector: Mapped[Optional[str]] = mapped_column(Text, default=None)
    epss_score: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(5, 4), default=None,
    )
    epss_percentile: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(5, 4), default=None,
    )
    in_cisa_kev: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false",
    )
    kev_added_date: Mapped[Optional[date]] = mapped_column(Date, default=None)
    published_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    last_modified_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    references: Mapped[Optional[dict]] = mapped_column(JSONB, default=None)
