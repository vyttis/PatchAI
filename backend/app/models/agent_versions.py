"""AgentVersion model — tracks published agent builds.

Global table (NOT tenant-scoped): agent binaries are shared across all orgs.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TimestampMixin


class AgentVersion(TimestampMixin, Base):
    __tablename__ = "agent_versions"

    version: Mapped[str] = mapped_column(
        Text, primary_key=True,
        comment="Semver, e.g. '1.0.0'",
    )
    windows_msi_url: Mapped[Optional[str]] = mapped_column(Text, default=None)
    windows_sha256: Mapped[Optional[str]] = mapped_column(Text, default=None)
    windows_sig_url: Mapped[Optional[str]] = mapped_column(Text, default=None)
    release_notes: Mapped[Optional[str]] = mapped_column(Text, default=None)
    released_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    is_latest: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false",
    )
    minimum_supported_version: Mapped[Optional[str]] = mapped_column(
        Text, default=None,
    )
