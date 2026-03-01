"""User model — dashboard users authenticated via Supabase Auth JWT."""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin, TimestampMixin


class User(TenantMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_email"),
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
    email: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="viewer",
        comment="CHECK (role IN ('org_admin', 'admin', 'viewer'))",
    )
    last_login_at: Mapped[Optional[datetime]] = mapped_column(default=None)
