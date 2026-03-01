"""EnrollmentToken model — two-part token for device enrollment.

Security Invariant #11: Enrollment tokens = two-part format.
token_id (public, indexed) + token_secret (bcrypt'd). Client sends both.
Server fetches by token_id (O(1)), verifies one bcrypt hash. Never table-scan.
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin, TimestampMixin


class EnrollmentToken(TenantMixin, TimestampMixin, Base):
    __tablename__ = "enrollment_tokens"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    token_id: Mapped[str] = mapped_column(
        Text, unique=True, nullable=False,
        comment="Public part of two-part token (~16 chars urlsafe)",
    )
    token_hash: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="bcrypt hash of token_secret (private part)",
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
    label: Mapped[Optional[str]] = mapped_column(Text, default=None)
    expires_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    used_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        default=None,
    )
