"""Department model — organizational unit within a tenant."""

import uuid as _uuid

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin, TimestampMixin


class Department(TenantMixin, TimestampMixin, Base):
    __tablename__ = "departments"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    criticality: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="standard"
    )
