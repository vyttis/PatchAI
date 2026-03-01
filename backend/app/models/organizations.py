"""Organization model — top-level tenant entity."""

import uuid as _uuid
from datetime import datetime

from sqlalchemy import Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    settings: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        server_default="{}",
        comment="ai_policy, patch_policy, data_retention, notifications, sso",
    )
    created_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
