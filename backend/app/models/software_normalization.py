"""Software normalization models — mapping raw inventory names to CPE vendors/products.

SoftwareNormalizationLog: automated match results per device check-in.
TenantNormalizationOverride: admin-confirmed overrides per org.

Both inherit TenantMixin (Invariant #16).
"""

import uuid as _uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional

from sqlalchemy import ForeignKey, Numeric, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base
from backend.app.models.base import TenantMixin


class SoftwareNormalizationLog(TenantMixin, Base):
    __tablename__ = "software_normalization_log"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    device_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    raw_display_name: Mapped[Optional[str]] = mapped_column(Text, default=None)
    raw_publisher: Mapped[Optional[str]] = mapped_column(Text, default=None)
    product_code: Mapped[Optional[str]] = mapped_column(Text, default=None)
    normalized_vendor: Mapped[Optional[str]] = mapped_column(Text, default=None)
    normalized_product: Mapped[Optional[str]] = mapped_column(Text, default=None)
    confidence: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(3, 2), default=None,
    )
    match_method: Mapped[Optional[str]] = mapped_column(Text, default=None)
    normalized_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )


class TenantNormalizationOverride(TenantMixin, Base):
    __tablename__ = "tenant_normalization_overrides"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    match_key: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="{publisher}::{display_name}",
    )
    vendor: Mapped[str] = mapped_column(Text, nullable=False)
    product: Mapped[str] = mapped_column(Text, nullable=False)
    confirmed_by: Mapped[Optional[_uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        default=None,
    )
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(default=None)
