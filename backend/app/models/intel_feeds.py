"""Intel feed models — blob storage, health tracking, and last-known-good cache.

Invariant #8: All intel feed fetches store raw blob BEFORE parsing. Parse errors
store parse_error status and alert ops. Never silently lose provenance.

Invariant #13: Parse errors ≠ availability failures. Store blob, mark parse_error,
alert ops. Do NOT serve last_good_data on parse error.
"""

import uuid as _uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Integer, LargeBinary, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base


class IntelFeedBlob(Base):
    __tablename__ = "intel_feed_blobs"

    id: Mapped[_uuid.UUID] = mapped_column(
        primary_key=True,
        default=_uuid.uuid4,
    )
    feed_source: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="kev | msrc | epss | nvd | ghsa | vendor",
    )
    fetched_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
    blob_hash: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="SHA256 of raw bytes for dedup",
    )
    byte_size: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    entity_count: Mapped[Optional[int]] = mapped_column(Integer, default=None)
    storage_path: Mapped[Optional[str]] = mapped_column(
        Text, default=None,
        comment="Supabase Storage path for large blobs (EPSS CSV, large NVD)",
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="pending",
        comment="pending | processed | parse_error",
    )
    error: Mapped[Optional[str]] = mapped_column(Text, default=None)


class IntelFeedHealth(Base):
    __tablename__ = "intel_feed_health"

    feed_source: Mapped[str] = mapped_column(
        Text, primary_key=True,
        comment="kev | msrc | epss | nvd | ghsa | vendor",
    )
    last_fetched_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0",
    )
    parse_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0",
    )
    last_parse_error: Mapped[Optional[str]] = mapped_column(Text, default=None)
    last_parse_error_at: Mapped[Optional[datetime]] = mapped_column(default=None)
    is_stale: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false",
    )


class IntelLastGood(Base):
    __tablename__ = "intel_last_good"

    feed_source: Mapped[str] = mapped_column(
        Text, primary_key=True,
    )
    data: Mapped[Optional[bytes]] = mapped_column(LargeBinary, default=None)
    stored_at: Mapped[datetime] = mapped_column(
        default=None,
        server_default=func.now(),
    )
