"""Pydantic schemas for MTTRem metrics endpoints."""

from decimal import Decimal
from typing import Optional

from pydantic import BaseModel


class MTTRemRingRow(BaseModel):
    """Single row from the mttrem_by_ring view."""

    ring: Optional[str] = None
    p50: Optional[float] = None
    p90: Optional[float] = None
    avg_hours: Optional[float] = None
    sample_count: int = 0


class MTTRemResponse(BaseModel):
    """Response for GET /api/v1/orgs/{id}/metrics/mttrem."""

    period_days: int
    kev_only: bool
    rows: list[MTTRemRingRow]
