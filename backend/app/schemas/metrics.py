"""Pydantic schemas for MTTRem metrics endpoints."""

from typing import Optional

from pydantic import BaseModel


class MTTRemGroupRow(BaseModel):
    """Single row in per-group breakdown."""

    ring: Optional[str] = None
    criticality: Optional[str] = None
    p50: Optional[float] = None
    p90: Optional[float] = None
    avg_hours: Optional[float] = None
    sample_count: int = 0


class MTTRemResponse(BaseModel):
    """Response for GET /api/v1/orgs/{id}/metrics/mttrem."""

    period_days: int
    kev_only: bool
    p50: Optional[float] = None
    p90: Optional[float] = None
    mean_hours: Optional[float] = None
    sample_count: int = 0
    by_group: list[MTTRemGroupRow] = []
