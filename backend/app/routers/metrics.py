"""Metrics router — MTTRem KPI endpoint with percentiles and multi-dimension grouping.

GET /api/v1/orgs/{id}/metrics/mttrem?period=30d&group_by=ring,criticality&kev_only=false
Returns p50, p90, mean across all patched device-vulnerabilities, with per-group breakdowns.
"""

import uuid as _uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.schemas.auth import OrgScope
from backend.app.schemas.metrics import MTTRemGroupRow, MTTRemResponse
from backend.app.services.stats import parse_period as _parse_period
from backend.app.services.stats import percentile as _percentile

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["metrics"])


def _compute_group_stats(hours_list: list[float]) -> dict:
    """Compute p50, p90, mean for a list of hours values."""
    if not hours_list:
        return {"p50": None, "p90": None, "avg_hours": None, "sample_count": 0}
    sorted_vals = sorted(hours_list)
    return {
        "p50": _percentile(sorted_vals, 0.5),
        "p90": _percentile(sorted_vals, 0.9),
        "avg_hours": round(sum(sorted_vals) / len(sorted_vals), 2),
        "sample_count": len(sorted_vals),
    }


# ---------------------------------------------------------------------------
# GET /metrics/mttrem
# ---------------------------------------------------------------------------


@router.get("/metrics/mttrem", response_model=MTTRemResponse)
async def get_mttrem(
    org_id: _uuid.UUID,
    period: str = Query("30d", description="Period: '7d', '30d', '90d'"),
    group_by: str = Query("ring", description="Comma-separated: ring, criticality"),
    kev_only: bool = Query(False, description="Filter to KEV CVEs only"),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Return MTTRem metrics with percentiles, grouped by ring and/or criticality.

    Computes p50/p90 in Python for SQLite compatibility (no percentile_cont).
    """
    period_days = _parse_period(period)
    cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)

    dv = DeviceVulnerability
    dj = DeploymentJob

    # Parse group_by dimensions
    dimensions = [d.strip() for d in group_by.split(",") if d.strip()]
    group_ring = "ring" in dimensions
    group_criticality = "criticality" in dimensions

    # Build base conditions
    conditions = [
        dv.org_id == scope.org_id,
        dv.patched_at.isnot(None),
        dv.signal_ingested_at.isnot(None),
        dv.patched_at >= cutoff,
    ]

    if kev_only:
        conditions.append(
            dv.vuln_id.in_(
                select(Vulnerability.id).where(Vulnerability.in_cisa_kev == True)  # noqa: E712
            )
        )

    # Compute hours expression (works on both PG and SQLite)
    hours_expr = (
        func.extract("epoch", dv.patched_at - dv.signal_ingested_at) / 3600
    )

    # Select columns: hours + grouping dimensions
    select_cols = [hours_expr.label("hours")]
    joins_needed = []

    if group_ring:
        select_cols.append(dj.ring.label("ring"))
        joins_needed.append("dj")

    if group_criticality:
        select_cols.append(Device.criticality.label("criticality"))
        joins_needed.append("device")

    # Build query with required joins
    base = select(*select_cols).select_from(dv.__table__)

    if "dj" in joins_needed:
        base = base.join(
            dj.__table__,
            and_(dj.device_id == dv.device_id, dj.remediation_id == dv.remediation_id),
        )

    if "device" in joins_needed:
        base = base.join(Device.__table__, Device.id == dv.device_id)

    # If we need ring but no explicit dj join yet, add it
    if group_ring and "dj" not in joins_needed:
        base = base.join(
            dj.__table__,
            and_(dj.device_id == dv.device_id, dj.remediation_id == dv.remediation_id),
        )

    stmt = base.where(*conditions)
    result = await db.execute(stmt)
    raw_rows = result.all()

    # Collect all hours values + grouped values
    all_hours: list[float] = []
    groups: dict[tuple, list[float]] = defaultdict(list)

    for row in raw_rows:
        h = float(row.hours) if row.hours is not None else None
        if h is None or h < 0:
            continue
        all_hours.append(h)

        # Build group key
        key_parts: list[Optional[str]] = []
        if group_ring:
            key_parts.append(getattr(row, "ring", None))
        if group_criticality:
            key_parts.append(getattr(row, "criticality", None))
        groups[tuple(key_parts)].append(h)

    # Compute overall stats
    overall = _compute_group_stats(all_hours)

    # Compute per-group stats
    by_group = []
    for key, hours_list in sorted(groups.items()):
        stats = _compute_group_stats(hours_list)
        row_data = {
            "p50": stats["p50"],
            "p90": stats["p90"],
            "avg_hours": stats["avg_hours"],
            "sample_count": stats["sample_count"],
        }
        idx = 0
        if group_ring:
            row_data["ring"] = key[idx] if idx < len(key) else None
            idx += 1
        if group_criticality:
            row_data["criticality"] = key[idx] if idx < len(key) else None
            idx += 1
        by_group.append(MTTRemGroupRow(**row_data))

    return MTTRemResponse(
        period_days=period_days,
        kev_only=kev_only,
        p50=overall["p50"],
        p90=overall["p90"],
        mean_hours=overall["avg_hours"],
        sample_count=overall["sample_count"],
        by_group=by_group,
    )
