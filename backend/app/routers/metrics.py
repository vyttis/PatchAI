"""Metrics router — MTTRem KPI endpoint.

GET /api/v1/orgs/{id}/metrics/mttrem?period=30d&group_by=ring&kev_only=false
Returns data from device_vulnerabilities + deployment_jobs, grouped by ring.
"""

import uuid as _uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.schemas.auth import OrgScope
from backend.app.schemas.metrics import MTTRemResponse, MTTRemRingRow

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["metrics"])


def _parse_period(period: str) -> int:
    """Parse period string like '30d' into days. Default 30."""
    period = period.strip().lower()
    if period.endswith("d"):
        try:
            return int(period[:-1])
        except ValueError:
            return 30
    return 30


@router.get("/metrics/mttrem", response_model=MTTRemResponse)
async def get_mttrem(
    org_id: _uuid.UUID,
    period: str = Query("30d", description="Period like '30d', '7d', '90d'"),
    group_by: str = Query("ring", description="Group by dimension (ring)"),
    kev_only: bool = Query(False, description="Filter to KEV CVEs only"),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Return MTTRem metrics grouped by deployment ring.

    Queries device_vulnerabilities joined with deployment_jobs.
    On PostgreSQL, the mttrem_by_ring view provides percentiles.
    Here we query directly for SQLite compatibility in tests.
    """
    period_days = _parse_period(period)
    cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)

    # Build query: device_vulnerabilities JOIN deployment_jobs
    dv = DeviceVulnerability
    dj = DeploymentJob

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

    # Compute hours as raw expression (works on both PG and SQLite)
    hours_expr = (
        func.extract("epoch", dv.patched_at - dv.signal_ingested_at) / 3600
    )

    stmt = (
        select(
            dj.ring,
            func.avg(hours_expr).label("avg_hours"),
            func.count().label("sample_count"),
        )
        .select_from(dv.__table__.join(
            dj.__table__,
            and_(
                dj.device_id == dv.device_id,
                dj.remediation_id == dv.remediation_id,
            ),
        ))
        .where(*conditions)
        .group_by(dj.ring)
    )

    result = await db.execute(stmt)
    rows = []
    for row in result.all():
        rows.append(MTTRemRingRow(
            ring=row.ring,
            avg_hours=float(row.avg_hours) if row.avg_hours is not None else None,
            sample_count=row.sample_count,
        ))

    return MTTRemResponse(
        period_days=period_days,
        kev_only=kev_only,
        rows=rows,
    )
