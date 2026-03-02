"""MTTRem executive report generator.

Aggregates overall + KEV-only MTTRem, ring/criticality breakdowns,
top unresolved exposures, patch rate, and fleet size.
Optionally enhances with AI narration (template fallback when AI disabled).
"""

import logging
import uuid as _uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.services.ai import AIService
from backend.app.services.stats import percentile as _percentile

logger = logging.getLogger(__name__)


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


def _hours_between(signal: datetime, patched: datetime) -> float:
    """Compute hours between two timestamps in Python (SQLite-compatible)."""
    delta = patched - signal
    return delta.total_seconds() / 3600


async def _query_mttrem_hours(
    db: AsyncSession,
    org_id: _uuid.UUID,
    cutoff: datetime,
    *,
    kev_only: bool = False,
) -> list[float]:
    """Query all MTTRem hours for patched DVs within period.

    Computes hours in Python for SQLite compatibility (no EXTRACT(EPOCH)).
    """
    dv = DeviceVulnerability

    conditions = [
        dv.org_id == org_id,
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

    stmt = (
        select(dv.patched_at, dv.signal_ingested_at)
        .select_from(dv.__table__)
        .where(*conditions)
    )
    result = await db.execute(stmt)
    hours = []
    for r in result.all():
        if r.patched_at and r.signal_ingested_at:
            h = _hours_between(r.signal_ingested_at, r.patched_at)
            if h >= 0:
                hours.append(round(h, 2))
    return hours


async def _query_by_ring(
    db: AsyncSession,
    org_id: _uuid.UUID,
    cutoff: datetime,
) -> dict[str, list[float]]:
    """Group MTTRem hours by deployment ring."""
    dv = DeviceVulnerability
    dj = DeploymentJob

    stmt = (
        select(dv.patched_at, dv.signal_ingested_at, dj.ring.label("ring"))
        .select_from(dv.__table__)
        .join(
            dj.__table__,
            and_(dj.device_id == dv.device_id, dj.remediation_id == dv.remediation_id),
        )
        .where(
            dv.org_id == org_id,
            dv.patched_at.isnot(None),
            dv.signal_ingested_at.isnot(None),
            dv.patched_at >= cutoff,
        )
    )
    result = await db.execute(stmt)
    groups: dict[str, list[float]] = defaultdict(list)
    for r in result.all():
        if r.patched_at and r.signal_ingested_at:
            h = _hours_between(r.signal_ingested_at, r.patched_at)
            if h >= 0:
                groups[r.ring or "unknown"].append(round(h, 2))
    return groups


async def _query_by_criticality(
    db: AsyncSession,
    org_id: _uuid.UUID,
    cutoff: datetime,
) -> dict[str, list[float]]:
    """Group MTTRem hours by device criticality."""
    dv = DeviceVulnerability

    stmt = (
        select(dv.patched_at, dv.signal_ingested_at, Device.criticality.label("criticality"))
        .select_from(dv.__table__)
        .join(Device.__table__, Device.id == dv.device_id)
        .where(
            dv.org_id == org_id,
            dv.patched_at.isnot(None),
            dv.signal_ingested_at.isnot(None),
            dv.patched_at >= cutoff,
        )
    )
    result = await db.execute(stmt)
    groups: dict[str, list[float]] = defaultdict(list)
    for r in result.all():
        if r.patched_at and r.signal_ingested_at:
            h = _hours_between(r.signal_ingested_at, r.patched_at)
            if h >= 0:
                groups[r.criticality or "standard"].append(round(h, 2))
    return groups


async def generate_mttrem_executive_report(
    db: AsyncSession,
    org_id: _uuid.UUID,
    user_id: _uuid.UUID,
    period_days: int = 30,
) -> dict:
    """Generate a comprehensive MTTRem executive report.

    Returns structured dict matching MTTRemExecutiveReport schema.
    AI narration is optional — falls back to template when AI disabled.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=period_days)

    # Overall MTTRem
    all_hours = await _query_mttrem_hours(db, org_id, cutoff)
    overall = _compute_group_stats(all_hours)

    # KEV-only MTTRem
    kev_hours = await _query_mttrem_hours(db, org_id, cutoff, kev_only=True)
    kev_stats = _compute_group_stats(kev_hours)

    # Ring breakdowns
    ring_groups = await _query_by_ring(db, org_id, cutoff)
    by_ring = []
    for ring, hours in sorted(ring_groups.items()):
        stats = _compute_group_stats(hours)
        by_ring.append({"group": ring, **stats})

    # Criticality breakdowns
    crit_groups = await _query_by_criticality(db, org_id, cutoff)
    by_criticality = []
    for crit, hours in sorted(crit_groups.items()):
        stats = _compute_group_stats(hours)
        by_criticality.append({"group": crit, **stats})

    # Fleet size
    fleet_size = (
        await db.execute(
            select(func.count()).select_from(Device).where(Device.org_id == org_id)
        )
    ).scalar() or 0

    # Patch rate
    total_exposed = (
        await db.execute(
            select(func.count())
            .select_from(DeviceVulnerability)
            .where(DeviceVulnerability.org_id == org_id, DeviceVulnerability.created_at >= cutoff)
        )
    ).scalar() or 0

    total_patched = (
        await db.execute(
            select(func.count())
            .select_from(DeviceVulnerability)
            .where(
                DeviceVulnerability.org_id == org_id,
                DeviceVulnerability.status == "patched",
                DeviceVulnerability.patched_at >= cutoff,
            )
        )
    ).scalar() or 0

    patch_rate = round(total_patched / total_exposed, 4) if total_exposed > 0 else 0.0

    # Top 5 unresolved exposures
    top_stmt = (
        select(Vulnerability.cve_id, func.count().label("device_count"))
        .select_from(DeviceVulnerability)
        .join(Vulnerability, Vulnerability.id == DeviceVulnerability.vuln_id)
        .where(
            DeviceVulnerability.org_id == org_id,
            DeviceVulnerability.status == "exposed",
        )
        .group_by(Vulnerability.cve_id)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_result = await db.execute(top_stmt)
    top_unresolved = [
        {"cve_id": r.cve_id, "device_count": r.device_count}
        for r in top_result.all()
    ]

    # Build report data for AI narration
    report_data = {
        "period_days": period_days,
        "total_exposed": total_exposed,
        "total_patched": total_patched,
        "patch_rate": patch_rate,
        "mttrem_p50": overall["p50"],
        "top_unresolved": top_unresolved,
    }

    # Optional AI narration (template fallback when AI disabled)
    narrative = None
    ai_generated = False
    try:
        ai_service = AIService()
        narration = await ai_service.narrate_compliance_report(
            db, org_id, user_id, report_data,
        )
        narrative = narration.get("narrative")
        ai_generated = narration.get("ai_generated", False)
    except Exception:
        # AI failure should never break the report
        from backend.app.services.ai import render_template_report

        narrative = render_template_report(report_data)
        logger.warning("AI narration failed, using template fallback", exc_info=True)

    return {
        "period_days": period_days,
        "generated_at": now,
        "fleet_size": fleet_size,
        "total_exposed": total_exposed,
        "total_patched": total_patched,
        "patch_rate": patch_rate,
        "overall_p50": overall["p50"],
        "overall_p90": overall["p90"],
        "overall_mean": overall["avg_hours"],
        "kev_p50": kev_stats["p50"],
        "kev_p90": kev_stats["p90"],
        "by_ring": by_ring,
        "by_criticality": by_criticality,
        "top_unresolved": top_unresolved,
        "narrative": narrative,
        "ai_generated": ai_generated,
    }
