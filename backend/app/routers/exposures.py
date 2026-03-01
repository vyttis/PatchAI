"""Exposure and dashboard endpoints — zero-day response workflow API.

Language: "zero-day response" everywhere. Never "detection" (Invariant #14).
All endpoints enforce tenant isolation via get_org_scope() (Invariant #16).
"""

import logging
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import and_, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope, require_role
from backend.app.models.audit_log import AuditLog
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.schemas.auth import OrgScope
from backend.app.schemas.exposures import (
    AcceptRiskRequest,
    DashboardResponse,
    ExposureDetail,
    ExposureHistoryEntry,
    ExposureListItem,
)
from backend.app.services import audit
from backend.app.workers.zeroday_monitor import _parse_interval

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["exposures"])


# ---------------------------------------------------------------------------
# GET /exposures — list open + recently closed (30d)
# ---------------------------------------------------------------------------


@router.get("/exposures", response_model=list[ExposureListItem])
async def list_exposures(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """List open + recently closed (30d) UnpatchedExposures with CVE info."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    stmt = (
        select(UnpatchedExposure, Vulnerability)
        .join(Vulnerability, Vulnerability.id == UnpatchedExposure.vuln_id)
        .where(
            UnpatchedExposure.org_id == scope.org_id,
            (
                UnpatchedExposure.status.in_(["open", "mitigated"])
                | (UnpatchedExposure.patched_at > cutoff)
                | (UnpatchedExposure.status == "accepted_risk")
            ),
        )
        .order_by(UnpatchedExposure.created_at.desc())
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        ExposureListItem(
            id=exp.id,
            vuln_id=exp.vuln_id,
            cve_id=vuln.cve_id,
            cvss=float(vuln.cvss_base_score) if vuln.cvss_base_score else None,
            epss=float(vuln.epss_score) if vuln.epss_score else None,
            in_kev=vuln.in_cisa_kev,
            affected_count=exp.affected_count or 0,
            status=exp.status,
            mitigations=exp.mitigations,
            created_at=exp.created_at,
            last_checked_at=exp.last_checked_at,
            patched_at=exp.patched_at,
        )
        for exp, vuln in rows
    ]


# ---------------------------------------------------------------------------
# GET /exposures/{eid} — detail
# ---------------------------------------------------------------------------


@router.get("/exposures/{eid}", response_model=ExposureDetail)
async def get_exposure_detail(
    org_id: _uuid.UUID,
    eid: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Get exposure detail with CVE info, mitigations, and recheck countdown."""
    stmt = (
        select(UnpatchedExposure, Vulnerability)
        .join(Vulnerability, Vulnerability.id == UnpatchedExposure.vuln_id)
        .where(
            UnpatchedExposure.id == eid,
            UnpatchedExposure.org_id == scope.org_id,
        )
    )
    result = await db.execute(stmt)
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Exposure not found")

    exp, vuln = row
    next_recheck = None
    if exp.last_checked_at and exp.status in ("open", "mitigated"):
        interval = _parse_interval(exp.recheck_interval)
        next_recheck = exp.last_checked_at + interval

    deployment_rec = None
    if exp.mitigations and "deployment_recommendation" in exp.mitigations:
        deployment_rec = exp.mitigations["deployment_recommendation"]

    return ExposureDetail(
        id=exp.id,
        vuln_id=exp.vuln_id,
        cve_id=vuln.cve_id,
        cvss=float(vuln.cvss_base_score) if vuln.cvss_base_score else None,
        epss=float(vuln.epss_score) if vuln.epss_score else None,
        in_kev=vuln.in_cisa_kev,
        affected_count=exp.affected_count or 0,
        status=exp.status,
        mitigations=exp.mitigations,
        created_at=exp.created_at,
        last_checked_at=exp.last_checked_at,
        patched_at=exp.patched_at,
        title=vuln.description[:120] if vuln.description else None,
        description=vuln.description,
        kev_added_date=vuln.kev_added_date,
        recheck_interval=exp.recheck_interval,
        next_recheck=next_recheck,
        deployment_recommendation=deployment_rec,
    )


# ---------------------------------------------------------------------------
# POST /exposures/{eid}/accept — accept risk (CRITICAL audit event)
# ---------------------------------------------------------------------------


@router.post("/exposures/{eid}/accept", response_model=ExposureDetail)
async def accept_exposure_risk(
    org_id: _uuid.UUID,
    eid: _uuid.UUID,
    body: AcceptRiskRequest,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Accept risk for an exposure. Requires note field.

    "exposure.accepted_risk" is a CRITICAL event (Invariant #10):
    audit INSERT must succeed BEFORE status change proceeds.
    """
    # Load exposure
    stmt = select(UnpatchedExposure).where(
        UnpatchedExposure.id == eid,
        UnpatchedExposure.org_id == scope.org_id,
    )
    result = await db.execute(stmt)
    exposure = result.scalar_one_or_none()
    if exposure is None:
        raise HTTPException(status_code=404, detail="Exposure not found")

    previous_status = exposure.status

    # CRITICAL: write audit FIRST — action must not proceed if INSERT fails
    await audit.record(
        db,
        event_type="exposure.accepted_risk",
        org_id=scope.org_id,
        user_id=scope.user.id,
        resource=f"exposure:{eid}",
        changes={
            "note": body.note,
            "previous_status": previous_status,
            "new_status": "accepted_risk",
        },
    )

    # Only after audit succeeds: update status
    exposure.status = "accepted_risk"
    await db.commit()
    await db.refresh(exposure)

    # Load vuln for response
    vuln = await db.get(Vulnerability, exposure.vuln_id)
    return ExposureDetail(
        id=exposure.id,
        vuln_id=exposure.vuln_id,
        cve_id=vuln.cve_id if vuln else "",
        cvss=float(vuln.cvss_base_score) if vuln and vuln.cvss_base_score else None,
        epss=float(vuln.epss_score) if vuln and vuln.epss_score else None,
        in_kev=vuln.in_cisa_kev if vuln else False,
        affected_count=exposure.affected_count or 0,
        status=exposure.status,
        mitigations=exposure.mitigations,
        created_at=exposure.created_at,
        last_checked_at=exposure.last_checked_at,
        patched_at=exposure.patched_at,
        title=vuln.description[:120] if vuln and vuln.description else None,
        description=vuln.description if vuln else None,
        kev_added_date=vuln.kev_added_date if vuln else None,
        recheck_interval=exposure.recheck_interval,
    )


# ---------------------------------------------------------------------------
# GET /exposures/{eid}/history — recheck log from audit_log
# ---------------------------------------------------------------------------


@router.get("/exposures/{eid}/history", response_model=list[ExposureHistoryEntry])
async def get_exposure_history(
    org_id: _uuid.UUID,
    eid: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Return recheck log for an exposure from audit_log."""
    resource_key = f"exposure:{eid}"
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.org_id == scope.org_id,
            AuditLog.resource == resource_key,
            AuditLog.event_type.like("exposure.%"),
        )
        .order_by(AuditLog.timestamp.desc())
        .limit(100)
    )
    result = await db.execute(stmt)
    entries = result.scalars().all()

    return [
        ExposureHistoryEntry(
            timestamp=e.timestamp,
            event_type=e.event_type,
            result=e.result,
            changes=e.changes,
        )
        for e in entries
    ]


# ---------------------------------------------------------------------------
# GET /dashboard — fleet overview summary
# ---------------------------------------------------------------------------


@router.get("/dashboard", response_model=DashboardResponse)
async def get_dashboard(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard summary: KEV exposures, unpatched count, top 20 urgent,
    deployment summary, MTTRem, fleet health."""
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)
    cutoff_30d = now - timedelta(days=30)

    # 1. KEV exposures (open, where vuln is in CISA KEV)
    kev_count_stmt = (
        select(func.count())
        .select_from(UnpatchedExposure)
        .join(Vulnerability, Vulnerability.id == UnpatchedExposure.vuln_id)
        .where(
            UnpatchedExposure.org_id == scope.org_id,
            UnpatchedExposure.status == "open",
            Vulnerability.in_cisa_kev == True,  # noqa: E712
        )
    )
    kev_count = (await db.execute(kev_count_stmt)).scalar() or 0

    # Top 5 KEV exposures
    kev_top5_stmt = (
        select(UnpatchedExposure, Vulnerability)
        .join(Vulnerability, Vulnerability.id == UnpatchedExposure.vuln_id)
        .where(
            UnpatchedExposure.org_id == scope.org_id,
            UnpatchedExposure.status == "open",
            Vulnerability.in_cisa_kev == True,  # noqa: E712
        )
        .order_by(UnpatchedExposure.affected_count.desc())
        .limit(5)
    )
    kev_top5_result = await db.execute(kev_top5_stmt)
    kev_top5 = [
        {
            "cve_id": vuln.cve_id,
            "affected_count": exp.affected_count or 0,
            "kev_date": str(vuln.kev_added_date) if vuln.kev_added_date else None,
        }
        for exp, vuln in kev_top5_result.all()
    ]

    # 2. All open unpatched exposures
    unpatched_count_stmt = (
        select(func.count())
        .select_from(UnpatchedExposure)
        .where(
            UnpatchedExposure.org_id == scope.org_id,
            UnpatchedExposure.status == "open",
        )
    )
    unpatched_count = (await db.execute(unpatched_count_stmt)).scalar() or 0

    unpatched_top5_stmt = (
        select(UnpatchedExposure, Vulnerability)
        .join(Vulnerability, Vulnerability.id == UnpatchedExposure.vuln_id)
        .where(
            UnpatchedExposure.org_id == scope.org_id,
            UnpatchedExposure.status == "open",
        )
        .order_by(UnpatchedExposure.affected_count.desc())
        .limit(5)
    )
    unpatched_top5_result = await db.execute(unpatched_top5_stmt)
    unpatched_top5 = [
        {
            "cve_id": vuln.cve_id,
            "affected_count": exp.affected_count or 0,
        }
        for exp, vuln in unpatched_top5_result.all()
    ]

    # 3. Top 20 urgent device vulnerabilities
    top20_stmt = (
        select(DeviceVulnerability, Vulnerability)
        .join(Vulnerability, Vulnerability.id == DeviceVulnerability.vuln_id)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.status == "exposed",
        )
        .order_by(DeviceVulnerability.urgency_score.desc().nullslast())
        .limit(20)
    )
    top20_result = await db.execute(top20_stmt)
    top_20_urgent = [
        {
            "cve_id": vuln.cve_id,
            "title": (vuln.description or "")[:80],
            "urgency_score": dv.urgency_score,
            "in_kev": vuln.in_cisa_kev,
            "epss": float(vuln.epss_score) if vuln.epss_score else None,
            "patch_available": dv.remediation_id is not None,
        }
        for dv, vuln in top20_result.all()
    ]

    # 4. Deployment summary
    deploy_stmt = (
        select(DeploymentJob.state, func.count())
        .where(DeploymentJob.org_id == scope.org_id)
        .group_by(DeploymentJob.state)
    )
    deploy_result = await db.execute(deploy_stmt)
    deploy_counts = {row[0]: row[1] for row in deploy_result.all()}
    active_states = {"queued", "downloading", "installing", "pending_reboot", "verifying"}
    deployment_summary = {
        "active": sum(deploy_counts.get(s, 0) for s in active_states),
        "completed_24h": 0,
        "failed_24h": 0,
        "pending_approval": 0,
    }

    # 5. MTTRem (30d)
    mttrem_stmt = (
        select(func.count())
        .select_from(DeviceVulnerability)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.patched_at.isnot(None),
            DeviceVulnerability.signal_ingested_at.isnot(None),
            DeviceVulnerability.patched_at >= cutoff_30d,
        )
    )
    mttrem_count = (await db.execute(mttrem_stmt)).scalar() or 0
    mttrem = {
        "p50_hours": None,
        "p90_hours": None,
        "kev_p50_hours": None,
        "period_days": 30,
        "sample_count": mttrem_count,
    }

    # 6. Fleet health
    total_devices_stmt = (
        select(func.count())
        .select_from(Device)
        .where(Device.org_id == scope.org_id)
    )
    total_devices = (await db.execute(total_devices_stmt)).scalar() or 0

    checked_in_24h_stmt = (
        select(func.count())
        .select_from(Device)
        .where(
            Device.org_id == scope.org_id,
            Device.last_seen_at > cutoff_24h,
        )
    )
    checked_in_24h = (await db.execute(checked_in_24h_stmt)).scalar() or 0

    fleet_health = {
        "total_devices": total_devices,
        "checked_in_24h": checked_in_24h,
        "overdue_critical_devices": 0,
    }

    return DashboardResponse(
        kev_exposures={"count": kev_count, "top_5": kev_top5},
        unpatched_exposures={"count": unpatched_count, "top_5": unpatched_top5},
        top_20_urgent=top_20_urgent,
        deployment_summary=deployment_summary,
        mttrem=mttrem,
        fleet_health=fleet_health,
    )
