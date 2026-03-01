"""Reports, compliance, GDPR, and asset management endpoints.

Compliance evidence CSV, NIS2 summary, GDPR deletion requests,
reporting endpoints, and device criticality/tags/department management.

All org-scoped endpoints enforce tenant isolation via get_org_scope() (Invariant #16).
"""

import csv
import io
import logging
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_current_user, get_org_scope, require_role
from backend.app.models.audit_log import AuditLog
from backend.app.models.deletion_requests import DeletionRequest
from backend.app.models.departments import Department
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.nis2_incidents import NIS2Incident
from backend.app.models.remediations import Remediation
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.schemas.auth import CurrentUser, OrgScope
from backend.app.schemas.reports import (
    ComplianceReport,
    DeletionRequestCreate,
    DeletionRequestResponse,
    DepartmentCreate,
    DepartmentResponse,
    DeviceCriticalityUpdate,
    DeviceTagsUpdate,
    ExposureTimelineEntry,
    KEVHistoryRow,
    NIS2ComplianceSummary,
)
from backend.app.services.stats import parse_period as _parse_period
from backend.app.services.stats import percentile as _percentile

logger = logging.getLogger(__name__)

router = APIRouter(tags=["reports"])


# ---------------------------------------------------------------------------
# Compliance Evidence CSV
# ---------------------------------------------------------------------------


async def _query_compliance_evidence(db: AsyncSession, org_id: _uuid.UUID) -> list[dict]:
    """Query compliance evidence: patched device-vulnerabilities with full context."""
    dv = DeviceVulnerability
    v = Vulnerability
    d = Device

    stmt = (
        select(
            v.cve_id,
            v.in_cisa_kev,
            v.epss_score,
            v.cvss_base_score,
            dv.signal_ingested_at,
            dv.patched_at,
            dv.urgency_score,
            d.hostname,
            d.criticality,
            dv.remediation_id,
            dv.id.label("dv_id"),
        )
        .select_from(dv.__table__)
        .join(v.__table__, v.id == dv.vuln_id)
        .join(d.__table__, d.id == dv.device_id)
        .where(
            dv.org_id == org_id,
            dv.status == "patched",
        )
        .order_by(dv.patched_at.desc())
    )
    result = await db.execute(stmt)
    rows = []
    for r in result.all():
        # Compute mttrem_hours in Python (SQLite doesn't have generated column)
        mttrem_hours = None
        if r.patched_at and r.signal_ingested_at:
            delta = r.patched_at - r.signal_ingested_at
            mttrem_hours = round(delta.total_seconds() / 3600, 2)

        rows.append({
            "cve_id": r.cve_id,
            "hostname": r.hostname,
            "criticality": r.criticality,
            "cvss": float(r.cvss_base_score) if r.cvss_base_score else None,
            "epss": float(r.epss_score) if r.epss_score else None,
            "in_cisa_kev": r.in_cisa_kev,
            "signal_ingested_at": str(r.signal_ingested_at) if r.signal_ingested_at else None,
            "patched_at": str(r.patched_at) if r.patched_at else None,
            "mttrem_hours": mttrem_hours,
            "urgency_score": r.urgency_score,
        })
    return rows


@router.get("/api/v1/orgs/{org_id}/compliance/evidence.csv")
async def compliance_evidence_csv(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Download compliance evidence as CSV.

    Joins device_vulnerabilities + vulnerabilities + devices for all patched entries.
    """
    rows = await _query_compliance_evidence(db, scope.org_id)

    headers = [
        "cve_id", "hostname", "criticality", "cvss", "epss",
        "in_cisa_kev", "signal_ingested_at", "patched_at",
        "mttrem_hours", "urgency_score",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="compliance_evidence.csv"'},
    )


# ---------------------------------------------------------------------------
# NIS2 Compliance Summary
# ---------------------------------------------------------------------------


@router.get(
    "/api/v1/orgs/{org_id}/compliance/nis2",
    response_model=NIS2ComplianceSummary,
)
async def nis2_compliance_summary(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """NIS2 compliance summary: patch management, vulnerability handling, incidents."""
    now = datetime.now(timezone.utc)

    # Patch management active: any deployment jobs exist
    deploy_count = (await db.execute(
        select(func.count()).select_from(DeploymentJob)
        .where(DeploymentJob.org_id == scope.org_id)
    )).scalar() or 0
    patch_management_active = deploy_count > 0

    # Vulnerability handling: KEV CVEs addressed
    kev_addressed_stmt = (
        select(func.count())
        .select_from(DeviceVulnerability)
        .join(Vulnerability, Vulnerability.id == DeviceVulnerability.vuln_id)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.status == "patched",
            Vulnerability.in_cisa_kev == True,  # noqa: E712
        )
    )
    total_kev_addressed = (await db.execute(kev_addressed_stmt)).scalar() or 0

    # Avg MTTRem for KEV
    hours_expr = func.extract(
        "epoch", DeviceVulnerability.patched_at - DeviceVulnerability.signal_ingested_at
    ) / 3600
    avg_kev_mttrem_stmt = (
        select(func.avg(hours_expr))
        .select_from(DeviceVulnerability)
        .join(Vulnerability, Vulnerability.id == DeviceVulnerability.vuln_id)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.status == "patched",
            DeviceVulnerability.patched_at.isnot(None),
            DeviceVulnerability.signal_ingested_at.isnot(None),
            Vulnerability.in_cisa_kev == True,  # noqa: E712
        )
    )
    avg_kev = (await db.execute(avg_kev_mttrem_stmt)).scalar()
    avg_mttrem_kev_hours = round(float(avg_kev), 2) if avg_kev else None

    # Open incidents with overdue flags
    incidents_result = await db.execute(
        select(NIS2Incident)
        .where(NIS2Incident.org_id == scope.org_id, NIS2Incident.status == "open")
        .order_by(NIS2Incident.detected_at.desc())
    )
    incidents = incidents_result.scalars().all()
    open_incidents = []
    for inc in incidents:
        ew_overdue = bool(
            inc.early_warning_due
            and not inc.early_warning_sent_at
            and now > inc.early_warning_due
        )
        notif_overdue = bool(
            inc.notification_due
            and not inc.notification_sent_at
            and now > inc.notification_due
        )
        open_incidents.append({
            "id": str(inc.id),
            "title": inc.title,
            "severity": inc.severity,
            "early_warning_overdue": ew_overdue,
            "notification_overdue": notif_overdue,
        })

    # Incident reporting compliance
    all_incidents = await db.execute(
        select(NIS2Incident).where(NIS2Incident.org_id == scope.org_id)
    )
    all_inc = all_incidents.scalars().all()
    total_incidents = len(all_inc)
    on_time_ew = sum(
        1 for i in all_inc
        if i.early_warning_sent_at and i.early_warning_due and i.early_warning_sent_at <= i.early_warning_due
    )
    on_time_notif = sum(
        1 for i in all_inc
        if i.notification_sent_at and i.notification_due and i.notification_sent_at <= i.notification_due
    )

    return NIS2ComplianceSummary(
        patch_management_active=patch_management_active,
        vulnerability_handling_evidence={
            "total_kev_addressed": total_kev_addressed,
            "avg_mttrem_kev_hours": avg_mttrem_kev_hours,
        },
        open_incidents=open_incidents,
        incident_reporting_compliance={
            "total_incidents": total_incidents,
            "on_time_early_warning": on_time_ew,
            "on_time_notification": on_time_notif,
        },
    )


# ---------------------------------------------------------------------------
# Reports: Compliance, KEV History, Exposure Timeline
# ---------------------------------------------------------------------------


@router.get("/api/v1/orgs/{org_id}/reports/compliance", response_model=ComplianceReport)
async def compliance_report(
    org_id: _uuid.UUID,
    period: str = Query("30d"),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Patch rates, MTTRem trend, top exposures for compliance reporting."""
    period_days = _parse_period(period)
    cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)

    # Total exposed (ever, within period)
    total_exposed = (await db.execute(
        select(func.count()).select_from(DeviceVulnerability)
        .where(DeviceVulnerability.org_id == scope.org_id, DeviceVulnerability.created_at >= cutoff)
    )).scalar() or 0

    # Total patched (within period)
    total_patched = (await db.execute(
        select(func.count()).select_from(DeviceVulnerability)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.status == "patched",
            DeviceVulnerability.patched_at >= cutoff,
        )
    )).scalar() or 0

    patch_rate = round(total_patched / total_exposed, 4) if total_exposed > 0 else 0.0

    # MTTRem p50
    hours_expr = func.extract(
        "epoch", DeviceVulnerability.patched_at - DeviceVulnerability.signal_ingested_at
    ) / 3600
    mttrem_stmt = (
        select(hours_expr.label("hours"))
        .select_from(DeviceVulnerability)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.patched_at.isnot(None),
            DeviceVulnerability.signal_ingested_at.isnot(None),
            DeviceVulnerability.patched_at >= cutoff,
        )
    )
    result = await db.execute(mttrem_stmt)
    all_hours = sorted(float(r.hours) for r in result.all() if r.hours is not None and r.hours >= 0)
    mttrem_p50 = _percentile(all_hours, 0.5)

    # Top 5 unresolved exposures
    top_stmt = (
        select(Vulnerability.cve_id, func.count().label("device_count"))
        .select_from(DeviceVulnerability)
        .join(Vulnerability, Vulnerability.id == DeviceVulnerability.vuln_id)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.status == "exposed",
        )
        .group_by(Vulnerability.cve_id)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_result = await db.execute(top_stmt)
    top_unresolved = [{"cve_id": r.cve_id, "device_count": r.device_count} for r in top_result.all()]

    return ComplianceReport(
        period_days=period_days,
        patch_rate=patch_rate,
        total_exposed=total_exposed,
        total_patched=total_patched,
        mttrem_p50=mttrem_p50,
        top_unresolved=top_unresolved,
    )


@router.get("/api/v1/orgs/{org_id}/reports/kev-history", response_model=list[KEVHistoryRow])
async def kev_history(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """All KEV CVEs ever affecting org with per-CVE MTTRem."""
    hours_expr = func.extract(
        "epoch", DeviceVulnerability.patched_at - DeviceVulnerability.signal_ingested_at
    ) / 3600

    stmt = (
        select(
            Vulnerability.cve_id,
            Vulnerability.kev_added_date,
            func.count().label("affected_count"),
            func.count(DeviceVulnerability.patched_at).label("patched_count"),
            func.avg(hours_expr).label("avg_mttrem"),
        )
        .select_from(DeviceVulnerability)
        .join(Vulnerability, Vulnerability.id == DeviceVulnerability.vuln_id)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            Vulnerability.in_cisa_kev == True,  # noqa: E712
        )
        .group_by(Vulnerability.cve_id, Vulnerability.kev_added_date)
        .order_by(Vulnerability.kev_added_date.desc().nullslast())
    )
    result = await db.execute(stmt)
    return [
        KEVHistoryRow(
            cve_id=r.cve_id,
            kev_added_date=r.kev_added_date,
            affected_count=r.affected_count,
            patched_count=r.patched_count,
            avg_mttrem_hours=round(float(r.avg_mttrem), 2) if r.avg_mttrem else None,
        )
        for r in result.all()
    ]


@router.get(
    "/api/v1/orgs/{org_id}/reports/exposure-timeline",
    response_model=list[ExposureTimelineEntry],
)
async def exposure_timeline(
    org_id: _uuid.UUID,
    vuln_id: str = Query(..., description="CVE ID like CVE-2024-12345"),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Full event timeline for one CVE: signal, matching, deployment, verification."""
    # Find the vulnerability
    vuln = (await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == vuln_id)
    )).scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="CVE not found")

    events: list[ExposureTimelineEntry] = []

    # Signal ingested
    if vuln.published_at:
        events.append(ExposureTimelineEntry(
            timestamp=vuln.published_at,
            event="signal_ingested",
            details={"cve_id": vuln.cve_id, "source": "published_at"},
        ))
    if vuln.kev_added_date:
        kev_dt = datetime(vuln.kev_added_date.year, vuln.kev_added_date.month,
                          vuln.kev_added_date.day, tzinfo=timezone.utc)
        events.append(ExposureTimelineEntry(
            timestamp=kev_dt,
            event="kev_added",
            details={"cve_id": vuln.cve_id},
        ))

    # Device matches
    dv_stmt = (
        select(DeviceVulnerability)
        .where(
            DeviceVulnerability.org_id == scope.org_id,
            DeviceVulnerability.vuln_id == vuln.id,
        )
        .order_by(DeviceVulnerability.created_at)
    )
    dv_result = await db.execute(dv_stmt)
    dvs = dv_result.scalars().all()
    for dv in dvs:
        if dv.created_at:
            events.append(ExposureTimelineEntry(
                timestamp=dv.created_at,
                event="device_matched",
                details={"device_id": str(dv.device_id), "status": dv.status},
            ))
        if dv.patched_at:
            events.append(ExposureTimelineEntry(
                timestamp=dv.patched_at,
                event="device_patched",
                details={"device_id": str(dv.device_id)},
            ))

    # Audit log events for this CVE
    audit_stmt = (
        select(AuditLog)
        .where(
            AuditLog.org_id == scope.org_id,
            AuditLog.resource == str(vuln.id),
        )
        .order_by(AuditLog.timestamp)
        .limit(100)
    )
    audit_result = await db.execute(audit_stmt)
    for al in audit_result.scalars().all():
        events.append(ExposureTimelineEntry(
            timestamp=al.timestamp,
            event=al.event_type,
            details=al.changes,
        ))

    events.sort(key=lambda e: e.timestamp or datetime.min.replace(tzinfo=timezone.utc))
    return events


# ---------------------------------------------------------------------------
# GDPR Deletion Requests
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/orgs/{org_id}/deletion-requests",
    response_model=DeletionRequestResponse,
    status_code=201,
)
async def create_deletion_request(
    org_id: _uuid.UUID,
    body: DeletionRequestCreate,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin")),
    db: AsyncSession = Depends(get_db),
):
    """Request org data erasure or export (GDPR Article 17/20)."""
    if body.request_type not in ("org_erasure", "data_export"):
        raise HTTPException(status_code=400, detail="Invalid request_type")

    req = DeletionRequest(
        org_id=scope.org_id,
        user_id=scope.user.id,
        request_type=body.request_type,
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    return DeletionRequestResponse.model_validate(req)


@router.get(
    "/api/v1/orgs/{org_id}/deletion-requests",
    response_model=list[DeletionRequestResponse],
)
async def list_deletion_requests(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """List deletion/export requests for the org."""
    result = await db.execute(
        select(DeletionRequest)
        .where(DeletionRequest.org_id == scope.org_id)
        .order_by(DeletionRequest.requested_at.desc())
    )
    return [DeletionRequestResponse.model_validate(r) for r in result.scalars().all()]


@router.post(
    "/api/v1/users/me/deletion-request",
    response_model=DeletionRequestResponse,
    status_code=201,
)
async def create_user_deletion_request(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Individual user erasure request (GDPR Article 17)."""
    req = DeletionRequest(
        org_id=user.org_id,
        user_id=user.id,
        request_type="user_erasure",
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)
    return DeletionRequestResponse.model_validate(req)


# ---------------------------------------------------------------------------
# Asset Management
# ---------------------------------------------------------------------------


@router.put("/api/v1/orgs/{org_id}/devices/{device_id}/criticality")
async def update_device_criticality(
    org_id: _uuid.UUID,
    device_id: _uuid.UUID,
    body: DeviceCriticalityUpdate,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update device criticality and recalculate urgency scores."""
    valid = {"critical", "high", "standard", "low"}
    if body.criticality not in valid:
        raise HTTPException(status_code=400, detail=f"criticality must be one of {valid}")

    device = await db.get(Device, device_id)
    if not device or device.org_id != scope.org_id:
        raise HTTPException(status_code=404, detail="Device not found")

    device.criticality = body.criticality
    await db.flush()

    # Recalculate urgency scores for all this device's vulnerabilities
    updated = await _recalculate_urgency(db, device)

    await db.commit()
    return {"device_id": str(device_id), "criticality": body.criticality, "urgency_updated": updated}


@router.put("/api/v1/orgs/{org_id}/devices/{device_id}/tags")
async def update_device_tags(
    org_id: _uuid.UUID,
    device_id: _uuid.UUID,
    body: DeviceTagsUpdate,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Update device tags and recalculate urgency scores."""
    device = await db.get(Device, device_id)
    if not device or device.org_id != scope.org_id:
        raise HTTPException(status_code=404, detail="Device not found")

    device.tags = body.tags
    await db.flush()

    updated = await _recalculate_urgency(db, device)

    await db.commit()
    return {"device_id": str(device_id), "tags": body.tags, "urgency_updated": updated}


async def _recalculate_urgency(db: AsyncSession, device: Device) -> int:
    """Recalculate urgency_score for all device_vulnerabilities of a device."""
    from backend.app.workers.vuln_matching import _signal_ingested_at, compute_urgency_score

    dv_stmt = (
        select(DeviceVulnerability)
        .where(
            DeviceVulnerability.device_id == device.id,
            DeviceVulnerability.status == "exposed",
        )
    )
    result = await db.execute(dv_stmt)
    dvs = result.scalars().all()

    updated = 0
    now = datetime.now(timezone.utc)
    for dv in dvs:
        vuln = await db.get(Vulnerability, dv.vuln_id)
        if not vuln:
            continue
        sig = _signal_ingested_at(vuln)
        days = (now - sig).days if sig else 0
        new_score = compute_urgency_score(vuln, device, days)
        if dv.urgency_score != new_score:
            dv.urgency_score = new_score
            updated += 1

    return updated


# ---------------------------------------------------------------------------
# Departments
# ---------------------------------------------------------------------------


@router.post(
    "/api/v1/orgs/{org_id}/departments",
    response_model=DepartmentResponse,
    status_code=201,
)
async def create_department(
    org_id: _uuid.UUID,
    body: DepartmentCreate,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Create a department."""
    dept = Department(
        org_id=scope.org_id,
        name=body.name,
        criticality=body.criticality,
    )
    db.add(dept)
    await db.commit()
    await db.refresh(dept)
    return DepartmentResponse(
        id=dept.id, name=dept.name, criticality=dept.criticality, device_count=0,
    )


@router.get(
    "/api/v1/orgs/{org_id}/departments",
    response_model=list[DepartmentResponse],
)
async def list_departments(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """List departments with device counts."""
    stmt = (
        select(Department, func.count(Device.id).label("device_count"))
        .outerjoin(Device, Device.dept_id == Department.id)
        .where(Department.org_id == scope.org_id)
        .group_by(Department.id)
        .order_by(Department.name)
    )
    result = await db.execute(stmt)
    return [
        DepartmentResponse(
            id=dept.id, name=dept.name, criticality=dept.criticality,
            device_count=count,
        )
        for dept, count in result.all()
    ]
