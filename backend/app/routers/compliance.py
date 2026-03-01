"""NIS2 compliance router — incident management with deadline tracking."""

import uuid as _uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope
from backend.app.models.nis2_incidents import NIS2Incident
from backend.app.schemas.auth import OrgScope
from backend.app.schemas.compliance import NIS2IncidentCreate, NIS2IncidentResponse

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["compliance"])


def _add_overdue_flags(
    incident: NIS2Incident, now: datetime
) -> NIS2IncidentResponse:
    """Convert ORM model to response with overdue flags computed."""
    resp = NIS2IncidentResponse.model_validate(incident)
    if incident.early_warning_due and not incident.early_warning_sent_at:
        resp.is_early_warning_overdue = now > incident.early_warning_due
    if incident.notification_due and not incident.notification_sent_at:
        resp.is_notification_overdue = now > incident.notification_due
    if incident.final_report_due and incident.status == "open":
        resp.is_final_report_overdue = now > incident.final_report_due
    return resp


@router.post("/incidents", response_model=NIS2IncidentResponse, status_code=201)
async def create_incident(
    org_id: _uuid.UUID,
    body: NIS2IncidentCreate,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Create a NIS2 incident."""
    incident = NIS2Incident(
        org_id=scope.org_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        affected_systems=body.affected_systems,
        detected_at=body.detected_at,
        related_cve_ids=body.related_cve_ids,
        created_by=scope.user.id,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return _add_overdue_flags(incident, datetime.now(timezone.utc))


@router.get("/incidents", response_model=list[NIS2IncidentResponse])
async def list_incidents(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """List all NIS2 incidents for the org, with overdue flags."""
    result = await db.execute(
        select(NIS2Incident)
        .where(NIS2Incident.org_id == scope.org_id)
        .order_by(NIS2Incident.detected_at.desc())
    )
    incidents = result.scalars().all()
    now = datetime.now(timezone.utc)
    return [_add_overdue_flags(i, now) for i in incidents]


@router.get("/incidents/overdue", response_model=list[NIS2IncidentResponse])
async def list_overdue_incidents(
    org_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """List NIS2 incidents past any deadline."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(NIS2Incident)
        .where(NIS2Incident.org_id == scope.org_id)
        .where(NIS2Incident.status == "open")
    )
    incidents = result.scalars().all()
    overdue = []
    for i in incidents:
        resp = _add_overdue_flags(i, now)
        if (
            resp.is_early_warning_overdue
            or resp.is_notification_overdue
            or resp.is_final_report_overdue
        ):
            overdue.append(resp)
    return overdue
