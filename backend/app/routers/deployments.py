"""Deployment endpoints — ring rollout management.

POST /deployments: create plan + dispatch canary (CRITICAL audit: policy.evaluated)
POST /deployments/{did}/approve-next-ring: dispatch next ring (CRITICAL audit: deployment.dispatched)
GET /deployments/{did}: ring progress + anomaly status

All endpoints enforce tenant isolation via get_org_scope() (Invariant #16).
"""

import logging
import uuid as _uuid
from collections import defaultdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope, require_role
from backend.app.dependencies.redis import get_redis
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.remediations import Remediation
from backend.app.schemas.auth import OrgScope
from backend.app.schemas.deployments import (
    ApproveNextRingResponse,
    CreateDeploymentRequest,
    DeploymentJobStatus,
    DeploymentPlanSummary,
    DeploymentProgressResponse,
)
from backend.app.services import audit
from backend.app.workers.ring_rollout import (
    check_canary_anomaly,
    create_deployment_plan,
    dispatch_ring,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/orgs/{org_id}", tags=["deployments"])


# ---------------------------------------------------------------------------
# POST /deployments — create deployment plan + dispatch canary
# ---------------------------------------------------------------------------


@router.post("/deployments", response_model=DeploymentPlanSummary, status_code=201)
async def create_deployment(
    org_id: _uuid.UUID,
    body: CreateDeploymentRequest,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
    redis: Optional[Redis] = Depends(get_redis),
):
    """Create a deployment plan and dispatch canary ring.

    1. audit.record("policy.evaluated") — CRITICAL, must succeed
    2. Create DeploymentPlan (canary/pilot/broad split)
    3. Dispatch canary ring
    4. Schedule Celery task to check canary anomaly
    5. Return plan summary
    """
    # Load remediation
    remediation = await db.get(Remediation, body.remediation_id)
    if not remediation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation not found",
        )

    # CRITICAL: audit policy evaluation BEFORE any deployment action
    await audit.record(
        db,
        event_type="policy.evaluated",
        org_id=scope.org_id,
        user_id=scope.user.id,
        resource=str(body.remediation_id),
        changes={
            "vuln_id": str(body.vuln_id),
            "remediation_id": str(body.remediation_id),
            "policy": body.policy,
        },
    )

    # Create plan
    plan = await create_deployment_plan(
        db, body.vuln_id, body.remediation_id, scope.org_id, body.policy,
    )

    # Dispatch canary ring
    await dispatch_ring(
        db, redis, plan, "canary", remediation, user_id=scope.user.id,
    )
    await db.commit()

    # Schedule canary anomaly check (delayed)
    try:
        from backend.app.workers.tasks import check_canary_anomaly_task
        delay_hours = body.policy.get("ring_delay_hours", {}).get("pilot", 4)
        check_canary_anomaly_task.apply_async(
            args=[str(body.remediation_id), str(scope.org_id)],
            countdown=int(delay_hours * 3600),
        )
    except Exception:
        logger.warning("Failed to schedule canary anomaly check", exc_info=True)

    return DeploymentPlanSummary(
        deployment_id=plan.plan_id,
        remediation_id=plan.remediation_id,
        canary_count=len(plan.canary),
        pilot_count=len(plan.pilot),
        broad_count=len(plan.broad),
        total_devices=len(plan.canary) + len(plan.pilot) + len(plan.broad),
        ring_dispatched="canary",
    )


# ---------------------------------------------------------------------------
# POST /deployments/{did}/approve-next-ring
# ---------------------------------------------------------------------------


@router.post(
    "/deployments/{remediation_id}/approve-next-ring",
    response_model=ApproveNextRingResponse,
)
async def approve_next_ring(
    org_id: _uuid.UUID,
    remediation_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    _admin: None = Depends(require_role("org_admin", "admin")),
    db: AsyncSession = Depends(get_db),
    redis: Optional[Redis] = Depends(get_redis),
):
    """Approve and dispatch the next ring (pilot or broad).

    Checks canary anomaly status before proceeding.
    "deployment.dispatched" is a CRITICAL audit event.
    """
    # Check for canary anomaly
    anomaly = await check_canary_anomaly(db, remediation_id, scope.org_id)
    if anomaly["halt"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "Canary anomaly detected — deployment halted",
                "anomaly": anomaly["details"],
            },
        )

    # Determine which ring to dispatch next
    existing_rings_stmt = (
        select(DeploymentJob.ring)
        .where(
            DeploymentJob.remediation_id == remediation_id,
            DeploymentJob.org_id == scope.org_id,
        )
        .distinct()
    )
    result = await db.execute(existing_rings_stmt)
    dispatched_rings = {row[0] for row in result.all()}

    if "pilot" not in dispatched_rings:
        next_ring = "pilot"
    elif "broad" not in dispatched_rings:
        next_ring = "broad"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All rings already dispatched",
        )

    # Load remediation for playbook snapshot
    remediation = await db.get(Remediation, remediation_id)
    if not remediation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation not found",
        )

    # CRITICAL: audit deployment dispatch BEFORE creating jobs
    await audit.record(
        db,
        event_type="deployment.dispatched",
        org_id=scope.org_id,
        user_id=scope.user.id,
        resource=str(remediation_id),
        changes={
            "ring": next_ring,
            "remediation_id": str(remediation_id),
        },
    )

    # Re-create plan for the next ring
    plan = await create_deployment_plan(
        db, None, remediation_id, scope.org_id, {},
    )

    # Dispatch next ring
    jobs = await dispatch_ring(
        db, redis, plan, next_ring, remediation, user_id=scope.user.id,
    )
    await db.commit()

    return ApproveNextRingResponse(
        ring_dispatched=next_ring,
        devices_dispatched=len(jobs),
    )


# ---------------------------------------------------------------------------
# GET /deployments/{did} — ring progress + anomaly status
# ---------------------------------------------------------------------------


@router.get(
    "/deployments/{remediation_id}",
    response_model=DeploymentProgressResponse,
)
async def get_deployment_progress(
    org_id: _uuid.UUID,
    remediation_id: _uuid.UUID,
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Get deployment progress — ring status, job states, anomaly status."""
    stmt = select(DeploymentJob).where(
        DeploymentJob.remediation_id == remediation_id,
        DeploymentJob.org_id == scope.org_id,
    )
    result = await db.execute(stmt)
    jobs = result.scalars().all()

    if not jobs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No deployment jobs found",
        )

    # Group by ring → state → count
    ring_status: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for job in jobs:
        ring_status[job.ring][job.state] += 1

    # Check anomaly
    anomaly = await check_canary_anomaly(db, remediation_id, scope.org_id)

    job_statuses = [
        DeploymentJobStatus(
            id=j.id,
            device_id=j.device_id,
            ring=j.ring,
            state=j.state,
            failure_reason=j.failure_reason,
            deferred_count=j.deferred_count,
            retry_count=j.retry_count,
            created_at=j.created_at,
            completed_at=j.completed_at,
        )
        for j in jobs
    ]

    return DeploymentProgressResponse(
        remediation_id=remediation_id,
        ring_status=dict(ring_status),
        anomaly_detected=anomaly["halt"],
        anomaly_details=anomaly["details"] if anomaly["halt"] else None,
        jobs=job_statuses,
    )
