"""Ring rollout — canary/pilot/broad deployment with anomaly halt.

Ring sizes (from CLAUDE.md):
  - Canary: max(3, 1% of affected)
  - Pilot: 10% of affected
  - Broad: remainder

Anomaly halt thresholds:
  - Failure rate >20% → halt
  - cpu_percent > 80, crash_events_24h > 2, reboots_7d > 5, disk_free < 3GB → halt
"""

import json
import logging
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.remediations import Remediation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class DeploymentPlan:
    """Immutable plan produced by create_deployment_plan."""

    plan_id: _uuid.UUID
    org_id: _uuid.UUID
    vuln_id: _uuid.UUID
    remediation_id: _uuid.UUID
    canary: list = field(default_factory=list)
    pilot: list = field(default_factory=list)
    broad: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Plan creation
# ---------------------------------------------------------------------------


async def create_deployment_plan(
    db: AsyncSession,
    vuln_id: _uuid.UUID,
    remediation_id: _uuid.UUID,
    org_id: _uuid.UUID,
    policy: dict,
) -> DeploymentPlan:
    """Get affected devices and split into canary/pilot/broad rings.

    Canary: max(3, 1% of fleet)
    Pilot: 10% of fleet
    Broad: remainder
    """
    # Get all exposed devices for this vuln + org
    stmt = (
        select(Device)
        .join(
            DeviceVulnerability,
            DeviceVulnerability.device_id == Device.id,
        )
        .where(
            DeviceVulnerability.vuln_id == vuln_id,
            DeviceVulnerability.org_id == org_id,
            DeviceVulnerability.status == "exposed",
        )
        .order_by(Device.criticality.desc(), Device.hostname)
    )
    result = await db.execute(stmt)
    all_affected = result.scalars().all()

    total = len(all_affected)
    canary_count = max(3, int(total * 0.01)) if total > 0 else 0
    pilot_count = int(total * 0.10)

    # Ensure we don't exceed total
    canary_count = min(canary_count, total)
    pilot_count = min(pilot_count, total - canary_count)

    plan = DeploymentPlan(
        plan_id=_uuid.uuid4(),
        org_id=org_id,
        vuln_id=vuln_id,
        remediation_id=remediation_id,
        canary=list(all_affected[:canary_count]),
        pilot=list(all_affected[canary_count:canary_count + pilot_count]),
        broad=list(all_affected[canary_count + pilot_count:]),
    )

    logger.info(
        "Deployment plan %s: %d canary, %d pilot, %d broad (total %d)",
        plan.plan_id, len(plan.canary), len(plan.pilot), len(plan.broad), total,
    )
    return plan


# ---------------------------------------------------------------------------
# Ring dispatch
# ---------------------------------------------------------------------------


async def dispatch_ring(
    db: AsyncSession,
    redis,
    plan: DeploymentPlan,
    ring: str,
    remediation: Remediation,
    user_id: Optional[_uuid.UUID] = None,
) -> list[DeploymentJob]:
    """Create DeploymentJob rows and push commands to Redis.

    For each device in the ring:
    1. Create DeploymentJob with playbook snapshot
    2. Redis rpush command for agent BLPOP (Invariant #12)
    3. Redis setex fast_cadence for 10 minutes
    """
    devices = getattr(plan, ring)
    jobs = []

    for device in devices:
        job = DeploymentJob(
            org_id=plan.org_id,
            device_id=device.id,
            remediation_id=plan.remediation_id,
            ring=ring,
            state="queued",
            state_updated_at=datetime.now(timezone.utc),
            playbook_snapshot=remediation.playbook,
            created_by_user_id=user_id,
        )
        db.add(job)
        await db.flush()
        jobs.append(job)

        # Push command for agent long-poll (BLPOP)
        if redis:
            command = json.dumps({
                "type": "install",
                "job_id": str(job.id),
                "playbook": job.playbook_snapshot,
            })
            await redis.rpush(f"commands:{device.id}", command)
            # Fast cadence: 10 minutes (600 seconds)
            await redis.setex(f"fast_cadence:{device.id}", 600, "1")

    logger.info(
        "Dispatched %d jobs for ring=%s plan=%s",
        len(jobs), ring, plan.plan_id,
    )
    return jobs


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------

# Telemetry thresholds from CLAUDE.md
ANOMALY_THRESHOLDS = {
    "cpu_percent_1s": 80,
    "crash_events_24h": 2,
    "reboots_7d": 5,
    "disk_free_gb_min": 3,  # below this = anomaly
}

FAILURE_RATE_THRESHOLD = 0.20  # >20% = halt


async def check_canary_anomaly(
    db: AsyncSession,
    remediation_id: _uuid.UUID,
    org_id: _uuid.UUID,
) -> dict:
    """Check if canary ring should halt deployment.

    Returns dict with 'halt' bool and 'details'.

    Halt conditions:
    1. Failure rate >20%
    2. Any completed job's telemetry_after exceeds thresholds
    """
    stmt = select(DeploymentJob).where(
        DeploymentJob.remediation_id == remediation_id,
        DeploymentJob.org_id == org_id,
        DeploymentJob.ring == "canary",
    )
    result = await db.execute(stmt)
    canary_jobs = result.scalars().all()

    total = len(canary_jobs)
    if total == 0:
        return {"halt": False, "details": {"reason": "no_canary_jobs"}}

    # 1. Failure rate check
    failed = [
        j for j in canary_jobs
        if j.state in ("failed", "failed_final")
    ]
    failure_rate = len(failed) / total

    if failure_rate > FAILURE_RATE_THRESHOLD:
        return {
            "halt": True,
            "details": {
                "reason": "failure_rate",
                "failure_rate": round(failure_rate, 4),
                "failed_count": len(failed),
                "total_count": total,
                "threshold": FAILURE_RATE_THRESHOLD,
            },
        }

    # 2. Telemetry anomaly check
    for job in canary_jobs:
        if not job.telemetry_after:
            continue
        tel = job.telemetry_after

        if tel.get("cpu_percent_1s", 0) > ANOMALY_THRESHOLDS["cpu_percent_1s"]:
            return {
                "halt": True,
                "details": {
                    "reason": "telemetry_cpu",
                    "job_id": str(job.id),
                    "cpu_percent": tel["cpu_percent_1s"],
                    "threshold": ANOMALY_THRESHOLDS["cpu_percent_1s"],
                },
            }
        if tel.get("crash_events_24h", 0) > ANOMALY_THRESHOLDS["crash_events_24h"]:
            return {
                "halt": True,
                "details": {
                    "reason": "telemetry_crashes",
                    "job_id": str(job.id),
                    "crash_events": tel["crash_events_24h"],
                    "threshold": ANOMALY_THRESHOLDS["crash_events_24h"],
                },
            }
        if tel.get("reboots_7d", 0) > ANOMALY_THRESHOLDS["reboots_7d"]:
            return {
                "halt": True,
                "details": {
                    "reason": "telemetry_reboots",
                    "job_id": str(job.id),
                    "reboots": tel["reboots_7d"],
                    "threshold": ANOMALY_THRESHOLDS["reboots_7d"],
                },
            }
        disk_free = tel.get("system_disk_free_gb")
        if disk_free is not None and disk_free < ANOMALY_THRESHOLDS["disk_free_gb_min"]:
            return {
                "halt": True,
                "details": {
                    "reason": "telemetry_disk",
                    "job_id": str(job.id),
                    "disk_free_gb": disk_free,
                    "threshold": ANOMALY_THRESHOLDS["disk_free_gb_min"],
                },
            }

    return {
        "halt": False,
        "details": {
            "failure_rate": round(failure_rate, 4),
            "failed_count": len(failed),
            "total_count": total,
        },
    }
