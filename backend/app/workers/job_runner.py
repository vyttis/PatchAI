"""Job runner — post-deployment verification.

verify_remediation() pushes a verify command to the agent and sets
a short fast-cadence window (120s) so the agent picks it up quickly.

Called by verify_remediation_task (Celery) after a job reaches "complete".
"""

import json
import logging
import uuid as _uuid

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.deployment_jobs import DeploymentJob

logger = logging.getLogger(__name__)

VERIFY_FAST_CADENCE_SECONDS = 120  # 2 minutes


async def verify_remediation(
    db: AsyncSession,
    redis: Redis | None,
    job_id: _uuid.UUID,
) -> dict:
    """Push verify command to agent + set 2-min fast cadence.

    Called after job reaches 'complete'. Agent will re-collect
    KB baseline and report back via POST /job-status.
    """
    job = await db.get(DeploymentJob, job_id)
    if not job:
        logger.warning("verify_remediation: job %s not found", job_id)
        return {"status": "job_not_found"}

    if redis:
        command = json.dumps({
            "type": "verify",
            "job_id": str(job.id),
            "playbook": job.playbook_snapshot,
        })
        await redis.rpush(f"commands:{job.device_id}", command)
        # Fast cadence: 2 minutes for verification pickup
        await redis.setex(
            f"fast_cadence:{job.device_id}",
            VERIFY_FAST_CADENCE_SECONDS,
            "1",
        )

    logger.info("Verify command dispatched for job %s device %s", job.id, job.device_id)
    return {"status": "verify_dispatched", "job_id": str(job_id)}
