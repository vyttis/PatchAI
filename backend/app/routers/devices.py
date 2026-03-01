"""Device router — mTLS-protected endpoints for agent communication.

All endpoints require get_mtls_device() — agent auth is mTLS only (Invariant #6).
WebSocket endpoint uses JWT auth (dashboard users, not agents).
"""

import asyncio
import json
import logging
import uuid as _uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.dependencies.device_auth import get_mtls_device
from backend.app.dependencies.redis import get_redis
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.devices import Device
from backend.app.schemas.devices import JobStatusRequest, JobStatusResponse, NextCommandResponse
from backend.app.schemas.enrollment import DeviceCheckinRequest, DeviceCheckinResponse
from backend.app.services.state_machine import transition

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


# ---------------------------------------------------------------------------
# WebSocket JWT helper
# ---------------------------------------------------------------------------


def _validate_ws_token(token: str, org_id: _uuid.UUID) -> dict:
    """Validate JWT for WebSocket connection. Returns payload dict.

    Reuses the same JWT validation logic as get_current_user() but
    also checks that the token's org_id matches the requested org_id
    (Invariant #16: tenant isolation).
    """
    try:
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
    except JWTError as exc:
        raise ValueError(f"Invalid JWT: {exc}") from exc

    token_org_id = payload.get("org_id")
    if not token_org_id or _uuid.UUID(token_org_id) != org_id:
        raise ValueError("org_id mismatch")

    return payload


# ---------------------------------------------------------------------------
# POST /checkin — inventory delta check-in
# ---------------------------------------------------------------------------


@router.post("/checkin", response_model=DeviceCheckinResponse)
async def device_checkin(
    body: DeviceCheckinRequest,
    device: Device = Depends(get_mtls_device),
    db: AsyncSession = Depends(get_db),
    redis: Optional[Redis] = Depends(get_redis),
):
    """Receive device inventory check-in with delta hashing.

    1. Always update last_seen_at + hostname/os_build
    2. Compare section_hashes with device.inventory_section_hashes
    3. If hashes differ or full_checkin: update stored hashes + process sections
    4. If KB section has stale metadata: annotate in inventory_section_hashes
    5. Check Redis for pending commands + fast cadence
    """
    device.last_seen_at = datetime.now(timezone.utc)
    if body.hostname:
        device.hostname = body.hostname
    if body.os_build:
        device.os_build = body.os_build

    # Delta hash comparison
    if body.section_hashes:
        stored_hashes = device.inventory_section_hashes or {}
        hashes_changed = body.section_hashes != {
            k: v for k, v in stored_hashes.items() if k in ("apps", "kbs", "os")
        }

        if hashes_changed or body.full_checkin:
            # Update stored hashes
            new_stored = dict(stored_hashes)
            new_stored.update(body.section_hashes)

            # Check for stale KB data
            if body.sections and "kbs" in body.sections:
                kb_data = body.sections["kbs"]
                kb_meta = kb_data.get("meta", {}) if isinstance(kb_data, dict) else {}
                new_stored["kbs_stale"] = kb_meta.get("stale", False)
            else:
                # No KB section sent — keep previous stale flag
                pass

            # Store actual inventory content for vuln matching (Phase 2C)
            if body.sections:
                if "apps" in body.sections and isinstance(body.sections["apps"], list):
                    new_stored["apps_inventory"] = body.sections["apps"]
                if "kbs" in body.sections:
                    kb_section = body.sections["kbs"]
                    if isinstance(kb_section, list):
                        new_stored["kbs_installed"] = kb_section
                    elif isinstance(kb_section, dict):
                        new_stored["kbs_installed"] = kb_section.get("kbs", [])

            device.inventory_section_hashes = new_stored

            # Phase 2C: enqueue vulnerability matching
            try:
                from backend.app.workers.tasks import vuln_match_apps_task, vuln_match_os_task
                vuln_match_os_task.delay(str(device.id))
                vuln_match_apps_task.delay(str(device.id))
            except Exception:
                logger.warning("Failed to enqueue vuln matching for device %s", device.id)

    await db.commit()

    # Check for pending commands and fast cadence in Redis
    commands_pending = False
    fast_cadence = False
    if redis:
        try:
            commands_pending = bool(await redis.exists(f"commands:{device.id}"))
        except Exception:
            logger.debug("Redis commands check failed", exc_info=True)
        try:
            fast_cadence = bool(await redis.exists(f"fast_cadence:{device.id}"))
        except Exception:
            logger.debug("Redis fast_cadence check failed", exc_info=True)

    return DeviceCheckinResponse(commands_pending=commands_pending, fast_cadence=fast_cadence)


# ---------------------------------------------------------------------------
# GET /next-command — BLPOP long-poll (Invariant #12)
# ---------------------------------------------------------------------------


@router.get("/next-command", response_model=NextCommandResponse)
async def next_command(
    device: Device = Depends(get_mtls_device),
    redis: Optional[Redis] = Depends(get_redis),
):
    """BLPOP long-poll for next command (Invariant #12).

    Timeout = 55s. Always returns 200 with JSON body.
    Returns {command: null} on timeout, NOT 204.
    If no Redis configured: return {command: null} immediately.
    """
    if not redis:
        return NextCommandResponse(command=None)

    try:
        result = await redis.blpop(f"commands:{device.id}", timeout=55)
    except Exception:
        logger.warning("Redis BLPOP failed for device %s", device.id, exc_info=True)
        return NextCommandResponse(command=None)

    if result is None:
        # Timeout — no command available
        return NextCommandResponse(command=None)

    # result = (key, value) tuple from BLPOP
    _key, raw = result
    try:
        command = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        logger.error("Malformed command in Redis for device %s: %s", device.id, raw)
        return NextCommandResponse(command=None)

    return NextCommandResponse(command=command)


# ---------------------------------------------------------------------------
# POST /job-status — agent reports job execution state
# ---------------------------------------------------------------------------


@router.post("/job-status", response_model=JobStatusResponse)
async def update_job_status(
    body: JobStatusRequest,
    device: Device = Depends(get_mtls_device),
    db: AsyncSession = Depends(get_db),
    redis: Optional[Redis] = Depends(get_redis),
):
    """Update job execution status from agent.

    1. Validate job belongs to this device (ownership check)
    2. Store telemetry if provided (before=queued, after=other states)
    3. state_machine.transition() — CRITICAL audit before state change (Invariant #10)
    4. Publish to Redis pub/sub for WebSocket live feed
    5. If new_state=complete → enqueue verify_remediation
    """
    job = await db.get(DeploymentJob, body.job_id)
    if not job or job.device_id != device.id:
        raise HTTPException(status_code=404, detail="Job not found")

    old_state = job.state

    # Store telemetry snapshot
    if body.telemetry:
        if job.state == "queued":
            job.telemetry_before = body.telemetry
        else:
            job.telemetry_after = body.telemetry

    # Transition state — audit-before-change via state_machine (Invariant #10)
    await transition(db, job, body.status, reason=body.reason)
    await db.commit()

    # Publish state change to WebSocket channel via Redis pub/sub
    if redis:
        try:
            msg = json.dumps({
                "event": "job.state_changed",
                "job_id": str(job.id),
                "device_id": str(job.device_id),
                "old_state": old_state,
                "new_state": body.status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            await redis.publish(f"deployments:{job.org_id}", msg)
        except Exception:
            logger.warning("Redis publish failed for job %s", job.id, exc_info=True)

    # If complete: enqueue verification task
    if body.status == "complete":
        try:
            from backend.app.workers.tasks import verify_remediation_task
            verify_remediation_task.delay(str(job.id))
        except Exception:
            logger.warning("Failed to enqueue verify_remediation for job %s", job.id)

    return JobStatusResponse(accepted=True)


# ---------------------------------------------------------------------------
# WebSocket /ws/orgs/{org_id}/deployments — live deployment feed
# ---------------------------------------------------------------------------


@router.websocket("/ws/orgs/{org_id}/deployments")
async def deployment_ws(websocket: WebSocket, org_id: _uuid.UUID):
    """WebSocket for live deployment updates.

    1. Accept connection
    2. Validate JWT token from query param (Invariant #16: tenant isolation)
    3. Subscribe to Redis pub/sub channel deployments:{org_id}
    4. Forward messages to WebSocket client
    """
    await websocket.accept()

    # Auth: extract token from query params
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing auth token")
        return

    # Validate JWT + org_id match
    try:
        _validate_ws_token(token, org_id)
    except (ValueError, Exception):
        await websocket.close(code=4003, reason="Invalid token")
        return

    # Need Redis for pub/sub
    if not settings.redis_url:
        await websocket.close(code=4002, reason="Real-time updates unavailable")
        return

    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"deployments:{org_id}")

    try:
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg["type"] == "message":
                await websocket.send_text(msg["data"])
            # Brief yield to allow disconnect detection
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.debug("WebSocket error for org %s", org_id, exc_info=True)
    finally:
        await pubsub.unsubscribe(f"deployments:{org_id}")
        await pubsub.aclose()
        await redis_client.aclose()
