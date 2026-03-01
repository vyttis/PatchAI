"""Device router — mTLS-protected endpoints for agent communication.

All endpoints require get_mtls_device() — agent auth is mTLS only (Invariant #6).
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Response
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.device_auth import get_mtls_device
from backend.app.dependencies.redis import get_redis
from backend.app.models.devices import Device
from backend.app.schemas.enrollment import DeviceCheckinRequest, DeviceCheckinResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


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
    5. Check Redis for pending commands
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

            device.inventory_section_hashes = new_stored
            # Phase 2: enqueue vuln_match_apps.delay(device.id), vuln_match_os.delay(device.id)

    await db.commit()

    # Check for pending commands in Redis
    commands_pending = False
    if redis:
        try:
            commands_pending = bool(await redis.exists(f"commands:{device.id}"))
        except Exception:
            logger.debug("Redis commands check failed", exc_info=True)

    return DeviceCheckinResponse(commands_pending=commands_pending)


@router.get("/next-command", status_code=204)
async def next_command(
    device: Device = Depends(get_mtls_device),
):
    """Long-poll for next command. Phase 3B stub — returns 204."""
    return Response(status_code=204)


@router.post("/job-status", status_code=204)
async def update_job_status(
    device: Device = Depends(get_mtls_device),
):
    """Update job execution status. Phase 3A stub — returns 204."""
    return Response(status_code=204)
