"""Device router — mTLS-protected endpoints for agent communication.

All endpoints require get_mtls_device() — agent auth is mTLS only (Invariant #6).
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.device_auth import get_mtls_device
from backend.app.models.devices import Device
from backend.app.schemas.enrollment import DeviceCheckinRequest, DeviceCheckinResponse

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])


@router.post("/checkin", response_model=DeviceCheckinResponse)
async def device_checkin(
    body: DeviceCheckinRequest,
    device: Device = Depends(get_mtls_device),
    db: AsyncSession = Depends(get_db),
):
    """Receive device inventory check-in, update last_seen_at."""
    device.last_seen_at = datetime.now(timezone.utc)
    if body.hostname:
        device.hostname = body.hostname
    if body.os_build:
        device.os_build = body.os_build
    await db.commit()
    return DeviceCheckinResponse(commands_pending=False)


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
