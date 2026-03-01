"""Device authentication via mTLS headers.

Security Invariant #3:  get_mtls_device() validates cert_fingerprint against DB
                        on every agent request. Tier 1: Redis revocation check.
                        Tier 2: DB query. Never skip either tier.
Security Invariant #6:  Agent auth = mTLS only. Agents do NOT use JWT.
"""

import logging
import uuid as _uuid
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.redis import get_redis
from backend.app.models.devices import Device

logger = logging.getLogger(__name__)


def extract_org_from_cn(cert_cn: str) -> _uuid.UUID:
    """Extract org_id from certificate CN.

    CN format: {device_id}.{org_id}
    """
    parts = cert_cn.rsplit(".", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid cert CN format: {cert_cn}")
    return _uuid.UUID(parts[1])


async def get_mtls_device(
    request: Request,
    redis: Optional[Redis] = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
) -> Device:
    """Validate mTLS device identity from headers injected by Fly.io proxy.

    Tier 1: Redis revocation check (fast path)
    Tier 2: DB check (authoritative)
    """
    cert_cn = request.headers.get("x-device-cert-cn")
    cert_fp = request.headers.get("x-device-cert-fingerprint")

    if not cert_cn or not cert_fp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing mTLS device identity headers",
        )

    # Tier 1: Redis revocation check (fast path)
    if redis:
        try:
            org_id = extract_org_from_cn(cert_cn)
            is_revoked = await redis.sismember(f"revoked:{org_id}", cert_fp)
            if is_revoked:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Certificate revoked",
                )
        except HTTPException:
            raise
        except (RedisError, ValueError) as exc:
            # Redis failure or bad CN format — fall through to DB (never silent pass)
            logger.warning("Redis revocation check failed: %s", exc)

    # Tier 2: DB check (authoritative)
    device = await db.scalar(
        select(Device).where(
            Device.cert_fingerprint == cert_fp,
            Device.cert_revoked_at.is_(None),
        )
    )
    if not device:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Device not found or certificate revoked",
        )
    return device
