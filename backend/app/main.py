"""PatchPilot API — FastAPI application entry point.

Middleware order (outermost first):
1. HardHeaderStrip — strips mTLS identity headers unconditionally (Invariant #2)
2. MTLSHeaderGuard — validates mTLS headers on agent routes
3. FastAPI app
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.config import settings
from backend.app.middleware.hard_header_strip import HardHeaderStrip
from backend.app.middleware.mtls_guard import MTLSHeaderGuard
from backend.app.routers.compliance import router as compliance_router
from backend.app.routers.deployment_packs import router as deployment_packs_router
from backend.app.routers.devices import router as devices_router
from backend.app.routers.enrollment import router as enrollment_router
from backend.app.routers.health import router as health_router
from backend.app.routers.metrics import router as metrics_router
from backend.app.routers.deployments import router as deployments_router
from backend.app.routers.exposures import router as exposures_router
from backend.app.routers.normalization import router as normalization_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Invariant #4: warm revocation cache on startup
    try:
        if settings.redis_url:
            from redis.asyncio import Redis

            from backend.app.database import async_session
            from backend.app.services.pki import warm_revocation_cache_on_startup

            redis = Redis.from_url(settings.redis_url, decode_responses=True)
            try:
                async with async_session() as db:
                    count = await warm_revocation_cache_on_startup(redis, db)
                    logger.info("Revocation cache warmed: %d certs", count)
            finally:
                await redis.aclose()
    except Exception:
        logger.warning("Failed to warm revocation cache on startup", exc_info=True)
    yield


app = FastAPI(
    title="PatchPilot API",
    description="Exploit-to-Remediation Automation Platform",
    version="0.1.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(compliance_router)
app.include_router(enrollment_router)
app.include_router(devices_router)
app.include_router(deployment_packs_router)
app.include_router(metrics_router)
app.include_router(normalization_router)
app.include_router(exposures_router)
app.include_router(deployments_router)

# Wrap app with middleware — outermost layer processes first.
# MTLSHeaderGuard runs after HardHeaderStrip has cleaned headers.
app_with_middleware = HardHeaderStrip(MTLSHeaderGuard(app))
