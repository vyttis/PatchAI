"""PatchPilot API — FastAPI application entry point.

Middleware order (outermost first):
1. HardHeaderStrip — strips mTLS identity headers unconditionally (Invariant #2)
2. MTLSHeaderGuard — validates mTLS headers on agent routes
3. FastAPI app
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.config import settings
from backend.app.middleware.hard_header_strip import HardHeaderStrip
from backend.app.middleware.mtls_guard import MTLSHeaderGuard
from backend.app.routers.compliance import router as compliance_router
from backend.app.routers.health import router as health_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Phase 1B: warm_revocation_cache_on_startup() (Invariant #4)
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

# Wrap app with middleware — outermost layer processes first.
# MTLSHeaderGuard runs after HardHeaderStrip has cleaned headers.
app_with_middleware = HardHeaderStrip(MTLSHeaderGuard(app))
