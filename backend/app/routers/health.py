"""Health check endpoint — used by Fly.io service health checks.

GET /health -> {"status": "ok", "version": "0.1.0"}
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health():
    """Fly.io health check endpoint."""
    return {"status": "ok", "version": "0.1.0"}
