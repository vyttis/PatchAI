"""Tests for HardHeaderStrip ASGI middleware (Security Invariant #2).

Verifies that X-Device-Cert-CN and X-Device-Cert-Fingerprint headers
are unconditionally stripped from all incoming requests.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from backend.app.main import app_with_middleware


@pytest.mark.asyncio
async def test_strips_mtls_headers():
    """Client-sent mTLS identity headers must be stripped."""
    transport = ASGITransport(app=app_with_middleware)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/health",
            headers={
                "X-Device-Cert-CN": "spoofed-device",
                "X-Device-Cert-Fingerprint": "spoofed-fingerprint",
            },
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_preserves_other_headers():
    """Non-mTLS headers must pass through unmodified."""
    transport = ASGITransport(app=app_with_middleware)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/health",
            headers={"X-Custom-Header": "should-pass"},
        )
    assert response.status_code == 200
