"""Phase 4B tests — MTTRem executive report, SSO stubs, pool tuning, rate limiter, GDPR retention.

7 integration tests using async SQLite fixtures from conftest.py.

Phase 4B Gate:
  - MTTRem executive report returns correct structure → test 1
  - SSO SAML stub returns 501 → test 2
  - SSO OIDC stub returns 501 → test 3
  - Connection pool settings are production-ready → test 4
  - Rate limiter returns 429 on burst → test 5
  - Rate limiter graceful fallback when Redis fails → test 6
  - GDPR retention deletes old non-critical entries → test 7
"""

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from backend.app.models.audit_log import AuditLog
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.intel_feeds import IntelFeedBlob
from backend.app.models.organizations import Organization
from backend.app.models.vulnerabilities import Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db, org_id, *, settings=None):
    """Create org with optional settings."""
    org = Organization(id=org_id, name="TestOrg4B", settings=settings or {})
    db.add(org)
    await db.flush()
    return org


async def _create_device(db, org_id, hostname="DESKTOP-TEST", criticality="standard"):
    device = Device(
        org_id=org_id,
        hostname=hostname,
        os_build="19045",
        criticality=criticality,
        inventory_section_hashes={},
    )
    db.add(device)
    await db.flush()
    return device


async def _create_vuln(db, cve_id="CVE-2024-EXEC01", *, cvss=8.0, epss=0.5, in_kev=True):
    vuln = Vulnerability(
        cve_id=cve_id,
        cvss_base_score=Decimal(str(cvss)),
        epss_score=Decimal(str(epss)),
        in_cisa_kev=in_kev,
        published_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
    )
    db.add(vuln)
    await db.flush()
    return vuln


async def _create_patched_dv(db, org_id, device_id, vuln_id, *, hours_delta):
    """Create a patched device-vulnerability with known MTTRem hours."""
    now = datetime.now(timezone.utc)
    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device_id,
        vuln_id=vuln_id,
        status="patched",
        signal_ingested_at=now - timedelta(hours=hours_delta),
        patched_at=now,
        urgency_score=80,
    )
    db.add(dv)
    await db.flush()
    return dv


# ---------------------------------------------------------------------------
# Test 1: MTTRem executive report structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mttrem_executive_report(db, org_id, user_id):
    """Executive report returns correct structure with p50, patch_rate, template narrative."""
    org = await _create_org(db, org_id)
    device = await _create_device(db, org_id)

    # Seed 5 patched DVs with known hours: 2, 4, 6, 8, 10
    for i, hours in enumerate([2, 4, 6, 8, 10]):
        vuln = await _create_vuln(db, f"CVE-2024-EX{i:03d}", cvss=7.0, in_kev=True)
        await _create_patched_dv(db, org_id, device.id, vuln.id, hours_delta=hours)

    await db.commit()

    from backend.app.services.executive_report import generate_mttrem_executive_report

    result = await generate_mttrem_executive_report(db, org_id, user_id, 30)

    assert result["period_days"] == 30
    assert result["fleet_size"] >= 1
    assert result["total_patched"] == 5
    assert result["patch_rate"] > 0
    # Median of [2, 4, 6, 8, 10] = 6.0
    assert result["overall_p50"] == 6.0
    assert result["overall_p90"] is not None
    assert result["overall_mean"] is not None
    # AI disabled by default → template fallback
    assert result["ai_generated"] is False
    assert result["narrative"] is not None
    assert "Compliance Report" in result["narrative"]


# ---------------------------------------------------------------------------
# Test 2: SSO SAML stub returns 501
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sso_saml_stub_501():
    """POST /api/v1/auth/saml/acs returns 501 Not Implemented."""
    from httpx import ASGITransport, AsyncClient

    from backend.app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/auth/saml/acs")

    assert resp.status_code == 501
    body = resp.json()
    assert "SAML" in body["detail"]
    assert "not yet implemented" in body["detail"].lower()


# ---------------------------------------------------------------------------
# Test 3: SSO OIDC stub returns 501
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sso_oidc_stub_501():
    """POST /api/v1/auth/oidc/callback returns 501 Not Implemented."""
    from httpx import ASGITransport, AsyncClient

    from backend.app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/auth/oidc/callback")

    assert resp.status_code == 501
    body = resp.json()
    assert "OIDC" in body["detail"]
    assert "not yet implemented" in body["detail"].lower()


# ---------------------------------------------------------------------------
# Test 4: Connection pool settings verify
# ---------------------------------------------------------------------------


def test_connection_pool_settings():
    """Verify production pool settings are configured for non-SQLite."""
    from backend.app.database import _engine_kwargs

    # In test environment, database_url is sqlite, so pool params are NOT set
    # in _engine_kwargs. We verify the code path by checking the logic directly.
    from backend.app.config import settings

    if not settings.database_url.startswith("sqlite"):
        assert _engine_kwargs.get("pool_size") == 20
        assert _engine_kwargs.get("max_overflow") == 10
        assert _engine_kwargs.get("pool_pre_ping") is True
        assert _engine_kwargs.get("pool_recycle") == 3600
    else:
        # SQLite test mode — verify that pool settings are NOT applied (correct behavior)
        assert "pool_size" not in _engine_kwargs
        assert "pool_pre_ping" not in _engine_kwargs

    # Also verify the config settings for rate limiting exist
    assert settings.rate_limit_device_rpm == 10
    assert settings.rate_limit_org_rpm == 100


# ---------------------------------------------------------------------------
# Test 5: Rate limiter returns 429 on burst
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limiter_429_on_burst():
    """Sending more than limit requests triggers 429 + Retry-After."""
    from backend.app.middleware.rate_limiter import RateLimiter

    # Track calls to inner app
    calls = []

    async def inner_app(scope, receive, send):
        calls.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # Create a mock Redis that tracks INCR calls
    mock_pool = MagicMock()
    incr_count = {}

    class FakeRedis:
        def __init__(self, connection_pool):
            pass

        async def incr(self, key):
            incr_count[key] = incr_count.get(key, 0) + 1
            return incr_count[key]

        async def expire(self, key, ttl):
            pass

        async def ttl(self, key):
            return 30

        async def aclose(self):
            pass

    with patch("backend.app.middleware.rate_limiter.Redis", FakeRedis):
        limiter = RateLimiter(inner_app, redis_pool=mock_pool, device_rpm=3, org_rpm=100)

        responses = []
        for i in range(5):
            response_parts = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(msg):
                response_parts.append(msg)

            scope = {
                "type": "http",
                "path": "/api/v1/devices/checkin",
                "headers": [(b"x-device-cert-cn", b"dev1.org1")],
            }
            await limiter(scope, receive, send)
            # Find response start
            for part in response_parts:
                if part.get("type") == "http.response.start":
                    responses.append(part)
                    break

    # First 3 should pass (200), 4th and 5th should be 429
    statuses = [r["status"] for r in responses]
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429
    assert statuses[4] == 429

    # Verify Retry-After header on 429 response
    last_429 = responses[3]
    headers = dict(last_429.get("headers", []))
    assert b"retry-after" in headers


# ---------------------------------------------------------------------------
# Test 6: Rate limiter graceful fallback on Redis error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limiter_redis_fallback():
    """When Redis raises an error, requests pass through (graceful degradation)."""
    from backend.app.middleware.rate_limiter import RateLimiter

    call_count = 0

    async def inner_app(scope, receive, send):
        nonlocal call_count
        call_count += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # Redis that always raises errors
    class FailRedis:
        def __init__(self, connection_pool):
            pass

        async def incr(self, key):
            raise ConnectionError("Redis down")

        async def aclose(self):
            pass

    mock_pool = MagicMock()

    with patch("backend.app.middleware.rate_limiter.Redis", FailRedis):
        limiter = RateLimiter(inner_app, redis_pool=mock_pool, device_rpm=1, org_rpm=1)

        for _ in range(5):
            response_parts = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(msg):
                response_parts.append(msg)

            scope = {
                "type": "http",
                "path": "/api/v1/devices/checkin",
                "headers": [(b"x-device-cert-cn", b"dev1.org1")],
            }
            await limiter(scope, receive, send)

    # All 5 requests should pass through despite Redis errors
    assert call_count == 5


# ---------------------------------------------------------------------------
# Test 7: GDPR retention cleanup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gdpr_retention_cleanup(db, org_id):
    """Retention cleanup deletes old non-critical entries, preserves critical ones."""
    # Create org with short retention for testing
    org = await _create_org(db, org_id, settings={
        "data_retention": {"audit_days": 1, "blob_days": 1}
    })

    now = datetime.now(timezone.utc)
    two_days_ago = now - timedelta(days=2)

    # Insert audit entries directly
    from sqlalchemy import insert

    # 1. Old non-critical entry (should be deleted)
    await db.execute(insert(AuditLog).values(
        id=uuid.uuid4(),
        timestamp=two_days_ago,
        org_id=org_id,
        event_type="device.checkin",
        result="ok",
    ))

    # 2. Old CRITICAL entry (should be preserved — Invariant #10)
    await db.execute(insert(AuditLog).values(
        id=uuid.uuid4(),
        timestamp=two_days_ago,
        org_id=org_id,
        event_type="deployment.dispatched",
        result="ok",
    ))

    # 3. Recent non-critical entry (should be preserved — within retention)
    await db.execute(insert(AuditLog).values(
        id=uuid.uuid4(),
        timestamp=now,
        org_id=org_id,
        event_type="device.checkin",
        result="ok",
    ))

    # 4. Old processed blob (should be deleted)
    await db.execute(insert(IntelFeedBlob).values(
        id=uuid.uuid4(),
        feed_source="kev",
        fetched_at=two_days_ago,
        blob_hash="abc123",
        status="processed",
    ))

    # 5. Old parse_error blob (should be preserved — Invariant #8)
    await db.execute(insert(IntelFeedBlob).values(
        id=uuid.uuid4(),
        feed_source="msrc",
        fetched_at=two_days_ago,
        blob_hash="def456",
        status="parse_error",
    ))

    await db.flush()

    # Run retention cleanup
    from backend.app.workers.retention import gdpr_retention_cleanup

    result = await gdpr_retention_cleanup(db)

    assert result["audit_deleted"] >= 1  # Old non-critical deleted
    assert result["blobs_deleted"] >= 1  # Old processed blob deleted

    # Verify: old critical entry preserved
    critical_entries = (await db.execute(
        select(AuditLog).where(
            AuditLog.org_id == org_id,
            AuditLog.event_type == "deployment.dispatched",
        )
    )).scalars().all()
    assert len(critical_entries) == 1

    # Verify: recent non-critical entry preserved
    recent_entries = (await db.execute(
        select(AuditLog).where(
            AuditLog.org_id == org_id,
            AuditLog.event_type == "device.checkin",
            AuditLog.timestamp >= now - timedelta(hours=1),
        )
    )).scalars().all()
    assert len(recent_entries) == 1

    # Verify: parse_error blob preserved
    error_blobs = (await db.execute(
        select(IntelFeedBlob).where(IntelFeedBlob.status == "parse_error")
    )).scalars().all()
    assert len(error_blobs) == 1


# ---------------------------------------------------------------------------
# Test 8: Celery Beat schedule includes retention task
# ---------------------------------------------------------------------------


def test_beat_schedule_includes_retention():
    """Verify gdpr_retention_cleanup is in the Celery Beat schedule at 04:00."""
    from backend.app.workers.celery_app import app as celery_app

    schedule = celery_app.conf.beat_schedule
    assert "gdpr_retention_cleanup" in schedule
    entry = schedule["gdpr_retention_cleanup"]
    assert entry["task"] == "backend.app.workers.tasks.gdpr_retention_cleanup"
    # Verify it runs at hour=4
    assert entry["schedule"].hour == {4}


# ---------------------------------------------------------------------------
# Test 9: Rate limiter skips next-command (BLPOP long-poll)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limiter_skips_next_command():
    """Rate limiter should skip /next-command path to avoid blocking BLPOP long-poll."""
    from backend.app.middleware.rate_limiter import RateLimiter

    call_count = 0

    async def inner_app(scope, receive, send):
        nonlocal call_count
        call_count += 1
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    # Even with a very low limit, next-command should never be rate limited
    mock_pool = MagicMock()

    # Use a Redis mock that always says "over limit"
    class AlwaysOverLimit:
        def __init__(self, connection_pool):
            pass

        async def incr(self, key):
            return 999

        async def expire(self, key, ttl):
            pass

        async def ttl(self, key):
            return 30

        async def aclose(self):
            pass

    with patch("backend.app.middleware.rate_limiter.Redis", AlwaysOverLimit):
        limiter = RateLimiter(inner_app, redis_pool=mock_pool, device_rpm=1, org_rpm=1)

        response_parts = []

        async def receive():
            return {"type": "http.request", "body": b""}

        async def send(msg):
            response_parts.append(msg)

        scope = {
            "type": "http",
            "path": "/api/v1/devices/next-command",
            "headers": [(b"x-device-cert-cn", b"dev1.org1")],
        }
        await limiter(scope, receive, send)

    # Request should pass through (200, not 429)
    assert call_count == 1
    assert response_parts[0]["status"] == 200
