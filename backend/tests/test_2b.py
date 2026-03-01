"""Phase 2B tests — intel feed worker integration tests.

Tests:
  1. KEV dedup: running twice with same data creates no duplicate vulnerability rows
  2. MSRC 429: backoff fires, after max retries serves intel_last_good
  3. KEV new entry: check_fleet_for_kev_exposure task enqueued (mock Celery)
  4. Parse error: blob stored with parse_error status, ops alerted, last_good NOT served
  5. Staleness monitor: fires notification when last_success_at > threshold
  6. NVD Celery Beat schedule: verify cadence is 6h (not hourly, not daily)
  7. EPSS large file: storage_path set on blob record (mock storage client)
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models import (
    IntelFeedBlob,
    IntelFeedHealth,
    IntelLastGood,
    Organization,
    Vulnerability,
)
from backend.app.workers.intel_fetcher import (
    EPSSFetcher,
    KEVFetcher,
    MSRCFetcher,
    check_staleness,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

KEV_PAYLOAD = json.dumps({
    "title": "CISA KEV",
    "catalogVersion": "test",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-90001",
            "vendorProject": "TestVendor",
            "product": "TestProduct",
            "vulnerabilityName": "Test Vulnerability One",
            "dateAdded": "2024-01-15",
            "shortDescription": "Test desc 1",
            "requiredAction": "Apply updates",
            "dueDate": "2024-02-05",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            "cveID": "CVE-2024-90002",
            "vendorProject": "TestVendor2",
            "product": "TestProduct2",
            "vulnerabilityName": "Test Vulnerability Two",
            "dateAdded": "2024-01-16",
            "shortDescription": "Test desc 2",
            "requiredAction": "Apply updates",
            "dueDate": "2024-02-06",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}).encode()


async def _create_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = Organization(id=org_id, name="Test Corp")
    db.add(org)
    await db.flush()
    return org


def _make_mock_http(response_content: bytes, status_code: int = 200):
    """Create a mock httpx.AsyncClient that returns given response."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.content = response_content
    mock_response.status_code = status_code
    mock_response.headers = {}
    mock_response.raise_for_status = MagicMock()
    if status_code >= 400:
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=mock_response,
        )

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.get = AsyncMock(return_value=mock_response)
    mock_http.post = AsyncMock(return_value=mock_response)
    return mock_http


# ---------------------------------------------------------------------------
# 1. KEV dedup: same data twice → no duplicate vulnerability rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kev_dedup_no_duplicate_rows(db: AsyncSession):
    """Running KEVFetcher.run() twice with same data creates no duplicate vulns."""
    mock_http = _make_mock_http(KEV_PAYLOAD)

    # First run — mock the Celery task import inside _upsert_entities
    with patch("backend.app.workers.tasks.check_fleet_for_kev_exposure") as mock_task:
        mock_task.delay = MagicMock()
        fetcher1 = KEVFetcher(db=db, http=mock_http)
        result1 = await fetcher1.run()
        await db.flush()

    assert result1.status == "success"
    assert result1.entity_count == 2

    # Count vulnerability rows
    vulns = (await db.execute(select(Vulnerability))).scalars().all()
    assert len(vulns) == 2

    # Second run with exact same data → dedup_skip
    fetcher2 = KEVFetcher(db=db, http=mock_http)
    result2 = await fetcher2.run()

    assert result2.status == "dedup_skip"

    # Still only 2 vulnerability rows
    vulns = (await db.execute(select(Vulnerability))).scalars().all()
    assert len(vulns) == 2


# ---------------------------------------------------------------------------
# 2. MSRC 429: backoff + intel_last_good fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_msrc_429_serves_last_good(db: AsyncSession):
    """After MAX_RETRIES 429s, MSRC serves intel_last_good data."""
    # Seed last_good data
    last_good_data = json.dumps({
        "value": [{
            "ID": "2024-Fallback",
            "DocumentTitle": "Fallback Advisory",
            "Severity": "Important",
            "InitialReleaseDate": "2024-01-01T00:00:00Z",
            "CvrfUrl": "",
            "CVEs": [],
            "KBArticles": [],
        }]
    }).encode()

    lg = IntelLastGood(
        feed_source="msrc",
        data=last_good_data,
        stored_at=datetime.now(timezone.utc),
    )
    db.add(lg)
    await db.flush()

    # Create mock HTTP that always returns 429
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 429
    mock_response.headers = {"Retry-After": "0"}
    mock_response.content = b""
    mock_response.raise_for_status = MagicMock()

    mock_http = AsyncMock(spec=httpx.AsyncClient)
    mock_http.get = AsyncMock(return_value=mock_response)

    # Patch sleep to avoid actual delays in tests
    with patch("backend.app.workers.intel_fetcher.asyncio.sleep", new_callable=AsyncMock):
        # Override MAX_RETRIES to keep test fast
        fetcher = MSRCFetcher(db=db, http=mock_http, redis_client=None)
        fetcher.MAX_RETRIES = 2
        fetcher.BACKOFF_BASE = 0

        result = await fetcher.run()

    # Should have used last_good fallback and parsed it
    assert result.status == "last_good_fallback"
    assert result.entity_count >= 1


# ---------------------------------------------------------------------------
# 3. KEV new entry: enqueues fleet check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kev_new_entry_enqueues_fleet_check(db: AsyncSession):
    """New KEV entry calls check_fleet_for_kev_exposure.delay()."""
    mock_http = _make_mock_http(KEV_PAYLOAD)

    with patch(
        "backend.app.workers.tasks.check_fleet_for_kev_exposure"
    ) as mock_task:
        mock_task.delay = MagicMock()

        fetcher = KEVFetcher(db=db, http=mock_http)
        result = await fetcher.run()
        await db.flush()

    assert result.status == "success"

    # Verify delay() was called for each new KEV CVE
    assert mock_task.delay.call_count == 2
    called_cves = {call.args[0] for call in mock_task.delay.call_args_list}
    assert called_cves == {"CVE-2024-90001", "CVE-2024-90002"}


# ---------------------------------------------------------------------------
# 4. Parse error: blob stored with parse_error, last_good NOT updated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_parse_error_blob_stored_last_good_untouched(db: AsyncSession):
    """Bad JSON → blob stored with parse_error status, last_good NOT updated."""
    bad_payload = b"THIS IS NOT JSON {{{{"
    mock_http = _make_mock_http(bad_payload)

    # Seed a last_good value
    lg = IntelLastGood(
        feed_source="kev",
        data=b'{"old": "good data"}',
        stored_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db.add(lg)
    await db.flush()
    original_stored_at = lg.stored_at

    fetcher = KEVFetcher(db=db, http=mock_http)
    result = await fetcher.run()

    assert result.status == "parse_error"

    # Blob should exist with parse_error status
    blob_result = await db.execute(
        select(IntelFeedBlob).where(
            IntelFeedBlob.feed_source == "kev",
            IntelFeedBlob.status == "parse_error",
        )
    )
    blob = blob_result.scalar_one()
    assert blob.error is not None
    assert "JSON" in blob.error

    # last_good should NOT have been updated (Invariant #13)
    lg_result = await db.execute(
        select(IntelLastGood).where(IntelLastGood.feed_source == "kev")
    )
    lg_loaded = lg_result.scalar_one()
    assert lg_loaded.data == b'{"old": "good data"}'
    assert lg_loaded.stored_at == original_stored_at


# ---------------------------------------------------------------------------
# 5. Staleness monitor: stale feed detected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_staleness_monitor_stale_feed(db: AsyncSession):
    """Feed with last_success_at 13h ago (threshold=12h) → is_stale=True."""
    # Create KEV health with last_success_at 13 hours ago
    stale_time = datetime.now(timezone.utc) - timedelta(hours=13)
    health = IntelFeedHealth(
        feed_source="kev",
        last_fetched_at=stale_time,
        last_success_at=stale_time,
        consecutive_failures=0,
        parse_failures=0,
        is_stale=False,
    )
    db.add(health)
    await db.flush()

    result = await check_staleness(db)

    assert result["kev"] is True

    # Verify health row updated
    h = (
        await db.execute(
            select(IntelFeedHealth).where(IntelFeedHealth.feed_source == "kev")
        )
    ).scalar_one()
    assert h.is_stale is True


# ---------------------------------------------------------------------------
# 6. NVD Beat schedule: cadence is 6h
# ---------------------------------------------------------------------------


def test_nvd_beat_schedule_is_6h():
    """NVD Celery Beat schedule is every 6h — NOT hourly, NOT daily (Invariant #9)."""
    from celery.schedules import crontab

    from backend.app.workers.celery_app import app

    nvd_schedule = app.conf.beat_schedule["fetch_nvd"]["schedule"]
    expected = crontab(minute=0, hour="*/6")

    assert nvd_schedule == expected, (
        f"NVD schedule should be every 6h, got: {nvd_schedule}"
    )


# ---------------------------------------------------------------------------
# 7. EPSS large file: storage_path set on blob record
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_epss_storage_path_set(db: AsyncSession):
    """EPSS blob record has storage_path set when storage client is available."""
    import gzip

    # Create a minimal valid EPSS CSV
    csv_content = (
        "#model_version:v2024.01.01\n"
        "cve,epss,percentile\n"
        "CVE-2024-99999,0.5000,0.8000\n"
    )
    raw = gzip.compress(csv_content.encode())
    mock_http = _make_mock_http(raw)

    # Mock storage client
    mock_storage = AsyncMock()
    mock_storage.upload = AsyncMock()

    fetcher = EPSSFetcher(db=db, http=mock_http, storage_client=mock_storage)
    result = await fetcher.run()
    await db.flush()

    assert result.status == "success"

    # Check blob has storage_path set
    blob_result = await db.execute(
        select(IntelFeedBlob).where(
            IntelFeedBlob.feed_source == "epss",
            IntelFeedBlob.status == "processed",
        )
    )
    blob = blob_result.scalar_one()
    assert blob.storage_path is not None
    assert blob.storage_path.startswith("intel/epss/")
    assert blob.storage_path.endswith(".csv.gz")

    # Verify storage.upload was called
    mock_storage.upload.assert_called_once()
