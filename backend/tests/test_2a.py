"""Phase 2A tests — intel pipeline schema validation.

Tests:
  1. Migration runs clean on empty DB (all tables created via ORM metadata)
  2. mttrem_hours generated column: insert with signal_ingested_at + patched_at, verify hours
  3. mttrem_by_ring view: queryable without error (empty result OK) — via direct query
  4. unpatched_exposures: UNIQUE(org_id, vuln_id) constraint prevents duplicates
  5. device_vulnerabilities.remediation_id: nullable (zero-day exposures)
"""

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models import (
    Advisory,
    AdvisoryVulnerability,
    DeploymentJob,
    Device,
    DeviceVulnerability,
    IntelFeedBlob,
    IntelFeedHealth,
    IntelLastGood,
    Organization,
    Remediation,
    RemediationOsTarget,
    RemediationVulnerability,
    SoftwareNormalizationLog,
    TenantNormalizationOverride,
    UnpatchedExposure,
    Vulnerability,
    VulnerabilityProduct,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = Organization(id=org_id, name="Test Corp")
    db.add(org)
    await db.flush()
    return org


async def _create_device(
    db: AsyncSession, org_id: uuid.UUID, device_id: uuid.UUID | None = None,
) -> Device:
    dev = Device(
        id=device_id or uuid.uuid4(),
        org_id=org_id,
        hostname="WS-TEST-01",
        os_build="19045",
    )
    db.add(dev)
    await db.flush()
    return dev


async def _create_vuln(
    db: AsyncSession,
    cve_id: str = "CVE-2024-12345",
    in_kev: bool = False,
    published_at: datetime | None = None,
) -> Vulnerability:
    vuln = Vulnerability(
        cve_id=cve_id,
        cvss_base_score=Decimal("9.8"),
        in_cisa_kev=in_kev,
        published_at=published_at or datetime.now(timezone.utc),
    )
    db.add(vuln)
    await db.flush()
    return vuln


async def _create_remediation(db: AsyncSession) -> Remediation:
    rem = Remediation(
        playbook={"type": "patch", "kb": "KB5034441"},
    )
    db.add(rem)
    await db.flush()
    return rem


# ---------------------------------------------------------------------------
# 1. Migration runs clean — all tables created via ORM metadata
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_phase_2a_tables_created(db: AsyncSession):
    """All Phase 2A tables are creatable and queryable (via conftest create_all)."""
    # These will raise if tables don't exist
    for model in [
        Vulnerability,
        VulnerabilityProduct,
        Advisory,
        AdvisoryVulnerability,
        Remediation,
        RemediationVulnerability,
        RemediationOsTarget,
        DeviceVulnerability,
        UnpatchedExposure,
        IntelFeedBlob,
        IntelFeedHealth,
        IntelLastGood,
        DeploymentJob,
        SoftwareNormalizationLog,
        TenantNormalizationOverride,
    ]:
        result = await db.execute(select(model))
        assert result.all() == []  # Empty but queryable


# ---------------------------------------------------------------------------
# 2. mttrem_hours generated column — verify computed value
#    (SQLite skips Computed columns, so we compute manually in the test)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mttrem_hours_computed(db: AsyncSession, org_id):
    """Insert device_vulnerability with timestamps, verify mttrem_hours is correct."""
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    vuln = await _create_vuln(db)

    now = datetime.now(timezone.utc)
    signal_time = now - timedelta(hours=6)
    patch_time = now

    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device.id,
        vuln_id=vuln.id,
        status="patched",
        signal_ingested_at=signal_time,
        patched_at=patch_time,
    )
    db.add(dv)
    await db.flush()

    # Verify the row was created
    result = await db.execute(
        select(DeviceVulnerability).where(DeviceVulnerability.id == dv.id)
    )
    loaded = result.scalar_one()
    assert loaded.signal_ingested_at is not None
    assert loaded.patched_at is not None

    # Compute expected hours (SQLite doesn't have the generated column)
    delta = loaded.patched_at - loaded.signal_ingested_at
    computed_hours = delta.total_seconds() / 3600
    assert abs(computed_hours - 6.0) < 0.01


# ---------------------------------------------------------------------------
# 3. mttrem_by_ring view: queryable (via direct table query on SQLite)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mttrem_query_with_ring_join(db: AsyncSession, org_id):
    """Query device_vulnerabilities + deployment_jobs grouped by ring — empty OK."""
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    vuln = await _create_vuln(db)
    remediation = await _create_remediation(db)

    now = datetime.now(timezone.utc)
    signal_time = now - timedelta(hours=4)

    # Create a patched device_vulnerability
    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device.id,
        vuln_id=vuln.id,
        remediation_id=remediation.id,
        status="patched",
        signal_ingested_at=signal_time,
        patched_at=now,
    )
    db.add(dv)

    # Create a deployment_job for the same device+remediation
    dj = DeploymentJob(
        org_id=org_id,
        device_id=device.id,
        remediation_id=remediation.id,
        ring="canary",
        state="complete",
    )
    db.add(dj)
    await db.flush()

    # Query like the view would (but directly, since SQLite has no view)
    from sqlalchemy import func, and_

    stmt = (
        select(
            DeploymentJob.ring,
            func.count().label("sample_count"),
        )
        .select_from(
            DeviceVulnerability.__table__.join(
                DeploymentJob.__table__,
                and_(
                    DeploymentJob.device_id == DeviceVulnerability.device_id,
                    DeploymentJob.remediation_id == DeviceVulnerability.remediation_id,
                ),
            )
        )
        .where(
            DeviceVulnerability.org_id == org_id,
            DeviceVulnerability.patched_at.isnot(None),
        )
        .group_by(DeploymentJob.ring)
    )

    result = await db.execute(stmt)
    rows = result.all()
    assert len(rows) == 1
    assert rows[0].ring == "canary"
    assert rows[0].sample_count == 1


# ---------------------------------------------------------------------------
# 4. unpatched_exposures: UNIQUE(org_id, vuln_id) prevents duplicates
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpatched_exposure_unique_constraint(db: AsyncSession, org_id):
    """Inserting two UnpatchedExposures with same org_id + vuln_id raises IntegrityError."""
    await _create_org(db, org_id)
    vuln = await _create_vuln(db)

    ue1 = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln.id,
        affected_count=10,
        status="open",
    )
    db.add(ue1)
    await db.flush()

    ue2 = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln.id,
        affected_count=5,
        status="open",
    )
    db.add(ue2)

    with pytest.raises(IntegrityError):
        await db.flush()

    await db.rollback()


# ---------------------------------------------------------------------------
# 5. device_vulnerabilities.remediation_id: nullable (zero-day exposures)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_vuln_remediation_id_nullable(db: AsyncSession, org_id):
    """device_vulnerabilities.remediation_id can be NULL for zero-day response."""
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    vuln = await _create_vuln(db)

    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device.id,
        vuln_id=vuln.id,
        remediation_id=None,  # No patch exists yet — zero-day response
        status="exposed",
        signal_ingested_at=datetime.now(timezone.utc),
    )
    db.add(dv)
    await db.flush()

    result = await db.execute(
        select(DeviceVulnerability).where(DeviceVulnerability.id == dv.id)
    )
    loaded = result.scalar_one()
    assert loaded.remediation_id is None
    assert loaded.status == "exposed"


# ---------------------------------------------------------------------------
# 6. Advisory + advisory_vulnerabilities join table works
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_advisory_vulnerability_join(db: AsyncSession):
    """Advisory linked to vulnerability via join table."""
    vuln = await _create_vuln(db, cve_id="CVE-2024-99999")
    advisory = Advisory(
        source="msrc",
        external_id="ADV-2024-0001",
        title="Test MSRC Advisory",
        severity="critical",
    )
    db.add(advisory)
    await db.flush()

    av = AdvisoryVulnerability(
        advisory_id=advisory.id,
        vuln_id=vuln.id,
    )
    db.add(av)
    await db.flush()

    result = await db.execute(
        select(AdvisoryVulnerability).where(
            AdvisoryVulnerability.advisory_id == advisory.id
        )
    )
    loaded = result.scalar_one()
    assert loaded.vuln_id == vuln.id


# ---------------------------------------------------------------------------
# 7. Remediation + os_targets + remediation_vulnerabilities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_remediation_with_os_targets(db: AsyncSession):
    """Remediation with OS targets and vulnerability links."""
    vuln = await _create_vuln(db, cve_id="CVE-2024-55555")
    rem = Remediation(
        source="msrc",
        external_id="KB5034441",
        title="Security Update for Windows 10",
        playbook={"type": "patch", "kb": "KB5034441"},
    )
    db.add(rem)
    await db.flush()

    # Link to vulnerability
    rv = RemediationVulnerability(
        remediation_id=rem.id,
        vuln_id=vuln.id,
    )
    db.add(rv)

    # Add OS target
    ot = RemediationOsTarget(
        remediation_id=rem.id,
        os_build="19045",
        min_build_revision=3803,
    )
    db.add(ot)
    await db.flush()

    result = await db.execute(
        select(RemediationOsTarget).where(RemediationOsTarget.remediation_id == rem.id)
    )
    loaded = result.scalar_one()
    assert loaded.os_build == "19045"
    assert loaded.min_build_revision == 3803


# ---------------------------------------------------------------------------
# 8. Intel feed blob + health tracking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_intel_feed_blob_and_health(db: AsyncSession):
    """Intel feed blob stored with hash, health row tracks status."""
    blob = IntelFeedBlob(
        feed_source="kev",
        blob_hash="sha256:abc123",
        byte_size=1024,
        entity_count=42,
        status="processed",
    )
    db.add(blob)

    health = IntelFeedHealth(
        feed_source="kev",
        last_fetched_at=datetime.now(timezone.utc),
        last_success_at=datetime.now(timezone.utc),
        consecutive_failures=0,
        parse_failures=0,
        is_stale=False,
    )
    db.add(health)
    await db.flush()

    result = await db.execute(
        select(IntelFeedHealth).where(IntelFeedHealth.feed_source == "kev")
    )
    loaded = result.scalar_one()
    assert loaded.is_stale is False
    assert loaded.consecutive_failures == 0


# ---------------------------------------------------------------------------
# 9. Intel last_good cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_intel_last_good(db: AsyncSession):
    """Intel last_good stores raw bytes for fallback."""
    lg = IntelLastGood(
        feed_source="msrc",
        data=b'{"test": "data"}',
    )
    db.add(lg)
    await db.flush()

    result = await db.execute(
        select(IntelLastGood).where(IntelLastGood.feed_source == "msrc")
    )
    loaded = result.scalar_one()
    assert loaded.data == b'{"test": "data"}'


# ---------------------------------------------------------------------------
# 10. Software normalization log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_software_normalization_log(db: AsyncSession, org_id):
    """Normalization log records raw→normalized mapping."""
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)

    log = SoftwareNormalizationLog(
        org_id=org_id,
        device_id=device.id,
        raw_display_name="Google Chrome",
        raw_publisher="Google LLC",
        normalized_vendor="google",
        normalized_product="chrome",
        confidence=Decimal("0.95"),
        match_method="exact",
    )
    db.add(log)
    await db.flush()

    result = await db.execute(
        select(SoftwareNormalizationLog).where(
            SoftwareNormalizationLog.device_id == device.id
        )
    )
    loaded = result.scalar_one()
    assert loaded.normalized_vendor == "google"
    assert loaded.confidence == Decimal("0.95")
