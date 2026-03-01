"""Phase 2C tests — software normalization v2 + vulnerability matching.

8 integration tests using async SQLite fixtures from conftest.py.
"""

import inspect
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal

import pytest

from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.organizations import Organization
from backend.app.models.remediations import (
    Remediation,
    RemediationOsTarget,
    RemediationVulnerability,
)
from backend.app.models.software_normalization import (
    SoftwareNormalizationLog,
    TenantNormalizationOverride,
)
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.models.vulnerability_products import VulnerabilityProduct
from backend.app.services.normalization import AppRecord, SoftwareNormalizerV2
from backend.app.workers.vuln_matching import (
    compute_urgency_score,
    vuln_match_apps,
    vuln_match_os,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db, org_id):
    """Create an org row so ForeignKey constraints are satisfied."""
    org = Organization(id=org_id, name="TestOrg")
    db.add(org)
    await db.flush()
    return org


async def _create_device(db, org_id, *, os_build="19045", criticality="standard",
                          kbs_installed=None, apps_inventory=None, kbs_stale=False,
                          tags=None):
    """Create a device with inventory data stored in inventory_section_hashes."""
    inv = {}
    if kbs_installed is not None:
        inv["kbs_installed"] = kbs_installed
    if apps_inventory is not None:
        inv["apps_inventory"] = apps_inventory
    inv["kbs_stale"] = kbs_stale

    device = Device(
        org_id=org_id,
        hostname="TEST-PC",
        os_build=os_build,
        criticality=criticality,
        inventory_section_hashes=inv,
        tags=tags,
    )
    db.add(device)
    await db.flush()
    return device


async def _create_vuln(db, cve_id="CVE-2024-99999", *, cvss=9.8, epss=0.95,
                        in_kev=True, kev_date=None, published_at=None):
    """Create a Vulnerability row."""
    vuln = Vulnerability(
        cve_id=cve_id,
        cvss_base_score=Decimal(str(cvss)),
        epss_score=Decimal(str(epss)),
        in_cisa_kev=in_kev,
        kev_added_date=kev_date or date(2024, 6, 1),
        published_at=published_at or datetime(2024, 5, 15, tzinfo=timezone.utc),
    )
    db.add(vuln)
    await db.flush()
    return vuln


async def _create_remediation_with_os_target(db, vuln, *, kb_number="KB5040442",
                                               os_build="19045", min_build_revision=None):
    """Create a Remediation + RemediationOsTarget + RemediationVulnerability."""
    rem = Remediation(
        source="msrc",
        external_id=kb_number,
        title=f"Security Update {kb_number}",
        playbook={"type": "patch", "kb": kb_number},
    )
    db.add(rem)
    await db.flush()

    rv = RemediationVulnerability(remediation_id=rem.id, vuln_id=vuln.id)
    db.add(rv)

    ot = RemediationOsTarget(
        remediation_id=rem.id,
        os_build=os_build,
        min_build_revision=min_build_revision,
    )
    db.add(ot)
    await db.flush()
    return rem


# ---------------------------------------------------------------------------
# Test 1: OS matching — UBR below threshold → DeviceVulnerability created
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_os_matching_ubr_below_threshold(db, org_id):
    """Device with OS build below UBR threshold should get DeviceVulnerability."""
    await _create_org(db, org_id)

    # Device os_build "19045" — no UBR, no matching KB
    device = await _create_device(db, org_id, os_build="19045", kbs_installed=[])
    vuln = await _create_vuln(db)
    await _create_remediation_with_os_target(
        db, vuln, kb_number="KB5040442", os_build="19045", min_build_revision=4000,
    )
    await db.flush()

    count = await vuln_match_os(db, device.id)
    assert count == 1

    # Verify DeviceVulnerability row
    from sqlalchemy import select
    stmt = select(DeviceVulnerability).where(
        DeviceVulnerability.device_id == device.id,
        DeviceVulnerability.org_id == org_id,
    )
    result = await db.execute(stmt)
    dv = result.scalar_one()
    assert dv.status == "exposed"
    assert dv.vuln_id == vuln.id
    assert dv.urgency_score is not None
    assert dv.urgency_score > 0


# ---------------------------------------------------------------------------
# Test 2: OS matching — KB installed → no DeviceVulnerability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_os_matching_kb_installed_skips(db, org_id):
    """Device with the required KB already installed should NOT get DeviceVulnerability."""
    await _create_org(db, org_id)

    # Device has KB5040442 installed
    device = await _create_device(
        db, org_id, os_build="19045", kbs_installed=["KB5040442", "KB5039212"],
    )
    vuln = await _create_vuln(db)
    await _create_remediation_with_os_target(
        db, vuln, kb_number="KB5040442", os_build="19045",
    )
    await db.flush()

    count = await vuln_match_os(db, device.id)
    assert count == 0

    from sqlalchemy import select
    stmt = select(DeviceVulnerability).where(
        DeviceVulnerability.device_id == device.id,
    )
    result = await db.execute(stmt)
    assert result.scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# Test 3: App matching — low confidence → no false positive
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_app_matching_low_confidence_skips(db, org_id):
    """Apps normalizing below 0.6 confidence should NOT create DeviceVulnerability."""
    await _create_org(db, org_id)

    # Unknown publisher → will hit fuzzy/unmatched path (confidence ≤ 0.5)
    device = await _create_device(db, org_id, apps_inventory=[
        {"display_name": "SuperObscureTool", "publisher": "Unknown Corp XYZ", "version": "1.0.0"},
    ])
    await db.flush()

    count = await vuln_match_apps(db, device.id)
    assert count == 0

    from sqlalchemy import select
    stmt = select(DeviceVulnerability).where(
        DeviceVulnerability.device_id == device.id,
    )
    result = await db.execute(stmt)
    assert result.scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# Test 4: App matching — no remediation → UnpatchedExposure created
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_app_matching_no_remediation_creates_unpatched_exposure(db, org_id):
    """App vulnerability with NO remediation → UnpatchedExposure (first-class entity).

    Zero-day RESPONSE, not detection (Invariant #14).
    """
    await _create_org(db, org_id)

    # Create a VulnerabilityProduct matching Google Chrome
    vuln = await _create_vuln(db, cve_id="CVE-2024-88888", cvss=8.5, in_kev=False)
    vp = VulnerabilityProduct(
        vuln_id=vuln.id,
        cpe_vendor="google",
        cpe_product="chrome",
        version_start_including="100.0",
        version_end_excluding="130.0",
    )
    db.add(vp)
    await db.flush()

    # NO Remediation exists for this vuln

    device = await _create_device(db, org_id, apps_inventory=[
        {"display_name": "Google Chrome", "publisher": "Google LLC", "version": "120.0.0"},
    ])
    await db.flush()

    count = await vuln_match_apps(db, device.id)
    assert count >= 1

    # Verify UnpatchedExposure was created (not NULL device_vuln)
    from sqlalchemy import select
    stmt = select(UnpatchedExposure).where(
        UnpatchedExposure.org_id == org_id,
        UnpatchedExposure.vuln_id == vuln.id,
    )
    result = await db.execute(stmt)
    exposure = result.scalar_one()
    assert exposure.status == "open"
    assert exposure.affected_count >= 1


# ---------------------------------------------------------------------------
# Test 5: Tenant override → confidence 1.0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_override_confidence_1_0(db, org_id):
    """TenantNormalizationOverride maps to confidence 1.0, correct vendor/product."""
    await _create_org(db, org_id)

    # Create override
    override = TenantNormalizationOverride(
        org_id=org_id,
        match_key="Custom Corp::Custom Tool Pro",
        vendor="custom_corp",
        product="custom_tool",
        confirmed_by=uuid.uuid4(),
        confirmed_at=datetime.now(timezone.utc),
    )
    db.add(override)
    await db.flush()

    normalizer = SoftwareNormalizerV2(db, org_id)
    result = await normalizer.normalize(
        AppRecord(
            display_name="Custom Tool Pro",
            publisher="Custom Corp",
            version="3.0",
        ),
    )

    assert result.confidence == Decimal("1.00")
    assert result.match_method == "tenant_override"
    assert result.vendor == "custom_corp"
    assert result.product == "custom_tool"


# ---------------------------------------------------------------------------
# Test 6: Urgency — KEV critical > standard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_urgency_kev_critical_higher(db, org_id):
    """Critical device with KEV CVE must score higher urgency than standard device."""
    await _create_org(db, org_id)

    # Use moderate CVSS/EPSS so scores don't both cap at 100
    vuln = await _create_vuln(db, cvss=6.0, epss=0.3, in_kev=True)

    device_critical = await _create_device(db, org_id, criticality="critical")
    device_standard = await _create_device(db, org_id, criticality="standard")
    await db.flush()

    # Create remediation + OS target for both
    rem = await _create_remediation_with_os_target(
        db, vuln, kb_number="KB9999999", os_build="19045",
    )
    await db.flush()

    # Run OS matching for both devices
    await vuln_match_os(db, device_critical.id)
    await vuln_match_os(db, device_standard.id)
    await db.flush()

    from sqlalchemy import select

    # Get DeviceVulnerability for critical
    stmt_c = select(DeviceVulnerability).where(
        DeviceVulnerability.device_id == device_critical.id,
    )
    result_c = await db.execute(stmt_c)
    dv_critical = result_c.scalar_one()

    # Get DeviceVulnerability for standard
    stmt_s = select(DeviceVulnerability).where(
        DeviceVulnerability.device_id == device_standard.id,
    )
    result_s = await db.execute(stmt_s)
    dv_standard = result_s.scalar_one()

    assert dv_critical.urgency_score > dv_standard.urgency_score


# ---------------------------------------------------------------------------
# Test 7: OS and app paths are separate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_os_and_app_paths_separate(db, org_id):
    """vuln_match_os and vuln_match_apps are distinct functions that don't call each other."""
    from backend.app.workers import vuln_matching

    # Both should be async functions
    assert inspect.iscoroutinefunction(vuln_matching.vuln_match_os)
    assert inspect.iscoroutinefunction(vuln_matching.vuln_match_apps)

    # They are distinct objects
    assert vuln_matching.vuln_match_os is not vuln_matching.vuln_match_apps

    # Inspect source: vuln_match_os should NOT call vuln_match_apps and vice versa
    os_source = inspect.getsource(vuln_matching.vuln_match_os)
    apps_source = inspect.getsource(vuln_matching.vuln_match_apps)
    assert "vuln_match_apps" not in os_source
    assert "vuln_match_os" not in apps_source


# ---------------------------------------------------------------------------
# Test 8: Unmatched app → confidence 0.0 in SoftwareNormalizationLog
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unmatched_app_logged_confidence_0(db, org_id):
    """App with unrecognized publisher/name → SoftwareNormalizationLog with confidence=0.0."""
    await _create_org(db, org_id)

    normalizer = SoftwareNormalizerV2(db, org_id)
    device_id = uuid.uuid4()  # Dummy device for log

    result = await normalizer.normalize(
        AppRecord(
            display_name="TotallyUnknownApp v12.3",
            publisher="Mystery Publisher Inc",
            version="12.3",
        ),
        device_id=device_id,
    )
    await db.flush()

    assert result.confidence == Decimal("0.00")
    assert result.match_method == "unmatched"
    assert result.vendor == ""
    assert result.product == ""

    # Verify log entry
    from sqlalchemy import select
    stmt = select(SoftwareNormalizationLog).where(
        SoftwareNormalizationLog.org_id == org_id,
        SoftwareNormalizationLog.confidence == 0,
    )
    result_rows = await db.execute(stmt)
    log_entry = result_rows.scalar_one()
    assert log_entry.raw_display_name == "TotallyUnknownApp v12.3"
    assert log_entry.raw_publisher == "Mystery Publisher Inc"
    assert log_entry.match_method == "unmatched"
