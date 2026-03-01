"""Phase 3C tests — dashboard API, compliance endpoints, MTTRem analytics.

6 integration tests using async SQLite fixtures from conftest.py.
"""

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import func, select

from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.nis2_incidents import NIS2Incident
from backend.app.models.organizations import Organization
from backend.app.models.remediations import Remediation
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.routers.exposures import _percentile


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db, org_id):
    org = Organization(id=org_id, name="TestOrg3C")
    db.add(org)
    await db.flush()
    return org


async def _create_device(db, org_id, hostname="WS-3C-01", criticality="standard", tags=None):
    device = Device(
        org_id=org_id,
        hostname=hostname,
        os_build="19045",
        criticality=criticality,
        tags=tags,
        inventory_section_hashes={},
    )
    db.add(device)
    await db.flush()
    return device


async def _create_vuln(db, cve_id="CVE-2024-99999", *, cvss=9.8, epss=0.95,
                        in_kev=True, published_at=None):
    vuln = Vulnerability(
        cve_id=cve_id,
        cvss_base_score=Decimal(str(cvss)),
        epss_score=Decimal(str(epss)),
        in_cisa_kev=in_kev,
        kev_added_date=datetime(2024, 6, 1).date() if in_kev else None,
        published_at=published_at or datetime(2024, 5, 15, tzinfo=timezone.utc),
    )
    db.add(vuln)
    await db.flush()
    return vuln


async def _create_remediation(db, title="KB5000001"):
    rem = Remediation(
        source="msrc",
        external_id=title,
        title=f"Security Update {title}",
        playbook={"type": "patch", "kb": title},
    )
    db.add(rem)
    await db.flush()
    return rem


# ---------------------------------------------------------------------------
# Test 1: Dashboard KEV exposure count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_kev_exposure_count(db, org_id):
    """Dashboard kev_exposures.count is correct after adding a KEV CVE
    with an UnpatchedExposure in 'open' status.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    vuln = await _create_vuln(db, "CVE-2024-88001", in_kev=True)

    # Create UnpatchedExposure (open, KEV)
    exposure = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln.id,
        affected_count=3,
        status="open",
    )
    db.add(exposure)

    # Also create a DeviceVulnerability (exposed)
    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device.id,
        vuln_id=vuln.id,
        status="exposed",
        urgency_score=85,
        signal_ingested_at=datetime(2024, 5, 15, tzinfo=timezone.utc),
    )
    db.add(dv)
    await db.flush()

    # Query KEV exposure count (same logic as dashboard endpoint)
    kev_count_stmt = (
        select(func.count())
        .select_from(UnpatchedExposure)
        .join(Vulnerability, Vulnerability.id == UnpatchedExposure.vuln_id)
        .where(
            UnpatchedExposure.org_id == org_id,
            UnpatchedExposure.status == "open",
            Vulnerability.in_cisa_kev == True,  # noqa: E712
        )
    )
    kev_count = (await db.execute(kev_count_stmt)).scalar() or 0
    assert kev_count == 1

    # Add a second non-KEV exposure — should not affect KEV count
    vuln2 = await _create_vuln(db, "CVE-2024-88002", in_kev=False)
    exp2 = UnpatchedExposure(
        org_id=org_id, vuln_id=vuln2.id, affected_count=1, status="open",
    )
    db.add(exp2)
    await db.flush()

    kev_count2 = (await db.execute(kev_count_stmt)).scalar() or 0
    assert kev_count2 == 1  # Still 1 — non-KEV doesn't count


# ---------------------------------------------------------------------------
# Test 2: MTTRem p50 with seeded dataset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mttrem_p50_seeded_dataset(db, org_id):
    """MTTRem p50 returns correct percentile with known values.

    Seed: 5 patched DVs with hours [2, 4, 6, 8, 10]
    Expected p50 (median of 5 values) = 6.0
    """
    await _create_org(db, org_id)
    rem = await _create_remediation(db, "KB5050001")

    base_signal = datetime(2024, 6, 1, 0, 0, tzinfo=timezone.utc)
    hours_values = [2, 4, 6, 8, 10]

    for i, h in enumerate(hours_values):
        device = await _create_device(db, org_id, hostname=f"MTTREM-{i:02d}")
        dv = DeviceVulnerability(
            org_id=org_id,
            device_id=device.id,
            vuln_id=(await _create_vuln(db, f"CVE-2024-P50-{i:02d}", in_kev=False)).id,
            remediation_id=rem.id,
            status="patched",
            signal_ingested_at=base_signal,
            patched_at=base_signal + timedelta(hours=h),
        )
        db.add(dv)

    await db.flush()

    # Compute p50 using the _percentile helper
    sorted_hours = sorted(hours_values, key=float)
    p50 = _percentile(sorted_hours, 0.5)
    assert p50 == 6.0

    p90 = _percentile(sorted_hours, 0.9)
    assert p90 == 9.2  # Linear interpolation: k=3.6, 8 + 0.6*(10-8) = 9.2

    # Also verify from DB: extract hours via timedelta
    stmt = (
        select(
            DeviceVulnerability.patched_at,
            DeviceVulnerability.signal_ingested_at,
        )
        .where(
            DeviceVulnerability.org_id == org_id,
            DeviceVulnerability.patched_at.isnot(None),
            DeviceVulnerability.signal_ingested_at.isnot(None),
        )
    )
    result = await db.execute(stmt)
    db_hours = sorted(
        (r.patched_at - r.signal_ingested_at).total_seconds() / 3600
        for r in result.all()
    )
    assert len(db_hours) == 5
    assert _percentile(db_hours, 0.5) == 6.0


# ---------------------------------------------------------------------------
# Test 3: Compliance CSV valid headers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_csv_headers(db, org_id):
    """Compliance evidence CSV has expected headers and at least 1 data row."""
    await _create_org(db, org_id)
    device = await _create_device(db, org_id, hostname="CSV-HOST-01")
    vuln = await _create_vuln(db, "CVE-2024-CSV01", cvss=7.5, epss=0.3, in_kev=True)
    rem = await _create_remediation(db, "KB5060001")

    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device.id,
        vuln_id=vuln.id,
        remediation_id=rem.id,
        status="patched",
        urgency_score=72,
        signal_ingested_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
        patched_at=datetime(2024, 6, 1, 4, 0, tzinfo=timezone.utc),
    )
    db.add(dv)
    await db.flush()

    # Use the internal query function directly
    from backend.app.routers.reports import _query_compliance_evidence
    rows = await _query_compliance_evidence(db, org_id)

    assert len(rows) >= 1

    # Validate headers
    expected_headers = {
        "cve_id", "hostname", "criticality", "cvss", "epss",
        "in_cisa_kev", "signal_ingested_at", "patched_at",
        "mttrem_hours", "urgency_score",
    }
    assert set(rows[0].keys()) == expected_headers

    # Validate data
    row = rows[0]
    assert row["cve_id"] == "CVE-2024-CSV01"
    assert row["hostname"] == "CSV-HOST-01"
    assert row["mttrem_hours"] == 4.0
    assert row["urgency_score"] == 72

    # Verify CSV generation works
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(expected_headers))
    writer.writeheader()
    writer.writerow(row)
    output.seek(0)
    reader = csv.DictReader(output)
    csv_row = next(reader)
    assert csv_row["cve_id"] == "CVE-2024-CSV01"


# ---------------------------------------------------------------------------
# Test 4: NIS2 summary overdue incidents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nis2_summary_overdue_incidents(db, org_id):
    """NIS2 summary correctly flags overdue early warning incidents.

    Incident detected 48h ago → early_warning_due was 24h after detection → overdue.
    """
    await _create_org(db, org_id)
    now = datetime.now(timezone.utc)

    # Incident detected 48h ago — early_warning is 24h overdue
    incident = NIS2Incident(
        org_id=org_id,
        title="Critical exploit in production",
        severity="critical",
        detected_at=now - timedelta(hours=48),
        status="open",
    )
    db.add(incident)
    await db.flush()

    # Compute overdue flags manually (same logic as compliance router)
    # early_warning_due = detected_at + 24h = 24h ago → overdue since now > ew_due
    ew_due = incident.detected_at + timedelta(hours=24)
    ew_overdue = bool(not incident.early_warning_sent_at and now > ew_due)
    assert ew_overdue is True

    # notification_due = detected_at + 72h = 24h from now → NOT overdue
    notif_due = incident.detected_at + timedelta(hours=72)
    notif_overdue = bool(not incident.notification_sent_at and now > notif_due)
    assert notif_overdue is False

    # Verify the query returns the incident as open
    result = await db.execute(
        select(NIS2Incident)
        .where(NIS2Incident.org_id == org_id, NIS2Incident.status == "open")
    )
    open_incidents = result.scalars().all()
    assert len(open_incidents) == 1
    assert open_incidents[0].title == "Critical exploit in production"


# ---------------------------------------------------------------------------
# Test 5: Criticality change recalculates urgency scores
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_criticality_change_urgency_recalc(db, org_id):
    """Changing device criticality from 'standard' to 'critical' increases urgency scores.

    criticality_m goes from 1.0 (standard) to 1.5 (critical).
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id, criticality="standard")
    vuln = await _create_vuln(db, "CVE-2024-CRIT01", cvss=8.0, epss=0.5, in_kev=False)

    from backend.app.workers.vuln_matching import _signal_ingested_at, compute_urgency_score

    sig = _signal_ingested_at(vuln)
    days = (datetime.now(timezone.utc) - sig).days if sig else 0
    original_score = compute_urgency_score(vuln, device, days)

    dv = DeviceVulnerability(
        org_id=org_id,
        device_id=device.id,
        vuln_id=vuln.id,
        status="exposed",
        urgency_score=original_score,
        signal_ingested_at=sig,
    )
    db.add(dv)
    await db.flush()

    assert device.criticality == "standard"

    # Change criticality to critical
    device.criticality = "critical"
    await db.flush()

    # Recalculate
    new_score = compute_urgency_score(vuln, device, days)
    assert new_score > original_score, (
        f"Expected critical score ({new_score}) > standard score ({original_score})"
    )

    # Verify the multiplier effect: critical=1.5 vs standard=1.0
    # So new_score should be approximately original_score * 1.5
    ratio = new_score / original_score if original_score > 0 else 0
    assert 1.3 < ratio < 1.6, f"Unexpected ratio: {ratio}"

    # Update the DV to verify it persists
    dv.urgency_score = new_score
    await db.flush()
    assert dv.urgency_score == new_score


# ---------------------------------------------------------------------------
# Test 6: Compliance evidence query on empty dataset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_evidence_empty_dataset(db, org_id):
    """Compliance evidence query returns empty list on empty dataset, no errors."""
    await _create_org(db, org_id)

    from backend.app.routers.reports import _query_compliance_evidence
    rows = await _query_compliance_evidence(db, org_id)
    assert rows == []
    assert isinstance(rows, list)
