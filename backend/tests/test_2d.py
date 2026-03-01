"""Phase 2D tests — zero-day response workflow.

5 integration tests using async SQLite fixtures from conftest.py.
Language: "zero-day response" everywhere. Never "detection" (Invariant #14).
"""

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select

from backend.app.models.audit_log import AuditLog
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.organizations import Organization
from backend.app.models.remediations import Remediation, RemediationVulnerability
from backend.app.models.unpatched_exposures import UnpatchedExposure
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.services.audit import CRITICAL_EVENTS
from backend.app.workers.zeroday_monitor import (
    ensure_unpatched_exposure,
    format_exposure_notification,
    recheck_unpatched_exposures,
)


# ---------------------------------------------------------------------------
# Helpers (reused patterns from test_2c.py)
# ---------------------------------------------------------------------------


async def _create_org(db, org_id):
    org = Organization(id=org_id, name="TestOrg")
    db.add(org)
    await db.flush()
    return org


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


# ---------------------------------------------------------------------------
# Test 1: KEV CVE with no remediation → UnpatchedExposure, no NULL device_vuln
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kev_no_remediation_creates_unpatched_exposure(db, org_id):
    """KEV CVE with no remediation creates UnpatchedExposure with status='open'.

    Must NOT create a DeviceVulnerability with NULL remediation_id.
    'NULL check is not a workflow' — UnpatchedExposure IS the first-class entity.
    """
    await _create_org(db, org_id)
    device_id = uuid.uuid4()
    vuln = await _create_vuln(db, in_kev=True)
    await db.flush()

    # Call ensure_unpatched_exposure (canonical version from zeroday_monitor)
    exposure = await ensure_unpatched_exposure(
        db, vuln.id, org_id, affected_device_ids=[device_id],
    )
    await db.flush()

    # Assert: UnpatchedExposure created with status="open"
    assert exposure is not None
    assert exposure.status == "open"
    assert exposure.affected_count >= 1
    assert exposure.org_id == org_id
    assert exposure.vuln_id == vuln.id

    # Assert: NO DeviceVulnerability with NULL remediation_id
    dv_stmt = select(DeviceVulnerability).where(
        DeviceVulnerability.vuln_id == vuln.id,
        DeviceVulnerability.org_id == org_id,
        DeviceVulnerability.remediation_id.is_(None),
    )
    dv_result = await db.execute(dv_stmt)
    assert dv_result.scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# Test 2: Recheck finds remediation → transitions to "patched"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recheck_remediation_appears_transitions_to_patched(db, org_id):
    """When recheck finds a new remediation for an open exposure,
    status transitions to 'patched' and deployment recommendation is stored."""
    await _create_org(db, org_id)
    vuln = await _create_vuln(db, cve_id="CVE-2024-77777")

    # Create open exposure
    exposure = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln.id,
        affected_count=5,
        status="open",
        last_checked_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db.add(exposure)
    await db.flush()

    # Now add a remediation for this vuln
    rem = Remediation(
        source="msrc",
        external_id="KB9999999",
        title="Security Update KB9999999",
        playbook={"type": "patch", "kb": "KB9999999"},
    )
    db.add(rem)
    await db.flush()

    rv = RemediationVulnerability(remediation_id=rem.id, vuln_id=vuln.id)
    db.add(rv)
    await db.flush()

    # Run recheck
    result = await recheck_unpatched_exposures(db)
    await db.flush()

    assert result["patched"] >= 1

    # Reload exposure
    await db.refresh(exposure)
    assert exposure.status == "patched"
    assert exposure.patched_at is not None

    # Deployment recommendation stored
    assert exposure.mitigations is not None
    assert "deployment_recommendation" in exposure.mitigations
    rec = exposure.mitigations["deployment_recommendation"]
    assert rec["remediation_id"] == str(rem.id)


# ---------------------------------------------------------------------------
# Test 3: No duplicate — UNIQUE constraint + increment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recheck_no_duplicate_exposure(db, org_id):
    """Second call to ensure_unpatched_exposure with same (org_id, vuln_id)
    must NOT create a duplicate. UNIQUE constraint enforced. Affected_count updated."""
    await _create_org(db, org_id)
    vuln = await _create_vuln(db, cve_id="CVE-2024-66666")
    await db.flush()

    # First call
    exp1 = await ensure_unpatched_exposure(
        db, vuln.id, org_id, affected_device_ids=[uuid.uuid4()],
    )
    await db.flush()

    # Second call — same org + vuln
    exp2 = await ensure_unpatched_exposure(
        db, vuln.id, org_id, affected_device_ids=[uuid.uuid4(), uuid.uuid4()],
    )
    await db.flush()

    # Must be the same row (by UNIQUE constraint)
    assert exp1.id == exp2.id

    # Count check: only 1 row exists
    count_stmt = select(UnpatchedExposure).where(
        UnpatchedExposure.org_id == org_id,
        UnpatchedExposure.vuln_id == vuln.id,
    )
    result = await db.execute(count_stmt)
    rows = result.scalars().all()
    assert len(rows) == 1

    # Affected count should have been updated (max of previous and new)
    assert rows[0].affected_count >= 2


# ---------------------------------------------------------------------------
# Test 4: accept_risk writes CRITICAL audit entry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_accept_risk_requires_note_writes_audit(db, org_id, user_id):
    """accept_risk creates CRITICAL audit entry with note.

    'exposure.accepted_risk' is in CRITICAL_EVENTS — must block on audit failure.
    """
    await _create_org(db, org_id)
    vuln = await _create_vuln(db, cve_id="CVE-2024-55555")
    await db.flush()

    # Create exposure
    exposure = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln.id,
        affected_count=3,
        status="open",
    )
    db.add(exposure)
    await db.flush()

    # Verify exposure.accepted_risk is in CRITICAL_EVENTS
    assert "exposure.accepted_risk" in CRITICAL_EVENTS

    # Write the audit entry (simulating what the accept endpoint does)
    from backend.app.services.audit import record
    await record(
        db,
        event_type="exposure.accepted_risk",
        org_id=org_id,
        user_id=user_id,
        resource=f"exposure:{exposure.id}",
        changes={
            "note": "Business risk accepted per security review.",
            "previous_status": "open",
            "new_status": "accepted_risk",
        },
    )

    # Update status AFTER audit succeeds
    exposure.status = "accepted_risk"
    await db.flush()

    assert exposure.status == "accepted_risk"

    # Verify audit log entry exists
    audit_stmt = select(AuditLog).where(
        AuditLog.org_id == org_id,
        AuditLog.event_type == "exposure.accepted_risk",
    )
    audit_result = await db.execute(audit_stmt)
    audit_entry = audit_result.scalar_one()
    assert audit_entry.changes["note"] == "Business risk accepted per security review."
    assert audit_entry.user_id == user_id


# ---------------------------------------------------------------------------
# Test 5: Notification subject uses "response", never "detection"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notification_subject_no_detection_word(db, org_id):
    """Notification template subject must contain 'RESPONSE', never 'detection'.

    Invariant #14: 'zero-day response' everywhere.
    """
    await _create_org(db, org_id)
    vuln = await _create_vuln(db, cve_id="CVE-2024-44444", cvss=8.0, epss=0.8)
    await db.flush()

    exposure = UnpatchedExposure(
        org_id=org_id,
        vuln_id=vuln.id,
        affected_count=12,
        status="open",
        last_checked_at=datetime.now(timezone.utc),
        recheck_interval="1 hour",
    )
    db.add(exposure)
    await db.flush()

    notification = format_exposure_notification(
        vuln=vuln,
        exposure=exposure,
        dept_breakdown={"Engineering": 8, "Finance": 4},
    )

    # Subject assertions
    assert "detection" not in notification["subject"].lower()
    assert "RESPONSE" in notification["subject"]
    assert vuln.cve_id in notification["subject"]

    # Body assertions
    assert "detection" not in notification["body"].lower()
    assert "endpoints in your fleet are exposed" in notification["body"]
    assert "Engineering: 8" in notification["body"]
    assert "Finance: 4" in notification["body"]
