"""Phase 3A tests — deployment job state machine, ring rollout, anomaly halt.

7 integration tests using async SQLite fixtures from conftest.py.
"""

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from backend.app.models.audit_log import AuditLog
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.devices import Device
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.organizations import Organization
from backend.app.models.remediations import Remediation, RemediationVulnerability
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.services.audit import AuditInsertError, CRITICAL_EVENTS
from backend.app.services.state_machine import InvalidTransition, transition
from backend.app.workers.ring_rollout import (
    check_canary_anomaly,
    create_deployment_plan,
    dispatch_ring,
    DeploymentPlan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db, org_id):
    org = Organization(id=org_id, name="TestOrg")
    db.add(org)
    await db.flush()
    return org


async def _create_device(db, org_id, hostname="WORKSTATION-01"):
    device = Device(
        org_id=org_id,
        hostname=hostname,
        os_build="19045",
        criticality="standard",
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


async def _create_job(db, org_id, device_id, remediation_id, ring="canary",
                       state="queued", **kwargs):
    job = DeploymentJob(
        org_id=org_id,
        device_id=device_id,
        remediation_id=remediation_id,
        ring=ring,
        state=state,
        state_updated_at=datetime.now(timezone.utc),
        playbook_snapshot={"type": "patch", "kb": "KB5000001"},
        **kwargs,
    )
    db.add(job)
    await db.flush()
    return job


class FakeRedis:
    """Minimal in-memory Redis mock for testing."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._lists: dict[str, list[str]] = {}

    async def rpush(self, key: str, value: str) -> int:
        self._lists.setdefault(key, []).append(value)
        return len(self._lists[key])

    async def setex(self, key: str, seconds: int, value: str) -> bool:
        self._store[key] = value
        return True

    async def exists(self, key: str) -> bool:
        return key in self._store or key in self._lists

    def get_store(self) -> dict:
        return dict(self._store)

    def get_lists(self) -> dict:
        return dict(self._lists)


# ---------------------------------------------------------------------------
# Test 1: InvalidTransition for COMPLETE → QUEUED
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_transition_complete_to_queued(db, org_id):
    """A job in 'complete' state cannot transition to 'queued'.

    COMPLETE has no valid outgoing transitions in the state machine.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(db, org_id, device.id, rem.id, state="complete")
    await db.flush()

    with pytest.raises(InvalidTransition, match="not allowed"):
        await transition(db, job, "queued")


# ---------------------------------------------------------------------------
# Test 2: InvalidTransition for unlisted transition (downloading → complete)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_transition_unlisted(db, org_id):
    """A job in 'downloading' state cannot skip to 'complete'.

    downloading only allows: installing, failed.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(db, org_id, device.id, rem.id, state="downloading")
    await db.flush()

    with pytest.raises(InvalidTransition, match="not allowed"):
        await transition(db, job, "complete")


# ---------------------------------------------------------------------------
# Test 3: Audit log written BEFORE state change; audit failure blocks transition
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_before_state_change(db, org_id):
    """Audit log is written BEFORE state changes.

    If audit INSERT fails (AuditInsertError), the state must NOT change.
    'job.state_changed' is in CRITICAL_EVENTS — verified here.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(db, org_id, device.id, rem.id, state="queued")
    await db.flush()

    # Verify job.state_changed is in CRITICAL_EVENTS
    assert "job.state_changed" in CRITICAL_EVENTS

    # Normal transition: queued → downloading (audit succeeds)
    await transition(db, job, "downloading")
    await db.flush()
    assert job.state == "downloading"

    # Verify audit log was written
    audit_stmt = select(AuditLog).where(
        AuditLog.org_id == org_id,
        AuditLog.event_type == "job.state_changed",
    )
    audit_result = await db.execute(audit_stmt)
    audit_entry = audit_result.scalar_one()
    assert audit_entry.changes["old_state"] == "queued"
    assert audit_entry.changes["new_state"] == "downloading"

    # Now test audit failure blocks state change:
    # Create a second job to test the failure path
    job2 = await _create_job(db, org_id, device.id, rem.id, state="queued")
    await db.flush()

    import backend.app.services.audit as audit_module
    original_record = audit_module.record

    async def _failing_record(*args, **kwargs):
        raise AuditInsertError("Simulated audit failure")

    # Monkey-patch audit.record to simulate failure
    audit_module.record = _failing_record
    try:
        with pytest.raises(AuditInsertError):
            await transition(db, job2, "downloading")

        # State must NOT have changed
        assert job2.state == "queued"
    finally:
        audit_module.record = original_record


# ---------------------------------------------------------------------------
# Test 4: Canary 2/8 failed → 25% > 20% → halt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_canary_anomaly_25pct_halt(db, org_id):
    """Canary ring with 2/8 devices failed (25%) exceeds 20% threshold.

    check_canary_anomaly must return halt=True.
    """
    await _create_org(db, org_id)
    rem = await _create_remediation(db, title="KB6000001")

    # Create 8 canary jobs: 2 failed, 6 complete
    for i in range(8):
        device = await _create_device(db, org_id, hostname=f"DEV-{i:02d}")
        state = "failed" if i < 2 else "complete"
        await _create_job(
            db, org_id, device.id, rem.id, ring="canary", state=state,
        )
    await db.flush()

    result = await check_canary_anomaly(db, rem.id, org_id)
    assert result["halt"] is True
    assert result["details"]["reason"] == "failure_rate"
    assert result["details"]["failure_rate"] == 0.25
    assert result["details"]["failed_count"] == 2
    assert result["details"]["total_count"] == 8


# ---------------------------------------------------------------------------
# Test 5: Canary 1/8 failed → 12.5% < 20% → pass
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_canary_anomaly_12pct_pass(db, org_id):
    """Canary ring with 1/8 devices failed (12.5%) is below 20% threshold.

    check_canary_anomaly must return halt=False.
    """
    await _create_org(db, org_id)
    rem = await _create_remediation(db, title="KB7000001")

    # Create 8 canary jobs: 1 failed, 7 complete
    for i in range(8):
        device = await _create_device(db, org_id, hostname=f"DEV-{i:02d}")
        state = "failed" if i == 0 else "complete"
        await _create_job(
            db, org_id, device.id, rem.id, ring="canary", state=state,
        )
    await db.flush()

    result = await check_canary_anomaly(db, rem.id, org_id)
    assert result["halt"] is False
    assert result["details"]["failure_rate"] == 0.125
    assert result["details"]["failed_count"] == 1


# ---------------------------------------------------------------------------
# Test 6: Deferred 3 times → forced_reboot, not user_deferred
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deferred_3_times_forced_reboot(db, org_id):
    """A job that has been deferred 3 times cannot defer again.

    Must raise InvalidTransition for user_deferred.
    Must allow forced_reboot.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(
        db, org_id, device.id, rem.id,
        state="pending_reboot", deferred_count=3,
    )
    await db.flush()

    # Cannot defer a 4th time
    with pytest.raises(InvalidTransition, match="Max 3 deferrals"):
        await transition(db, job, "user_deferred")

    # But forced_reboot is allowed
    await transition(db, job, "forced_reboot")
    await db.flush()

    assert job.state == "forced_reboot"
    assert job.forced_reboot_at is not None


# ---------------------------------------------------------------------------
# Test 7: Ring dispatch sets fast_cadence key in Redis
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ring_dispatch_fast_cadence_redis(db, org_id):
    """dispatch_ring must set fast_cadence:{device_id} key in Redis for each device.

    Also verifies commands:{device_id} list is populated.
    """
    await _create_org(db, org_id)
    rem = await _create_remediation(db, title="KB8000001")
    devices = []
    for i in range(4):
        d = await _create_device(db, org_id, hostname=f"FC-{i:02d}")
        devices.append(d)
    await db.flush()

    plan = DeploymentPlan(
        plan_id=uuid.uuid4(),
        org_id=org_id,
        vuln_id=uuid.uuid4(),
        remediation_id=rem.id,
        canary=devices,
    )

    fake_redis = FakeRedis()
    jobs = await dispatch_ring(db, fake_redis, plan, "canary", rem)
    await db.flush()

    assert len(jobs) == 4

    # Verify Redis fast_cadence keys
    for device in devices:
        key = f"fast_cadence:{device.id}"
        assert key in fake_redis.get_store(), f"Missing fast_cadence key for {device.hostname}"
        assert fake_redis.get_store()[key] == "1"

    # Verify Redis commands lists
    for device in devices:
        cmd_key = f"commands:{device.id}"
        assert cmd_key in fake_redis.get_lists(), f"Missing commands for {device.hostname}"
        assert len(fake_redis.get_lists()[cmd_key]) == 1

    # Verify job properties
    for job in jobs:
        assert job.ring == "canary"
        assert job.state == "queued"
        assert job.playbook_snapshot == rem.playbook
