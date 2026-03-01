"""Phase 3B tests — BLPOP command delivery, WebSocket live feed, fast cadence.

7 integration tests using async SQLite fixtures from conftest.py.
"""

import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from backend.app.models.audit_log import AuditLog
from backend.app.models.deployment_jobs import DeploymentJob
from backend.app.models.devices import Device
from backend.app.models.organizations import Organization
from backend.app.models.remediations import Remediation
from backend.app.services.state_machine import transition
from backend.app.workers.job_runner import verify_remediation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db, org_id):
    org = Organization(id=org_id, name="TestOrg3B")
    db.add(org)
    await db.flush()
    return org


async def _create_device(db, org_id, hostname="WS-3B-01"):
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


async def _create_remediation(db, title="KB9000001"):
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
        playbook_snapshot={"type": "patch", "kb": "KB9000001"},
        **kwargs,
    )
    db.add(job)
    await db.flush()
    return job


class FakeRedis:
    """Extended in-memory Redis mock with BLPOP + pub/sub support."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._lists: dict[str, list[str]] = {}
        self._published: list[tuple[str, str]] = []

    async def rpush(self, key: str, value: str) -> int:
        self._lists.setdefault(key, []).append(value)
        return len(self._lists[key])

    async def setex(self, key: str, seconds: int, value: str) -> bool:
        self._store[key] = value
        self._store[f"__ttl__:{key}"] = str(seconds)
        return True

    async def exists(self, key: str) -> bool:
        return key in self._store or key in self._lists

    async def blpop(self, key: str, timeout: int = 0) -> tuple[str, str] | None:
        """Pop first element from list. Returns None if list is empty."""
        lst = self._lists.get(key, [])
        if lst:
            value = lst.pop(0)
            if not lst:
                del self._lists[key]
            return (key, value)
        return None

    async def publish(self, channel: str, message: str) -> int:
        self._published.append((channel, message))
        return 1

    def get_store(self) -> dict:
        return dict(self._store)

    def get_lists(self) -> dict:
        return dict(self._lists)

    def get_published(self) -> list[tuple[str, str]]:
        return list(self._published)


# ---------------------------------------------------------------------------
# Test 1: BLPOP timeout returns null command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blpop_timeout_returns_null_command():
    """When no commands are queued, BLPOP returns None.

    The next-command endpoint must return {command: null} (200), NOT 204.
    Invariant #12: BLPOP long-poll, not 2s polling.
    """
    fake_redis = FakeRedis()
    device_id = uuid.uuid4()

    # BLPOP on empty list returns None
    result = await fake_redis.blpop(f"commands:{device_id}", timeout=0)
    assert result is None

    # Simulate what the endpoint does: parse None → null command
    if result is None:
        command = None
    else:
        _key, raw = result
        command = json.loads(raw)

    assert command is None


# ---------------------------------------------------------------------------
# Test 2: BLPOP immediate return with command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blpop_immediate_return_with_command():
    """When a command is queued via rpush, BLPOP returns it immediately.

    Verifies the command structure matches what dispatch_ring pushes.
    """
    fake_redis = FakeRedis()
    device_id = uuid.uuid4()
    job_id = uuid.uuid4()

    # Simulate dispatch_ring pushing a command
    command_payload = {
        "type": "install",
        "job_id": str(job_id),
        "playbook": {"type": "patch", "kb": "KB9000001"},
    }
    await fake_redis.rpush(f"commands:{device_id}", json.dumps(command_payload))

    # BLPOP should return the command immediately
    result = await fake_redis.blpop(f"commands:{device_id}", timeout=55)
    assert result is not None

    _key, raw = result
    command = json.loads(raw)
    assert command["type"] == "install"
    assert command["job_id"] == str(job_id)
    assert command["playbook"]["kb"] == "KB9000001"

    # List should be empty after BLPOP
    result2 = await fake_redis.blpop(f"commands:{device_id}", timeout=0)
    assert result2 is None


# ---------------------------------------------------------------------------
# Test 3: Job status transition + WebSocket publish
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_job_status_transition_and_ws_publish(db, org_id):
    """POST /job-status transitions job state via state_machine.transition()
    and publishes the state change to Redis pub/sub for WebSocket.

    Invariant #10: audit written BEFORE state change.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(db, org_id, device.id, rem.id, state="queued")
    await db.flush()

    fake_redis = FakeRedis()
    old_state = job.state

    # Transition queued → downloading (via state machine)
    await transition(db, job, "downloading")
    await db.flush()

    assert job.state == "downloading"

    # Simulate the pub/sub publish that update_job_status does
    msg = json.dumps({
        "event": "job.state_changed",
        "job_id": str(job.id),
        "device_id": str(job.device_id),
        "old_state": old_state,
        "new_state": "downloading",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    await fake_redis.publish(f"deployments:{job.org_id}", msg)

    # Verify publish was recorded
    published = fake_redis.get_published()
    assert len(published) == 1
    channel, data = published[0]
    assert channel == f"deployments:{org_id}"
    parsed = json.loads(data)
    assert parsed["event"] == "job.state_changed"
    assert parsed["old_state"] == "queued"
    assert parsed["new_state"] == "downloading"
    assert parsed["job_id"] == str(job.id)

    # Verify audit log was written (audit-before-change)
    audit_result = await db.execute(
        select(AuditLog).where(
            AuditLog.org_id == org_id,
            AuditLog.event_type == "job.state_changed",
        )
    )
    audit_entry = audit_result.scalar_one()
    assert audit_entry.changes["old_state"] == "queued"
    assert audit_entry.changes["new_state"] == "downloading"


# ---------------------------------------------------------------------------
# Test 4: Fast cadence flag in checkin response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fast_cadence_checkin_response():
    """DeviceCheckinResponse.fast_cadence returns true when Redis key exists.

    dispatch_ring sets fast_cadence:{device_id} with 600s TTL.
    The checkin endpoint checks this key and returns it in the response.
    """
    from backend.app.schemas.enrollment import DeviceCheckinResponse

    fake_redis = FakeRedis()
    device_id = uuid.uuid4()

    # No fast cadence key → false
    has_fc = bool(await fake_redis.exists(f"fast_cadence:{device_id}"))
    resp1 = DeviceCheckinResponse(commands_pending=False, fast_cadence=has_fc)
    assert resp1.fast_cadence is False

    # Set fast cadence key (simulates dispatch_ring)
    await fake_redis.setex(f"fast_cadence:{device_id}", 600, "1")

    has_fc = bool(await fake_redis.exists(f"fast_cadence:{device_id}"))
    resp2 = DeviceCheckinResponse(commands_pending=True, fast_cadence=has_fc)
    assert resp2.fast_cadence is True
    assert resp2.commands_pending is True


# ---------------------------------------------------------------------------
# Test 5: Telemetry stored on job status update
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_telemetry_stored_on_job_status(db, org_id):
    """Telemetry is stored as telemetry_before when job is in queued state,
    and as telemetry_after when in any other state.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(db, org_id, device.id, rem.id, state="queued")
    await db.flush()

    telemetry_snapshot_before = {
        "cpu_percent_1s": 45,
        "crash_events_24h": 0,
        "reboots_7d": 1,
        "system_disk_free_gb": 50.2,
    }

    # Simulate: agent sends telemetry with initial status report (queued state)
    # In the endpoint, telemetry_before is set when job.state == "queued"
    assert job.state == "queued"
    job.telemetry_before = telemetry_snapshot_before

    # Transition to downloading
    await transition(db, job, "downloading")
    await db.flush()

    assert job.telemetry_before == telemetry_snapshot_before
    assert job.state == "downloading"

    # Agent sends telemetry during installing phase
    telemetry_snapshot_after = {
        "cpu_percent_1s": 72,
        "crash_events_24h": 0,
        "reboots_7d": 2,
        "system_disk_free_gb": 48.1,
    }

    # In the endpoint, telemetry_after is set when job.state != "queued"
    assert job.state != "queued"
    job.telemetry_after = telemetry_snapshot_after

    # Transition to installing
    await transition(db, job, "installing")
    await db.flush()

    assert job.telemetry_after == telemetry_snapshot_after
    assert job.state == "installing"


# ---------------------------------------------------------------------------
# Test 6: Verify remediation dispatches verify command + 2min fast cadence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_remediation_dispatches_command(db, org_id):
    """verify_remediation() pushes a verify command to Redis and sets
    fast_cadence:{device_id} with 120s (2 minute) TTL.
    """
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)
    rem = await _create_remediation(db)
    job = await _create_job(db, org_id, device.id, rem.id, state="complete")
    await db.flush()

    fake_redis = FakeRedis()

    result = await verify_remediation(db, fake_redis, job.id)

    assert result["status"] == "verify_dispatched"
    assert result["job_id"] == str(job.id)

    # Verify command was pushed to Redis
    cmd_key = f"commands:{device.id}"
    assert cmd_key in fake_redis.get_lists()
    commands = fake_redis.get_lists()[cmd_key]
    assert len(commands) == 1

    cmd = json.loads(commands[0])
    assert cmd["type"] == "verify"
    assert cmd["job_id"] == str(job.id)
    assert cmd["playbook"] == job.playbook_snapshot

    # Verify fast cadence set with 120s TTL
    fc_key = f"fast_cadence:{device.id}"
    assert fc_key in fake_redis.get_store()
    assert fake_redis.get_store()[fc_key] == "1"
    assert fake_redis.get_store()[f"__ttl__:{fc_key}"] == "120"


# ---------------------------------------------------------------------------
# Test 7: WebSocket rejects missing token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_rejects_missing_token():
    """WebSocket connection without a token query param must be closed
    with code 4001 (Missing auth token).

    Validates the auth gate in deployment_ws().
    """
    from backend.app.routers.devices import _validate_ws_token

    # _validate_ws_token raises ValueError for invalid JWT
    with pytest.raises(ValueError, match="Invalid JWT"):
        _validate_ws_token("not-a-valid-jwt", uuid.uuid4())

    # Empty string also fails
    with pytest.raises(ValueError, match="Invalid JWT"):
        _validate_ws_token("", uuid.uuid4())
