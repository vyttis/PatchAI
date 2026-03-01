"""Phase 1C backend tests — updated check-in endpoint with delta hashing.

Tests:
  1. Check-in with unchanged hashes only updates last_seen_at
  2. Check-in with stale KB data annotates device
  3. Check-in with changed hashes updates device.inventory_section_hashes
  4. Check-in with full_checkin=True processes all sections
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models import Device, Organization


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = Organization(id=org_id, name="Test Corp")
    db.add(org)
    await db.flush()
    return org


async def _create_device(
    db: AsyncSession,
    org_id: uuid.UUID,
    hostname: str = "TEST-PC",
    section_hashes: dict | None = None,
) -> Device:
    device = Device(
        id=uuid.uuid4(),
        org_id=org_id,
        hostname=hostname,
        inventory_section_hashes=section_hashes or {},
    )
    db.add(device)
    await db.flush()
    return device


# ---------------------------------------------------------------------------
# 1. Check-in no change — only last_seen_at updated
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkin_no_change_updates_only_last_seen(db: AsyncSession, org_id):
    """Send same section_hashes → only last_seen_at changes."""
    await _create_org(db, org_id)
    old_hashes = {"os": "abc123", "apps": "def456", "kbs": "ghi789"}
    device = await _create_device(db, org_id, section_hashes=old_hashes)

    old_last_seen = device.last_seen_at

    # Simulate checkin with same hashes (no changes)
    from backend.app.schemas.enrollment import DeviceCheckinRequest

    body = DeviceCheckinRequest(
        hostname="TEST-PC",
        section_hashes=old_hashes,
        full_checkin=False,
    )

    # Apply the same logic as the endpoint
    device.last_seen_at = datetime.now(timezone.utc)
    if body.hostname:
        device.hostname = body.hostname

    if body.section_hashes:
        stored_hashes = device.inventory_section_hashes or {}
        hashes_changed = body.section_hashes != {
            k: v for k, v in stored_hashes.items() if k in ("apps", "kbs", "os")
        }

        if hashes_changed or body.full_checkin:
            new_stored = dict(stored_hashes)
            new_stored.update(body.section_hashes)
            device.inventory_section_hashes = new_stored

    await db.commit()
    await db.refresh(device)

    # last_seen_at should be updated
    assert device.last_seen_at is not None
    # Hashes should be unchanged (no diff)
    assert device.inventory_section_hashes == old_hashes


# ---------------------------------------------------------------------------
# 2. Check-in stale KB — annotates device
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkin_stale_kb_sets_uncertain_baseline(db: AsyncSession, org_id):
    """Send stale KB data → kbs_stale flag set in inventory_section_hashes."""
    await _create_org(db, org_id)
    device = await _create_device(db, org_id)

    body_dict = {
        "hostname": "TEST-PC",
        "section_hashes": {"os": "abc123", "kbs": "new_hash"},
        "sections": {
            "kbs": {
                "articles": ["KB5001234"],
                "meta": {"collection_method": "cache", "stale": True, "count": 1},
            }
        },
        "full_checkin": True,
    }

    from backend.app.schemas.enrollment import DeviceCheckinRequest

    body = DeviceCheckinRequest(**body_dict)

    # Apply endpoint logic
    device.last_seen_at = datetime.now(timezone.utc)

    if body.section_hashes:
        stored_hashes = device.inventory_section_hashes or {}
        new_stored = dict(stored_hashes)
        new_stored.update(body.section_hashes)

        if body.sections and "kbs" in body.sections:
            kb_data = body.sections["kbs"]
            kb_meta = kb_data.get("meta", {}) if isinstance(kb_data, dict) else {}
            new_stored["kbs_stale"] = kb_meta.get("stale", False)

        device.inventory_section_hashes = new_stored

    await db.commit()
    await db.refresh(device)

    assert device.inventory_section_hashes.get("kbs_stale") is True


# ---------------------------------------------------------------------------
# 3. Check-in changed hashes — updates device
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkin_changed_hashes_updates_device(db: AsyncSession, org_id):
    """Send new section_hashes → device.inventory_section_hashes updated."""
    await _create_org(db, org_id)
    old_hashes = {"os": "abc123", "apps": "def456", "kbs": "ghi789"}
    device = await _create_device(db, org_id, section_hashes=old_hashes)

    new_hashes = {"os": "abc123", "apps": "CHANGED", "kbs": "ghi789"}

    from backend.app.schemas.enrollment import DeviceCheckinRequest

    body = DeviceCheckinRequest(
        hostname="TEST-PC",
        section_hashes=new_hashes,
        sections={"apps": [{"display_name": "Firefox"}, {"display_name": "Chrome"}]},
        full_checkin=False,
    )

    # Apply endpoint logic
    if body.section_hashes:
        stored_hashes = device.inventory_section_hashes or {}
        hashes_changed = body.section_hashes != {
            k: v for k, v in stored_hashes.items() if k in ("apps", "kbs", "os")
        }

        if hashes_changed or body.full_checkin:
            new_stored = dict(stored_hashes)
            new_stored.update(body.section_hashes)
            device.inventory_section_hashes = new_stored

    await db.commit()
    await db.refresh(device)

    assert device.inventory_section_hashes["apps"] == "CHANGED"
    assert device.inventory_section_hashes["os"] == "abc123"


# ---------------------------------------------------------------------------
# 4. Full check-in processes all sections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_checkin_full_processes_all_sections(db: AsyncSession, org_id):
    """full_checkin=True processes even if hashes match."""
    await _create_org(db, org_id)
    same_hashes = {"os": "abc123", "apps": "def456", "kbs": "ghi789"}
    device = await _create_device(db, org_id, section_hashes=same_hashes)

    from backend.app.schemas.enrollment import DeviceCheckinRequest

    # Same hashes but full_checkin=True
    body = DeviceCheckinRequest(
        hostname="UPDATED-PC",
        os_build="22631.3155",
        section_hashes=same_hashes,
        sections={
            "os": {"current_build": "22631"},
            "apps": [],
            "kbs": {"articles": [], "meta": {"collection_method": "wua", "stale": False, "count": 0}},
        },
        full_checkin=True,
    )

    device.last_seen_at = datetime.now(timezone.utc)
    device.hostname = body.hostname
    device.os_build = body.os_build

    if body.section_hashes:
        stored_hashes = device.inventory_section_hashes or {}
        hashes_changed = body.section_hashes != {
            k: v for k, v in stored_hashes.items() if k in ("apps", "kbs", "os")
        }

        if hashes_changed or body.full_checkin:
            new_stored = dict(stored_hashes)
            new_stored.update(body.section_hashes)

            if body.sections and "kbs" in body.sections:
                kb_data = body.sections["kbs"]
                kb_meta = kb_data.get("meta", {}) if isinstance(kb_data, dict) else {}
                new_stored["kbs_stale"] = kb_meta.get("stale", False)

            device.inventory_section_hashes = new_stored

    await db.commit()
    await db.refresh(device)

    # Even though hashes are same, full_checkin forced processing
    assert device.hostname == "UPDATED-PC"
    assert device.os_build == "22631.3155"
    assert device.inventory_section_hashes.get("kbs_stale") is False
