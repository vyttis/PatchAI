"""Phase 4A tests — governed AI layer with GDPR consent gate, redaction, blast-radius guard.

7 integration tests using async SQLite fixtures from conftest.py.

Phase 4A Gate:
  - AI disabled by default → test 1 (AIDisabledError)
  - Audit written before API call → test 2 (audit exists despite API failure)
  - Blast radius blocks non-admin at 201 devices → test 3
  - Redaction removes hostnames → test 4
  - Device-{hash} present in sanitized payload → test 5
  - nl_block_deploy_all blocks "all devices" → test 6
  - narrate_compliance_report returns template when AI disabled → test 7
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from backend.app.models.audit_log import AuditLog
from backend.app.models.device_vulnerabilities import DeviceVulnerability
from backend.app.models.devices import Device
from backend.app.models.organizations import Organization
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.services.ai import (
    AIDisabledError,
    AIFeatureDisabledError,
    AIRedactor,
    AIService,
    BlastRadiusExceededError,
    BlockedActionError,
    estimate_blast_radius,
    render_template_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db, org_id, *, ai_policy=None):
    """Create org with optional ai_policy in settings."""
    settings = {}
    if ai_policy is not None:
        settings["ai_policy"] = ai_policy
    org = Organization(id=org_id, name="TestOrg4A", settings=settings)
    db.add(org)
    await db.flush()
    return org


async def _create_device(db, org_id, hostname="LAPTOP-JSMITH"):
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


async def _create_vuln(db, cve_id="CVE-2024-AI001", *, cvss=8.0, epss=0.7, in_kev=True):
    vuln = Vulnerability(
        cve_id=cve_id,
        cvss_base_score=Decimal(str(cvss)),
        epss_score=Decimal(str(epss)),
        in_cisa_kev=in_kev,
        published_at=datetime(2024, 5, 15, tzinfo=timezone.utc),
    )
    db.add(vuln)
    await db.flush()
    return vuln


# ---------------------------------------------------------------------------
# Test 1: AI disabled raises AIDisabledError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ai_disabled_raises_error(db, org_id, user_id):
    """When org has no ai_policy or external_ai_enabled=false,
    any AI call raises AIDisabledError.
    """
    # Org with default settings — AI disabled
    await _create_org(db, org_id)

    service = AIService()

    with pytest.raises(AIDisabledError, match="not enabled"):
        await service.execute_nl_query(
            db, org_id, user_id, "What are our top vulnerabilities?", "admin"
        )

    # Also test with explicit False
    org = await db.get(Organization, org_id)
    org.settings = {"ai_policy": {"external_ai_enabled": False}}
    await db.flush()

    with pytest.raises(AIDisabledError, match="not enabled"):
        await service.execute_nl_query(
            db, org_id, user_id, "Show me unpatched devices", "admin"
        )


# ---------------------------------------------------------------------------
# Test 2: Audit written before API call (mock Claude to throw)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_written_before_api_call(db, org_id, user_id):
    """When the Claude API throws an error, the audit log entry must
    still exist — proving audit was written BEFORE the API call.
    """
    await _create_org(db, org_id, ai_policy={
        "external_ai_enabled": True,
        "allowed_features": ["nl_query"],
        "redaction": {"hostnames": True, "ip_addresses": True},
        "nl_blast_radius_limit": 200,
        "nl_block_deploy_all": True,
    })
    # Create some fleet data for context
    await _create_device(db, org_id, hostname="AUDIT-HOST-01")
    await _create_vuln(db, "CVE-2024-AUDIT01")

    service = AIService()

    # Mock the Anthropic client to raise an error
    mock_response = MagicMock()
    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(side_effect=Exception("API connection failed"))

    with patch("backend.app.services.ai.anthropic") as mock_anthropic:
        mock_anthropic.AsyncAnthropic.return_value = mock_client

        with pytest.raises(Exception, match="API connection failed"):
            await service.execute_nl_query(
                db, org_id, user_id, "Show me top risks", "admin"
            )

    # Verify the audit log entry was written BEFORE the API call failed
    result = await db.execute(
        select(AuditLog).where(
            AuditLog.org_id == org_id,
            AuditLog.event_type == "ai.external_call",
        )
    )
    audit_entries = result.scalars().all()
    assert len(audit_entries) == 1

    entry = audit_entries[0]
    assert entry.ai_feature == "nl_query"
    assert entry.user_id == user_id
    assert entry.changes is not None
    assert "payload_hash" in entry.changes
    assert entry.changes["feature"] == "nl_query"


# ---------------------------------------------------------------------------
# Test 3: Blast radius gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blast_radius_gate(db, org_id, user_id):
    """Blast radius > limit blocks 'admin' but passes for 'org_admin'."""
    await _create_org(db, org_id, ai_policy={
        "external_ai_enabled": True,
        "allowed_features": ["nl_query"],
        "nl_blast_radius_limit": 200,
        "nl_block_deploy_all": False,  # Disable to test blast radius separately
    })
    await _create_device(db, org_id, hostname="BR-HOST-01")

    service = AIService()

    # Mock Claude API to return text with blast radius > 200
    mock_content = MagicMock()
    mock_content.text = "I recommend deploying the patch affecting 201 devices in the canary ring first."
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(return_value=mock_response)

    with patch("backend.app.services.ai.anthropic") as mock_anthropic:
        mock_anthropic.AsyncAnthropic.return_value = mock_client

        # admin role should be blocked
        with pytest.raises(BlastRadiusExceededError) as exc_info:
            await service.execute_nl_query(
                db, org_id, user_id, "Deploy patch to all servers", "admin"
            )
        assert exc_info.value.actual == 201
        assert exc_info.value.limit == 200

        # org_admin role should pass
        result = await service.execute_nl_query(
            db, org_id, user_id, "Deploy patch to all servers", "org_admin"
        )
        assert result["blast_radius"] == 201
        assert result["requires_confirmation"] is True


# ---------------------------------------------------------------------------
# Test 4: Redaction removes hostnames
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redaction_removes_hostname(db):
    """AIRedactor.sanitize() removes 'LAPTOP-JSMITH' from payload."""
    redactor = AIRedactor()

    payload = {
        "hostname": "LAPTOP-JSMITH",
        "summary": "LAPTOP-JSMITH has 3 critical vulnerabilities",
        "ip_address": "10.0.1.42",
    }
    policy = {"redaction": {"hostnames": True, "ip_addresses": True}}

    sanitized, redaction_map = redactor.sanitize(payload, policy)

    # Original hostname must NOT appear anywhere in sanitized payload
    sanitized_str = json.dumps(sanitized)
    assert "LAPTOP-JSMITH" not in sanitized_str

    # IP address must NOT appear
    assert "10.0.1.42" not in sanitized_str

    # Redaction map must contain the anonymised → original mapping
    assert len(redaction_map) >= 1
    # At least one Device-xxxx key
    device_keys = [k for k in redaction_map if k.startswith("Device-")]
    assert len(device_keys) >= 1
    # The original hostname is a value in the map
    assert "LAPTOP-JSMITH" in redaction_map.values()


# ---------------------------------------------------------------------------
# Test 5: Device-{hash} present in sanitized payload
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_device_hash_in_sanitized_payload(db):
    """Sanitized payload contains Device-{hash[:4]} pattern."""
    redactor = AIRedactor()

    payload = {
        "hostname": "LAPTOP-JSMITH",
        "description": "LAPTOP-JSMITH needs immediate patching",
    }
    policy = {"redaction": {"hostnames": True, "ip_addresses": False}}

    sanitized, redaction_map = redactor.sanitize(payload, policy)

    sanitized_str = json.dumps(sanitized)

    # Must contain Device-xxxx pattern
    assert "Device-" in sanitized_str

    # The sanitized hostname field should be Device-{hash}
    assert sanitized["hostname"].startswith("Device-")
    assert len(sanitized["hostname"]) == len("Device-") + 4  # Device- + 4 hex chars


# ---------------------------------------------------------------------------
# Test 6: nl_block_deploy_all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nl_block_deploy_all(db, org_id, user_id):
    """'patch all devices' in AI response is blocked when nl_block_deploy_all=true."""
    await _create_org(db, org_id, ai_policy={
        "external_ai_enabled": True,
        "allowed_features": ["nl_query"],
        "nl_blast_radius_limit": 99999,  # High limit to not trigger blast radius
        "nl_block_deploy_all": True,
    })
    await _create_device(db, org_id, hostname="BLOCK-HOST-01")

    service = AIService()

    # Mock Claude API to return text with "all devices"
    mock_content = MagicMock()
    mock_content.text = "You should patch all devices immediately to mitigate the risk."
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    mock_client = AsyncMock()
    mock_client.messages.create = AsyncMock(return_value=mock_response)

    with patch("backend.app.services.ai.anthropic") as mock_anthropic:
        mock_anthropic.AsyncAnthropic.return_value = mock_client

        with pytest.raises(BlockedActionError, match="all devices"):
            await service.execute_nl_query(
                db, org_id, user_id, "How do I fix everything?", "org_admin"
            )


# ---------------------------------------------------------------------------
# Test 7: narrate_compliance_report template fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_narrate_report_template_fallback(db, org_id, user_id):
    """When AI is disabled, narrate_compliance_report returns a template
    string — no API call made.
    """
    # Org with AI disabled
    await _create_org(db, org_id)

    service = AIService()

    report_data = {
        "period_days": 30,
        "total_exposed": 50,
        "total_patched": 42,
        "patch_rate": 0.84,
        "mttrem_p50": 6.5,
        "top_unresolved": [
            {"cve_id": "CVE-2024-9999", "device_count": 8},
        ],
    }

    # Should NOT call Anthropic API at all
    with patch("backend.app.services.ai.anthropic") as mock_anthropic:
        result = await service.narrate_compliance_report(
            db, org_id, user_id, report_data
        )

        # No API call made
        mock_anthropic.AsyncAnthropic.assert_not_called()

    assert result["ai_generated"] is False
    assert "42 of 50" in result["narrative"]
    assert "84.0%" in result["narrative"]
    assert "6.5 hours" in result["narrative"]
    assert "CVE-2024-9999" in result["narrative"]
    assert "without AI narration" in result["narrative"]


# ---------------------------------------------------------------------------
# Bonus: estimate_blast_radius unit tests
# ---------------------------------------------------------------------------


def test_estimate_blast_radius_parsing():
    """estimate_blast_radius correctly parses device count from AI text."""
    assert estimate_blast_radius("deploying to 150 devices") == 150
    assert estimate_blast_radius("affecting 201 devices in production") == 201
    assert estimate_blast_radius("no devices mentioned") == 0
    assert estimate_blast_radius("patching 50 endpoints") == 50


def test_render_template_report():
    """Template report contains expected data."""
    report = render_template_report({
        "period_days": 30,
        "total_exposed": 100,
        "total_patched": 80,
        "patch_rate": 0.8,
        "mttrem_p50": 4.2,
    })
    assert "30" in report
    assert "80 of 100" in report
    assert "80.0%" in report
    assert "4.2 hours" in report
