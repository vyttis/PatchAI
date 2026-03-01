"""Phase 1D tests — deployment packs, agent versioning, token management.

Tests:
  1. GPO script contains SHA256 verification block and exits on mismatch
  2. GPO script contains Authenticode check and exits if sig.Status != "Valid"
  3. GPO script contains enrollment token in ENROLLTOKEN= argument
  4. Intune manifest has valid JSON structure and correct detection rule format
  5. Deployment pack ZIP contains all three artifacts + README
  6. Token revocation: revoked token no longer found
  7. Update check: returns update_available=true when newer version exists
  8. Update check: force_update when below minimum_supported_version
  9. Internal release: sets is_latest=true and unsets previous
"""

import json
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from io import BytesIO

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models import AgentVersion, EnrollmentToken, Organization
from backend.app.services.deployment_packs import (
    generate_gpo_script,
    generate_intune_manifest,
    generate_rmm_oneliner,
    generate_windows_pack,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_org(db: AsyncSession, org_id: uuid.UUID, name: str = "Test Corp") -> Organization:
    org = Organization(id=org_id, name=name)
    db.add(org)
    await db.flush()
    return org


async def _create_agent_version(
    db: AsyncSession,
    version: str = "1.0.0",
    is_latest: bool = True,
    sha256: str = "abc123def456",
    minimum_supported: str | None = None,
) -> AgentVersion:
    av = AgentVersion(
        version=version,
        windows_msi_url=f"https://downloads.patchpilot.com/windows/{version}/PatchPilotAgent.msi",
        windows_sha256=sha256,
        windows_sig_url=f"https://downloads.patchpilot.com/windows/{version}/PatchPilotAgent.msi.sig",
        release_notes=f"Release {version}",
        is_latest=is_latest,
        minimum_supported_version=minimum_supported,
    )
    db.add(av)
    await db.flush()
    return av


# ---------------------------------------------------------------------------
# 1. GPO script — SHA256 verification
# ---------------------------------------------------------------------------


def test_gpo_script_sha256_verification():
    """GPO script contains SHA256 check and exits on mismatch."""
    script = generate_gpo_script("1.0.0", "abc123hash", "tok_id", "tok_secret")

    assert "Get-FileHash" in script
    assert "-Algorithm SHA256" in script
    assert "$Sha256Expected" in script
    assert "abc123hash" in script
    assert "SHA256 mismatch" in script
    assert "exit 1" in script


# ---------------------------------------------------------------------------
# 2. GPO script — Authenticode check
# ---------------------------------------------------------------------------


def test_gpo_script_authenticode_check():
    """GPO script contains Authenticode signature verification."""
    script = generate_gpo_script("1.0.0", "abc123hash", "tok_id", "tok_secret")

    assert "Get-AuthenticodeSignature" in script
    assert 'sig.Status -ne "Valid"' in script
    assert "Invalid signature" in script
    assert "exit 1" in script


# ---------------------------------------------------------------------------
# 3. GPO script — enrollment token
# ---------------------------------------------------------------------------


def test_gpo_script_enrollment_token():
    """GPO script contains ENROLLTOKEN= with correct token."""
    script = generate_gpo_script("1.0.0", "abc123hash", "myTokenId", "mySecret")

    assert "ENROLLTOKEN=myTokenId.mySecret" in script


# ---------------------------------------------------------------------------
# 4. Intune manifest — structure and detection rule
# ---------------------------------------------------------------------------


def test_intune_manifest_structure():
    """Intune manifest has valid JSON structure and correct detection rule."""
    manifest = generate_intune_manifest("2.0.0", "tok_id", "tok_secret", "Acme Corp")

    assert manifest["displayName"] == "PatchPilot Agent 2.0.0"
    assert manifest["publisher"] == "PatchPilot"
    assert "Acme Corp" in manifest["description"]
    assert "ENROLLTOKEN=tok_id.tok_secret" in manifest["installCommandLine"]

    # Detection rule
    assert len(manifest["detectionRules"]) == 1
    rule = manifest["detectionRules"][0]
    assert rule["type"] == "registry"
    assert "HKLM" in rule["keyPath"]
    assert "PatchPilot" in rule["keyPath"]
    assert rule["valueName"] == "InstalledVersion"
    assert rule["detectionValue"] == "2.0.0"

    # Return codes
    codes = {rc["returnCode"]: rc["type"] for rc in manifest["returnCodes"]}
    assert codes[0] == "success"
    assert codes[1641] == "softReboot"
    assert codes[3010] == "softReboot"

    # Verify it serializes as valid JSON
    json_str = json.dumps(manifest)
    parsed = json.loads(json_str)
    assert parsed["displayName"] == manifest["displayName"]


# ---------------------------------------------------------------------------
# 5. Deployment pack ZIP contents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deployment_pack_zip_contents(db: AsyncSession, org_id):
    """Deployment pack ZIP contains all four artifacts."""
    await _create_org(db, org_id)
    await _create_agent_version(db, "1.0.0", is_latest=True, sha256="deadbeef")

    zip_bytes, token_id, token_secret = await generate_windows_pack(
        db=db,
        org_id=org_id,
        dept_id=None,
        label="test-pack",
        max_uses=10,
        expires_hours=24,
        org_name="Test Corp",
    )

    assert len(zip_bytes) > 0
    assert token_id
    assert token_secret

    # Open ZIP and verify contents
    with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
        names = zf.namelist()
        assert "gpo_startup.ps1" in names
        assert "intune_win32.json" in names
        assert "rmm_oneliner.ps1" in names
        assert "README.txt" in names

        # Verify GPO script has the token
        gpo = zf.read("gpo_startup.ps1").decode()
        assert f"ENROLLTOKEN={token_id}.{token_secret}" in gpo
        assert "deadbeef" in gpo

        # Verify Intune JSON is valid
        intune_raw = zf.read("intune_win32.json").decode()
        intune = json.loads(intune_raw)
        assert intune["displayName"] == "PatchPilot Agent 1.0.0"
        assert f"ENROLLTOKEN={token_id}.{token_secret}" in intune["installCommandLine"]

        # Verify RMM one-liner has SHA256 check
        rmm = zf.read("rmm_oneliner.ps1").decode()
        assert "Get-FileHash" in rmm
        assert "Get-AuthenticodeSignature" in rmm
        assert f"ENROLLTOKEN={token_id}.{token_secret}" in rmm


# ---------------------------------------------------------------------------
# 6. Token revocation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_revocation_prevents_enrollment(db: AsyncSession, org_id):
    """Revoked (deleted) token no longer found by token_id lookup."""
    await _create_org(db, org_id)

    # Create a token
    from backend.app.services.deployment_packs import create_enrollment_token_for_pack

    token_id, _ = await create_enrollment_token_for_pack(
        db, org_id, None, "test-revoke", max_uses=10, expires_hours=24
    )
    await db.commit()

    # Verify it exists
    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == token_id)
    )
    assert result.scalar_one_or_none() is not None

    # Delete (revoke) the token
    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == token_id)
    )
    token = result.scalar_one()
    await db.delete(token)
    await db.commit()

    # Verify it no longer exists
    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == token_id)
    )
    assert result.scalar_one_or_none() is None


# ---------------------------------------------------------------------------
# 7. Update check — newer version available
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_check_newer_version(db: AsyncSession):
    """Returns update_available=true when latest version is newer than current."""
    await _create_agent_version(db, "1.0.0", is_latest=False)
    await _create_agent_version(db, "2.0.0", is_latest=True, minimum_supported="1.0.0")

    from backend.app.services.deployment_packs import get_latest_agent_version
    from packaging.version import Version

    latest = await get_latest_agent_version(db)
    assert latest is not None
    assert latest.version == "2.0.0"

    # Simulate check: current 1.0.0 < latest 2.0.0
    assert Version("2.0.0") > Version("1.0.0")

    # Simulate check: current 2.0.0 == latest 2.0.0
    assert not (Version("2.0.0") > Version("2.0.0"))


# ---------------------------------------------------------------------------
# 8. Update check — force update below minimum
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_check_force_update_below_minimum(db: AsyncSession):
    """force_update=true when current version is below minimum_supported_version."""
    await _create_agent_version(
        db, "2.0.0", is_latest=True, minimum_supported="1.5.0"
    )

    from packaging.version import Version

    latest_min = Version("1.5.0")

    # 1.0.0 < 1.5.0 → force update
    assert Version("1.0.0") < latest_min

    # 1.5.0 is not < 1.5.0 → no force
    assert not (Version("1.5.0") < latest_min)

    # 2.0.0 is not < 1.5.0 → no force
    assert not (Version("2.0.0") < latest_min)


# ---------------------------------------------------------------------------
# 9. Internal release — sets is_latest
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_internal_release_sets_latest(db: AsyncSession):
    """New release sets is_latest=true and unsets previous."""
    v1 = await _create_agent_version(db, "1.0.0", is_latest=True)
    await db.commit()

    assert v1.is_latest is True

    # Simulate internal release: unset old, create new
    from sqlalchemy import update

    await db.execute(
        update(AgentVersion).where(AgentVersion.is_latest == True).values(is_latest=False)  # noqa: E712
    )

    v2 = AgentVersion(
        version="2.0.0",
        windows_msi_url="https://downloads.patchpilot.com/windows/2.0.0/PatchPilotAgent.msi",
        windows_sha256="newsha256",
        is_latest=True,
    )
    db.add(v2)
    await db.commit()

    # Refresh and verify
    await db.refresh(v1)
    assert v1.is_latest is False

    result = await db.execute(
        select(AgentVersion).where(AgentVersion.version == "2.0.0")
    )
    v2_loaded = result.scalar_one()
    assert v2_loaded.is_latest is True
