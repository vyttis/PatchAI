"""Deployment pack generator — GPO, Intune, and RMM artifacts.

Generates ZIP bundles containing PowerShell scripts and Intune manifests
pre-configured with enrollment tokens for mass agent rollout.
"""

import io
import json
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.agent_versions import AgentVersion
from backend.app.models.enrollment_tokens import EnrollmentToken

DOWNLOAD_BASE_URL = "https://downloads.patchpilot.com/windows"


async def create_enrollment_token_for_pack(
    db: AsyncSession,
    org_id,
    dept_id,
    label: str,
    max_uses: int = 500,
    expires_hours: int = 24,
) -> tuple[str, str]:
    """Create an enrollment token for embedding in deployment packs.

    Returns (token_id, token_secret). Same crypto pattern as enrollment router.
    Invariant #11: two-part format, bcrypt-hashed secret.
    """
    token_id = secrets.token_urlsafe(12)
    token_secret = secrets.token_urlsafe(32)
    token_hash = bcrypt.hashpw(
        token_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)

    token = EnrollmentToken(
        token_id=token_id,
        token_hash=token_hash,
        org_id=org_id,
        dept_id=dept_id,
        label=f"deploy-pack:{label}",
        expires_at=expires_at,
        max_uses=max_uses,
    )
    db.add(token)
    await db.flush()

    return token_id, token_secret


async def get_latest_agent_version(db: AsyncSession) -> Optional[AgentVersion]:
    """Fetch the agent version marked as latest."""
    result = await db.execute(
        select(AgentVersion).where(AgentVersion.is_latest == True).limit(1)  # noqa: E712
    )
    return result.scalar_one_or_none()


def generate_gpo_script(
    version: str, sha256: str, token_id: str, token_secret: str
) -> str:
    """Generate GPO startup PowerShell script with SHA256 + Authenticode verification."""
    return f'''# PatchPilot Agent — GPO Startup Script
# Version: {version}
# Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

$ErrorActionPreference = "Stop"
$InstallerUrl = "{DOWNLOAD_BASE_URL}/{version}/PatchPilotAgent.msi"
$Sha256Expected = "{sha256}"
$TempPath = "$env:TEMP\\PatchPilotAgent.msi"

# Download
Invoke-WebRequest -Uri $InstallerUrl -OutFile $TempPath -UseBasicParsing

# Verify SHA256 (fail hard if mismatch)
$Sha256Actual = (Get-FileHash $TempPath -Algorithm SHA256).Hash
if ($Sha256Actual -ne $Sha256Expected) {{
    Remove-Item $TempPath -Force
    Write-Error "SHA256 mismatch — aborting install"; exit 1
}}

# Verify Authenticode signature (fail hard if invalid)
$sig = Get-AuthenticodeSignature $TempPath
if ($sig.Status -ne "Valid") {{
    Remove-Item $TempPath -Force
    Write-Error "Invalid signature — aborting install"; exit 1
}}

# Silent install with enrollment token
Start-Process msiexec -ArgumentList "/i $TempPath /quiet ENROLLTOKEN={token_id}.{token_secret}" -Wait
Remove-Item $TempPath -Force
'''


def generate_intune_manifest(
    version: str, token_id: str, token_secret: str, org_name: str
) -> dict:
    """Generate Intune Win32 app manifest JSON."""
    return {
        "displayName": f"PatchPilot Agent {version}",
        "description": f"PatchPilot endpoint agent — auto-enrolled to {org_name}",
        "publisher": "PatchPilot",
        "installCommandLine": (
            f"msiexec /i PatchPilotAgent.msi /quiet "
            f"ENROLLTOKEN={token_id}.{token_secret}"
        ),
        "uninstallCommandLine": "msiexec /x {product_code} /quiet",
        "detectionRules": [
            {
                "type": "registry",
                "keyPath": "HKLM\\SOFTWARE\\PatchPilot",
                "valueName": "InstalledVersion",
                "operator": "equal",
                "detectionValue": version,
            }
        ],
        "returnCodes": [
            {"returnCode": 0, "type": "success"},
            {"returnCode": 1641, "type": "softReboot"},
            {"returnCode": 3010, "type": "softReboot"},
        ],
    }


def generate_rmm_oneliner(
    version: str, sha256: str, token_id: str, token_secret: str
) -> str:
    """Generate single-line PowerShell for RMM/SSH deployment."""
    url = f"{DOWNLOAD_BASE_URL}/{version}/PatchPilotAgent.msi"
    return (
        f'$p="$env:TEMP\\PatchPilotAgent.msi"; '
        f'Invoke-WebRequest -Uri "{url}" -OutFile $p -UseBasicParsing; '
        f'$h=(Get-FileHash $p -Algorithm SHA256).Hash; '
        f'if($h -ne "{sha256}"){{Remove-Item $p -Force; '
        f'Write-Error "SHA256 mismatch"; exit 1}}; '
        f'$s=Get-AuthenticodeSignature $p; '
        f'if($s.Status -ne "Valid"){{Remove-Item $p -Force; '
        f'Write-Error "Invalid signature"; exit 1}}; '
        f'Start-Process msiexec -ArgumentList "/i $p /quiet '
        f'ENROLLTOKEN={token_id}.{token_secret}" -Wait; '
        f'Remove-Item $p -Force'
    )


def generate_readme(label: str, version: str) -> str:
    """Generate README.txt with deployment instructions."""
    return f"""PatchPilot Deployment Pack — {label}
Agent Version: {version}
Generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}

FILES:
  gpo_startup.ps1   — GPO Computer Startup Script
  intune_win32.json  — Microsoft Intune Win32 app manifest
  rmm_oneliner.ps1   — Single-line PowerShell for RMM tools
  README.txt         — This file

DEPLOYMENT OPTIONS:

1. GROUP POLICY (GPO):
   Copy gpo_startup.ps1 to a network share.
   Create a GPO: Computer Configuration > Policies > Windows Settings >
   Scripts > Startup. Add the script.

2. MICROSOFT INTUNE:
   Upload PatchPilotAgent.msi as a Win32 app.
   Use intune_win32.json as the app configuration reference.
   The install command and detection rules are pre-configured.

3. RMM / REMOTE DEPLOYMENT:
   Run the contents of rmm_oneliner.ps1 via your RMM tool or SSH.
   It downloads, verifies, and installs the agent in one command.

SECURITY:
  All scripts verify the MSI SHA256 hash before installation.
  All scripts verify the Authenticode digital signature.
  The enrollment token expires — check your PatchPilot dashboard for status.
"""


async def generate_windows_pack(
    db: AsyncSession,
    org_id,
    dept_id,
    label: str,
    max_uses: int = 500,
    expires_hours: int = 24,
    org_name: str = "Organization",
) -> tuple[bytes, str, str]:
    """Generate a deployment pack ZIP for Windows.

    Returns (zip_bytes, token_id, token_secret).
    Raises ValueError if no agent version is published.
    """
    token_id, token_secret = await create_enrollment_token_for_pack(
        db, org_id, dept_id, label, max_uses, expires_hours
    )

    agent_version = await get_latest_agent_version(db)
    if not agent_version:
        raise ValueError("No agent version published — upload a release first")

    version = agent_version.version
    sha256 = agent_version.windows_sha256 or ""

    gpo = generate_gpo_script(version, sha256, token_id, token_secret)
    intune = generate_intune_manifest(version, token_id, token_secret, org_name)
    rmm = generate_rmm_oneliner(version, sha256, token_id, token_secret)
    readme = generate_readme(label, version)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("gpo_startup.ps1", gpo)
        zf.writestr("intune_win32.json", json.dumps(intune, indent=2))
        zf.writestr("rmm_oneliner.ps1", rmm)
        zf.writestr("README.txt", readme)
    buf.seek(0)

    return buf.read(), token_id, token_secret
