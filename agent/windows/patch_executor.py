"""Winget + fallback chain for patch execution.

Three-path fallback:
1. winget upgrade --silent (if winget_available from last check-in)
2. Relay node download (if relay_node_available)
3. Direct MSI download with SHA256 verification

SYSTEM context workaround: schtasks to run winget as NETWORK SERVICE.

Phase 3A: stubs with telemetry before/after collection.
Full implementation: Phase 3B (BLPOP command delivery integration).
"""

import logging
from dataclasses import dataclass
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of a playbook execution."""

    status: str  # "success" | "failed" | "pending_reboot" | "not_implemented"
    reason: Optional[str] = None
    requires_reboot: bool = False
    telemetry_before: Optional[dict] = None
    telemetry_after: Optional[dict] = None


def execute_playbook(playbook: dict, job_id: str) -> ExecutionResult:
    """Execute a remediation playbook. Collects telemetry before + after.

    Dispatches to _execute_patch or _execute_config_mitigation based on
    playbook["type"]. Collects per-job telemetry snapshots (cpu, crash events,
    reboots, disk) before and after execution.
    """
    from agent.windows.telemetry import collect_job_telemetry_snapshot

    telemetry_before = collect_job_telemetry_snapshot(job_id)

    if playbook.get("type") == "patch":
        result = _execute_patch(playbook, job_id)
    elif playbook.get("type") == "config_mitigation":
        result = _execute_config_mitigation(playbook)
    else:
        result = ExecutionResult(
            status="failed",
            reason=f"Unknown playbook type: {playbook.get('type')}",
        )

    telemetry_after = collect_job_telemetry_snapshot(job_id)
    result.telemetry_before = telemetry_before
    result.telemetry_after = telemetry_after

    return result


def _execute_patch(playbook: dict, job_id: str) -> ExecutionResult:
    """Execute a patch installation using three-path fallback.

    Path 1: winget upgrade --silent (if winget_available)
    Path 2: Relay node download (if relay_node_available)
    Path 3: Direct MSI download with SHA256 verification

    Phase 3A: stub implementation. Full integration in Phase 3B.
    """
    winget_id = playbook.get("winget_id")
    if winget_id and _winget_available():
        return _run_winget(winget_id)

    if _relay_available():
        return _download_and_install_via_relay(playbook)

    return _download_and_install_direct(playbook)


def _execute_config_mitigation(playbook: dict) -> ExecutionResult:
    """Execute a configuration mitigation (registry change, GPO, etc.).

    Phase 3A stub.
    """
    logger.info("Config mitigation stub: %s", playbook.get("title", "unknown"))
    return ExecutionResult(
        status="not_implemented",
        reason="Config mitigation execution — Phase 3B",
    )


# ---------------------------------------------------------------------------
# Winget path
# ---------------------------------------------------------------------------


def _winget_available() -> bool:
    """Check if winget is available on this system. Phase 3B stub."""
    return False


def _run_winget(winget_id: str) -> ExecutionResult:
    """Run winget upgrade via scheduled task (SYSTEM context workaround).

    Phase 3A stub.
    """
    logger.info("Winget stub: would install %s", winget_id)
    return ExecutionResult(
        status="not_implemented",
        reason=f"Winget install {winget_id} — Phase 3B",
    )


def execute_winget_via_scheduled_task(winget_id: str) -> int:
    """SYSTEM context workaround: create scheduled task as NETWORK SERVICE.

    Creates a temporary scheduled task that runs:
      winget upgrade --id {winget_id} --silent
    as NETWORK SERVICE, then waits for completion and cleans up.

    Phase 3A stub — raises NotImplementedError.
    """
    task_name = f"PatchPilot_Winget_{uuid4().hex[:8]}"
    # Full implementation in Phase 3B:
    # cmd = f'schtasks /create /tn {task_name} /sc once /st 00:00 '
    #       f'/tr "winget upgrade --id {winget_id} --silent" '
    #       f'/ru "NETWORK SERVICE" /f'
    # subprocess.run(cmd, shell=True, check=True)
    # subprocess.run(f"schtasks /run /tn {task_name}", shell=True, check=True)
    # Poll schtasks /query until complete
    # subprocess.run(f"schtasks /delete /tn {task_name} /f", shell=True)
    raise NotImplementedError(
        f"Winget scheduled task execution for {winget_id} — Phase 3B"
    )


# ---------------------------------------------------------------------------
# Relay path
# ---------------------------------------------------------------------------


def _relay_available() -> bool:
    """Check if a relay node is available. Phase 3B stub."""
    return False


def _download_and_install_via_relay(playbook: dict) -> ExecutionResult:
    """Download patch from relay node and install. Phase 3B stub."""
    return ExecutionResult(
        status="not_implemented",
        reason="Relay download — Phase 3B",
    )


# ---------------------------------------------------------------------------
# Direct download path
# ---------------------------------------------------------------------------


def _download_and_install_direct(playbook: dict) -> ExecutionResult:
    """Download MSI directly with SHA256 verification and install.

    Phase 3A stub.
    """
    return ExecutionResult(
        status="not_implemented",
        reason="Direct download — Phase 3B",
    )
