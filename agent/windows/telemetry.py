"""Per-job telemetry snapshot (before + after).

Metrics:
- cpu_percent_1s (psutil)
- crash_events_24h (Event Log: IDs 6008, 1001, 41)
- reboots_7d (Event Log: IDs 6009, 1074)
- system_disk_free_gb (psutil)

Stored in deployment_jobs.telemetry_before/after JSONB.

wevtutil and psutil disk_usage("C:\\") are guarded for Linux CI.
"""

import logging
import subprocess
import sys
from datetime import datetime, timezone

import psutil

logger = logging.getLogger(__name__)

WEVTUTIL_TIMEOUT = 10  # seconds


def collect_job_telemetry_snapshot(job_id: str) -> dict:
    """Collect a telemetry snapshot for a deployment job.

    Called before AND after patch job execution. Lightweight.
    """
    return {
        "job_id": job_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "cpu_percent_1s": _safe_cpu_percent(),
        "crash_events_24h": _count_event_log_events("System", [6008, 1001, 41], 24),
        "reboots_7d": _count_event_log_events("System", [6009, 1074], 7 * 24),
        "system_disk_free_gb": _safe_disk_free_gb(),
    }


def _safe_cpu_percent() -> float:
    """Get CPU percent over 1 second. Returns 0.0 on error."""
    try:
        return psutil.cpu_percent(interval=1)
    except Exception:
        logger.warning("Failed to collect CPU percent", exc_info=True)
        return 0.0


def _safe_disk_free_gb() -> float:
    """Get free disk space in GB. Uses C:\\ on Windows, / on Linux."""
    disk_path = "C:\\" if sys.platform == "win32" else "/"
    try:
        usage = psutil.disk_usage(disk_path)
        return round(usage.free / (1024**3), 2)
    except Exception:
        logger.warning("Failed to collect disk free for %s", disk_path, exc_info=True)
        return 0.0


def _count_event_log_events(log_name: str, event_ids: list[int], since_hours: int) -> int:
    """Count Windows Event Log entries matching event_ids within since_hours.

    Uses wevtutil qe with XPath filter. Returns 0 on any error (including
    wevtutil not available on Linux).
    """
    try:
        id_clauses = " or ".join(f"EventID={eid}" for eid in event_ids)
        time_diff_ms = since_hours * 3600 * 1000
        xpath = (
            f"*[System[({id_clauses}) and "
            f"TimeCreated[timediff(@SystemTime) <= {time_diff_ms}]]]"
        )

        proc = subprocess.run(
            ["wevtutil", "qe", log_name, "/q:" + xpath, "/f:text", "/c:10000"],
            capture_output=True,
            text=True,
            timeout=WEVTUTIL_TIMEOUT,
        )
        if proc.returncode != 0:
            return 0

        # Count event blocks in text output
        return proc.stdout.count("Event[")
    except FileNotFoundError:
        # wevtutil not available (Linux CI)
        return 0
    except subprocess.TimeoutExpired:
        logger.warning("wevtutil timed out after %ds", WEVTUTIL_TIMEOUT)
        return 0
    except Exception:
        logger.warning("Event log query failed", exc_info=True)
        return 0
