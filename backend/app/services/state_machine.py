"""Deployment job state machine — validated transitions with audit-before-change.

Invariant #10: "job.state_changed" is a CRITICAL event — audit INSERT must
succeed BEFORE the state change proceeds. If audit fails, state does NOT change.

Invalid transitions raise InvalidTransition — never silent fail.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.services import audit

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Transition map
# ---------------------------------------------------------------------------

VALID_TRANSITIONS: dict[str, list[str]] = {
    "queued": ["downloading", "failed"],
    "downloading": ["installing", "failed"],
    "installing": ["pending_reboot", "verifying", "failed"],
    "pending_reboot": ["user_deferred", "forced_reboot", "verifying"],
    "user_deferred": ["pending_reboot", "forced_reboot"],
    "forced_reboot": ["verifying"],
    "verifying": ["complete", "failed"],
    "failed": ["diagnosing"],
    "diagnosing": ["queued", "failed_final"],  # queued = auto-retry
    "complete": [],
    "failed_final": [],
}


class InvalidTransition(Exception):
    """Raised when a state transition is not in VALID_TRANSITIONS."""

    pass


# ---------------------------------------------------------------------------
# Core transition function
# ---------------------------------------------------------------------------


async def transition(
    db: AsyncSession,
    job,
    new_state: str,
    reason: str | None = None,
) -> None:
    """Validate transition → write CRITICAL audit → update state.

    Raises InvalidTransition if the transition is not allowed.
    Raises AuditInsertError if the audit INSERT fails — state is NOT changed.

    Reboot deferral rules:
    - PENDING_REBOOT → USER_DEFERRED: only if deferred_count < 3
    - USER_DEFERRED → FORCED_REBOOT: allowed when deferred_count >= 3
    """
    old_state = job.state
    allowed = VALID_TRANSITIONS.get(old_state, [])

    if new_state not in allowed:
        raise InvalidTransition(
            f"{old_state} \u2192 {new_state} not allowed"
        )

    # Deferral enforcement
    if old_state == "pending_reboot" and new_state == "user_deferred":
        if job.deferred_count >= 3:
            raise InvalidTransition(
                "Max 3 deferrals reached, must force reboot"
            )

    # CRITICAL: write audit BEFORE changing state (Invariant #10).
    # If audit.record raises AuditInsertError, state does NOT change.
    await audit.record(
        db,
        event_type="job.state_changed",
        org_id=job.org_id,
        device_id=job.device_id,
        resource=str(job.id),
        changes={
            "old_state": old_state,
            "new_state": new_state,
            "reason": reason,
        },
    )

    # --- Only after audit succeeds ---
    now = datetime.now(timezone.utc)
    job.state = new_state
    job.state_updated_at = now

    if old_state == "pending_reboot" and new_state == "user_deferred":
        job.deferred_count += 1

    if new_state == "forced_reboot":
        job.forced_reboot_at = now

    if new_state == "complete":
        job.completed_at = now

    if new_state in ("failed", "failed_final") and reason:
        job.failure_reason = reason

    # Auto-retry: diagnosing → queued increments retry_count
    if old_state == "diagnosing" and new_state == "queued":
        job.retry_count += 1
