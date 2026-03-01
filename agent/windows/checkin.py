"""mTLS check-in loop with delta hashing.

- mTLS client cert for device authentication (Invariant #6: mTLS only, no JWT)
- Inventory delta: hash each section (apps, kbs, os) independently
- Send only changed sections each check-in
- Daily forced full send at 03:00 local time regardless of hash
- Long-poll for commands after check-in

Implementation: Phase 1C
"""

import asyncio
import hashlib
import json
import logging
import random
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

HASH_CACHE_PATH = Path(r"C:\ProgramData\PatchPilot\inventory_hashes.json")
DEFAULT_INTERVAL_SECONDS = 300
FAST_CADENCE_SECONDS = 30
FAST_CADENCE_DURATION = 600  # 10 minutes
JITTER_FACTOR = 0.2  # ±20%
FORCE_FULL_HOUR = 3  # 03:00 local time
FORCE_FULL_MINUTE_WINDOW = 5  # 03:00 to 03:05


def _section_hash(data: Any) -> str:
    """SHA-256[:16] of JSON-serialized section data."""
    blob = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _load_hash_cache(cache_path: Path) -> dict[str, str]:
    """Load section hashes from local cache file."""
    try:
        if cache_path.exists():
            return json.loads(cache_path.read_text())
    except Exception:
        logger.debug("Failed to read hash cache", exc_info=True)
    return {}


def _save_hash_cache(cache_path: Path, hashes: dict[str, str]) -> None:
    """Persist section hashes to local cache file."""
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(hashes))
    except Exception:
        logger.warning("Failed to save hash cache", exc_info=True)


def _is_force_full_window() -> bool:
    """Check if current local time is in the 03:00-03:05 force-full window."""
    now = datetime.now()
    return now.hour == FORCE_FULL_HOUR and now.minute < FORCE_FULL_MINUTE_WINDOW


def build_checkin_payload(
    inventory: dict[str, Any],
    hostname: str,
    os_build: Optional[str] = None,
    cache_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Build a delta check-in payload.

    Compares SHA-256[:16] per section (apps, kbs, os) against cached hashes.
    Only includes sections whose hash differs. If cache doesn't exist (first run)
    or it's the 03:00 window, forces a full check-in with all sections.

    Returns dict suitable for POST /api/v1/devices/checkin.
    """
    cache_path = cache_path or HASH_CACHE_PATH
    old_hashes = _load_hash_cache(cache_path)
    force_full = not old_hashes or _is_force_full_window()

    new_hashes: dict[str, str] = {}
    changed_sections: dict[str, Any] = {}

    for section_name in ("apps", "kbs", "os"):
        data = inventory.get(section_name)
        if data is None:
            continue
        h = _section_hash(data)
        new_hashes[section_name] = h
        if force_full or h != old_hashes.get(section_name):
            changed_sections[section_name] = data

    _save_hash_cache(cache_path, new_hashes)

    return {
        "hostname": hostname,
        "os_build": os_build,
        "section_hashes": new_hashes,
        "sections": changed_sections if changed_sections else None,
        "full_checkin": force_full,
    }


class CheckinClient:
    """mTLS check-in client for PatchPilot agent.

    Reads config from agent.json (JSON, not YAML — no pyyaml dep).
    Uses httpx with client certificate for mTLS.
    """

    def __init__(
        self,
        server_url: str,
        cert_path: str,
        key_path: str,
        ca_cert_path: str,
        device_id: str,
        hostname: str,
    ):
        self.server_url = server_url.rstrip("/")
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_cert_path = ca_cert_path
        self.device_id = device_id
        self.hostname = hostname
        self._fast_cadence_until: float = 0
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                cert=(self.cert_path, self.key_path),
                verify=self.ca_cert_path,
                timeout=httpx.Timeout(60.0, connect=10.0),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def check_in(self, inventory: dict, cache_path: Optional[Path] = None) -> dict:
        """Send delta check-in to server. Returns response dict."""
        os_build = inventory.get("os", {}).get("current_build")
        payload = build_checkin_payload(
            inventory=inventory,
            hostname=self.hostname,
            os_build=os_build,
            cache_path=cache_path,
        )

        client = self._get_client()
        resp = await client.post(
            f"{self.server_url}/api/v1/devices/checkin",
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()

    def _interval(self) -> float:
        """Get check-in interval with jitter. Respects fast cadence if active."""
        import time

        if time.time() < self._fast_cadence_until:
            base = FAST_CADENCE_SECONDS
        else:
            base = DEFAULT_INTERVAL_SECONDS
        return base * random.uniform(1 - JITTER_FACTOR, 1 + JITTER_FACTOR)

    def activate_fast_cadence(self) -> None:
        """Switch to fast cadence (30s) for 10 minutes."""
        import time

        self._fast_cadence_until = time.time() + FAST_CADENCE_DURATION

    async def run_loop(self, collect_inventory_fn) -> None:
        """Main check-in loop. Never returns (runs until process exit).

        Args:
            collect_inventory_fn: callable returning dict with keys: apps, kbs, os
        """
        logger.info("Check-in loop starting for device %s", self.device_id)
        while True:
            try:
                inventory = collect_inventory_fn()
                response = await self.check_in(inventory)
                if response.get("commands_pending"):
                    logger.info("Commands pending — will poll for next command")
                    # Phase 3B: long-poll GET /next-command
            except httpx.HTTPStatusError as exc:
                logger.error("Check-in HTTP error: %s", exc.response.status_code)
            except Exception:
                logger.error("Check-in failed", exc_info=True)

            await asyncio.sleep(self._interval())
