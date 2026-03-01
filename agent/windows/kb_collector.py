"""Dual-method KB collection with cache fallback.

Methods (tried in order):
1. WUA COM API (authoritative, cap 2000 entries, timeout-guarded 30s)
2. CBS registry + DISM /get-packages (fast, deterministic)
3. Local JSON cache fallback (stale after 8h)

Payload includes: collection_method, stale bool, cached_at timestamp.
Server annotates vulnerability matches as "uncertain KB baseline" when stale=true.

All Windows-only APIs (win32com, winreg, dism) are guarded for Linux CI.
"""

import json
import logging
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

KB_CACHE_PATH = Path(r"C:\ProgramData\PatchPilot\kb_cache.json")
STALE_THRESHOLD_SECONDS = 8 * 3600  # 8 hours
WUA_CAP = 2000
DISM_TIMEOUT_SECONDS = 30

try:
    import win32com.client  # noqa: F401

    _HAS_WIN32COM = True
except ImportError:
    _HAS_WIN32COM = False

try:
    import winreg  # noqa: F401

    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False

_KB_PATTERN = re.compile(r"KB\d{5,}")


class KBCollector:
    """Collects installed KBs via WUA COM API, CBS registry+DISM, or cache fallback."""

    def __init__(self, cache_path: Path | None = None):
        self.cache_path = cache_path or KB_CACHE_PATH

    def collect(self) -> tuple[set[str], dict[str, Any]]:
        """Returns (set_of_kb_strings, metadata_dict).

        Tries methods in order: WUA COM -> CBS Registry+DISM -> Cache fallback.
        metadata: {collection_method, stale, cached_at, count}
        """
        # Method 1: WUA COM API
        kbs = self._collect_wua()
        if kbs is not None:
            self._save_cache(kbs)
            return kbs, self._make_meta("wua", stale=False, count=len(kbs))

        # Method 2: CBS Registry + DISM
        kbs = self._collect_cbs_dism()
        if kbs is not None:
            self._save_cache(kbs)
            return kbs, self._make_meta("cbs", stale=False, count=len(kbs))

        # Method 3: Cache fallback
        kbs, cached_at = self._load_cache()
        now = time.time()
        is_stale = cached_at is None or (now - cached_at) > STALE_THRESHOLD_SECONDS
        cached_at_iso = (
            datetime.fromtimestamp(cached_at, tz=timezone.utc).isoformat()
            if cached_at
            else None
        )
        return kbs, {
            "collection_method": "cache",
            "stale": is_stale,
            "cached_at": cached_at_iso,
            "count": len(kbs),
        }

    def _collect_wua(self) -> set[str] | None:
        """Method 1: WUA COM API. Returns set of KB strings or None on failure."""
        if not _HAS_WIN32COM:
            return None
        try:
            import win32com.client

            session = win32com.client.Dispatch("Microsoft.Update.Session")
            searcher = session.CreateUpdateSearcher()
            total_count = searcher.GetTotalHistoryCount()
            count = min(total_count, WUA_CAP)
            history = searcher.QueryHistory(0, count)

            kbs: set[str] = set()
            for i in range(history.Count):
                entry = history.Item(i)
                # Operation 1 = installation, ResultCode 2 = succeeded
                if entry.Operation == 1 and entry.ResultCode == 2:
                    title = entry.Title or ""
                    for match in _KB_PATTERN.finditer(title.upper()):
                        kbs.add(match.group())
            return kbs if kbs else None
        except Exception:
            logger.warning("WUA COM collection failed", exc_info=True)
            return None

    def _collect_cbs_dism(self) -> set[str] | None:
        """Method 2: CBS registry + DISM /get-packages. Returns set or None."""
        kbs: set[str] = set()

        # CBS Registry
        if _HAS_WINREG:
            try:
                import winreg

                cbs_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cbs_path) as key:
                    i = 0
                    while True:
                        try:
                            name = winreg.EnumKey(key, i)
                            i += 1
                            for match in _KB_PATTERN.finditer(name.upper()):
                                kbs.add(match.group())
                        except OSError:
                            break
            except Exception:
                logger.debug("CBS registry read failed", exc_info=True)

        # DISM /get-packages
        try:
            proc = subprocess.run(
                ["dism", "/online", "/get-packages", "/format:table"],
                capture_output=True,
                text=True,
                timeout=DISM_TIMEOUT_SECONDS,
            )
            if proc.returncode == 0:
                for match in _KB_PATTERN.finditer(proc.stdout.upper()):
                    kbs.add(match.group())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.debug("DISM /get-packages unavailable or timed out")
        except Exception:
            logger.debug("DISM /get-packages failed", exc_info=True)

        return kbs if kbs else None

    def _save_cache(self, kbs: set[str]) -> None:
        """Write KB set to local JSON cache."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {"kbs": sorted(kbs), "cached_at": time.time()}
            self.cache_path.write_text(json.dumps(data))
        except Exception:
            logger.warning("Failed to save KB cache", exc_info=True)

    def _load_cache(self) -> tuple[set[str], float | None]:
        """Load KB set from local JSON cache. Returns (set, cached_at_timestamp)."""
        try:
            if self.cache_path.exists():
                data = json.loads(self.cache_path.read_text())
                return set(data.get("kbs", [])), data.get("cached_at")
        except Exception:
            logger.warning("Failed to load KB cache", exc_info=True)
        return set(), None

    @staticmethod
    def _make_meta(method: str, stale: bool, count: int) -> dict[str, Any]:
        return {
            "collection_method": method,
            "stale": stale,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "count": count,
        }
