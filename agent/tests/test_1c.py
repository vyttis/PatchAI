"""Phase 1C agent tests — inventory, KB collection, telemetry, check-in delta.

All Windows APIs (winreg, win32com, wevtutil, dism) are mocked for Linux CI.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Check-in delta payload tests
# ---------------------------------------------------------------------------


class TestBuildCheckinPayload:
    """Tests for build_checkin_payload delta hashing logic."""

    def test_unchanged_section_excluded(self, hash_cache_path):
        """Section with same hash as cache is NOT in sections dict."""
        from agent.windows.checkin import _section_hash, build_checkin_payload

        inventory = {
            "os": {"current_build": "22631", "ubr": 100},
            "apps": [{"display_name": "Firefox"}],
            "kbs": {"articles": ["KB5001234"], "meta": {}},
        }

        # Pre-populate cache with matching hashes
        hashes = {k: _section_hash(v) for k, v in inventory.items()}
        hash_cache_path.write_text(json.dumps(hashes))

        payload = build_checkin_payload(
            inventory=inventory,
            hostname="TEST-PC",
            cache_path=hash_cache_path,
        )

        # No sections changed → sections should be None (or empty)
        assert payload["sections"] is None or payload["sections"] == {}
        assert payload["full_checkin"] is False

    def test_changed_section_included(self, hash_cache_path):
        """Section with different hash IS in sections dict, cache updated."""
        from agent.windows.checkin import _section_hash, build_checkin_payload

        old_inventory = {
            "os": {"current_build": "22631"},
            "apps": [{"display_name": "Firefox"}],
            "kbs": {"articles": ["KB5001234"], "meta": {}},
        }

        # Cache with old hashes
        old_hashes = {k: _section_hash(v) for k, v in old_inventory.items()}
        hash_cache_path.write_text(json.dumps(old_hashes))

        # New inventory — apps changed
        new_inventory = {
            "os": {"current_build": "22631"},
            "apps": [{"display_name": "Firefox"}, {"display_name": "Chrome"}],
            "kbs": {"articles": ["KB5001234"], "meta": {}},
        }

        payload = build_checkin_payload(
            inventory=new_inventory,
            hostname="TEST-PC",
            cache_path=hash_cache_path,
        )

        # apps changed → should be in sections
        assert "apps" in payload["sections"]
        # os unchanged → should NOT be in sections
        assert "os" not in payload["sections"]
        assert payload["full_checkin"] is False

        # Verify cache was updated
        updated_cache = json.loads(hash_cache_path.read_text())
        from agent.windows.checkin import _section_hash

        assert updated_cache["apps"] == _section_hash(new_inventory["apps"])

    def test_full_checkin_when_no_cache(self, hash_cache_path):
        """full_checkin=True when hash cache file doesn't exist."""
        from agent.windows.checkin import build_checkin_payload

        inventory = {
            "os": {"current_build": "22631"},
            "apps": [],
            "kbs": {"articles": [], "meta": {}},
        }

        # No cache file exists → force full
        payload = build_checkin_payload(
            inventory=inventory,
            hostname="TEST-PC",
            cache_path=hash_cache_path,
        )

        assert payload["full_checkin"] is True
        # All sections should be included
        assert "os" in payload["sections"]
        assert "apps" in payload["sections"]
        assert "kbs" in payload["sections"]

    def test_forced_at_0300(self, hash_cache_path):
        """full_checkin=True during 03:00-03:05 window."""
        from agent.windows.checkin import _section_hash, build_checkin_payload

        inventory = {
            "os": {"current_build": "22631"},
            "apps": [],
            "kbs": {"articles": [], "meta": {}},
        }

        # Pre-populate cache with matching hashes
        hashes = {k: _section_hash(v) for k, v in inventory.items()}
        hash_cache_path.write_text(json.dumps(hashes))

        # Mock datetime.now to return 03:02
        mock_dt = datetime(2026, 3, 1, 3, 2, 0)
        with patch("agent.windows.checkin.datetime") as mock_datetime:
            mock_datetime.now.return_value = mock_dt
            mock_datetime.side_effect = lambda *a, **kw: datetime(*a, **kw)

            payload = build_checkin_payload(
                inventory=inventory,
                hostname="TEST-PC",
                cache_path=hash_cache_path,
            )

        assert payload["full_checkin"] is True


# ---------------------------------------------------------------------------
# KB collector tests
# ---------------------------------------------------------------------------


class TestKBCollector:
    """Tests for dual-method KB collection with cache fallback."""

    def test_fallback_to_cache(self, kb_cache_fresh):
        """When WUA + CBS both unavailable, falls back to cache."""
        from agent.windows.kb_collector import KBCollector

        collector = KBCollector(cache_path=kb_cache_fresh)
        # On Linux CI, both WUA and CBS will fail naturally
        kbs, meta = collector.collect()

        assert isinstance(kbs, set)
        assert meta["collection_method"] == "cache"
        assert "KB5001234" in kbs
        assert "KB5005678" in kbs

    def test_stale_when_cache_only_and_old(self, kb_cache_stale):
        """stale=True in metadata when only cache available and old."""
        from agent.windows.kb_collector import KBCollector

        collector = KBCollector(cache_path=kb_cache_stale)
        kbs, meta = collector.collect()

        assert meta["collection_method"] == "cache"
        assert meta["stale"] is True

    def test_fresh_cache_not_stale(self, kb_cache_fresh):
        """stale=False when cache is recent (< 8h)."""
        from agent.windows.kb_collector import KBCollector

        collector = KBCollector(cache_path=kb_cache_fresh)
        kbs, meta = collector.collect()

        assert meta["collection_method"] == "cache"
        assert meta["stale"] is False

    def test_wua_success_with_mock(self, kb_cache_path):
        """WUA method returns KB set when win32com is mocked."""
        from agent.windows import kb_collector

        # Mock the WUA COM interface
        mock_entry = MagicMock()
        mock_entry.Operation = 1
        mock_entry.ResultCode = 2
        mock_entry.Title = "2024-01 Cumulative Update (KB5001234)"

        mock_history = MagicMock()
        mock_history.Count = 1
        mock_history.Item.return_value = mock_entry

        mock_searcher = MagicMock()
        mock_searcher.GetTotalHistoryCount.return_value = 1
        mock_searcher.QueryHistory.return_value = mock_history

        mock_session = MagicMock()
        mock_session.CreateUpdateSearcher.return_value = mock_searcher

        mock_dispatch = MagicMock(return_value=mock_session)

        # Create mock win32com.client module
        mock_win32com = MagicMock()
        mock_win32com.client.Dispatch = mock_dispatch

        # Temporarily enable WUA path and inject mock module
        orig_has_win32com = kb_collector._HAS_WIN32COM
        kb_collector._HAS_WIN32COM = True
        try:
            with patch.dict("sys.modules", {
                "win32com": mock_win32com,
                "win32com.client": mock_win32com.client,
            }):
                collector = kb_collector.KBCollector(cache_path=kb_cache_path)
                kbs, meta = collector.collect()
        finally:
            kb_collector._HAS_WIN32COM = orig_has_win32com

        assert "KB5001234" in kbs
        assert meta["collection_method"] == "wua"
        assert meta["stale"] is False

    def test_no_cache_returns_empty(self, tmp_path):
        """When no methods work and no cache exists, returns empty set."""
        from agent.windows.kb_collector import KBCollector

        collector = KBCollector(cache_path=tmp_path / "nonexistent.json")
        kbs, meta = collector.collect()

        assert kbs == set()
        assert meta["collection_method"] == "cache"
        assert meta["stale"] is True


# ---------------------------------------------------------------------------
# Telemetry tests
# ---------------------------------------------------------------------------


class TestTelemetry:
    """Tests for per-job telemetry snapshot."""

    def test_snapshot_returns_all_keys(self):
        """Dict has all required keys."""
        from agent.windows.telemetry import collect_job_telemetry_snapshot

        snapshot = collect_job_telemetry_snapshot("job-123")

        assert snapshot["job_id"] == "job-123"
        assert "collected_at" in snapshot
        assert "cpu_percent_1s" in snapshot
        assert "crash_events_24h" in snapshot
        assert "reboots_7d" in snapshot
        assert "system_disk_free_gb" in snapshot
        # On Linux, event log queries return 0
        assert snapshot["crash_events_24h"] == 0
        assert snapshot["reboots_7d"] == 0

    def test_handles_missing_wevtutil(self):
        """Returns 0 for event counts when subprocess fails."""
        from agent.windows.telemetry import _count_event_log_events

        # On Linux, wevtutil doesn't exist — should return 0, not raise
        result = _count_event_log_events("System", [6008, 1001, 41], 24)
        assert result == 0

    def test_disk_free_positive(self):
        """Disk free should be a positive number on any platform."""
        from agent.windows.telemetry import _safe_disk_free_gb

        free_gb = _safe_disk_free_gb()
        assert free_gb > 0


# ---------------------------------------------------------------------------
# Inventory tests
# ---------------------------------------------------------------------------


class TestInventory:
    """Tests for OS identity and installed apps — mock winreg."""

    def test_os_identity_returns_empty_on_linux(self):
        """Returns empty dict when winreg is unavailable (Linux CI)."""
        from agent.windows.inventory import get_os_identity

        result = get_os_identity()
        assert result == {}

    def test_installed_apps_returns_empty_on_linux(self):
        """Returns empty list when winreg is unavailable (Linux CI)."""
        from agent.windows.inventory import get_installed_apps

        result = get_installed_apps()
        assert result == []

    def test_os_identity_with_mock_winreg(self):
        """Returns dict with expected keys when winreg is mocked."""
        import sys
        from agent.windows import inventory

        values = {
            "CurrentBuild": ("22631", 1),
            "UBR": (3155, 4),
            "EditionID": ("Professional", 1),
            "ProductName": ("Windows 11 Pro", 1),
            "DisplayVersion": ("23H2", 1),
        }

        def query_value_ex(key, name):
            if name in values:
                return values[name]
            raise OSError("not found")

        mock_key_ctx = MagicMock()
        mock_key_ctx.__enter__ = MagicMock(return_value=mock_key_ctx)
        mock_key_ctx.__exit__ = MagicMock(return_value=False)

        mock_winreg = MagicMock()
        mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
        mock_winreg.HKEY_CURRENT_USER = 0x80000001
        mock_winreg.OpenKey.return_value = mock_key_ctx
        mock_winreg.QueryValueEx = query_value_ex

        # Inject mock winreg into sys.modules and the inventory module
        orig_has_winreg = inventory._HAS_WINREG
        inventory._HAS_WINREG = True
        old_winreg = sys.modules.get("winreg")
        sys.modules["winreg"] = mock_winreg
        # Set winreg as module attribute so the function can use it
        setattr(inventory, "winreg", mock_winreg)
        try:
            result = inventory.get_os_identity()
        finally:
            inventory._HAS_WINREG = orig_has_winreg
            if old_winreg is not None:
                sys.modules["winreg"] = old_winreg
            else:
                sys.modules.pop("winreg", None)
            if hasattr(inventory, "winreg") and not orig_has_winreg:
                delattr(inventory, "winreg")

        assert result["current_build"] == "22631"
        assert result["ubr"] == 3155
        assert result["edition"] == "Professional"
        assert result["product_name"] == "Windows 11 Pro"
        assert result["display_version"] == "23H2"
