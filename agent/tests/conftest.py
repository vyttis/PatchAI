"""Agent test fixtures — mock Windows APIs for Linux CI."""

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def tmp_cache_dir(tmp_path):
    """Temporary directory for cache files."""
    return tmp_path


@pytest.fixture
def hash_cache_path(tmp_cache_dir):
    """Temporary path for inventory hash cache."""
    return tmp_cache_dir / "inventory_hashes.json"


@pytest.fixture
def kb_cache_path(tmp_cache_dir):
    """Temporary path for KB cache."""
    return tmp_cache_dir / "kb_cache.json"


@pytest.fixture
def kb_cache_fresh(kb_cache_path):
    """Pre-populated KB cache that is NOT stale (< 8h old)."""
    data = {"kbs": ["KB5001234", "KB5005678"], "cached_at": time.time()}
    kb_cache_path.write_text(json.dumps(data))
    return kb_cache_path


@pytest.fixture
def kb_cache_stale(kb_cache_path):
    """Pre-populated KB cache that IS stale (> 8h old)."""
    data = {"kbs": ["KB5001234", "KB5005678"], "cached_at": time.time() - 30000}
    kb_cache_path.write_text(json.dumps(data))
    return kb_cache_path


@pytest.fixture
def mock_winreg():
    """Mock winreg module for Linux CI testing."""
    mock = MagicMock()
    mock.HKEY_LOCAL_MACHINE = 0x80000002
    mock.HKEY_CURRENT_USER = 0x80000001
    mock.REG_SZ = 1
    mock.REG_DWORD = 4
    return mock
