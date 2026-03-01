"""OS identity and registry-based application inventory.

Collects:
- OS build, edition, architecture from Windows NT CurrentVersion registry
- Installed applications from three registry hive paths (HKLM 64bit, HKLM 32bit, HKCU)
- Section hashing for delta check-in

All winreg calls are guarded by try/except ImportError so this module
runs on Linux CI (returns empty results when winreg is unavailable).
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    import winreg

    _HAS_WINREG = True
except ImportError:
    _HAS_WINREG = False

_FIELD_MAP = {
    "DisplayName": "display_name",
    "DisplayVersion": "display_version",
    "Publisher": "publisher",
    "InstallLocation": "install_location",
}


def get_os_identity() -> dict[str, Any]:
    """Read OS identity from HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion.

    Returns dict with: current_build, ubr, edition, product_name, display_version.
    Returns empty dict when winreg is not available (Linux CI).
    """
    if not _HAS_WINREG:
        return {}

    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    reg_fields = {
        "CurrentBuild": "current_build",
        "UBR": "ubr",
        "EditionID": "edition",
        "ProductName": "product_name",
        "DisplayVersion": "display_version",
    }
    result: dict[str, Any] = {}
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            for reg_name, out_name in reg_fields.items():
                try:
                    value, _ = winreg.QueryValueEx(key, reg_name)
                    result[out_name] = value
                except OSError:
                    result[out_name] = None
    except OSError:
        logger.warning("Failed to open Windows NT CurrentVersion registry key")
    return result


def get_installed_apps() -> list[dict[str, Any]]:
    """Read installed applications from three registry hive paths.

    Paths scanned:
    - HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall (64-bit)
    - HKLM\\SOFTWARE\\WOW6432Node\\...\\Uninstall (32-bit)
    - HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall

    Per app: display_name, display_version, publisher, install_location, product_code.
    product_code = subkey name if it starts with "{" (MSI ProductCode), else None.
    Entries without DisplayName are skipped.

    Returns [] when winreg is not available.
    """
    if not _HAS_WINREG:
        return []

    hive_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    apps: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()

    for hive, path in hive_paths:
        try:
            with winreg.OpenKey(hive, path) as parent_key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(parent_key, i)
                        i += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(parent_key, subkey_name) as subkey:
                            app = _read_app_entry(subkey, subkey_name)
                            if app:
                                dedup_key = (app["display_name"], app.get("display_version"))
                                if dedup_key not in seen:
                                    seen.add(dedup_key)
                                    apps.append(app)
                    except OSError:
                        continue
        except OSError:
            continue
    return apps


def _read_app_entry(subkey, subkey_name: str) -> dict[str, Any] | None:
    """Extract app metadata from a single registry subkey."""
    result: dict[str, Any] = {}
    for reg_field, out_field in _FIELD_MAP.items():
        try:
            value, _ = winreg.QueryValueEx(subkey, reg_field)
            result[out_field] = value
        except OSError:
            result[out_field] = None

    result["product_code"] = subkey_name if subkey_name.startswith("{") else None

    if not result.get("display_name"):
        return None
    return result
