"""
Windows Registry helper — safe wrappers around winreg stdlib module.

Provides platform-safe functions that return None on non-Windows systems
instead of crashing. All reads are wrapped in try/except to handle
permission errors gracefully.
"""

from __future__ import annotations

import os


def read_reg_value(hive_name: str, key_path: str, value_name: str) -> str | bytes | int | None:
    """Read a single registry value. Returns None on failure or non-Windows."""
    if os.name != "nt":
        return None

    try:
        import winreg

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS,
        }
        hive = hive_map.get(hive_name)
        if hive is None:
            return None

        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value

    except (OSError, ImportError):
        return None


def enum_reg_values(hive_name: str, key_path: str) -> list[tuple[str, str | bytes | int, int]]:
    """Enumerate all values under a registry key.
    Returns list of (name, data, type) tuples. Empty list on failure."""
    if os.name != "nt":
        return []

    try:
        import winreg

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS,
        }
        hive = hive_map.get(hive_name)
        if hive is None:
            return []

        results = []
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    results.append((name, data, reg_type))
                    i += 1
                except OSError:
                    break
        return results

    except (OSError, ImportError):
        return []


def enum_reg_subkeys(hive_name: str, key_path: str) -> list[str]:
    """Enumerate subkey names under a registry key. Empty list on failure."""
    if os.name != "nt":
        return []

    try:
        import winreg

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKU": winreg.HKEY_USERS,
        }
        hive = hive_map.get(hive_name)
        if hive is None:
            return []

        results = []
        with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    results.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        return results

    except (OSError, ImportError):
        return []
