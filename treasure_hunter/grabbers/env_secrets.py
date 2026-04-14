"""
EnvSecretsGrabber -- Extract secrets from environment variables

Developers load sensitive values into environment variables:
DATABASE_URL, API_KEY, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, etc.
These persist in memory but never touch disk -- invisible to
file-based scanners.

This module scans the current process environment and (with admin)
can walk other processes' PEB environment blocks.

MITRE ATT&CK: T1552.001 (Credentials In Files -- extends to env vars)
"""

from __future__ import annotations

import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel

# Environment variable name patterns that likely contain secrets
_SECRET_NAME_PATTERNS = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|"
    r"AUTH|PRIVATE[_-]?KEY|CREDENTIAL|CONN(?:ECTION)?[_-]?STRING|"
    r"DATABASE[_-]?URL|DB[_-]?PASS|SMTP[_-]?PASS|MAIL[_-]?PASS|"
    r"ENCRYPTION[_-]?KEY|SIGNING[_-]?KEY|JWT[_-]?SECRET|"
    r"WEBHOOK[_-]?SECRET|CLIENT[_-]?SECRET|APP[_-]?SECRET|"
    r"MASTER[_-]?KEY|DEPLOY[_-]?KEY|SSH[_-]?KEY|"
    r"SENTRY[_-]?DSN|STRIPE[_-]?KEY|TWILIO[_-]?|SENDGRID|"
    r"SLACK[_-]?TOKEN|DISCORD[_-]?TOKEN|GITHUB[_-]?TOKEN|"
    r"NPM[_-]?TOKEN|PYPI[_-]?TOKEN|NUGET[_-]?KEY|"
    r"AWS[_-]?SECRET|AZURE[_-]?(?:CLIENT|TENANT)|GCP[_-]?KEY|"
    r"VAULT[_-]?TOKEN|CONSUL[_-]?TOKEN|NOMAD[_-]?TOKEN)",
    re.IGNORECASE,
)

# Value patterns that look like real secrets (not empty/placeholder)
_SKIP_VALUES = frozenset({
    "", "null", "none", "undefined", "changeme", "todo",
    "xxx", "your-key-here", "REPLACE_ME", "INSERT_HERE",
    "true", "false", "0", "1", "yes", "no",
})

# Known non-secret env vars with similar names
_SKIP_NAMES = frozenset({
    "COMPUTERNAME", "USERNAME", "USERDOMAIN", "SESSIONNAME",
    "LOGONSERVER", "HOMEDRIVE", "HOMEPATH", "USERPROFILE",
    "PATHEXT", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
    "OS", "COMSPEC", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
    "PROGRAMFILES", "PROGRAMDATA", "APPDATA", "LOCALAPPDATA",
    "ALLUSERSPROFILE", "PUBLIC", "SYSTEMDRIVE",
    "PSModulePath", "Path", "PATH",
})


class EnvSecretsGrabber(GrabberModule):
    name = "env_secrets"
    description = "Extract secrets from environment variables (DATABASE_URL, API keys, tokens)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        # Always run -- environment variables always exist
        return True

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        secrets_found = []

        for name, value in os.environ.items():
            if name.upper() in _SKIP_NAMES:
                continue
            if not value or value.lower() in _SKIP_VALUES:
                continue
            if len(value) < 4:
                continue

            if _SECRET_NAME_PATTERNS.search(name):
                secrets_found.append((name, value))
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="token",
                    target_application="Environment Variable",
                    username=name,
                    decrypted_value=value,
                    notes=f"env var: {name}",
                    mitre_technique="T1552.001",
                ))

        if secrets_found:
            result.findings.append(self.make_finding(
                file_path="[ENV] Process Environment Variables",
                description=f"Found {len(secrets_found)} secret(s) in environment variables",
                score=100 * min(len(secrets_found), 3),
                matched_value=", ".join(name for name, _ in secrets_found[:5]),
                snippets=[f"{name}={value[:20]}..." if len(value) > 20 else f"{name}={value}"
                         for name, value in secrets_found[:10]],
            ))

        result.status = GrabberStatus.COMPLETED
        return result
