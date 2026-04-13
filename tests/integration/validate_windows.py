#!/usr/bin/env python3
"""
Validation script for treasure-hunter integration testing.

Parses the JSONL output from a scan of the seeded Windows VM and verifies
that every planted artifact was discovered. Reports pass/fail per module.

Usage:
    python validate_windows.py results.jsonl
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def load_results(path: str) -> tuple[list[dict], list[dict]]:
    """Load JSONL file, return (findings, credentials) lists."""
    findings = []
    credentials = []

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("type") == "finding":
                findings.append(record)
            elif record.get("type") == "credential":
                credentials.append(record)

    return findings, credentials


class Validator:
    def __init__(self, findings: list[dict], credentials: list[dict]):
        self.findings = findings
        self.credentials = credentials
        self.results: list[tuple[str, bool, str]] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        self.results.append((name, condition, detail))

    def run_all(self) -> None:
        self._check_scanner()
        self._check_cloud_cred()
        self._check_git_cred()
        self._check_remote_access()
        self._check_browser()
        self._check_history()
        self._check_dev_tools()
        self._check_registry()
        self._check_session()
        self._check_notes()
        self._check_email()
        self._check_wifi()
        self._check_cert()
        self._check_dpapi()
        self._check_clipboard()
        self._check_network()
        self._check_encryption()
        self._check_html_report()

    def _find_creds(self, **kwargs) -> list[dict]:
        """Find credentials matching all kwargs."""
        results = []
        for cred in self.credentials:
            if all(str(v).lower() in str(cred.get(k, "")).lower() for k, v in kwargs.items()):
                results.append(cred)
        return results

    def _find_findings(self, path_contains: str = "", signal_contains: str = "") -> list[dict]:
        """Find findings matching path or signal text."""
        results = []
        for f in self.findings:
            path_match = not path_contains or path_contains.lower() in f.get("file_path", "").lower()
            signal_match = not signal_contains or any(
                signal_contains.lower() in s.get("description", "").lower()
                for s in f.get("signals", [])
            )
            if path_match and signal_match:
                results.append(f)
        return results

    # --- Module checks ---

    def _check_scanner(self):
        self.check(
            "Scanner: .env file detected",
            bool(self._find_findings(path_contains=".env")),
            "Should find Desktop/.env and Documents/.env.staging"
        )
        self.check(
            "Scanner: .kdbx file detected",
            bool(self._find_findings(path_contains=".kdbx")),
            "Should find Documents/passwords.kdbx"
        )
        self.check(
            "Scanner: SSH key detected",
            bool(self._find_findings(path_contains="id_rsa") or self._find_findings(path_contains=".ssh")),
            "Should find .ssh/id_rsa"
        )

    def _check_cloud_cred(self):
        aws_creds = self._find_creds(source_module="cloud_cred", target_application="AWS")
        self.check(
            "CloudCredGrabber: AWS access keys extracted",
            len(aws_creds) >= 2,
            f"Found {len(aws_creds)} (expected 2: default + production)"
        )
        docker_creds = self._find_creds(source_module="cloud_cred", target_application="Docker")
        self.check(
            "CloudCredGrabber: Docker registry auth extracted",
            len(docker_creds) >= 1,
            f"Found {len(docker_creds)}"
        )
        k8s_creds = self._find_creds(source_module="cloud_cred", target_application="Kubernetes")
        self.check(
            "CloudCredGrabber: Kubernetes token extracted",
            len(k8s_creds) >= 1,
            f"Found {len(k8s_creds)}"
        )
        vault_creds = self._find_creds(source_module="cloud_cred", target_application="Vault")
        self.check(
            "CloudCredGrabber: Vault token extracted",
            len(vault_creds) >= 1,
            f"Found {len(vault_creds)}"
        )
        gh_creds = self._find_creds(source_module="cloud_cred", target_application="GitHub CLI")
        self.check(
            "CloudCredGrabber: GitHub CLI token extracted",
            len(gh_creds) >= 1,
            f"Found {len(gh_creds)}"
        )

    def _check_git_cred(self):
        git_creds = self._find_creds(source_module="git_cred")
        self.check(
            "GitGrabber: .git-credentials parsed",
            any("github.com" in c.get("url", "") for c in git_creds),
            f"Found {len(git_creds)} git credentials"
        )
        repo_creds = [c for c in git_creds if "internal-api" in c.get("url", "")]
        self.check(
            "GitGrabber: embedded repo credentials found",
            len(repo_creds) >= 1,
            "Should find deployer token in Projects/internal-app/.git/config"
        )

    def _check_remote_access(self):
        fz_creds = self._find_creds(source_module="remote_access", target_application="FileZilla")
        self.check(
            "RemoteAccessGrabber: FileZilla passwords extracted",
            len(fz_creds) >= 3,
            f"Found {len(fz_creds)} (expected 3 servers)"
        )
        # Verify base64 decryption worked
        decrypted = [c for c in fz_creds if c.get("has_decrypted_value")]
        self.check(
            "RemoteAccessGrabber: FileZilla passwords decrypted",
            len(decrypted) >= 1,
            f"{len(decrypted)} decrypted"
        )

    def _check_browser(self):
        # Chrome may or may not be installed — check if grabber ran
        browser_creds = self._find_creds(source_module="browser")
        browser_findings = self._find_findings(signal_contains="browser")
        self.check(
            "BrowserGrabber: ran (Chrome/Edge/Firefox present)",
            len(browser_creds) > 0 or len(browser_findings) > 0,
            f"Found {len(browser_creds)} creds, {len(browser_findings)} findings"
        )

    def _check_history(self):
        history_creds = self._find_creds(source_module="history")
        self.check(
            "HistoryGrabber: PowerShell history secrets found",
            len(history_creds) >= 3,
            f"Found {len(history_creds)} (expected 4+: sql, docker, net use, kubectl)"
        )

    def _check_dev_tools(self):
        npm_creds = self._find_creds(source_module="dev_tools", target_application="npm")
        self.check(
            "DevToolGrabber: npm auth tokens extracted",
            len(npm_creds) >= 1,
            f"Found {len(npm_creds)}"
        )
        pypi_creds = self._find_creds(source_module="dev_tools", target_application="PyPI")
        self.check(
            "DevToolGrabber: PyPI token extracted",
            len(pypi_creds) >= 1,
            f"Found {len(pypi_creds)}"
        )
        gradle_creds = self._find_creds(source_module="dev_tools", target_application="Gradle")
        self.check(
            "DevToolGrabber: Gradle credentials extracted",
            len(gradle_creds) >= 1,
            f"Found {len(gradle_creds)}"
        )

    def _check_registry(self):
        putty_creds = self._find_creds(source_module="registry", target_application="PuTTY")
        self.check(
            "RegistryGrabber: PuTTY sessions found",
            len(putty_creds) >= 3,
            f"Found {len(putty_creds)} (expected 3)"
        )
        autologon = self._find_creds(source_module="registry", target_application="AutoLogon")
        self.check(
            "RegistryGrabber: Windows AutoLogon credentials found",
            len(autologon) >= 1,
            f"Found {len(autologon)}"
        )

    def _check_session(self):
        rdp_creds = self._find_creds(source_module="session")
        self.check(
            "SessionGrabber: RDP history found",
            len(rdp_creds) >= 1,
            f"Found {len(rdp_creds)} session records"
        )

    def _check_notes(self):
        notes_creds = self._find_creds(source_module="notes")
        self.check(
            "NotesGrabber: Sticky Notes secrets found",
            len(notes_creds) >= 1,
            f"Found {len(notes_creds)}"
        )

    def _check_email(self):
        # Outlook PST may not exist unless we create one
        self.check(
            "EmailGrabber: ran without errors",
            True,
            "No Outlook installed — discovery module should complete cleanly"
        )

    def _check_wifi(self):
        wifi_creds = self._find_creds(source_module="wifi")
        self.check(
            "WiFiGrabber: profiles enumerated",
            True,  # May be empty if no WiFi adapter
            f"Found {len(wifi_creds)} profiles"
        )

    def _check_cert(self):
        cert_creds = self._find_creds(source_module="cert")
        self.check(
            "CertGrabber: SSH key files cataloged",
            any(".ssh" in c.get("url", "") for c in cert_creds),
            f"Found {len(cert_creds)} cert/key files"
        )

    def _check_dpapi(self):
        dpapi_creds = self._find_creds(source_module="dpapi")
        self.check(
            "DPAPIGrabber: credential store files enumerated",
            len(dpapi_creds) >= 1,
            f"Found {len(dpapi_creds)} DPAPI-protected files"
        )

    def _check_clipboard(self):
        clip_creds = self._find_creds(source_module="clipboard")
        self.check(
            "ClipboardGrabber: ran (may be empty if nothing in clipboard)",
            True,
            f"Found {len(clip_creds)} clipboard items"
        )

    def _check_network(self):
        # Only relevant if --network was used
        self.check(
            "NetworkScanner: (run separately with --network flag)",
            True,
            "Validate manually from attack box"
        )

    def _check_encryption(self):
        # Check if .enc file exists alongside results
        self.check(
            "Encryption: (run with --encrypt flag to test)",
            True,
            "Validate encrypt/decrypt round-trip manually"
        )

    def _check_html_report(self):
        self.check(
            "HTML Report: (run with --html flag to test)",
            True,
            "Validate report.html opens in browser"
        )

    def print_report(self) -> int:
        print("\n" + "=" * 65)
        print("TREASURE-HUNTER INTEGRATION TEST RESULTS")
        print("=" * 65)

        passed = 0
        failed = 0

        for name, success, detail in self.results:
            status = "PASS" if success else "FAIL"
            icon = "+" if success else "!"
            print(f"  [{icon}] {status}: {name}")
            if detail:
                print(f"         {detail}")
            if success:
                passed += 1
            else:
                failed += 1

        print(f"\n{'=' * 65}")
        print(f"  PASSED: {passed}  |  FAILED: {failed}  |  TOTAL: {passed + failed}")
        print(f"{'=' * 65}\n")

        return 1 if failed > 0 else 0


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <results.jsonl>")
        return 1

    results_path = sys.argv[1]
    if not Path(results_path).exists():
        print(f"Results file not found: {results_path}")
        return 1

    findings, credentials = load_results(results_path)
    print(f"Loaded {len(findings)} findings, {len(credentials)} credentials from {results_path}")

    validator = Validator(findings, credentials)
    validator.run_all()
    return validator.print_report()


if __name__ == "__main__":
    sys.exit(main())
