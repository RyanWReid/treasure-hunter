"""
SchTaskGrabber -- Extract credentials from Windows Scheduled Tasks

Scheduled tasks can contain:
- RunAs accounts (service accounts with stored passwords)
- Executable paths (reveals installed tools, potential DLL hijack)
- Command-line arguments (may contain passwords/tokens inline)

Task XML files are stored in C:\\Windows\\System32\\Tasks\\
Each is an XML file with the Task namespace defining triggers,
actions, and principals (the security context).

MITRE ATT&CK: T1053.005 (Scheduled Task/Job)
"""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel

_TASKS_DIR = r"C:\Windows\System32\Tasks"
_TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"

# Regex patterns for credentials in command-line arguments
_CRED_PATTERNS = [
    re.compile(r"(?:password|passwd|pwd|pass)[=:\s]+(\S+)", re.IGNORECASE),
    re.compile(r"-(?:p|password|pwd)\s+(\S+)", re.IGNORECASE),
    re.compile(r"(?:api[_-]?key|token|secret)\s*[=:]\s*(\S+)", re.IGNORECASE),
    re.compile(r"(?:user|username|login)\s*[=:]\s*(\S+)", re.IGNORECASE),
]

# Interesting RunAs patterns (service accounts, not SYSTEM/LOCAL SERVICE)
_SKIP_PRINCIPALS = frozenset({
    "system", "local service", "network service",
    "s-1-5-18", "s-1-5-19", "s-1-5-20",
    "nt authority\\system", "nt authority\\local service",
    "nt authority\\network service",
})


def parse_task_xml(file_path: str, content: str) -> dict | None:
    """Parse a scheduled task XML file and extract security-relevant info."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None

    ns = {"t": _TASK_NS}

    # Try with namespace first, then without
    def find(path_with_ns, path_without_ns):
        elem = root.find(path_with_ns, ns)
        if elem is None:
            elem = root.find(path_without_ns)
        return elem

    result = {"file": file_path, "credentials": [], "actions": []}

    # Extract principal (RunAs user)
    principal = find(
        ".//t:Principals/t:Principal",
        ".//Principals/Principal",
    )
    if principal is not None:
        user_elem = principal.find(f"{{{_TASK_NS}}}UserId")
        if user_elem is None:
            user_elem = principal.find("UserId")

        run_level_elem = principal.find(f"{{{_TASK_NS}}}RunLevel")
        if run_level_elem is None:
            run_level_elem = principal.find("RunLevel")

        # LogonType can be an attribute OR a child element
        logon_type = principal.attrib.get("logonType", "")
        if not logon_type:
            lt_elem = principal.find(f"{{{_TASK_NS}}}LogonType")
            if lt_elem is None:
                lt_elem = principal.find("LogonType")
            if lt_elem is not None and lt_elem.text:
                logon_type = lt_elem.text.strip()

        if user_elem is not None and user_elem.text:
            username = user_elem.text.strip()
            if username.lower() not in _SKIP_PRINCIPALS:
                result["run_as"] = username
                result["logon_type"] = logon_type
                if run_level_elem is not None:
                    result["run_level"] = run_level_elem.text or ""

                # Password-stored logon types
                if logon_type in ("Password", "InteractiveTokenOrPassword"):
                    result["has_stored_password"] = True

    # Extract actions (Exec commands)
    for exec_elem in root.iter(f"{{{_TASK_NS}}}Exec"):
        action = _parse_exec(exec_elem, _TASK_NS)
        if action:
            result["actions"].append(action)

    # Also try without namespace
    for exec_elem in root.iter("Exec"):
        action = _parse_exec(exec_elem, "")
        if action:
            result["actions"].append(action)

    # Check command arguments for embedded credentials
    for action in result["actions"]:
        args = action.get("arguments", "")
        for pattern in _CRED_PATTERNS:
            match = pattern.search(args)
            if match:
                result["credentials"].append({
                    "value": match.group(1),
                    "context": args[:200],
                    "pattern": pattern.pattern,
                })

    return result if (result.get("run_as") or result["actions"] or result["credentials"]) else None


def _parse_exec(exec_elem, namespace: str) -> dict | None:
    """Parse an Exec element from a task XML."""
    prefix = f"{{{namespace}}}" if namespace else ""
    command_elem = exec_elem.find(f"{prefix}Command")
    args_elem = exec_elem.find(f"{prefix}Arguments")
    workdir_elem = exec_elem.find(f"{prefix}WorkingDirectory")

    if command_elem is None or not command_elem.text:
        return None

    return {
        "command": command_elem.text.strip(),
        "arguments": (args_elem.text or "").strip() if args_elem is not None else "",
        "working_directory": (workdir_elem.text or "").strip() if workdir_elem is not None else "",
    }


class SchTaskGrabber(GrabberModule):
    name = "schtask"
    description = "Extract credentials and service accounts from Scheduled Tasks"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows",)
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        return os.path.isdir(_TASKS_DIR)

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        if not os.path.isdir(_TASKS_DIR):
            result.status = GrabberStatus.SKIPPED
            return result

        tasks_found = 0
        try:
            for root_dir, dirs, files in os.walk(_TASKS_DIR):
                for fname in files:
                    fpath = os.path.join(root_dir, fname)
                    try:
                        with open(fpath, "r", encoding="utf-16", errors="ignore") as f:
                            content = f.read(65536)
                    except OSError:
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read(65536)
                        except OSError:
                            continue

                    if not content.strip().startswith("<?xml") and "<Task" not in content[:500]:
                        continue

                    parsed = parse_task_xml(fpath, content)
                    if not parsed:
                        continue

                    tasks_found += 1

                    # RunAs service account with stored password
                    run_as = parsed.get("run_as", "")
                    if run_as and parsed.get("has_stored_password"):
                        result.credentials.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="password",
                            target_application="Scheduled Task",
                            username=run_as,
                            notes=f"logon_type={parsed.get('logon_type', '')}; task={fname}",
                            mitre_technique="T1053.005",
                            source_file=fpath,
                        ))
                        result.findings.append(self.make_finding(
                            file_path=fpath,
                            description=f"Scheduled task with stored password: {run_as}",
                            score=150,  # HIGH -- service account with password
                            matched_value=run_as,
                        ))
                    elif run_as:
                        result.findings.append(self.make_finding(
                            file_path=fpath,
                            description=f"Scheduled task runs as: {run_as}",
                            score=60,  # MEDIUM -- interesting service account
                            matched_value=run_as,
                        ))

                    # Credentials in command arguments
                    for cred in parsed.get("credentials", []):
                        result.credentials.append(ExtractedCredential(
                            source_module=self.name,
                            credential_type="password",
                            target_application="Scheduled Task (cmdline)",
                            decrypted_value=cred["value"],
                            notes=f"task={fname}; context={cred['context'][:100]}",
                            mitre_technique="T1053.005",
                            source_file=fpath,
                        ))
                        result.findings.append(self.make_finding(
                            file_path=fpath,
                            description=f"Credential in task command line: {fname}",
                            score=175,  # HIGH -- plaintext cred in task
                            matched_value=cred["value"][:20],
                        ))

        except (PermissionError, OSError) as e:
            result.errors.append(f"Task enumeration failed: {e}")

        result.status = GrabberStatus.COMPLETED
        return result
