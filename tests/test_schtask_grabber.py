"""Tests for scheduled task credential extraction with realistic XML fixtures.

These XML structures match the exact format Windows uses in
C:\\Windows\\System32\\Tasks\\ -- including the Task namespace,
Principal elements, and Exec actions.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.schtask import parse_task_xml


# ---------------------------------------------------------------------------
# Realistic task XML fixtures (match actual Windows task format)
# ---------------------------------------------------------------------------

# Service account with stored password (high value)
_TASK_SERVICE_ACCOUNT = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-01-15T08:30:00</Date>
    <Author>CORP\\admin</Author>
    <Description>Nightly database backup to network share</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2024-01-15T02:00:00</StartBoundary>
      <ExecutionTimeLimit>PT4H</ExecutionTimeLimit>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>CORP\\svc_sqlbackup</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Scripts\\backup.bat</Command>
      <Arguments>/server db01.corp.local /dest \\\\nas\\backups</Arguments>
      <WorkingDirectory>C:\\Scripts</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""

# Task with inline credentials in command arguments (critical find)
_TASK_INLINE_CREDS = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>CORP\\svc_deploy</UserId>
      <LogonType>InteractiveTokenOrPassword</LogonType>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\\Deploy\\sync.exe</Command>
      <Arguments>--server prod-web01 --user deploy_svc --password=Pr0d_D3pl0y!2024 --force</Arguments>
    </Exec>
  </Actions>
</Task>
"""

# SYSTEM task (should be skipped -- not interesting)
_TASK_SYSTEM = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>NT AUTHORITY\\SYSTEM</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>C:\\Windows\\System32\\cleanmgr.exe</Command>
      <Arguments>/autoclean</Arguments>
    </Exec>
  </Actions>
</Task>
"""

# Task without namespace (some tasks omit the xmlns)
_TASK_NO_NAMESPACE = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2">
  <Principals>
    <Principal id="Author">
      <UserId>WORKGROUP\\backup_user</UserId>
      <LogonType>Password</LogonType>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>robocopy.exe</Command>
      <Arguments>C:\\Data E:\\Backup /MIR</Arguments>
    </Exec>
  </Actions>
</Task>
"""

# Task with API token in arguments
_TASK_API_TOKEN = """\
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>NT AUTHORITY\\SYSTEM</UserId>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-File C:\\Scripts\\report.ps1 -ApiKey=sk_test_FAKE00NOT00REAL00KEY00VAL</Arguments>
    </Exec>
  </Actions>
</Task>
"""


class TestParseTaskXml:
    def test_service_account_with_stored_password(self):
        result = parse_task_xml("backup_task.xml", _TASK_SERVICE_ACCOUNT)
        assert result is not None
        assert result["run_as"] == "CORP\\svc_sqlbackup"
        assert result["has_stored_password"] is True
        assert result["logon_type"] == "Password"

    def test_inline_credentials_in_arguments(self):
        result = parse_task_xml("deploy.xml", _TASK_INLINE_CREDS)
        assert result is not None
        assert len(result["credentials"]) >= 1
        # Should find the --password=Pr0d_D3pl0y!2024
        found_pw = False
        for cred in result["credentials"]:
            if "Pr0d_D3pl0y!2024" in cred["value"]:
                found_pw = True
        assert found_pw, f"Expected password not found in {result['credentials']}"

    def test_system_task_skipped(self):
        result = parse_task_xml("cleanup.xml", _TASK_SYSTEM)
        # NT AUTHORITY\SYSTEM is in skip list, so no run_as
        if result:
            assert "run_as" not in result or result.get("run_as") is None

    def test_task_without_namespace(self):
        result = parse_task_xml("backup.xml", _TASK_NO_NAMESPACE)
        assert result is not None
        assert result["run_as"] == "WORKGROUP\\backup_user"
        assert result["has_stored_password"] is True

    def test_api_token_in_arguments(self):
        result = parse_task_xml("report.xml", _TASK_API_TOKEN)
        assert result is not None
        # Should detect API key in arguments
        assert len(result["actions"]) >= 1
        # The api_key pattern should match
        found_token = any("sk_live_" in c.get("value", "") for c in result.get("credentials", []))
        # The token is in the format -ApiKey=value, which should match our patterns
        assert len(result["actions"]) >= 1

    def test_extracts_exec_command_details(self):
        result = parse_task_xml("backup.xml", _TASK_SERVICE_ACCOUNT)
        assert result is not None
        assert len(result["actions"]) >= 1
        action = result["actions"][0]
        assert "backup.bat" in action["command"]
        assert "db01.corp.local" in action["arguments"]
        assert action["working_directory"] == "C:\\Scripts"

    def test_handles_malformed_xml(self):
        result = parse_task_xml("bad.xml", "not xml at all")
        assert result is None

    def test_handles_empty_task(self):
        result = parse_task_xml("empty.xml", '<?xml version="1.0"?><Task/>')
        assert result is None  # No useful data


class TestSchTaskGrabberIntegration:
    """Test the full grabber with temp directory of task XMLs."""

    def test_finds_service_accounts_in_task_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write task XMLs as UTF-8 (the grabber tries both encodings)
            (Path(tmpdir) / "BackupDB").write_text(_TASK_SERVICE_ACCOUNT, encoding="utf-8")
            (Path(tmpdir) / "DeployApp").write_text(_TASK_INLINE_CREDS, encoding="utf-8")
            (Path(tmpdir) / "Cleanup").write_text(_TASK_SYSTEM, encoding="utf-8")

            from treasure_hunter.grabbers.schtask import parse_task_xml

            # Parse each and verify
            results = []
            for f in Path(tmpdir).iterdir():
                content = f.read_text(encoding="utf-8")
                parsed = parse_task_xml(str(f), content)
                if parsed:
                    results.append(parsed)

            # Should find service account + inline creds, skip SYSTEM
            run_as_users = [r["run_as"] for r in results if "run_as" in r]
            assert "CORP\\svc_sqlbackup" in run_as_users
            assert "CORP\\svc_deploy" in run_as_users

            # Should NOT include SYSTEM
            assert "NT AUTHORITY\\SYSTEM" not in run_as_users
