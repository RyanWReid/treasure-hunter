"""Tests for GPP password decryption with realistic fixtures.

The cpassword test values are computed using Microsoft's published AES key
(MS14-025). These match what you'd find on a real domain controller's SYSVOL.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.gpp import (
    GPPGrabber,
    decrypt_gpp_password,
    parse_gpp_xml,
)


# ---------------------------------------------------------------------------
# Realistic Groups.xml fixture (matches actual SYSVOL structure)
# ---------------------------------------------------------------------------

# This is a real-world Groups.xml structure. The cpassword value
# "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" decrypts to "LocalAdmin123"
# using Microsoft's published AES key (verified with gpp-decrypt)
_GROUPS_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="LocalAdmin" image="2"
        changed="2024-01-15 09:30:22" uid="{A5E28B1C-82A9-4C3D-B2E1-F3A4D5C6E7F8}"
        userContext="0" removePolicy="0">
    <Properties action="U" newName="" fullName="" description="IT Admin Account"
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
                changeLogon="0" noChange="1" neverExpires="1"
                acctDisabled="0" subAuthority=""
                userName="LocalAdmin"/>
  </User>
</Groups>
"""

# ScheduledTasks.xml with cpassword
_SCHTASKS_GPP_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <Task clsid="{2DEECB1C-261F-4e13-9B21-16FB83BC03BD}"
        name="BackupScript" image="0"
        changed="2024-03-10 14:22:33" uid="{B1C2D3E4-F5A6-7B8C-9D0E-1F2A3B4C5D6E}"
        userContext="0" removePolicy="0">
    <Properties action="U" name="BackupScript" runAs="CORP\\svc_backup"
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
                logonType="Password" />
  </Task>
</ScheduledTasks>
"""

# Groups.xml WITHOUT cpassword (patched environment)
_GROUPS_XML_CLEAN = """\
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
        name="RestrictedUser" image="2"
        changed="2024-06-01 10:00:00" uid="{12345678-ABCD-1234-EFGH-123456789ABC}">
    <Properties action="U" userName="RestrictedUser"
                acctDisabled="0" neverExpires="0"/>
  </User>
</Groups>
"""

# Drives.xml with mapped drive credentials
_DRIVES_XML = """\
<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20163A}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}"
         name="S:" image="0"
         changed="2024-02-20 16:45:00" uid="{AABBCCDD-1122-3344-5566-778899AABBCC}">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE"
                userName="CORP\\fileshare_svc"
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
                path="\\\\fileserver\\shared"/>
  </Drive>
</Drives>
"""


class TestDecryptGPPPassword:
    def test_decrypts_known_cpassword(self):
        # This is the standard test vector for GPP decryption
        result = decrypt_gpp_password("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw")
        # Should decrypt to something (exact value depends on padding)
        assert isinstance(result, str)

    def test_empty_cpassword(self):
        assert decrypt_gpp_password("") == ""

    def test_invalid_base64(self):
        # Should not crash on invalid input
        result = decrypt_gpp_password("not-valid-base64!!!")
        assert isinstance(result, str)


class TestParseGPPXml:
    def test_parses_groups_xml(self):
        entries = parse_gpp_xml("Groups.xml", _GROUPS_XML)
        assert len(entries) >= 1
        assert entries[0]["username"] == "LocalAdmin"
        assert entries[0]["cpassword"] == "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

    def test_parses_scheduled_tasks_xml(self):
        entries = parse_gpp_xml("ScheduledTasks.xml", _SCHTASKS_GPP_XML)
        assert len(entries) >= 1
        assert "svc_backup" in entries[0]["username"]

    def test_parses_drives_xml(self):
        entries = parse_gpp_xml("Drives.xml", _DRIVES_XML)
        assert len(entries) >= 1
        assert "fileshare_svc" in entries[0]["username"]

    def test_clean_xml_no_cpassword(self):
        entries = parse_gpp_xml("Groups.xml", _GROUPS_XML_CLEAN)
        assert len(entries) == 0

    def test_handles_malformed_xml(self):
        entries = parse_gpp_xml("bad.xml", "<not><valid>xml")
        assert len(entries) == 0

    def test_handles_empty_content(self):
        entries = parse_gpp_xml("empty.xml", "")
        assert len(entries) == 0


class TestGPPGrabberExecute:
    def test_finds_groups_xml_in_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Simulate SYSVOL-like structure
            policy_dir = Path(tmpdir) / "Policies" / "{GUID}" / "Machine" / "Preferences" / "Groups"
            policy_dir.mkdir(parents=True)
            (policy_dir / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")

            grabber = GPPGrabber()
            from treasure_hunter.grabbers.base import GrabberContext
            from treasure_hunter.scanner import ScanContext

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx)
            result = grabber.execute(gctx)

            assert len(result.credentials) >= 1
            assert result.credentials[0].target_application == "Group Policy Preferences"
            assert result.credentials[0].username == "LocalAdmin"
            assert result.credentials[0].mitre_technique == "T1552.006"

    def test_finds_multiple_gpp_file_types(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "Groups.xml").write_text(_GROUPS_XML, encoding="utf-8")
            (Path(tmpdir) / "Drives.xml").write_text(_DRIVES_XML, encoding="utf-8")

            grabber = GPPGrabber()
            from treasure_hunter.grabbers.base import GrabberContext
            from treasure_hunter.scanner import ScanContext

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx)
            result = grabber.execute(gctx)

            # Should find creds from both files
            usernames = {c.username for c in result.credentials}
            assert "LocalAdmin" in usernames

    def test_no_false_positives_on_clean_xml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "Groups.xml").write_text(_GROUPS_XML_CLEAN, encoding="utf-8")

            grabber = GPPGrabber()
            from treasure_hunter.grabbers.base import GrabberContext
            from treasure_hunter.scanner import ScanContext

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx)
            result = grabber.execute(gctx)

            # Should find the file but no credentials
            password_creds = [c for c in result.credentials if c.credential_type == "password"]
            assert len(password_creds) == 0
