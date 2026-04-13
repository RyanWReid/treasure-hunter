"""Tests for email grabber with realistic Outlook/Thunderbird fixtures."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.email import EmailGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# Realistic Thunderbird prefs.js content
_THUNDERBIRD_PREFS = """\
// Mozilla User Preferences
user_pref("app.update.lastUpdateTime.addon-background-update-timer", 1700000000);
user_pref("mail.server.server1.directory-rel", "[ProfD]ImapMail/imap.gmail.com");
user_pref("mail.server.server1.hostname", "imap.gmail.com");
user_pref("mail.server.server1.port", 993);
user_pref("mail.server.server1.userName", "john.doe@gmail.com");
user_pref("mail.server.server1.type", "imap");
user_pref("mail.server.server2.hostname", "mail.corp.internal");
user_pref("mail.server.server2.userName", "jdoe@corp.internal");
user_pref("mail.server.server2.type", "imap");
user_pref("mail.smtpserver.smtp1.hostname", "smtp.gmail.com");
user_pref("mail.smtpserver.smtp1.username", "john.doe@gmail.com");
"""


class TestEmailGrabberPreflight:
    def test_true_when_thunderbird_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tb_dir = Path(tmpdir) / "Thunderbird" / "Profiles" / "abc123.default"
            tb_dir.mkdir(parents=True)
            (tb_dir / "prefs.js").write_text(_THUNDERBIRD_PREFS)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                user_profile_path=tmpdir,
            )
            grabber = EmailGrabber()
            assert grabber.preflight_check(gctx)

    def test_false_when_no_email_clients(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = EmailGrabber()
            assert not grabber.preflight_check(gctx)


class TestThunderbirdParsing:
    def test_extracts_email_accounts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tb_dir = Path(tmpdir) / "Thunderbird" / "Profiles" / "abc123.default"
            tb_dir.mkdir(parents=True)
            (tb_dir / "prefs.js").write_text(_THUNDERBIRD_PREFS)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                user_profile_path=tmpdir,
            )
            grabber = EmailGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            # Should find at least the email accounts
            tb_creds = [c for c in result.credentials if "Thunderbird" in c.target_application]
            assert len(tb_creds) >= 1


class TestOutlookDiscovery:
    def test_finds_pst_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outlook_dir = Path(tmpdir) / "Microsoft" / "Outlook"
            outlook_dir.mkdir(parents=True)
            # Create realistic PST file (just needs to exist with some size)
            pst_path = outlook_dir / "john.doe@corp.com.pst"
            pst_path.write_bytes(b"\x21\x42\x44\x4E" + b"\x00" * 1024)  # PST magic bytes

            ost_path = outlook_dir / "john.doe@corp.com.ost"
            ost_path.write_bytes(b"\x21\x42\x44\x4E" + b"\x00" * 2048)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                user_profile_path=tmpdir,
            )
            grabber = EmailGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
