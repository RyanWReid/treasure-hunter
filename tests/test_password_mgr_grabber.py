"""Tests for password manager vault discovery with realistic fixtures."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.password_mgr import PasswordMgrGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestPasswordMgrPreflight:
    def test_true_when_bitwarden_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bw = Path(tmpdir) / "Bitwarden"
            bw.mkdir()
            (bw / "data.json").write_text('{"encrypted": true}')

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                appdata_local=tmpdir,
                user_profile_path=tmpdir,
            )
            g = PasswordMgrGrabber()
            assert g.preflight_check(gctx)

    def test_true_when_kdbx_in_documents(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            docs = Path(tmpdir) / "Documents"
            docs.mkdir()
            (docs / "passwords.kdbx").write_bytes(b"\x03\xd9\xa2\x9a" + b"\x00" * 100)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, user_profile_path=tmpdir,
                appdata_roaming="", appdata_local="",
            )
            g = PasswordMgrGrabber()
            assert g.preflight_check(gctx)

    def test_false_when_nothing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, user_profile_path=tmpdir,
                appdata_roaming=tmpdir, appdata_local=tmpdir,
            )
            g = PasswordMgrGrabber()
            assert not g.preflight_check(gctx)


class TestPasswordMgrExecution:
    def test_discovers_bitwarden_vault(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bw = Path(tmpdir) / "Bitwarden"
            bw.mkdir()
            vault = bw / "data.json"
            vault.write_text('{"encKey":"encrypted","data":{"ciphers":[]}}')

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                appdata_local=tmpdir,
                user_profile_path=tmpdir,
            )
            g = PasswordMgrGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            bw_creds = [c for c in result.credentials if c.target_application == "Bitwarden"]
            assert len(bw_creds) >= 1
            assert any(f.total_score >= 200 for f in result.findings)  # CRITICAL

    def test_discovers_keepass_database(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            docs = Path(tmpdir) / "Documents"
            docs.mkdir()
            (docs / "work-passwords.kdbx").write_bytes(b"\x03\xd9\xa2\x9a" + b"\x00" * 500)
            (docs / "old-passwords.kdb").write_bytes(b"\x03\xd9\xa2\x9a" + b"\x00" * 300)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, user_profile_path=tmpdir,
                appdata_roaming=tmpdir, appdata_local=tmpdir,
            )
            g = PasswordMgrGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            kp_creds = [c for c in result.credentials if c.target_application == "KeePass"]
            assert len(kp_creds) >= 2  # .kdbx + .kdb

    def test_discovers_1password_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            op = Path(tmpdir) / "1Password" / "data"
            op.mkdir(parents=True)
            (op / "vault.db").write_bytes(b"\x00" * 1024)
            (op / "index.json").write_text('{}')

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                appdata_roaming=tmpdir,
                user_profile_path=tmpdir,
            )
            g = PasswordMgrGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            op_creds = [c for c in result.credentials if c.target_application == "1Password"]
            assert len(op_creds) >= 1

    def test_no_false_positives_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, user_profile_path=tmpdir,
                appdata_roaming=tmpdir, appdata_local=tmpdir,
            )
            g = PasswordMgrGrabber()
            result = g.execute(gctx)
            assert len(result.credentials) == 0

    def test_discovers_lastpass_chrome_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lp = Path(tmpdir) / "Google" / "Chrome" / "User Data" / "Default" / "Local Extension Settings" / "hdokiejnpimakedhajhdlcegeplioahd"
            lp.mkdir(parents=True)
            (lp / "000003.log").write_bytes(b"\x00" * 512)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                appdata_roaming=tmpdir,
                user_profile_path=tmpdir,
            )
            g = PasswordMgrGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            lp_creds = [c for c in result.credentials if "LastPass" in c.target_application]
            assert len(lp_creds) >= 1

    def test_handles_permission_error(self):
        ctx = ScanContext(target_paths=["/nonexistent"], grabbers_enabled=False)
        gctx = GrabberContext(
            scan_context=ctx, user_profile_path="/nonexistent",
            appdata_roaming="/nonexistent", appdata_local="/nonexistent",
        )
        g = PasswordMgrGrabber()
        result = g.execute(gctx)
        assert result.status == GrabberStatus.COMPLETED
        assert len(result.credentials) == 0
