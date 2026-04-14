"""Tests for WSL filesystem extraction grabber."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.wsl import WSLGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestWSLGrabberPreflight:
    def test_false_when_no_wsl(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=tmpdir, is_windows=True)
            g = WSLGrabber()
            assert not g.preflight_check(gctx)

    def test_true_when_ubuntu_rootfs_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = Path(tmpdir) / "Packages" / "CanonicalGroupLimited.Ubuntu22.04_abc" / "LocalState" / "rootfs"
            rootfs.mkdir(parents=True)
            (rootfs / "etc").mkdir()

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=tmpdir, is_windows=True)
            g = WSLGrabber()
            assert g.preflight_check(gctx)


class TestWSLGrabberExecute:
    def _make_wsl_env(self, tmpdir):
        """Create a realistic WSL rootfs structure."""
        rootfs = Path(tmpdir) / "Packages" / "CanonicalGroupLimited.Ubuntu22.04_abc" / "LocalState" / "rootfs"
        home = rootfs / "home" / "devuser"
        home.mkdir(parents=True)

        # SSH key
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEY\n-----END OPENSSH PRIVATE KEY-----")
        (ssh_dir / "config").write_text("Host prod\n  HostName prod.internal\n  User deploy")

        # Bash history with secrets
        (home / ".bash_history").write_text(
            "ls -la\n"
            "mysql -u root -p SuperSecret123\n"
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n"
            "git push origin main\n"
            "curl -u admin:password123 https://api.internal\n"
        )

        # AWS credentials
        aws_dir = home / ".aws"
        aws_dir.mkdir()
        (aws_dir / "credentials").write_text("[default]\naws_access_key_id=AKIAFAKEKEY\naws_secret_access_key=fakesecret")

        # .env file
        (home / ".env").write_text("DATABASE_URL=postgres://admin:dbpass@db:5432/app\nSECRET_KEY=mysecretkey123")

        # Git credentials
        (home / ".git-credentials").write_text("https://user:ghp_faketoken@github.com")

        return rootfs, tmpdir

    def test_finds_ssh_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs, base = self._make_wsl_env(tmpdir)
            ctx = ScanContext(target_paths=[base], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=base, is_windows=True)
            g = WSLGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            ssh_creds = [c for c in result.credentials if "SSH" in c.notes]
            assert len(ssh_creds) >= 1

    def test_finds_bash_history_secrets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs, base = self._make_wsl_env(tmpdir)
            ctx = ScanContext(target_paths=[base], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=base, is_windows=True)
            g = WSLGrabber()
            result = g.execute(gctx)

            history_creds = [c for c in result.credentials if "History" in c.target_application]
            assert len(history_creds) >= 1

    def test_finds_aws_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs, base = self._make_wsl_env(tmpdir)
            ctx = ScanContext(target_paths=[base], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=base, is_windows=True)
            g = WSLGrabber()
            result = g.execute(gctx)

            aws_creds = [c for c in result.credentials if "aws" in (c.source_file or "").lower()]
            assert len(aws_creds) >= 1

    def test_finds_env_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs, base = self._make_wsl_env(tmpdir)
            ctx = ScanContext(target_paths=[base], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=base, is_windows=True)
            g = WSLGrabber()
            result = g.execute(gctx)

            env_creds = [c for c in result.credentials if ".env" in (c.source_file or "")]
            assert len(env_creds) >= 1

    def test_empty_rootfs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rootfs = Path(tmpdir) / "Packages" / "CanonicalGroupLimited.Ubuntu_abc" / "LocalState" / "rootfs"
            rootfs.mkdir(parents=True)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_local=tmpdir, is_windows=True)
            g = WSLGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) == 0
