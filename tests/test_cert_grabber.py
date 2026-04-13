"""Tests for certificate/key discovery grabber with realistic fixtures."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.cert import CertGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# Realistic PEM private key header (truncated, not a real key)
_FAKE_PEM_KEY = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU5yTfKREEMEiG5YMcN0MYzTOJEFAKE0000000000000000000NOTREAL
-----END RSA PRIVATE KEY-----
"""

_FAKE_CERT = b"""-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUFAKE000000000000NOTREAL
-----END CERTIFICATE-----
"""


class TestCertGrabberPreflight:
    def test_true_when_ssh_dir_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir) / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "id_rsa").write_bytes(_FAKE_PEM_KEY)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = CertGrabber()
            assert grabber.preflight_check(gctx)

    def test_false_when_no_key_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = CertGrabber()
            assert not grabber.preflight_check(gctx)


class TestCertGrabberExecute:
    def test_finds_pem_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ssh_dir = Path(tmpdir) / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "id_rsa.pem").write_bytes(_FAKE_PEM_KEY)
            (ssh_dir / "id_rsa.pub").write_text("ssh-rsa AAAA... user@host")
            (ssh_dir / "known_hosts").write_text("github.com ssh-rsa AAAA...")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = CertGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            # Should find credential files
            assert len(result.credentials) >= 1

    def test_finds_pfx_certificates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "wildcard.pfx").write_bytes(b"\x30\x82\x00\x00" + b"\x00" * 100)
            (Path(tmpdir) / "server.p12").write_bytes(b"\x30\x82\x00\x00" + b"\x00" * 100)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = CertGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED

    def test_finds_gpg_keyrings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gpg_dir = Path(tmpdir) / ".gnupg"
            gpg_dir.mkdir()
            (gpg_dir / "secring.gpg").write_bytes(b"\x00" * 256)
            (gpg_dir / "pubring.gpg").write_bytes(b"\x00" * 512)
            priv_dir = gpg_dir / "private-keys-v1.d"
            priv_dir.mkdir()
            (priv_dir / "ABC123.key").write_bytes(b"\x00" * 128)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = CertGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.findings) >= 1

    def test_no_findings_in_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = CertGrabber()
            result = grabber.execute(gctx)
            assert len(result.credentials) == 0
