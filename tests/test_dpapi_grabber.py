"""Tests for DPAPI grabber -- credential file enumeration with realistic fixtures."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.dpapi import DPAPIGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# DPAPI credential blob header (first 20 bytes of a real blob)
_DPAPI_HEADER = bytes([
    0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF,
    0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0,
    0x4F, 0xC2, 0x97, 0xEB,
])

# DPAPI master key file header
_MASTER_KEY_HEADER = bytes([
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
])


class TestDPAPIGrabberPreflight:
    def test_true_when_credentials_dir_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cred_dir = Path(tmpdir) / "Microsoft" / "Credentials"
            cred_dir.mkdir(parents=True)
            (cred_dir / "{GUID-FAKE}").write_bytes(_DPAPI_HEADER + b"\x00" * 256)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                appdata_local=tmpdir,
            )
            grabber = DPAPIGrabber()
            assert grabber.preflight_check(gctx)

    def test_false_when_no_dpapi_dirs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, appdata_roaming=tmpdir, appdata_local=tmpdir)
            grabber = DPAPIGrabber()
            assert not grabber.preflight_check(gctx)


class TestDPAPIGrabberExecute:
    def test_enumerates_credential_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cred_dir = Path(tmpdir) / "Microsoft" / "Credentials"
            cred_dir.mkdir(parents=True)
            (cred_dir / "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}").write_bytes(
                _DPAPI_HEADER + b"\x00" * 256
            )
            (cred_dir / "{B2C3D4E5-F6A7-8901-BCDE-F12345678901}").write_bytes(
                _DPAPI_HEADER + b"\x00" * 512
            )

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                appdata_local=tmpdir,
            )
            grabber = DPAPIGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) >= 2
            assert all(c.mitre_technique == "T1555.004" for c in result.credentials)
            assert len(result.findings) >= 1

    def test_enumerates_master_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            protect_dir = Path(tmpdir) / "Microsoft" / "Protect"
            sid_dir = protect_dir / "S-1-5-21-FAKE"
            sid_dir.mkdir(parents=True)
            (sid_dir / "a1b2c3d4-e5f6-7890-abcd-ef1234567890").write_bytes(
                _MASTER_KEY_HEADER + b"\x00" * 512
            )

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming=tmpdir,
                appdata_local=tmpdir,
            )
            grabber = DPAPIGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) >= 1

    def test_handles_permission_errors(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_roaming="/nonexistent/path",
                appdata_local="/nonexistent/path",
            )
            grabber = DPAPIGrabber()
            result = grabber.execute(gctx)
            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) == 0
