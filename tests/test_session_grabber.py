"""Tests for RDP/session grabber with realistic .rdp file fixtures."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.session import SessionGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# Realistic .rdp file (Windows Remote Desktop Connection)
_RDP_FILE_WITH_CREDS = """\
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,3,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:prod-dc01.corp.internal:3389
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
gatewaybrokeringtype:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
username:s:CORP\\administrator
domain:s:CORP
password 51:b:01000000d08c9ddf0115d1118c7a00c04fc297eb010000FAKE
"""

_RDP_FILE_SIMPLE = """\
full address:s:jumpbox.dmz.corp.local
username:s:svc_jump
"""

_RDP_FILE_NO_CREDS = """\
full address:s:test-vm.lab.local
prompt for credentials:i:1
"""


class TestRDPFileParsing:
    def test_parses_full_rdp_with_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rdp_path = Path(tmpdir) / "Production-DC01.rdp"
            rdp_path.write_text(_RDP_FILE_WITH_CREDS, encoding="utf-8")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                user_profile_path=tmpdir,
            )
            grabber = SessionGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            # Should find the RDP file with credentials
            rdp_creds = [c for c in result.credentials if "RDP" in c.target_application]
            if rdp_creds:
                assert any("prod-dc01" in c.url.lower() for c in rdp_creds)
                assert any("administrator" in c.username.lower() for c in rdp_creds)

    def test_parses_simple_rdp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rdp_path = Path(tmpdir) / "jumpbox.rdp"
            rdp_path.write_text(_RDP_FILE_SIMPLE, encoding="utf-8")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = SessionGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED

    def test_handles_rdp_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rdp_path = Path(tmpdir) / "test.rdp"
            rdp_path.write_text(_RDP_FILE_NO_CREDS, encoding="utf-8")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = SessionGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED

    def test_discovers_multiple_rdp_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            docs = Path(tmpdir) / "Documents"
            docs.mkdir()
            desktop = Path(tmpdir) / "Desktop"
            desktop.mkdir()

            (docs / "server1.rdp").write_text(_RDP_FILE_WITH_CREDS)
            (desktop / "server2.rdp").write_text(_RDP_FILE_SIMPLE)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = SessionGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
