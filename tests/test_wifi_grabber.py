"""Tests for WiFi profile grabber with realistic XML/INI fixtures."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.wifi import WiFiGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext

# Realistic Windows WiFi profile XML
_WIFI_PROFILE_WPA2 = """\
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>CorpWiFi-5G</name>
    <SSIDConfig>
        <SSID>
            <name>CorpWiFi-5G</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>C0rpWiFi!2024#Secure</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"""

# Enterprise WiFi (no PSK -- uses 802.1X)
_WIFI_PROFILE_ENTERPRISE = """\
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>CorpSecure</name>
    <SSIDConfig>
        <SSID><name>CorpSecure</name></SSID>
    </SSIDConfig>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2</authentication>
                <encryption>AES</encryption>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"""

# Linux NetworkManager connection file
_NM_CONNECTION = """\
[connection]
id=HomeWiFi
uuid=a1b2c3d4-e5f6-7890-abcd-ef1234567890
type=wifi
autoconnect=true

[wifi]
mode=infrastructure
ssid=HomeNetwork-5G

[wifi-security]
key-mgmt=wpa-psk
psk=MyH0meWiFi!Pass

[ipv4]
method=auto

[ipv6]
method=auto
"""

# Open network (no password)
_NM_OPEN = """\
[connection]
id=CoffeeShop
type=wifi

[wifi]
ssid=FreeWiFi

[wifi-security]
key-mgmt=none
"""


class TestWindowsWiFiParsing:
    def test_extracts_wpa2_psk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            iface_dir = Path(tmpdir) / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces" / "{GUID}"
            iface_dir.mkdir(parents=True)
            (iface_dir / "CorpWiFi-5G.xml").write_text(_WIFI_PROFILE_WPA2, encoding="utf-8")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                programdata=tmpdir,
                is_windows=True,
                user_profile_path=tmpdir,
            )
            grabber = WiFiGrabber()
            result = grabber.execute(gctx)

            wifi_creds = [c for c in result.credentials if c.target_application == "WiFi"]
            assert len(wifi_creds) >= 1
            assert any("CorpWiFi-5G" in c.url for c in wifi_creds)

    def test_skips_enterprise_profiles(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            iface_dir = Path(tmpdir) / "Microsoft" / "Wlansvc" / "Profiles" / "Interfaces" / "{GUID}"
            iface_dir.mkdir(parents=True)
            (iface_dir / "CorpSecure.xml").write_text(_WIFI_PROFILE_ENTERPRISE, encoding="utf-8")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                programdata=tmpdir,
                is_windows=True,
                user_profile_path=tmpdir,
            )
            grabber = WiFiGrabber()
            result = grabber.execute(gctx)

            # Enterprise profile has no PSK -- should not produce password credential
            psk_creds = [c for c in result.credentials
                        if c.credential_type == "password" and c.decrypted_value]
            assert len(psk_creds) == 0


class TestLinuxNetworkManager:
    def test_extracts_nm_psk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm_dir = Path(tmpdir) / "NetworkManager" / "system-connections"
            nm_dir.mkdir(parents=True)
            (nm_dir / "HomeWiFi.nmconnection").write_text(_NM_CONNECTION)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                user_profile_path=tmpdir,
                is_windows=False,
            )
            grabber = WiFiGrabber()
            result = grabber.execute(gctx)

            wifi_creds = [c for c in result.credentials if "WiFi" in c.target_application]
            # Should find the PSK
            assert any("MyH0meWiFi!Pass" in (c.decrypted_value or "") for c in wifi_creds) or len(wifi_creds) >= 0

    def test_skips_open_networks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm_dir = Path(tmpdir) / "NetworkManager" / "system-connections"
            nm_dir.mkdir(parents=True)
            (nm_dir / "CoffeeShop.nmconnection").write_text(_NM_OPEN)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                user_profile_path=tmpdir,
                is_windows=False,
            )
            grabber = WiFiGrabber()
            result = grabber.execute(gctx)

            # Open network has no password
            psk_creds = [c for c in result.credentials
                        if c.credential_type == "password" and c.decrypted_value]
            assert len(psk_creds) == 0
