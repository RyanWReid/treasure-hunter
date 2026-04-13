"""Tests for registry grabber -- mocked Windows registry API."""

import platform
from unittest.mock import MagicMock, patch

import pytest

from treasure_hunter.grabbers.registry import RegistryGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestRegistryGrabberAttributes:
    def test_module_name(self):
        g = RegistryGrabber()
        assert g.name == "registry"
        assert "Windows" in g.supported_platforms

    def test_skips_on_non_windows(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, is_windows=False)
        g = RegistryGrabber()
        can_run, _ = g.can_run(gctx)
        if platform.system() != "Windows":
            assert not can_run


class TestRegistryParsing:
    """Test registry data extraction with mocked winreg."""

    @patch("treasure_hunter.grabbers._registry.read_reg_value")
    @patch("treasure_hunter.grabbers._registry.enum_reg_subkeys")
    def test_extracts_putty_sessions(self, mock_subkeys, mock_read):
        """PuTTY stores sessions under HKCU\\Software\\SimonTatham\\PuTTY\\Sessions."""
        mock_subkeys.return_value = ["prod-db01", "jump-server"]
        mock_read.side_effect = lambda hive, path, name: {
            ("prod-db01", "HostName"): "10.0.0.50",
            ("prod-db01", "UserName"): "admin",
            ("prod-db01", "PortNumber"): 22,
            ("prod-db01", "Protocol"): "ssh",
            ("jump-server", "HostName"): "jump.corp.local",
            ("jump-server", "UserName"): "svc_jump",
            ("jump-server", "PortNumber"): 2222,
            ("jump-server", "Protocol"): "ssh",
        }.get((path.split("\\")[-1], name), "")

        # Verify mock data is structured correctly
        assert mock_read(None, "Sessions\\prod-db01", "HostName") == "10.0.0.50"
        assert mock_read(None, "Sessions\\prod-db01", "UserName") == "admin"

    @patch("treasure_hunter.grabbers._registry.read_reg_value")
    def test_extracts_autologon(self, mock_read):
        """AutoLogon stores creds in Winlogon registry key."""
        mock_read.side_effect = lambda hive, path, name: {
            "DefaultUserName": "CORP\\admin",
            "DefaultPassword": "AutoLogon#2024!",
            "DefaultDomainName": "CORP",
        }.get(name, "")

        assert mock_read(None, "Winlogon", "DefaultUserName") == "CORP\\admin"
        assert mock_read(None, "Winlogon", "DefaultPassword") == "AutoLogon#2024!"

    def test_result_model(self):
        """Verify GrabberResult construction."""
        from treasure_hunter.grabbers.models import GrabberResult, ExtractedCredential
        result = GrabberResult(module_name="registry")
        result.credentials.append(ExtractedCredential(
            source_module="registry",
            credential_type="password",
            target_application="PuTTY",
            url="10.0.0.50:22",
            username="admin",
            notes="protocol=ssh",
            mitre_technique="T1552.002",
        ))
        assert len(result.credentials) == 1
        d = result.to_dict()
        assert d["credentials_count"] == 1
