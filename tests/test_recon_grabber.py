"""Tests for security recon grabber."""

import platform
from unittest.mock import patch, MagicMock

import pytest

from treasure_hunter.grabbers.recon import ReconGrabber, _SECURITY_PROCESSES
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestReconGrabberAttributes:
    def test_name(self):
        g = ReconGrabber()
        assert g.name == "recon"
        assert g.default_enabled is True

    def test_skips_non_windows(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, is_windows=False)
        g = ReconGrabber()
        assert not g.preflight_check(gctx)


class TestSecurityProcessDetection:
    def test_known_process_names(self):
        """Verify all expected security products are in the detection list."""
        assert "MsMpEng.exe" in _SECURITY_PROCESSES
        assert "csfalconservice.exe" in _SECURITY_PROCESSES
        assert "SentinelAgent.exe" in _SECURITY_PROCESSES
        assert "Sysmon64.exe" in _SECURITY_PROCESSES
        assert "elastic-agent.exe" in _SECURITY_PROCESSES
        assert "CylanceSvc.exe" in _SECURITY_PROCESSES

    def test_process_map_values(self):
        """Each process should map to a readable product name."""
        for proc, product in _SECURITY_PROCESSES.items():
            assert proc.endswith(".exe"), f"{proc} should end with .exe"
            assert len(product) > 2, f"{proc} has empty product name"


class TestReconExecution:
    @patch("treasure_hunter.grabbers.recon.ReconGrabber._detect_security_processes")
    @patch("treasure_hunter.grabbers.recon.ReconGrabber._check_security_registry")
    def test_reports_found_products(self, mock_reg, mock_procs):
        mock_procs.return_value = {"MsMpEng.exe": "Windows Defender"}
        mock_reg.return_value = ["[i] UAC Level / EnableLUA = 1"]

        ctx = ScanContext(target_paths=["C:\\"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, is_windows=True)
        g = ReconGrabber()
        result = g.execute(gctx)

        assert result.status == GrabberStatus.COMPLETED
        assert len(result.credentials) >= 1
        assert result.credentials[0].username == "Windows Defender"
        assert len(result.findings) >= 1

    @patch("treasure_hunter.grabbers.recon.ReconGrabber._detect_security_processes")
    @patch("treasure_hunter.grabbers.recon.ReconGrabber._check_security_registry")
    def test_reports_no_products(self, mock_reg, mock_procs):
        mock_procs.return_value = {}
        mock_reg.return_value = []

        ctx = ScanContext(target_paths=["C:\\"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, is_windows=True)
        g = ReconGrabber()
        result = g.execute(gctx)

        assert result.status == GrabberStatus.COMPLETED
        # Should still have a finding with "No known AV/EDR"
        assert len(result.findings) >= 1

    @patch("treasure_hunter.grabbers.recon.ReconGrabber._detect_security_processes")
    @patch("treasure_hunter.grabbers.recon.ReconGrabber._check_security_registry")
    def test_multiple_security_products(self, mock_reg, mock_procs):
        mock_procs.return_value = {
            "MsMpEng.exe": "Windows Defender",
            "Sysmon64.exe": "Sysmon (64-bit)",
            "csfalconservice.exe": "CrowdStrike Falcon",
        }
        mock_reg.return_value = []

        ctx = ScanContext(target_paths=["C:\\"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, is_windows=True)
        g = ReconGrabber()
        result = g.execute(gctx)

        assert len(result.credentials) == 3
        products = {c.username for c in result.credentials}
        assert "Windows Defender" in products
        assert "CrowdStrike Falcon" in products
