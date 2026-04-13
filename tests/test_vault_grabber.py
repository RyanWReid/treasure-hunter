"""Tests for Windows Vault grabber.

Vault API calls are Windows-only (ctypes vaultcli.dll), so these tests
focus on the file enumeration path which works cross-platform, and
mock the Vault API path.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from treasure_hunter.grabbers.vault import VaultGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestVaultGrabberPreflight:
    def test_false_on_non_windows(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx, is_windows=False)
        grabber = VaultGrabber()
        assert not grabber.preflight_check(gctx)

    def test_true_when_vault_dir_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "Microsoft" / "Vault"
            vault_dir.mkdir(parents=True)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                is_windows=True,
            )
            grabber = VaultGrabber()
            assert grabber.preflight_check(gctx)


class TestVaultGrabberExecute:
    def test_enumerates_vault_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "Microsoft" / "Vault"
            vault_dir.mkdir(parents=True)

            # Create fake vault files matching real structure
            web_vault = vault_dir / "{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}"
            web_vault.mkdir()
            (web_vault / "Policy.vpol").write_bytes(b"\x01\x00\x00\x00" * 16)
            (web_vault / "{GUID}.vcrd").write_bytes(b"\x02\x00\x00\x00" * 32)

            win_vault = vault_dir / "{77BC582B-F0A6-4E15-4E80-61736B6F3B29}"
            win_vault.mkdir()
            (win_vault / "Policy.vpol").write_bytes(b"\x01\x00\x00\x00" * 16)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                is_windows=True,
            )

            # Mock the Vault API since we're not on Windows
            with patch("treasure_hunter.grabbers.vault._extract_vault_credentials", return_value=[]):
                grabber = VaultGrabber()
                result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            # Should find the vault files
            assert len(result.credentials) >= 2  # Policy.vpol + .vcrd files
            assert any("Vault file" in c.notes for c in result.credentials)
            assert len(result.findings) >= 1

    def test_handles_empty_vault_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "Microsoft" / "Vault"
            vault_dir.mkdir(parents=True)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                is_windows=True,
            )

            with patch("treasure_hunter.grabbers.vault._extract_vault_credentials", return_value=[]):
                grabber = VaultGrabber()
                result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) == 0

    @patch("treasure_hunter.grabbers.vault._extract_vault_credentials")
    def test_vault_api_returns_credentials(self, mock_vault):
        mock_vault.return_value = [
            {"vault_index": 0, "item_count": 3},
            {"vault_index": 1, "item_count": 1},
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / "Microsoft" / "Vault"
            vault_dir.mkdir(parents=True)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                is_windows=True,
            )

            grabber = VaultGrabber()
            result = grabber.execute(gctx)

            # Should have credentials from API
            api_creds = [c for c in result.credentials if c.target_application == "Windows Vault" and c.credential_type == "password"]
            assert len(api_creds) == 2
