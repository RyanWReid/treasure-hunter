"""Tests for cryptocurrency wallet discovery grabber."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.crypto_wallet import CryptoWalletGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestCryptoWalletPreflight:
    def test_true_when_bitcoin_wallet_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            btc = Path(tmpdir) / "Bitcoin"
            btc.mkdir()
            (btc / "wallet.dat").write_bytes(b"\x00" * 1024)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            assert g.preflight_check(gctx)

    def test_false_when_no_wallets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            assert not g.preflight_check(gctx)


class TestCryptoWalletExecution:
    def test_finds_bitcoin_wallet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            btc = Path(tmpdir) / "Bitcoin"
            btc.mkdir()
            (btc / "wallet.dat").write_bytes(b"\x00" * 2048)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            btc_creds = [c for c in result.credentials if c.target_application == "Bitcoin Core"]
            assert len(btc_creds) >= 1
            assert any(f.total_score >= 200 for f in result.findings)

    def test_finds_electrum_wallets(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            electrum = Path(tmpdir) / "Electrum" / "wallets"
            electrum.mkdir(parents=True)
            (electrum / "default_wallet").write_text('{"keystore": {"type": "bip32"}}')

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            electrum_creds = [c for c in result.credentials if c.target_application == "Electrum"]
            assert len(electrum_creds) >= 1

    def test_finds_exodus_wallet(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            exodus = Path(tmpdir) / "Exodus" / "exodus.wallet"
            exodus.mkdir(parents=True)
            (exodus / "seed.seco").write_bytes(b"\x00" * 512)
            (exodus / "accounts.json").write_text("{}")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            exodus_creds = [c for c in result.credentials if c.target_application == "Exodus"]
            assert len(exodus_creds) >= 1

    def test_finds_metamask_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_dir = Path(tmpdir) / "Google" / "Chrome" / "User Data" / "Default" / "Local Extension Settings" / "nkbihfbeogaeaoehlefnkodbefgpgknn"
            ext_dir.mkdir(parents=True)
            (ext_dir / "000003.log").write_bytes(b"\x00" * 256)

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_local=tmpdir,
                appdata_roaming=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            result = g.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED
            mm_creds = [c for c in result.credentials if "MetaMask" in c.target_application]
            assert len(mm_creds) >= 1

    def test_no_false_positives(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx, appdata_roaming=tmpdir,
                appdata_local=tmpdir, user_profile_path=tmpdir,
            )
            g = CryptoWalletGrabber()
            result = g.execute(gctx)
            assert len(result.credentials) == 0
