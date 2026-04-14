"""
CryptoWalletGrabber -- Discover cryptocurrency wallet files

Cryptocurrency wallets contain private keys or encrypted key stores.
Even encrypted wallets are high-value targets for offline cracking
or exfiltration.

Targets:
- Bitcoin Core: wallet.dat
- Electrum: default_wallet, wallets/
- Exodus: exodus.wallet/ (seed phrase encrypted locally)
- MetaMask: Chrome extension LevelDB (vault with encrypted seed)
- Ledger Live: app.json (account metadata)
- Atomic Wallet: Local Storage/leveldb/
- Coinbase Wallet: Chrome extension
- Phantom: Chrome extension (Solana)
- Trust Wallet: Chrome extension

MITRE ATT&CK: T1005 (Data from Local System)
"""

from __future__ import annotations

import os

from .base import GrabberContext, GrabberModule
from .models import ExtractedCredential, GrabberResult, GrabberStatus, PrivilegeLevel


# (app_name, path_template, description, is_dir)
_WALLET_TARGETS = [
    # Bitcoin Core
    ("Bitcoin Core", "{appdata}/Bitcoin/wallet.dat", "Bitcoin Core wallet (private keys)", False),
    ("Bitcoin Core", "{appdata}/Bitcoin/wallets", "Bitcoin Core wallet directory", True),
    ("Bitcoin Core", "{home}/.bitcoin/wallet.dat", "Bitcoin Core wallet (Linux)", False),
    # Electrum
    ("Electrum", "{appdata}/Electrum/wallets", "Electrum wallet directory", True),
    ("Electrum", "{home}/.electrum/wallets", "Electrum wallets (Linux)", True),
    # Exodus
    ("Exodus", "{appdata}/Exodus/exodus.wallet", "Exodus wallet (encrypted seed)", True),
    ("Exodus", "{home}/.config/Exodus/exodus.wallet", "Exodus wallet (Linux)", True),
    # Ledger Live
    ("Ledger Live", "{appdata}/Ledger Live/app.json", "Ledger Live accounts", False),
    # Atomic Wallet
    ("Atomic Wallet", "{appdata}/atomic/Local Storage/leveldb", "Atomic Wallet data", True),
    # Wasabi Wallet
    ("Wasabi Wallet", "{appdata}/WasabiWallet/Client/Wallets", "Wasabi wallet files", True),
    ("Wasabi Wallet", "{home}/.walletwasabi/client/Wallets", "Wasabi wallets (Linux)", True),
    # Monero
    ("Monero", "{home}/Monero/wallets", "Monero wallet directory", True),
    ("Monero", "{home}/Documents/Monero", "Monero wallets (alt location)", True),
    # Ethereum (Geth)
    ("Geth/Ethereum", "{appdata}/Ethereum/keystore", "Ethereum keystore", True),
    ("Geth/Ethereum", "{home}/.ethereum/keystore", "Ethereum keystore (Linux)", True),
]

# Chrome extension IDs for crypto wallets
_CHROME_WALLET_EXTENSIONS = [
    ("MetaMask", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
    ("Phantom", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
    ("Coinbase Wallet", "hnfanknocfeofbddgcijnmhnfnkdnaad"),
    ("Trust Wallet", "egjidjbpglichdcondbcbdnbeeppgdph"),
    ("Brave Wallet", "odbfpeeihdkbihmopkbjmoonfanlbfcl"),
]


class CryptoWalletGrabber(GrabberModule):
    name = "crypto_wallet"
    description = "Discover cryptocurrency wallets (Bitcoin, Electrum, Exodus, MetaMask, Ledger)"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Windows", "Darwin", "Linux")
    default_enabled = True

    def preflight_check(self, context: GrabberContext) -> bool:
        for _, template, _, is_dir in _WALLET_TARGETS:
            path = self._expand(template, context)
            if path:
                if is_dir and os.path.isdir(path):
                    return True
                elif not is_dir and os.path.isfile(path):
                    return True
        # Check Chrome extensions
        chrome_ext_base = self._get_chrome_ext_base(context)
        if chrome_ext_base:
            for _, ext_id in _CHROME_WALLET_EXTENSIONS:
                if os.path.isdir(os.path.join(chrome_ext_base, ext_id)):
                    return True
        return False

    def execute(self, context: GrabberContext) -> GrabberResult:
        result = GrabberResult(module_name=self.name)

        # Check known wallet locations
        for app_name, template, description, is_dir in _WALLET_TARGETS:
            path = self._expand(template, context)
            if not path:
                continue

            if is_dir and os.path.isdir(path):
                file_count, total_size = self._dir_stats(path)
                if file_count > 0:
                    result.credentials.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="key",
                        target_application=app_name,
                        url=path,
                        notes=f"{description} ({file_count} files, {total_size:,} bytes)",
                        mitre_technique="T1005",
                        source_file=path,
                    ))
                    result.findings.append(self.make_finding(
                        file_path=path,
                        description=f"{app_name} wallet directory found",
                        score=200,  # CRITICAL -- cryptocurrency
                        matched_value=app_name,
                    ))

            elif not is_dir and os.path.isfile(path):
                try:
                    size = os.path.getsize(path)
                except OSError:
                    size = 0
                result.credentials.append(ExtractedCredential(
                    source_module=self.name,
                    credential_type="key",
                    target_application=app_name,
                    url=path,
                    notes=f"{description} ({size:,} bytes)",
                    mitre_technique="T1005",
                    source_file=path,
                ))
                result.findings.append(self.make_finding(
                    file_path=path,
                    description=f"{app_name} wallet file found",
                    score=250,  # CRITICAL -- direct wallet file
                    matched_value=app_name,
                ))

        # Check Chrome extensions for crypto wallets
        chrome_ext_base = self._get_chrome_ext_base(context)
        if chrome_ext_base:
            for wallet_name, ext_id in _CHROME_WALLET_EXTENSIONS:
                ext_path = os.path.join(chrome_ext_base, ext_id)
                if os.path.isdir(ext_path):
                    file_count, total_size = self._dir_stats(ext_path)
                    result.credentials.append(ExtractedCredential(
                        source_module=self.name,
                        credential_type="key",
                        target_application=f"{wallet_name} (Chrome Extension)",
                        url=ext_path,
                        notes=f"Chrome extension vault ({file_count} files, {total_size:,} bytes)",
                        mitre_technique="T1005",
                        source_file=ext_path,
                    ))
                    result.findings.append(self.make_finding(
                        file_path=ext_path,
                        description=f"{wallet_name} Chrome extension vault",
                        score=200,
                        matched_value=wallet_name,
                    ))

        result.status = GrabberStatus.COMPLETED
        return result

    @staticmethod
    def _expand(template: str, context: GrabberContext) -> str:
        return template.format(
            appdata=context.appdata_roaming or "",
            localappdata=context.appdata_local or "",
            home=context.user_profile_path,
        )

    @staticmethod
    def _get_chrome_ext_base(context: GrabberContext) -> str:
        """Get Chrome Local Extension Settings directory."""
        paths = [
            os.path.join(context.appdata_local or "", "Google", "Chrome",
                        "User Data", "Default", "Local Extension Settings"),
            os.path.join(context.user_profile_path, "Library", "Application Support",
                        "Google", "Chrome", "Default", "Local Extension Settings"),
            os.path.join(context.user_profile_path, ".config", "google-chrome",
                        "Default", "Local Extension Settings"),
        ]
        for p in paths:
            if os.path.isdir(p):
                return p
        return ""

    @staticmethod
    def _dir_stats(path: str) -> tuple[int, int]:
        """Count files and total size in a directory."""
        file_count = 0
        total_size = 0
        try:
            for root, dirs, files in os.walk(path):
                for f in files:
                    file_count += 1
                    try:
                        total_size += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
                # Don't recurse too deep
                if root.count(os.sep) - path.count(os.sep) > 3:
                    dirs.clear()
        except (PermissionError, OSError):
            pass
        return file_count, total_size
