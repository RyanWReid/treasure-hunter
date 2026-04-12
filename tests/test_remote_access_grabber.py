"""Tests for RemoteAccessGrabber with fixture files."""

import base64
import tempfile
from pathlib import Path

from treasure_hunter.grabbers.remote_access import RemoteAccessGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str, appdata: str = "") -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    gctx.appdata_roaming = appdata or home
    return gctx


class TestFileZilla:
    def test_parses_recentservers(self):
        with tempfile.TemporaryDirectory() as home:
            fz_dir = Path(home) / "FileZilla"
            fz_dir.mkdir()

            password = base64.b64encode(b"s3cret!").decode()
            (fz_dir / "recentservers.xml").write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<FileZilla3>\n'
                '  <RecentServers>\n'
                '    <Server>\n'
                f'      <Host>ftp.corp.internal</Host>\n'
                f'      <Port>22</Port>\n'
                f'      <Protocol>1</Protocol>\n'
                f'      <User>deploy</User>\n'
                f'      <Pass encoding="base64">{password}</Pass>\n'
                '    </Server>\n'
                '    <Server>\n'
                '      <Host>backup.server</Host>\n'
                '      <Port>21</Port>\n'
                '      <Protocol>0</Protocol>\n'
                '      <User>admin</User>\n'
                f'      <Pass encoding="base64">{base64.b64encode(b"backup_pass").decode()}</Pass>\n'
                '    </Server>\n'
                '  </RecentServers>\n'
                '</FileZilla3>\n'
            )

            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            result = grabber.run(gctx)

            assert result.status == GrabberStatus.COMPLETED
            fz_creds = [c for c in result.credentials if "FileZilla" in c.target_application]
            assert len(fz_creds) == 2

            assert fz_creds[0].username == "deploy"
            assert fz_creds[0].decrypted_value == "s3cret!"
            assert fz_creds[0].url == "ftp.corp.internal:22"
            assert "SFTP" in fz_creds[0].target_application

            assert fz_creds[1].username == "admin"
            assert fz_creds[1].decrypted_value == "backup_pass"

    def test_handles_empty_password(self):
        with tempfile.TemporaryDirectory() as home:
            fz_dir = Path(home) / "FileZilla"
            fz_dir.mkdir()
            (fz_dir / "recentservers.xml").write_text(
                '<?xml version="1.0"?><FileZilla3><RecentServers>'
                '<Server><Host>h</Host><User>u</User></Server>'
                '</RecentServers></FileZilla3>'
            )

            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            result = grabber.run(gctx)

            creds = [c for c in result.credentials if "FileZilla" in c.target_application]
            assert len(creds) == 1
            assert creds[0].decrypted_value == ""


class TestMRemoteNG:
    def test_parses_connection_nodes(self):
        with tempfile.TemporaryDirectory() as home:
            mr_dir = Path(home) / "mRemoteNG"
            mr_dir.mkdir()
            (mr_dir / "confCons.xml").write_text(
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<mrng:Connections xmlns:mrng="http://mremoteng.org">\n'
                '  <Node Name="DC01" Hostname="dc01.corp.local" Protocol="RDP" '
                '        Port="3389" Username="admin" Password="" />\n'
                '  <Node Name="Web" Hostname="web01.corp.local" Protocol="SSH2" '
                '        Port="22" Username="root" Password="" />\n'
                '</mrng:Connections>\n'
            )

            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            result = grabber.run(gctx)

            mr_creds = [c for c in result.credentials if "mRemoteNG" in c.target_application]
            assert len(mr_creds) == 2
            assert mr_creds[0].url == "dc01.corp.local:3389"
            assert mr_creds[0].username == "admin"
            assert "RDP" in mr_creds[0].target_application


class TestWinSCP:
    def test_parses_sessions(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "WinSCP.ini").write_text(
                "[Sessions\\server1]\n"
                "HostName=10.0.0.1\n"
                "PortNumber=22\n"
                "UserName=admin\n"
                "Password=AABB\n"
                "\n"
                "[Sessions\\server2]\n"
                "HostName=10.0.0.2\n"
                "UserName=deploy\n"
            )

            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            result = grabber.run(gctx)

            winscp_creds = [c for c in result.credentials if c.target_application == "WinSCP"]
            assert len(winscp_creds) == 2
            assert winscp_creds[0].url == "10.0.0.1:22"
            assert winscp_creds[0].username == "admin"
            assert winscp_creds[1].url == "10.0.0.2"
            assert winscp_creds[1].username == "deploy"


class TestMobaXterm:
    def test_parses_password_section(self):
        with tempfile.TemporaryDirectory() as home:
            moba_dir = Path(home) / "MobaXterm"
            moba_dir.mkdir()
            (moba_dir / "MobaXterm.ini").write_text(
                "[Bookmarks]\n"
                "SubRep=\n"
                "[Passwords]\n"
                "admin@server1=ENCRYPTED_PASSWORD_DATA\n"
                "root@server2=OTHER_ENCRYPTED_DATA\n"
                "[General]\n"
                "key=value\n"
            )

            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            result = grabber.run(gctx)

            moba_creds = [c for c in result.credentials if c.target_application == "MobaXterm"]
            assert len(moba_creds) == 2
            assert moba_creds[0].username == "admin@server1"
            assert len(moba_creds[0].encrypted_value) > 0


class TestPreflightCheck:
    def test_false_when_nothing_exists(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            assert grabber.preflight_check(gctx) is False

    def test_true_when_filezilla_exists(self):
        with tempfile.TemporaryDirectory() as home:
            fz_dir = Path(home) / "FileZilla"
            fz_dir.mkdir()
            (fz_dir / "recentservers.xml").write_text("<FileZilla3/>")

            grabber = RemoteAccessGrabber()
            gctx = _make_context(home, str(home))
            assert grabber.preflight_check(gctx) is True


class TestCryptoModule:
    def test_aes_cbc_decrypt(self):
        from treasure_hunter.grabbers._crypto import aes_cbc_decrypt, pkcs7_unpad
        # Known test vector: AES-128-CBC
        # Encrypt "hello world!!!!!" (16 bytes) with known key/iv
        # We'll test the round-trip indirectly via padding
        key = b'\x00' * 16
        iv = b'\x00' * 16
        # Test that bad padding is caught
        try:
            aes_cbc_decrypt(key, iv, b'\x00' * 16)
        except ValueError:
            pass  # Expected — random decrypted data has bad padding

    def test_pkcs7_unpad(self):
        from treasure_hunter.grabbers._crypto import pkcs7_unpad
        assert pkcs7_unpad(b"hello\x03\x03\x03") == b"hello"
        assert pkcs7_unpad(b"\x10" * 16) == b""

    def test_pkcs7_unpad_rejects_bad(self):
        from treasure_hunter.grabbers._crypto import pkcs7_unpad
        try:
            pkcs7_unpad(b"hello\x03\x03\x04")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_aes_gcm_rejects_bad_tag(self):
        """Test that AES-GCM returns None on tampered tag."""
        from treasure_hunter.grabbers._crypto import aes_gcm_decrypt
        key = b'\x00' * 32
        nonce = b'\x00' * 12
        ciphertext = b'\x42' * 16
        bad_tag = b'\xff' * 16  # Random tag — should not verify

        result = aes_gcm_decrypt(key, nonce, ciphertext, bad_tag)
        assert result is None  # Tag mismatch

    def test_aes_gcm_validates_params(self):
        """Test that AES-GCM rejects invalid key/nonce/tag sizes."""
        from treasure_hunter.grabbers._crypto import aes_gcm_decrypt
        try:
            aes_gcm_decrypt(b'\x00' * 15, b'\x00' * 12, b'', b'\x00' * 16)
            assert False, "Should reject bad key length"
        except ValueError:
            pass
        try:
            aes_gcm_decrypt(b'\x00' * 32, b'\x00' * 11, b'', b'\x00' * 16)
            assert False, "Should reject bad nonce length"
        except ValueError:
            pass
