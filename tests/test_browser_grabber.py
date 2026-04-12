"""Tests for BrowserGrabber with fixture SQLite databases."""

import json
import sqlite3
import tempfile
from pathlib import Path

from treasure_hunter.grabbers.browser import BrowserGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str) -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    gctx.appdata_local = home
    gctx.appdata_roaming = home
    return gctx


def _create_chrome_login_db(db_path: str, entries: list[tuple[str, str, bytes]]):
    """Create a minimal Chrome Login Data SQLite for testing."""
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE logins (
        origin_url TEXT NOT NULL DEFAULT '',
        action_url TEXT NOT NULL DEFAULT '',
        username_element TEXT NOT NULL DEFAULT '',
        username_value TEXT NOT NULL DEFAULT '',
        password_element TEXT NOT NULL DEFAULT '',
        password_value BLOB NOT NULL DEFAULT '',
        signon_realm TEXT NOT NULL DEFAULT '',
        date_created INTEGER NOT NULL DEFAULT 0
    )""")
    for url, username, password_blob in entries:
        conn.execute(
            "INSERT INTO logins (origin_url, username_value, password_value) VALUES (?, ?, ?)",
            (url, username, password_blob),
        )
    conn.commit()
    conn.close()


def _create_chrome_cookies_db(db_path: str, cookies: list[tuple[str, str, str]]):
    """Create a minimal Chrome Cookies SQLite for testing."""
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE cookies (
        host_key TEXT NOT NULL DEFAULT '',
        name TEXT NOT NULL DEFAULT '',
        path TEXT NOT NULL DEFAULT '/',
        encrypted_value BLOB NOT NULL DEFAULT '',
        expires_utc INTEGER NOT NULL DEFAULT 0
    )""")
    for host, name, path in cookies:
        conn.execute(
            "INSERT INTO cookies (host_key, name, path) VALUES (?, ?, ?)",
            (host, name, path),
        )
    conn.commit()
    conn.close()


class TestChromiumLoginExtraction:
    def test_extracts_logins_from_sqlite(self):
        with tempfile.TemporaryDirectory() as home:
            # Create Chrome profile structure
            profile_dir = Path(home) / "Google" / "Chrome" / "User Data" / "Default"
            profile_dir.mkdir(parents=True)

            _create_chrome_login_db(
                str(profile_dir / "Login Data"),
                [
                    ("https://example.com", "admin", b"encrypted_blob_1"),
                    ("https://mail.google.com", "user@gmail.com", b"encrypted_blob_2"),
                    ("https://internal.corp", "deploy", b"v10" + b"\x00" * 28),
                ],
            )

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            chrome_creds = [c for c in result.credentials
                           if c.target_application == "Chrome" and c.credential_type == "password"]
            assert len(chrome_creds) == 3
            assert chrome_creds[0].url == "https://example.com"
            assert chrome_creds[0].username == "admin"
            # Without DPAPI, passwords stay encrypted
            assert chrome_creds[0].encrypted_value or chrome_creds[0].decrypted_value == ""

    def test_handles_empty_login_db(self):
        with tempfile.TemporaryDirectory() as home:
            profile_dir = Path(home) / "Google" / "Chrome" / "User Data" / "Default"
            profile_dir.mkdir(parents=True)
            _create_chrome_login_db(str(profile_dir / "Login Data"), [])

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            chrome_pass = [c for c in result.credentials
                          if c.target_application == "Chrome" and c.credential_type == "password"]
            assert len(chrome_pass) == 0


class TestChromiumCookieExtraction:
    def test_extracts_session_cookies(self):
        with tempfile.TemporaryDirectory() as home:
            profile_dir = Path(home) / "Google" / "Chrome" / "User Data" / "Default" / "Network"
            profile_dir.mkdir(parents=True)

            _create_chrome_cookies_db(
                str(profile_dir / "Cookies"),
                [
                    (".google.com", "SID", "/"),
                    (".google.com", "HSID", "/"),
                    (".example.com", "tracking_id", "/"),  # Not interesting
                    (".github.com", "session", "/"),
                ],
            )

            # Also need Login Data for the profile to be recognized
            default_dir = Path(home) / "Google" / "Chrome" / "User Data" / "Default"
            _create_chrome_login_db(str(default_dir / "Login Data"), [])

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            cookies = [c for c in result.credentials if c.credential_type == "cookie"]
            cookie_names = {c.username for c in cookies}
            # Should find SID, HSID, session but NOT tracking_id
            assert "SID" in cookie_names
            assert "session" in cookie_names
            assert "tracking_id" not in cookie_names


class TestFirefoxExtraction:
    def test_extracts_encrypted_logins(self):
        with tempfile.TemporaryDirectory() as home:
            profile_dir = Path(home) / "Mozilla" / "Firefox" / "Profiles" / "abc123.default"
            profile_dir.mkdir(parents=True)

            (profile_dir / "logins.json").write_text(json.dumps({
                "logins": [
                    {
                        "hostname": "https://example.com",
                        "encryptedUsername": "MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwc",
                        "encryptedPassword": "MDoEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwc",
                        "formSubmitURL": "https://example.com/login",
                    },
                    {
                        "hostname": "https://intranet.corp",
                        "encryptedUsername": "base64encrypteduser",
                        "encryptedPassword": "base64encryptedpass",
                    },
                ]
            }))

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            ff_creds = [c for c in result.credentials if c.target_application == "Firefox"]
            assert len(ff_creds) == 2
            assert ff_creds[0].url == "https://example.com"
            assert len(ff_creds[0].encrypted_value) > 0
            assert "NSS-encrypted" in ff_creds[0].notes

    def test_handles_missing_logins_json(self):
        with tempfile.TemporaryDirectory() as home:
            profile_dir = Path(home) / "Mozilla" / "Firefox" / "Profiles" / "abc.default"
            profile_dir.mkdir(parents=True)
            # No logins.json

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)
            ff_creds = [c for c in result.credentials if c.target_application == "Firefox"]
            assert len(ff_creds) == 0


class TestMultipleBrowsers:
    def test_scans_all_installed_browsers(self):
        with tempfile.TemporaryDirectory() as home:
            # Chrome
            chrome_profile = Path(home) / "Google" / "Chrome" / "User Data" / "Default"
            chrome_profile.mkdir(parents=True)
            _create_chrome_login_db(str(chrome_profile / "Login Data"), [
                ("https://chrome-site.com", "chrome_user", b"enc1"),
            ])

            # Edge
            edge_profile = Path(home) / "Microsoft" / "Edge" / "User Data" / "Default"
            edge_profile.mkdir(parents=True)
            _create_chrome_login_db(str(edge_profile / "Login Data"), [
                ("https://edge-site.com", "edge_user", b"enc2"),
            ])

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            apps = {c.target_application for c in result.credentials if c.credential_type == "password"}
            assert "Chrome" in apps
            assert "Edge" in apps


class TestPreflightCheck:
    def test_false_when_no_browsers(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = BrowserGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is False

    def test_true_when_chrome_exists(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "Google" / "Chrome" / "User Data").mkdir(parents=True)
            grabber = BrowserGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is True


class TestFindingsGenerated:
    def test_creates_findings_with_score(self):
        with tempfile.TemporaryDirectory() as home:
            profile = Path(home) / "Google" / "Chrome" / "User Data" / "Default"
            profile.mkdir(parents=True)
            _create_chrome_login_db(str(profile / "Login Data"), [
                ("https://a.com", "user1", b"enc"),
                ("https://b.com", "user2", b"enc"),
            ])

            grabber = BrowserGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.findings) >= 1
            assert "[browser]" in result.findings[0].signals[0].description
