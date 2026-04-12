"""Tests for MessagingGrabber with fake LevelDB files."""

import tempfile
from pathlib import Path

from treasure_hunter.grabbers.messaging import MessagingGrabber
from treasure_hunter.grabbers._leveldb import extract_strings_from_leveldb
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str) -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    gctx.appdata_roaming = home
    return gctx


class TestLevelDBParser:
    def test_extracts_strings_from_log_file(self):
        with tempfile.TemporaryDirectory() as db_dir:
            # Create a fake .log file with embedded token
            token = b"xoxb-1234567890-ABCDEFGHIJKLMNOP"
            data = b"\x00" * 50 + token + b"\x00" * 50
            (Path(db_dir) / "000003.log").write_bytes(data)

            import re
            results = extract_strings_from_leveldb(
                db_dir,
                min_length=20,
                patterns=[re.compile(r"xox[bprs]-[0-9]{10,}-[0-9a-zA-Z]+")],
            )
            assert len(results) == 1
            assert results[0] == token.decode()

    def test_deduplicates(self):
        with tempfile.TemporaryDirectory() as db_dir:
            token = b"xoxb-1234567890-ABCDEFGHIJKLMNOP"
            data = token + b"\x00" * 10 + token
            (Path(db_dir) / "000003.log").write_bytes(data)

            import re
            results = extract_strings_from_leveldb(
                db_dir, min_length=20,
                patterns=[re.compile(r"xox[bprs]-[0-9]{10,}-[0-9a-zA-Z]+")],
            )
            assert len(results) == 1

    def test_reads_ldb_files(self):
        with tempfile.TemporaryDirectory() as db_dir:
            token = b"MjQwNzc3MDk3MDU4ODI2NzUy.AAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBB"
            data = b"\x00" * 20 + token + b"\x00" * 20
            (Path(db_dir) / "000001.ldb").write_bytes(data)

            import re
            results = extract_strings_from_leveldb(
                db_dir, min_length=20,
                patterns=[re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}")],
            )
            assert len(results) == 1

    def test_skips_non_leveldb_files(self):
        with tempfile.TemporaryDirectory() as db_dir:
            (Path(db_dir) / "readme.txt").write_bytes(b"xoxb-1234567890-ABCDEFGHIJKLMNOP")

            import re
            results = extract_strings_from_leveldb(
                db_dir, min_length=20,
                patterns=[re.compile(r"xox[bprs]-[0-9]{10,}-[0-9a-zA-Z]+")],
            )
            assert len(results) == 0  # .txt not read


class TestMessagingGrabberSlack:
    def test_extracts_slack_tokens(self):
        with tempfile.TemporaryDirectory() as home:
            slack_dir = Path(home) / "Slack" / "Local Storage" / "leveldb"
            slack_dir.mkdir(parents=True)

            token = b"xoxc-1234567890123-1234567890-abcdef"
            (slack_dir / "000003.log").write_bytes(b"\x00" * 10 + token + b"\x00" * 10)

            grabber = MessagingGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            slack_creds = [c for c in result.credentials if c.target_application == "Slack"]
            assert len(slack_creds) == 1
            assert slack_creds[0].decrypted_value.startswith("xoxc-")


class TestMessagingGrabberDiscord:
    def test_extracts_discord_tokens(self):
        with tempfile.TemporaryDirectory() as home:
            discord_dir = Path(home) / "discord" / "Local Storage" / "leveldb"
            discord_dir.mkdir(parents=True)

            # Fake Discord token format
            token = b"MjQwNzc3MDk3MDU4ODI2NzUy.YBcPGA.BBBBBBBBBBBBBBBBBBBBBBBBBBB"
            (discord_dir / "000003.log").write_bytes(b"\x00" * 10 + token + b"\x00" * 10)

            grabber = MessagingGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            discord_creds = [c for c in result.credentials if c.target_application == "Discord"]
            assert len(discord_creds) == 1


class TestPreflightCheck:
    def test_false_when_no_apps(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = MessagingGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is False

    def test_true_when_slack_exists(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "Slack" / "Local Storage" / "leveldb").mkdir(parents=True)
            grabber = MessagingGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is True
