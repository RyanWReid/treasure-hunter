"""Tests for HistoryGrabber."""

import tempfile
from pathlib import Path

from treasure_hunter.grabbers.history import HistoryGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str) -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    gctx.appdata_roaming = home
    return gctx


class TestHistoryGrabber:
    def test_finds_password_in_bash_history(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".bash_history").write_text(
                "ls -la\n"
                "cd /var/www\n"
                "mysql -u admin -p SuperSecret123\n"
                "cat /etc/hosts\n"
                "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n"
                "echo hello\n"
            )

            grabber = HistoryGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) >= 2  # mysql + export
            notes = " ".join(c.notes for c in result.credentials)
            assert "mysql" in notes
            assert "AWS_SECRET_ACCESS_KEY" in notes

    def test_finds_password_in_zsh_history(self):
        with tempfile.TemporaryDirectory() as home:
            # Zsh history has timestamp format
            (Path(home) / ".zsh_history").write_text(
                ": 1234567890:0;ssh admin@10.0.0.1\n"
                ": 1234567891:0;docker login -u user -p token123 registry.io\n"
                ": 1234567892:0;ls -la\n"
            )

            grabber = HistoryGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.credentials) >= 1
            notes = " ".join(c.notes for c in result.credentials)
            assert "docker" in notes or "ssh" in notes

    def test_deduplicates_identical_lines(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".bash_history").write_text(
                "mysql -u admin -p secret\n" * 10
            )

            grabber = HistoryGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.credentials) == 1

    def test_skips_benign_commands(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".bash_history").write_text(
                "ls -la\n"
                "cd /home\n"
                "git status\n"
                "python3 main.py\n"
            )

            grabber = HistoryGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.credentials) == 0

    def test_generates_findings(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".bash_history").write_text(
                "curl -u admin:password123 https://api.internal\n"
            )

            grabber = HistoryGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.findings) >= 1
            assert "[history]" in result.findings[0].signals[0].description

    def test_preflight_false_when_no_history(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = HistoryGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is False
