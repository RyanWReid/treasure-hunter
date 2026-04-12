"""Tests for GitGrabber with fixture files."""

import os
import tempfile
from pathlib import Path

from treasure_hunter.grabbers.git_cred import GitGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


def _make_context(home: str) -> GrabberContext:
    ctx = ScanContext(["/tmp"])
    gctx = GrabberContext.from_scan_context(ctx)
    gctx.user_profile_path = home
    return gctx


class TestGitCredentials:
    def test_parses_plaintext_credentials(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".git-credentials").write_text(
                "https://user1:ghp_ABCDtoken123@github.com\n"
                "https://deploy:glpat-secretkey@gitlab.com/group/repo\n"
            )

            grabber = GitGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert result.status == GrabberStatus.COMPLETED
            assert len(result.credentials) == 2

            assert result.credentials[0].username == "user1"
            assert result.credentials[0].decrypted_value == "ghp_ABCDtoken123"
            assert "github.com" in result.credentials[0].url

            assert result.credentials[1].username == "deploy"
            assert result.credentials[1].decrypted_value == "glpat-secretkey"

    def test_skips_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".git-credentials").write_text(
                "# comment\n"
                "\n"
                "https://user:pass@host.com\n"
            )

            grabber = GitGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.credentials) == 1

    def test_generates_findings(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".git-credentials").write_text(
                "https://user:pass@github.com\n"
            )

            grabber = GitGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            assert len(result.findings) >= 1
            assert "[git_cred]" in result.findings[0].signals[0].description
            assert result.findings[0].total_score >= 75


class TestGitConfig:
    def test_extracts_embedded_remote_creds(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".gitconfig").write_text(
                "[user]\n"
                "    name = Test User\n"
                "    email = test@example.com\n"
                "[credential]\n"
                "    helper = store\n"
                "[remote]\n"
                "    url = https://admin:SuperSecret123@github.com/org/private-repo.git\n"
            )

            grabber = GitGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            creds_with_pass = [c for c in result.credentials if c.decrypted_value]
            assert len(creds_with_pass) >= 1
            assert creds_with_pass[0].username == "admin"
            assert creds_with_pass[0].decrypted_value == "SuperSecret123"

    def test_extracts_extraheader_token(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".gitconfig").write_text(
                "[http]\n"
                "    extraheader = AUTHORIZATION: bearer ghp_MySecretTokenValue12345678\n"
            )

            grabber = GitGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            token_creds = [c for c in result.credentials if c.credential_type == "token"]
            assert len(token_creds) >= 1
            assert "ghp_MySecretTokenValue12345678" in token_creds[0].decrypted_value


class TestGitRepoScan:
    def test_finds_embedded_creds_in_repo_config(self):
        with tempfile.TemporaryDirectory() as home:
            # Create a fake repo structure
            repo_dir = Path(home) / "Projects" / "my-app" / ".git"
            repo_dir.mkdir(parents=True)
            (repo_dir / "config").write_text(
                "[core]\n"
                "    repositoryformatversion = 0\n"
                "[remote \"origin\"]\n"
                "    url = https://deployer:ghp_deploy_token@github.com/corp/internal.git\n"
                "    fetch = +refs/heads/*:refs/remotes/origin/*\n"
            )

            grabber = GitGrabber()
            gctx = _make_context(home)
            result = grabber.run(gctx)

            repo_creds = [c for c in result.credentials if "deployer" in c.username]
            assert len(repo_creds) >= 1
            assert repo_creds[0].decrypted_value == "ghp_deploy_token"
            assert "internal.git" in repo_creds[0].url

    def test_handles_no_dev_dirs(self):
        with tempfile.TemporaryDirectory() as home:
            # Empty home, no dev directories
            grabber = GitGrabber()
            gctx = _make_context(home)
            # Should not crash
            result = grabber.run(gctx)
            assert result.status == GrabberStatus.COMPLETED


class TestPreflightCheck:
    def test_false_when_nothing_exists(self):
        with tempfile.TemporaryDirectory() as home:
            grabber = GitGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is False

    def test_true_when_git_credentials_exists(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / ".git-credentials").write_text("https://x:y@z.com\n")
            grabber = GitGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is True

    def test_true_when_dev_dir_exists(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home) / "Projects").mkdir()
            grabber = GitGrabber()
            gctx = _make_context(home)
            assert grabber.preflight_check(gctx) is True
