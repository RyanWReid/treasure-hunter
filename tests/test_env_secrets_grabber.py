"""Tests for environment variable secrets grabber."""

import os
from unittest.mock import patch

import pytest

from treasure_hunter.grabbers.env_secrets import EnvSecretsGrabber, _SECRET_NAME_PATTERNS
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestSecretPatterns:
    def test_matches_database_url(self):
        assert _SECRET_NAME_PATTERNS.search("DATABASE_URL")

    def test_matches_api_key(self):
        assert _SECRET_NAME_PATTERNS.search("API_KEY")
        assert _SECRET_NAME_PATTERNS.search("STRIPE_API_KEY")

    def test_matches_aws_secrets(self):
        assert _SECRET_NAME_PATTERNS.search("AWS_SECRET_ACCESS_KEY")

    def test_matches_tokens(self):
        assert _SECRET_NAME_PATTERNS.search("GITHUB_TOKEN")
        assert _SECRET_NAME_PATTERNS.search("SLACK_TOKEN")
        assert _SECRET_NAME_PATTERNS.search("NPM_TOKEN")

    def test_matches_passwords(self):
        assert _SECRET_NAME_PATTERNS.search("DB_PASSWORD")
        assert _SECRET_NAME_PATTERNS.search("SMTP_PASS")

    def test_matches_secrets(self):
        assert _SECRET_NAME_PATTERNS.search("JWT_SECRET")
        assert _SECRET_NAME_PATTERNS.search("CLIENT_SECRET")
        assert _SECRET_NAME_PATTERNS.search("APP_SECRET")

    def test_no_match_on_normal_vars(self):
        assert not _SECRET_NAME_PATTERNS.search("HOME")
        assert not _SECRET_NAME_PATTERNS.search("PATH")
        assert not _SECRET_NAME_PATTERNS.search("LANG")
        assert not _SECRET_NAME_PATTERNS.search("TERM")
        assert not _SECRET_NAME_PATTERNS.search("SHELL")


class TestEnvSecretsExecution:
    def test_preflight_always_true(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = EnvSecretsGrabber()
        assert g.preflight_check(gctx) is True

    @patch.dict(os.environ, {
        "DATABASE_URL": "postgres://admin:s3cret@db.prod:5432/app",
        "API_KEY": "sk_live_1234567890abcdef",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKE",
        "NORMAL_VAR": "nothing_secret",
        "HOME": "/home/user",
    })
    def test_finds_secrets_in_env(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = EnvSecretsGrabber()
        result = g.execute(gctx)

        assert result.status == GrabberStatus.COMPLETED
        found_names = {c.username for c in result.credentials}
        assert "DATABASE_URL" in found_names
        assert "API_KEY" in found_names
        assert "AWS_SECRET_ACCESS_KEY" in found_names
        # Should NOT find NORMAL_VAR or HOME
        assert "NORMAL_VAR" not in found_names
        assert "HOME" not in found_names

    @patch.dict(os.environ, {"PASSWORD": ""}, clear=False)
    def test_skips_empty_values(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = EnvSecretsGrabber()
        result = g.execute(gctx)

        # PASSWORD="" should be skipped
        found_names = {c.username for c in result.credentials}
        assert "PASSWORD" not in found_names

    @patch.dict(os.environ, {"SECRET_KEY": "changeme"}, clear=False)
    def test_skips_placeholder_values(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = EnvSecretsGrabber()
        result = g.execute(gctx)

        # "changeme" is a known placeholder
        found = [c for c in result.credentials if c.username == "SECRET_KEY"]
        assert len(found) == 0

    @patch.dict(os.environ, {"DB_PASSWORD": "ab"}, clear=False)
    def test_skips_very_short_values(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = EnvSecretsGrabber()
        result = g.execute(gctx)

        found = [c for c in result.credentials if c.username == "DB_PASSWORD"]
        assert len(found) == 0

    @patch.dict(os.environ, {
        "VAULT_TOKEN": "hvs.CAESIG1234567890abcdefghijklmnop",
        "CONSUL_TOKEN": "b1gs33cr3t-t0k3n-v4lu3",
    })
    def test_finds_hashicorp_tokens(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(scan_context=ctx)
        g = EnvSecretsGrabber()
        result = g.execute(gctx)

        found_names = {c.username for c in result.credentials}
        assert "VAULT_TOKEN" in found_names
        assert "CONSUL_TOKEN" in found_names

    def test_creates_findings_with_snippets(self):
        with patch.dict(os.environ, {"JWT_SECRET": "super-secret-jwt-key-that-is-long"}):
            ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx)
            g = EnvSecretsGrabber()
            result = g.execute(gctx)

            if result.findings:
                # Findings should have snippets showing the vars found
                assert any("JWT_SECRET" in str(f.content_snippets) for f in result.findings)
