"""Tests for the lateral movement module."""

from __future__ import annotations

import threading
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from treasure_hunter.lateral import (
    LateralConfig,
    LateralScanner,
    LockoutTracker,
    _build_credential_matrix,
    _extract_host,
    _filter_usable_credentials,
)
from treasure_hunter.models import (
    CredentialTestResult,
    LateralAuthStatus,
    LateralResult,
    LateralTarget,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _make_cred(
    username="admin",
    password="P@ss",
    cred_type="password",
    source="browser",
    url="",
    app="Chrome",
):
    """Build a minimal ExtractedCredential-like object."""
    from treasure_hunter.grabbers.models import ExtractedCredential

    return ExtractedCredential(
        source_module=source,
        credential_type=cred_type,
        target_application=app,
        url=url,
        username=username,
        decrypted_value=password,
    )


# ===========================================================================
# LockoutTracker
# ===========================================================================

class TestLockoutTracker:
    def test_initial_state_not_locked(self):
        tracker = LockoutTracker(max_failures=3)
        assert not tracker.is_locked("admin")

    def test_locks_after_max_failures(self):
        tracker = LockoutTracker(max_failures=2)
        tracker.record_failure("admin")
        assert not tracker.is_locked("admin")
        tracker.record_failure("admin")
        assert tracker.is_locked("admin")

    def test_success_resets_counter(self):
        tracker = LockoutTracker(max_failures=2)
        tracker.record_failure("admin")
        tracker.record_failure("admin")
        assert tracker.is_locked("admin")
        tracker.record_success("admin")
        assert not tracker.is_locked("admin")

    def test_different_users_independent(self):
        tracker = LockoutTracker(max_failures=1)
        tracker.record_failure("alice")
        assert tracker.is_locked("alice")
        assert not tracker.is_locked("bob")

    def test_total_skips_increments(self):
        tracker = LockoutTracker(max_failures=1)
        tracker.record_failure("admin")
        tracker.is_locked("admin")  # skip 1
        tracker.is_locked("admin")  # skip 2
        assert tracker.total_skips == 2

    def test_thread_safety(self):
        tracker = LockoutTracker(max_failures=100)
        errors = []

        def hammer():
            try:
                for _ in range(50):
                    tracker.record_failure("user")
                    tracker.is_locked("user")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ===========================================================================
# LateralConfig
# ===========================================================================

class TestLateralConfig:
    def test_defaults(self):
        cfg = LateralConfig()
        assert not cfg.enabled
        assert cfg.target_spec == "auto"
        assert cfg.max_hosts == 10
        assert cfg.max_failures_per_account == 3
        assert cfg.max_hop_depth == 1
        assert cfg.current_depth == 0
        assert cfg.auto_cleanup is True

    def test_kill_switch(self):
        cfg = LateralConfig()
        assert not cfg.kill_switch.is_set()
        cfg.kill_switch.set()
        assert cfg.kill_switch.is_set()

    def test_whitelist_blacklist(self):
        cfg = LateralConfig(
            host_whitelist=["10.0.0.1"],
            host_blacklist=["10.0.0.2"],
        )
        assert "10.0.0.1" in cfg.host_whitelist
        assert "10.0.0.2" in cfg.host_blacklist


# ===========================================================================
# _filter_usable_credentials
# ===========================================================================

class TestFilterUsableCredentials:
    def test_password_type_only(self):
        creds = [
            _make_cred(cred_type="password"),
            _make_cred(cred_type="token", username="bot", password="tok123"),
            _make_cred(cred_type="cookie", username="u", password="v"),
            _make_cred(cred_type="key", username="k", password="data"),
        ]
        result = _filter_usable_credentials(creds)
        assert len(result) == 1
        assert result[0].credential_type == "password"

    def test_requires_username_and_decrypted_value(self):
        creds = [
            _make_cred(username="", password="pass"),
            _make_cred(username="admin", password=""),
            _make_cred(username="admin", password="pass"),
        ]
        result = _filter_usable_credentials(creds)
        assert len(result) == 1
        assert result[0].username == "admin"

    def test_deduplicates(self):
        creds = [
            _make_cred(username="admin", password="pass1"),
            _make_cred(username="admin", password="pass1"),
            _make_cred(username="Admin", password="pass1"),  # case-insensitive
        ]
        result = _filter_usable_credentials(creds)
        assert len(result) == 1

    def test_different_passwords_kept(self):
        creds = [
            _make_cred(username="admin", password="pass1"),
            _make_cred(username="admin", password="pass2"),
        ]
        result = _filter_usable_credentials(creds)
        assert len(result) == 2

    def test_empty_list(self):
        assert _filter_usable_credentials([]) == []


# ===========================================================================
# _build_credential_matrix
# ===========================================================================

class TestBuildCredentialMatrix:
    def test_targeted_pairing(self):
        creds = [
            _make_cred(username="admin", password="p1", url="https://10.0.0.5/login"),
        ]
        hosts = ["10.0.0.5", "10.0.0.6"]
        pairs = _build_credential_matrix(creds, hosts)
        # 10.0.0.5 should appear first (targeted)
        assert pairs[0][0] == "10.0.0.5"

    def test_general_spray(self):
        creds = [
            _make_cred(username="admin", password="p1"),
        ]
        hosts = ["10.0.0.5", "10.0.0.6"]
        pairs = _build_credential_matrix(creds, hosts)
        tested_hosts = [h for h, _ in pairs]
        assert "10.0.0.5" in tested_hosts
        assert "10.0.0.6" in tested_hosts

    def test_deduplication(self):
        creds = [
            _make_cred(username="admin", password="p1", url="https://10.0.0.5"),
        ]
        hosts = ["10.0.0.5"]
        pairs = _build_credential_matrix(creds, hosts)
        # Should not have duplicate (10.0.0.5, admin, p1)
        assert len(pairs) == 1

    def test_multiple_creds_multiple_hosts(self):
        creds = [
            _make_cred(username="admin", password="p1"),
            _make_cred(username="svc", password="p2"),
        ]
        hosts = ["h1", "h2"]
        pairs = _build_credential_matrix(creds, hosts)
        # 2 creds x 2 hosts = 4 pairs
        assert len(pairs) == 4


# ===========================================================================
# _extract_host
# ===========================================================================

class TestExtractHost:
    def test_simple_url(self):
        assert _extract_host("https://10.0.0.5/login") == "10.0.0.5"

    def test_with_port(self):
        assert _extract_host("http://server.corp.local:8080/api") == "server.corp.local"

    def test_with_auth(self):
        assert _extract_host("ftp://user:pass@files.corp.local/data") == "files.corp.local"

    def test_bare_hostname(self):
        assert _extract_host("myserver") == "myserver"


# ===========================================================================
# CredentialTestResult model
# ===========================================================================

class TestCredentialTestResult:
    def test_to_dict(self):
        r = CredentialTestResult(
            host="10.0.0.5",
            share="C$",
            username="admin",
            credential_source="browser",
            status=LateralAuthStatus.SUCCESS,
            error_code=0,
            timestamp=datetime(2026, 4, 13, 12, 0, 0),
        )
        d = r.to_dict()
        assert d["host"] == "10.0.0.5"
        assert d["status"] == "success"
        assert d["error_code"] == 0

    def test_status_values(self):
        assert LateralAuthStatus.SUCCESS.value == "success"
        assert LateralAuthStatus.LOGON_FAILURE.value == "logon_failure"
        assert LateralAuthStatus.SKIPPED_LOCKOUT.value == "skipped_lockout"


# ===========================================================================
# LateralTarget model
# ===========================================================================

class TestLateralTarget:
    def test_to_dict_basic(self):
        t = LateralTarget(host="10.0.0.5", port_open=True)
        d = t.to_dict()
        assert d["host"] == "10.0.0.5"
        assert d["port_open"] is True
        assert d["compromised"] is False

    def test_to_dict_with_auth(self):
        t = LateralTarget(
            host="10.0.0.5",
            port_open=True,
            compromised=True,
            auth_results=[
                CredentialTestResult(
                    host="10.0.0.5", share="C$", username="admin",
                    credential_source="browser",
                    status=LateralAuthStatus.SUCCESS,
                ),
            ],
        )
        d = t.to_dict()
        assert d["auth_attempts"] == 1
        assert d["auth_successes"] == 1


# ===========================================================================
# LateralResult model
# ===========================================================================

class TestLateralResult:
    def test_to_dict(self):
        r = LateralResult(
            started_at=datetime(2026, 4, 13, 12, 0, 0),
            completed_at=datetime(2026, 4, 13, 12, 1, 0),
            targets_discovered=5,
            targets_compromised=2,
            credentials_tested=10,
            auth_successes=2,
            auth_failures=8,
        )
        d = r.to_dict()
        assert d["targets_discovered"] == 5
        assert d["targets_compromised"] == 2

    def test_empty_result(self):
        r = LateralResult(started_at=datetime.now())
        d = r.to_dict()
        assert d["targets_discovered"] == 0
        assert d["targets"] == []


# ===========================================================================
# LateralScanner (mocked SMB)
# ===========================================================================

class TestLateralScanner:
    def _make_scanner(self, creds=None, target_spec="10.0.0.5", **kwargs):
        if creds is None:
            creds = [_make_cred(username="admin", password="pass")]
        config = LateralConfig(
            enabled=True,
            target_spec=target_spec,
            attempt_delay=0,  # no delay in tests
            **kwargs,
        )
        return LateralScanner(config=config, credentials=creds)

    def test_no_credentials(self):
        scanner = self._make_scanner(creds=[])
        result = scanner.run()
        assert result.targets_discovered == 0

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=[])
    def test_no_hosts(self, mock_enum):
        scanner = self._make_scanner()
        result = scanner.run()
        assert result.targets_discovered == 0

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["10.0.0.5"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=False)
    def test_host_unreachable(self, mock_port, mock_enum):
        scanner = self._make_scanner()
        result = scanner.run()
        assert result.targets_discovered == 0

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["10.0.0.5"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=True)
    @patch("treasure_hunter.lateral._connect_smb_share", return_value=(1326, ""))
    def test_auth_failure(self, mock_connect, mock_port, mock_enum):
        scanner = self._make_scanner()
        result = scanner.run()
        assert result.targets_discovered == 1
        assert result.targets_compromised == 0
        assert result.auth_failures > 0

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["10.0.0.5"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=True)
    @patch("treasure_hunter.lateral._connect_smb_share", return_value=(0, "\\\\10.0.0.5\\C$"))
    @patch("treasure_hunter.lateral._disconnect_smb_share", return_value=True)
    @patch("treasure_hunter.lateral.LateralScanner._scan_remote_host", return_value=None)
    def test_auth_success(self, mock_scan, mock_disconnect, mock_connect, mock_port, mock_enum):
        scanner = self._make_scanner()
        result = scanner.run()
        assert result.targets_compromised == 1
        assert result.auth_successes >= 1
        mock_scan.assert_called_once()
        mock_disconnect.assert_called()

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["h1", "h2", "h3"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=True)
    @patch("treasure_hunter.lateral._connect_smb_share", return_value=(1326, ""))
    def test_respects_max_hosts(self, mock_connect, mock_port, mock_enum):
        scanner = self._make_scanner(max_hosts=2)
        result = scanner.run()
        assert result.targets_discovered <= 2

    def test_respects_kill_switch(self):
        config = LateralConfig(enabled=True, attempt_delay=0)
        config.kill_switch.set()  # pre-set
        scanner = LateralScanner(
            config=config,
            credentials=[_make_cred()],
        )
        result = scanner.run()
        assert result.targets_discovered == 0

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["h1", "h2"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=True)
    @patch("treasure_hunter.lateral._connect_smb_share", return_value=(1326, ""))
    def test_host_whitelist(self, mock_connect, mock_port, mock_enum):
        scanner = self._make_scanner(host_whitelist=["h1"])
        result = scanner.run()
        # Only h1 should be tested
        tested_hosts = {t.host for t in result.targets}
        assert "h1" in tested_hosts
        assert "h2" not in tested_hosts

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["h1", "h2"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=True)
    @patch("treasure_hunter.lateral._connect_smb_share", return_value=(1326, ""))
    def test_host_blacklist(self, mock_connect, mock_port, mock_enum):
        scanner = self._make_scanner(host_blacklist=["h2"])
        result = scanner.run()
        tested_hosts = {t.host for t in result.targets}
        assert "h1" in tested_hosts
        assert "h2" not in tested_hosts

    @patch("treasure_hunter.lateral.enumerate_network_targets", return_value=["10.0.0.5"])
    @patch("treasure_hunter.lateral._is_port_open", return_value=True)
    @patch("treasure_hunter.lateral._connect_smb_share", return_value=(1326, ""))
    def test_lockout_skips(self, mock_connect, mock_port, mock_enum):
        creds = [
            _make_cred(username="admin", password=f"p{i}") for i in range(5)
        ]
        scanner = self._make_scanner(
            creds=creds,
            max_failures_per_account=2,
        )
        result = scanner.run()
        # After 2 failures for "admin", remaining attempts should be skipped
        assert result.lockout_skips > 0

    def test_depth_limit(self):
        config = LateralConfig(
            enabled=True,
            max_hop_depth=1,
            current_depth=1,  # already at max
            attempt_delay=0,
        )
        scanner = LateralScanner(
            config=config,
            credentials=[_make_cred()],
        )
        result = scanner.run()
        assert result.targets_discovered == 0


# ===========================================================================
# Reporter integration
# ===========================================================================

class TestReporterEmitMethods:
    def test_emit_lateral_attempt(self):
        from treasure_hunter.reporter import StreamingReporter
        reporter = StreamingReporter("/dev/null", "test", [])
        # Should not raise even when not started
        reporter.emit_lateral_attempt({"host": "10.0.0.5"})

    def test_emit_lateral_success(self):
        from treasure_hunter.reporter import StreamingReporter
        reporter = StreamingReporter("/dev/null", "test", [])
        reporter.emit_lateral_success({"host": "10.0.0.5"})

    def test_emit_lateral_summary(self):
        from treasure_hunter.reporter import StreamingReporter
        reporter = StreamingReporter("/dev/null", "test", [])
        reporter.emit_lateral_summary({"targets_discovered": 0})


# ===========================================================================
# CLI flags
# ===========================================================================

class TestCLILateralFlags:
    def test_lateral_flag_exists(self):
        from treasure_hunter.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--lateral"])
        assert args.lateral is True

    def test_lateral_targets_default(self):
        from treasure_hunter.cli import create_parser
        parser = create_parser()
        args = parser.parse_args([])
        assert args.lateral_targets == "auto"

    def test_lateral_max_hosts(self):
        from treasure_hunter.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--lateral", "--lateral-max-hosts", "5"])
        assert args.lateral_max_hosts == 5

    def test_lateral_max_failures(self):
        from treasure_hunter.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--lateral", "--lateral-max-failures", "2"])
        assert args.lateral_max_failures == 2

    def test_lateral_depth(self):
        from treasure_hunter.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--lateral", "--lateral-depth", "3"])
        assert args.lateral_depth == 3

    def test_lateral_timeout(self):
        from treasure_hunter.cli import create_parser
        parser = create_parser()
        args = parser.parse_args(["--lateral", "--lateral-timeout", "20"])
        assert args.lateral_timeout == 20
