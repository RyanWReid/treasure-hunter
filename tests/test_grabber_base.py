"""Tests for grabber module base class, registry, and context."""

import platform
import tempfile
from pathlib import Path

from treasure_hunter.grabbers import (
    ExtractedCredential,
    GrabberContext,
    GrabberModule,
    GrabberRegistry,
    GrabberResult,
    GrabberStatus,
    PrivilegeLevel,
)
from treasure_hunter.scanner import ScanContext


# --- Concrete test grabber for registry testing ---

class _FakeGrabber(GrabberModule):
    name = "fake_grabber"
    description = "Test grabber for unit tests"
    min_privilege = PrivilegeLevel.USER
    supported_platforms = ("Darwin", "Linux", "Windows")
    default_enabled = True

    def preflight_check(self, context):
        return True

    def execute(self, context):
        cred = ExtractedCredential(
            source_module=self.name,
            credential_type="password",
            target_application="TestApp",
            url="https://example.com",
            username="testuser",
            decrypted_value="hunter2",
        )
        finding = self.make_finding(
            file_path="/fake/path.db",
            description="Found test credential",
            score=100,
            matched_value="testuser",
        )
        return GrabberResult(
            module_name=self.name,
            status=GrabberStatus.COMPLETED,
            findings=[finding],
            credentials=[cred],
        )


class _AdminOnlyGrabber(GrabberModule):
    name = "admin_only"
    description = "Requires admin"
    min_privilege = PrivilegeLevel.ADMIN
    supported_platforms = ("Darwin", "Linux", "Windows")
    default_enabled = True

    def preflight_check(self, context):
        return True

    def execute(self, context):
        return GrabberResult(module_name=self.name)


class _DisabledGrabber(GrabberModule):
    name = "disabled_grabber"
    description = "Disabled by default"
    supported_platforms = ("Darwin", "Linux", "Windows")
    default_enabled = False

    def preflight_check(self, context):
        return True

    def execute(self, context):
        return GrabberResult(module_name=self.name)


class TestGrabberContext:
    def test_from_scan_context(self):
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        assert gctx.scan_context is ctx
        assert gctx.user_profile_path != ""
        assert isinstance(gctx.is_admin, bool)
        assert isinstance(gctx.is_windows, bool)

    def test_add_credentials_thread_safe(self):
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        cred = ExtractedCredential(
            source_module="test",
            credential_type="token",
            target_application="TestApp",
        )
        gctx.add_credentials([cred])
        gctx.add_credentials([cred, cred])
        assert len(gctx.all_credentials) == 3


class TestGrabberModule:
    def test_can_run_checks_platform(self):
        grabber = _FakeGrabber()
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        can_run, reason = grabber.can_run(gctx)
        assert can_run is True

    def test_admin_grabber_skipped_when_not_admin(self):
        grabber = _AdminOnlyGrabber()
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        gctx.is_admin = False
        can_run, reason = grabber.can_run(gctx)
        assert can_run is False
        assert "admin" in reason.lower()

    def test_admin_grabber_runs_when_admin(self):
        grabber = _AdminOnlyGrabber()
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        gctx.is_admin = True
        can_run, reason = grabber.can_run(gctx)
        assert can_run is True

    def test_run_wraps_execute(self):
        grabber = _FakeGrabber()
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        result = grabber.run(gctx)
        assert result.module_name == "fake_grabber"
        assert result.status == GrabberStatus.COMPLETED
        assert len(result.credentials) == 1
        assert len(result.findings) == 1
        assert result.duration_seconds >= 0

    def test_run_catches_exceptions(self):
        class _CrashGrabber(GrabberModule):
            name = "crasher"
            supported_platforms = ("Darwin", "Linux", "Windows")
            def preflight_check(self, ctx): return True
            def execute(self, ctx): raise RuntimeError("boom")

        grabber = _CrashGrabber()
        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        result = grabber.run(gctx)
        assert result.status == GrabberStatus.FAILED
        assert "boom" in result.errors[0]

    def test_make_finding(self):
        grabber = _FakeGrabber()
        finding = grabber.make_finding(
            "/test/file.db",
            "Found secret",
            score=150,
            matched_value="admin",
            snippets=["PASSWORD=admin"],
        )
        assert finding.total_score == 150
        assert finding.file_path == "/test/file.db"
        assert "[fake_grabber]" in finding.signals[0].description
        assert finding.content_snippets == ["PASSWORD=admin"]


class TestExtractedCredential:
    def test_to_dict(self):
        cred = ExtractedCredential(
            source_module="browser",
            credential_type="password",
            target_application="Chrome",
            url="https://example.com",
            username="admin",
            encrypted_value=b"\x01\x02\x03",
            decrypted_value="secret123",
            mitre_technique="T1555.003",
        )
        d = cred.to_dict()
        assert d["source_module"] == "browser"
        assert d["has_encrypted_value"] is True
        assert d["has_decrypted_value"] is True
        assert d["mitre_technique"] == "T1555.003"
        # encrypted/decrypted values NOT in dict (security)
        assert "encrypted_value" not in d
        assert "decrypted_value" not in d


class TestGrabberResult:
    def test_to_dict(self):
        result = GrabberResult(
            module_name="test",
            status=GrabberStatus.COMPLETED,
            credentials=[
                ExtractedCredential("test", "password", "App")
            ],
            errors=["minor issue"],
            duration_seconds=1.5,
        )
        d = result.to_dict()
        assert d["module_name"] == "test"
        assert d["status"] == "completed"
        assert d["credentials_count"] == 1
        assert d["duration_seconds"] == 1.5


class TestGrabberRegistry:
    def test_manual_discovery(self):
        """Test that the registry can discover modules in this package."""
        registry = GrabberRegistry()
        registry.discover()
        # No real grabber modules exist yet, so this should be empty or have test modules
        assert isinstance(registry.available_names, list)

    def test_get_enabled_modules_filters_disabled(self):
        registry = GrabberRegistry()
        # Manually register our test grabbers
        registry._module_classes = {
            "fake_grabber": _FakeGrabber,
            "disabled_grabber": _DisabledGrabber,
        }
        registry._discovered = True

        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        modules = registry.get_enabled_modules(gctx)

        names = [m.name for m in modules]
        assert "fake_grabber" in names
        assert "disabled_grabber" not in names

    def test_get_enabled_modules_filters_by_name(self):
        registry = GrabberRegistry()
        registry._module_classes = {
            "fake_grabber": _FakeGrabber,
            "admin_only": _AdminOnlyGrabber,
        }
        registry._discovered = True

        ctx = ScanContext(["/tmp"])
        gctx = GrabberContext.from_scan_context(ctx)
        gctx.is_admin = True
        modules = registry.get_enabled_modules(gctx, enabled_names=["admin_only"])

        names = [m.name for m in modules]
        assert "admin_only" in names
        assert "fake_grabber" not in names
