"""Tests for process memory grabber -- attributes and platform gating."""

import platform

import pytest

from treasure_hunter.grabbers.process import ProcessGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import PrivilegeLevel
from treasure_hunter.scanner import ScanContext


class TestProcessGrabberAttributes:
    def test_name(self):
        g = ProcessGrabber()
        assert g.name == "process"

    def test_requires_admin(self):
        g = ProcessGrabber()
        assert g.min_privilege == PrivilegeLevel.ADMIN

    def test_disabled_by_default(self):
        """Process scanning is high OPSEC risk -- must be explicitly enabled."""
        g = ProcessGrabber()
        assert g.default_enabled is False

    def test_skips_without_admin(self):
        ctx = ScanContext(target_paths=["/tmp"], grabbers_enabled=False)
        gctx = GrabberContext(
            scan_context=ctx,
            is_admin=False,
            user_profile_path="/tmp",
        )
        g = ProcessGrabber()
        can_run, reason = g.can_run(gctx)
        assert not can_run
        # May fail on platform check or privilege check depending on OS
        assert reason != ""
