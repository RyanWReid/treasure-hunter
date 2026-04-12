"""Base class and context for all grabber modules."""

from __future__ import annotations

import logging
import os
import platform
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..models import (
    FileMetadata,
    Finding,
    FindingCategory,
    Signal,
    compute_severity,
)
from .models import (
    ExtractedCredential,
    GrabberResult,
    GrabberStatus,
    PrivilegeLevel,
)

if TYPE_CHECKING:
    from ..scanner import ScanContext


def check_admin() -> bool:
    """Check if running with admin/root privileges. Platform-safe."""
    if os.name == "nt":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (AttributeError, OSError):
            return False
    else:
        return os.getuid() == 0


@dataclass
class GrabberContext:
    """Extended context for grabber modules. Wraps ScanContext with
    environment detection and shared credential storage."""

    scan_context: ScanContext
    user_profile_path: str = ""
    appdata_roaming: str = ""
    appdata_local: str = ""
    programdata: str = ""
    is_admin: bool = False
    is_windows: bool = False
    all_credentials: list[ExtractedCredential] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_credentials(self, creds: list[ExtractedCredential]) -> None:
        """Thread-safe credential accumulation."""
        with self._lock:
            self.all_credentials.extend(creds)

    @classmethod
    def from_scan_context(cls, ctx: ScanContext) -> GrabberContext:
        """Build a GrabberContext from environment detection."""
        home = os.path.expanduser("~")
        return cls(
            scan_context=ctx,
            user_profile_path=os.environ.get("USERPROFILE", home),
            appdata_roaming=os.environ.get("APPDATA", ""),
            appdata_local=os.environ.get("LOCALAPPDATA", ""),
            programdata=os.environ.get("PROGRAMDATA", ""),
            is_admin=check_admin(),
            is_windows=platform.system() == "Windows",
        )


class GrabberModule(ABC):
    """Base class all grabber modules must inherit from.

    Subclass this, set class attributes, and implement preflight_check()
    and execute(). Drop the file in treasure_hunter/grabbers/ and it
    will be auto-discovered by GrabberRegistry.
    """

    name: str = ""
    description: str = ""
    min_privilege: PrivilegeLevel = PrivilegeLevel.USER
    supported_platforms: tuple[str, ...] = ("Windows",)
    default_enabled: bool = True

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"grabber.{self.name}")

    def can_run(self, context: GrabberContext) -> tuple[bool, str]:
        """Check if this module can run on the current system.
        Returns (can_run, reason) tuple."""
        if platform.system() not in self.supported_platforms:
            return False, f"Unsupported platform: {platform.system()}"

        if self.min_privilege == PrivilegeLevel.ADMIN and not context.is_admin:
            return False, "Requires admin privileges"

        if self.min_privilege == PrivilegeLevel.SYSTEM and not context.is_admin:
            return False, "Requires SYSTEM privileges"

        if not self.preflight_check(context):
            return False, "Preflight check failed — targets not present"

        return True, ""

    def run(self, context: GrabberContext) -> GrabberResult:
        """Execute the grabber with timing and error handling.
        Subclasses should NOT override this — override execute() instead."""
        start = time.monotonic()
        try:
            result = self.execute(context)
            result.duration_seconds = time.monotonic() - start
            return result
        except Exception as e:
            self.logger.error(f"Grabber {self.name} failed: {e}")
            return GrabberResult(
                module_name=self.name,
                status=GrabberStatus.FAILED,
                errors=[str(e)],
                duration_seconds=time.monotonic() - start,
            )

    @abstractmethod
    def preflight_check(self, context: GrabberContext) -> bool:
        """Quick check: are the targets this module needs actually present?
        E.g., does Chrome's Login Data file exist?
        Must not raise exceptions."""
        ...

    @abstractmethod
    def execute(self, context: GrabberContext) -> GrabberResult:
        """Run the grabber's extraction logic.
        Must handle all internal errors gracefully."""
        ...

    def make_finding(
        self,
        file_path: str,
        description: str,
        score: int,
        matched_value: str = "",
        snippets: list[str] | None = None,
        metadata: FileMetadata | None = None,
    ) -> Finding:
        """Convenience helper to create a Finding from grabber output."""
        signal = Signal(
            category=FindingCategory.CONTENT,
            description=f"[{self.name}] {description}",
            score=score,
            matched_value=matched_value,
        )
        return Finding(
            file_path=file_path,
            severity=compute_severity(score),
            total_score=score,
            signals=[signal],
            metadata=metadata,
            content_snippets=snippets or [],
        )
