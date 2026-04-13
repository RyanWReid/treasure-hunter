"""Data models for scan findings and scoring."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


class Severity(enum.IntEnum):
    """Finding severity — drives sort order in reports."""

    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class FindingCategory(str, enum.Enum):
    """What type of signal triggered the finding."""

    EXTENSION = "extension"
    KEYWORD = "keyword"
    CONTENT = "content"
    ENTROPY = "entropy"
    RECENCY = "recency"
    METADATA = "metadata"
    GRABBER = "grabber"


@dataclass
class Signal:
    """A single indicator that contributed to a finding's score."""

    category: FindingCategory
    description: str
    score: int  # 0-100 contribution
    matched_value: str = ""


@dataclass
class FileMetadata:
    """Extracted metadata about a discovered file."""

    path: str
    size_bytes: int = 0
    created: datetime | None = None
    modified: datetime | None = None
    accessed: datetime | None = None
    owner: str = ""
    is_hidden: bool = False
    extension: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "owner": self.owner,
            "is_hidden": self.is_hidden,
            "extension": self.extension,
        }


@dataclass
class Finding:
    """A file that triggered one or more signals during scanning."""

    file_path: str
    severity: Severity
    total_score: int
    signals: list[Signal] = field(default_factory=list)
    metadata: FileMetadata | None = None
    content_snippets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "severity": self.severity.name,
            "total_score": self.total_score,
            "signals": [
                {
                    "category": s.category.value,
                    "description": s.description,
                    "score": s.score,
                    "matched_value": s.matched_value,
                }
                for s in self.signals
            ],
            "metadata": self.metadata.to_dict() if self.metadata else None,
            "content_snippets": self.content_snippets,
        }


@dataclass
class ScanResult:
    """Complete results from a treasure-hunter scan."""

    scan_id: str
    target_paths: list[str]
    started_at: datetime
    completed_at: datetime | None = None
    total_files_scanned: int = 0
    total_dirs_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_paths: list[str] = field(default_factory=list)
    grabber_results: list[Any] = field(default_factory=list)  # list[GrabberResult]
    lateral_result: Any = None  # LateralResult when lateral movement is enabled

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity >= Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity >= Severity.HIGH]

    @property
    def total_credentials_harvested(self) -> int:
        return sum(
            len(gr.credentials) for gr in self.grabber_results
            if hasattr(gr, "credentials")
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "scan_id": self.scan_id,
            "target_paths": self.target_paths,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "stats": {
                "total_files_scanned": self.total_files_scanned,
                "total_dirs_scanned": self.total_dirs_scanned,
                "total_findings": len(self.findings),
                "total_credentials_harvested": self.total_credentials_harvested,
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO]),
            },
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: x.total_score, reverse=True)],
            "errors": self.errors,
            "skipped_paths": self.skipped_paths,
        }
        if self.grabber_results:
            result["grabber_results"] = [
                gr.to_dict() for gr in self.grabber_results
            ]
        if self.lateral_result:
            result["lateral_result"] = self.lateral_result.to_dict()
        return result


class LateralAuthStatus(str, enum.Enum):
    """Outcome of a single SMB authentication attempt."""

    SUCCESS = "success"
    ACCESS_DENIED = "access_denied"
    WRONG_PASSWORD = "wrong_password"
    HOST_UNREACHABLE = "host_unreachable"
    ALREADY_CONNECTED = "already_connected"
    LOGON_FAILURE = "logon_failure"
    SKIPPED_LOCKOUT = "skipped_lockout"
    ERROR = "error"


@dataclass
class CredentialTestResult:
    """Result of one credential test against one host."""

    host: str
    share: str  # e.g., "C$"
    username: str
    credential_source: str  # source_module of the ExtractedCredential
    status: LateralAuthStatus
    error_code: int = 0
    timestamp: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "share": self.share,
            "username": self.username,
            "credential_source": self.credential_source,
            "status": self.status.value,
            "error_code": self.error_code,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class LateralTarget:
    """A discovered network host and its lateral movement status."""

    host: str
    port_open: bool = False
    shares_discovered: list[str] = field(default_factory=list)
    auth_results: list[CredentialTestResult] = field(default_factory=list)
    compromised: bool = False
    remote_scan_result: ScanResult | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "host": self.host,
            "port_open": self.port_open,
            "shares_discovered": self.shares_discovered,
            "compromised": self.compromised,
            "auth_attempts": len(self.auth_results),
            "auth_successes": sum(
                1 for r in self.auth_results
                if r.status == LateralAuthStatus.SUCCESS
            ),
        }
        if self.remote_scan_result:
            result["remote_scan"] = {
                "findings": len(self.remote_scan_result.findings),
                "files_scanned": self.remote_scan_result.total_files_scanned,
            }
        return result


@dataclass
class LateralResult:
    """Aggregate results from the lateral movement phase."""

    started_at: datetime
    completed_at: datetime | None = None
    targets_discovered: int = 0
    targets_compromised: int = 0
    credentials_tested: int = 0
    auth_successes: int = 0
    auth_failures: int = 0
    lockout_skips: int = 0
    targets: list[LateralTarget] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "targets_discovered": self.targets_discovered,
            "targets_compromised": self.targets_compromised,
            "credentials_tested": self.credentials_tested,
            "auth_successes": self.auth_successes,
            "auth_failures": self.auth_failures,
            "lockout_skips": self.lockout_skips,
            "targets": [t.to_dict() for t in self.targets],
            "errors": self.errors,
        }


def compute_severity(total_score: int) -> Severity:
    """Map a cumulative score to a severity level."""
    if total_score >= 200:
        return Severity.CRITICAL
    if total_score >= 120:
        return Severity.HIGH
    if total_score >= 60:
        return Severity.MEDIUM
    if total_score >= 25:
        return Severity.LOW
    return Severity.INFO
