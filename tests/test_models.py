"""Tests for data models, severity computation, and serialization."""

from datetime import datetime

import pytest

from treasure_hunter.models import (
    Finding, FileMetadata, ScanResult, Severity, Signal,
    FindingCategory, compute_severity,
    LateralAuthStatus, CredentialTestResult, LateralTarget, LateralResult,
)


class TestSeverityEnum:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_values(self):
        assert Severity.INFO.value == 1
        assert Severity.LOW.value == 2
        assert Severity.MEDIUM.value == 3
        assert Severity.HIGH.value == 4
        assert Severity.CRITICAL.value == 5


class TestComputeSeverity:
    def test_critical(self):
        assert compute_severity(200) == Severity.CRITICAL
        assert compute_severity(300) == Severity.CRITICAL
        assert compute_severity(999) == Severity.CRITICAL

    def test_high(self):
        assert compute_severity(120) == Severity.HIGH
        assert compute_severity(199) == Severity.HIGH

    def test_medium(self):
        assert compute_severity(60) == Severity.MEDIUM
        assert compute_severity(119) == Severity.MEDIUM

    def test_low(self):
        assert compute_severity(25) == Severity.LOW
        assert compute_severity(59) == Severity.LOW

    def test_info(self):
        assert compute_severity(0) == Severity.INFO
        assert compute_severity(24) == Severity.INFO


class TestSignal:
    def test_creation(self):
        s = Signal(
            category=FindingCategory.EXTENSION,
            description="SSH key detected",
            score=75,
            matched_value=".pem",
        )
        assert s.score == 75
        assert s.category == FindingCategory.EXTENSION


class TestFileMetadata:
    def test_to_dict(self):
        m = FileMetadata(
            path="/home/user/.ssh/id_rsa",
            size_bytes=1704,
            modified=datetime(2026, 1, 1, 12, 0, 0),
            owner="1000:1000",
            is_hidden=False,
            extension=".rsa",
        )
        d = m.to_dict()
        assert d["path"] == "/home/user/.ssh/id_rsa"
        assert d["size_bytes"] == 1704
        assert d["modified"] == "2026-01-01T12:00:00"

    def test_defaults(self):
        m = FileMetadata(path="/test")
        assert m.size_bytes == 0
        assert m.modified is None
        assert m.owner == ""


class TestFinding:
    def test_to_dict(self):
        f = Finding(
            file_path="/etc/shadow",
            severity=Severity.CRITICAL,
            total_score=250,
            signals=[Signal(
                category=FindingCategory.KEYWORD,
                description="Shadow file",
                score=100,
            )],
            content_snippets=["root:$6$..."],
        )
        d = f.to_dict()
        assert d["severity"] == "CRITICAL"
        assert d["total_score"] == 250
        assert len(d["signals"]) == 1
        assert d["signals"][0]["score"] == 100

    def test_empty_finding(self):
        f = Finding(file_path="/test", severity=Severity.LOW, total_score=25)
        d = f.to_dict()
        assert d["signals"] == []
        assert d["content_snippets"] == []


class TestScanResult:
    def test_to_dict(self):
        r = ScanResult(
            scan_id="scan-001",
            target_paths=["/home"],
            started_at=datetime(2026, 1, 1, 12, 0, 0),
            completed_at=datetime(2026, 1, 1, 12, 15, 0),
            total_files_scanned=5000,
            total_dirs_scanned=500,
            findings=[
                Finding(file_path="/f1", severity=Severity.CRITICAL, total_score=200),
                Finding(file_path="/f2", severity=Severity.HIGH, total_score=120),
                Finding(file_path="/f3", severity=Severity.LOW, total_score=30),
            ],
        )
        d = r.to_dict()
        assert d["scan_id"] == "scan-001"
        assert d["stats"]["total_files_scanned"] == 5000
        assert d["stats"]["critical"] == 1
        # high stat counts findings with severity == HIGH only
        assert d["stats"]["high"] == 1  # Only the HIGH finding, not CRITICAL
        assert len(d["findings"]) == 3

    def test_critical_findings_property(self):
        r = ScanResult(
            scan_id="test",
            target_paths=["/"],
            started_at=datetime.now(),
            findings=[
                Finding(file_path="/a", severity=Severity.CRITICAL, total_score=200),
                Finding(file_path="/b", severity=Severity.HIGH, total_score=120),
                Finding(file_path="/c", severity=Severity.MEDIUM, total_score=60),
            ],
        )
        assert len(r.critical_findings) == 1
        assert len(r.high_findings) == 2  # CRITICAL + HIGH

    def test_empty_result(self):
        r = ScanResult(
            scan_id="empty",
            target_paths=[],
            started_at=datetime.now(),
        )
        d = r.to_dict()
        assert d["stats"]["total_findings"] == 0


class TestLateralModels:
    def test_lateral_auth_status_values(self):
        assert LateralAuthStatus.SUCCESS.value == "success"
        assert LateralAuthStatus.LOGON_FAILURE.value == "logon_failure"
        assert LateralAuthStatus.SKIPPED_LOCKOUT.value == "skipped_lockout"

    def test_credential_test_result_to_dict(self):
        r = CredentialTestResult(
            host="10.0.0.5",
            share="C$",
            username="admin",
            credential_source="browser",
            status=LateralAuthStatus.SUCCESS,
            error_code=0,
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
        )
        d = r.to_dict()
        assert d["host"] == "10.0.0.5"
        assert d["status"] == "success"

    def test_lateral_target_to_dict(self):
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
        assert d["compromised"] is True
        assert d["auth_successes"] == 1

    def test_lateral_result_to_dict(self):
        r = LateralResult(
            started_at=datetime(2026, 1, 1),
            completed_at=datetime(2026, 1, 1, 0, 5),
            targets_discovered=5,
            targets_compromised=2,
        )
        d = r.to_dict()
        assert d["targets_discovered"] == 5
        assert d["targets_compromised"] == 2


class TestFindingCategory:
    def test_all_categories_have_values(self):
        assert FindingCategory.EXTENSION.value == "extension"
        assert FindingCategory.KEYWORD.value == "keyword"
        assert FindingCategory.CONTENT.value == "content"
        assert FindingCategory.ENTROPY.value == "entropy"
        assert FindingCategory.RECENCY.value == "recency"
        assert FindingCategory.METADATA.value == "metadata"
        assert FindingCategory.GRABBER.value == "grabber"
