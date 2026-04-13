"""Tests for HTML report generation."""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from treasure_hunter.report import generate_html_report
from treasure_hunter.models import (
    Finding, FileMetadata, ScanResult, Severity,
    Signal, FindingCategory,
)


def _make_result():
    return ScanResult(
        scan_id="test-report-001",
        target_paths=["C:\\Users\\test"],
        started_at=datetime(2026, 1, 1, 12, 0, 0),
        completed_at=datetime(2026, 1, 1, 12, 15, 30),
        total_files_scanned=5000,
        total_dirs_scanned=500,
        findings=[
            Finding(
                file_path="C:\\Users\\test\\.ssh\\id_rsa",
                severity=Severity.CRITICAL,
                total_score=300,
                signals=[Signal(
                    category=FindingCategory.EXTENSION,
                    description="SSH private key",
                    score=100,
                    matched_value=".pem",
                )],
                metadata=FileMetadata(
                    path="C:\\Users\\test\\.ssh\\id_rsa",
                    size_bytes=1704,
                    modified=datetime(2026, 1, 1),
                ),
            ),
            Finding(
                file_path="C:\\Users\\test\\Documents\\passwords.kdbx",
                severity=Severity.HIGH,
                total_score=150,
                signals=[Signal(
                    category=FindingCategory.KEYWORD,
                    description="Password manager database",
                    score=75,
                )],
            ),
            Finding(
                file_path="C:\\Users\\test\\config.env",
                severity=Severity.MEDIUM,
                total_score=80,
                signals=[],
            ),
        ],
        errors=["Access denied: C:\\Windows\\System32\\config"],
    )


class TestHTMLReportGeneration:
    def test_generates_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            result = _make_result()
            generate_html_report(result, str(html_path))

            assert html_path.exists()
            content = html_path.read_text(encoding="utf-8")
            assert len(content) > 100

    def test_contains_scan_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            generate_html_report(_make_result(), str(html_path))
            content = html_path.read_text(encoding="utf-8")

            assert "test-report-001" in content
            assert "5,000" in content or "5000" in content

    def test_contains_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            generate_html_report(_make_result(), str(html_path))
            content = html_path.read_text(encoding="utf-8")

            assert "id_rsa" in content
            assert "passwords.kdbx" in content
            assert "CRITICAL" in content

    def test_self_contained_no_external_resources(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            generate_html_report(_make_result(), str(html_path))
            content = html_path.read_text(encoding="utf-8")

            # Should not reference external CSS/JS
            assert "https://" not in content or "http://" not in content
            assert "<style" in content  # Inline CSS

    def test_handles_empty_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            result = ScanResult(
                scan_id="empty",
                target_paths=["/"],
                started_at=datetime.now(),
                completed_at=datetime.now(),
                findings=[],
            )
            generate_html_report(result, str(html_path))
            assert html_path.exists()

    def test_escapes_html_in_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = Path(tmpdir) / "report.html"
            result = ScanResult(
                scan_id="xss-test",
                target_paths=["<script>alert(1)</script>"],
                started_at=datetime.now(),
                findings=[Finding(
                    file_path='<img src=x onerror="alert(1)">',
                    severity=Severity.LOW,
                    total_score=30,
                )],
            )
            generate_html_report(result, str(html_path))
            content = html_path.read_text(encoding="utf-8")
            # Script tags should be escaped
            assert "<script>alert(1)</script>" not in content
