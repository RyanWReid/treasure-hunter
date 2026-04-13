"""Tests for exfiltration staging, compression, and size estimation."""

import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.exfil import stage_findings, compress_staged, estimate_exfil_size
from treasure_hunter.models import Finding, ScanResult, Severity, Signal, FindingCategory, FileMetadata
from datetime import datetime


def _make_result(tmpdir):
    """Create a ScanResult with real files on disk."""
    # Create actual files to stage
    secret_dir = Path(tmpdir) / "secrets"
    secret_dir.mkdir()

    files = []
    for name, content, severity, score in [
        ("id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nFAKE", Severity.CRITICAL, 300),
        (".env", "DB_PASSWORD=hunter2\nAPI_KEY=abc123", Severity.HIGH, 150),
        ("config.txt", "server=prod.internal", Severity.MEDIUM, 80),
    ]:
        fpath = secret_dir / name
        fpath.write_text(content)
        files.append(Finding(
            file_path=str(fpath),
            severity=severity,
            total_score=score,
            signals=[Signal(category=FindingCategory.EXTENSION, description="test", score=score)],
            metadata=FileMetadata(path=str(fpath), size_bytes=len(content)),
        ))

    return ScanResult(
        scan_id="test",
        target_paths=[tmpdir],
        started_at=datetime.now(),
        findings=files,
    )


class TestStageFindings:
    def test_copies_critical_and_high_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _make_result(tmpdir)
            stage_dir = Path(tmpdir) / "loot"

            manifest = stage_findings(result, str(stage_dir))

            assert manifest["total_files"] >= 2  # CRITICAL + HIGH at minimum
            assert stage_dir.exists()
            # Should have subdirectories by severity
            staged_files = list(stage_dir.rglob("*"))
            assert len([f for f in staged_files if f.is_file()]) >= 2

    def test_empty_results_stages_nothing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = ScanResult(
                scan_id="empty",
                target_paths=[tmpdir],
                started_at=datetime.now(),
                findings=[],
            )
            stage_dir = Path(tmpdir) / "loot"
            manifest = stage_findings(result, str(stage_dir))
            assert manifest["total_files"] == 0


class TestCompressStaged:
    def test_creates_zip_archive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _make_result(tmpdir)
            stage_dir = Path(tmpdir) / "loot"
            stage_findings(result, str(stage_dir))

            zip_path = compress_staged(str(stage_dir))
            assert zip_path is not None
            assert os.path.exists(zip_path)
            assert zip_path.endswith(".zip")
            assert os.path.getsize(zip_path) > 0


class TestEstimateExfilSize:
    def test_estimates_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _make_result(tmpdir)
            estimate = estimate_exfil_size(result)

            assert "total_files" in estimate
            assert "total_size_human" in estimate
            assert estimate["total_files"] >= 1

    def test_empty_result(self):
        result = ScanResult(
            scan_id="empty",
            target_paths=["/"],
            started_at=datetime.now(),
            findings=[],
        )
        estimate = estimate_exfil_size(result)
        assert estimate["total_files"] == 0
