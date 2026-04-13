"""Tests for delta scanning (baseline comparison)."""

import json
import tempfile
from datetime import datetime

import pytest

from treasure_hunter.delta import load_baseline, filter_new_findings
from treasure_hunter.models import Finding, ScanResult, Severity, Signal, FindingCategory


def _finding(path, score=100):
    return Finding(
        file_path=path,
        severity=Severity.HIGH,
        total_score=score,
        signals=[Signal(category=FindingCategory.EXTENSION, description="test", score=score)],
    )


class TestLoadBaseline:
    def test_loads_findings_from_jsonl(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"type": "scan_start", "scan_id": "old"}) + "\n")
            f.write(json.dumps({"type": "finding", "file_path": "/etc/passwd", "severity": "HIGH"}) + "\n")
            f.write(json.dumps({"type": "finding", "file_path": "/etc/shadow", "severity": "CRITICAL"}) + "\n")
            f.write(json.dumps({"type": "scan_complete", "stats": {}}) + "\n")
            f.flush()

            baseline = load_baseline(f.name)
            assert isinstance(baseline, set)
            assert "/etc/passwd" in baseline
            assert "/etc/shadow" in baseline

    def test_handles_missing_file(self):
        baseline = load_baseline("/nonexistent/baseline.jsonl")
        assert isinstance(baseline, set)
        assert len(baseline) == 0

    def test_handles_empty_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("")
            f.flush()
            baseline = load_baseline(f.name)
            assert isinstance(baseline, set)
            assert len(baseline) == 0

    def test_handles_malformed_json(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not json\n")
            f.write('{"type": "finding", "file_path": "/good"}\n')
            f.flush()
            baseline = load_baseline(f.name)
            assert "/good" in baseline


class TestFilterNewFindings:
    def test_removes_duplicates(self):
        baseline = {"/etc/passwd", "/etc/shadow"}

        result = ScanResult(
            scan_id="new",
            target_paths=["/"],
            started_at=datetime.now(),
            findings=[
                _finding("/etc/passwd"),    # In baseline
                _finding("/etc/hosts"),     # New
                _finding("/etc/shadow"),    # In baseline
                _finding("/var/log/auth"),  # New
            ],
        )

        filtered = filter_new_findings(result, baseline)
        paths = {f.file_path for f in filtered.findings}
        assert "/etc/hosts" in paths
        assert "/var/log/auth" in paths
        assert "/etc/passwd" not in paths
        assert "/etc/shadow" not in paths

    def test_all_new_findings_kept(self):
        result = ScanResult(
            scan_id="new",
            target_paths=["/"],
            started_at=datetime.now(),
            findings=[_finding("/new/file1"), _finding("/new/file2")],
        )
        filtered = filter_new_findings(result, set())
        assert len(filtered.findings) == 2

    def test_empty_scan_result(self):
        result = ScanResult(
            scan_id="new",
            target_paths=["/"],
            started_at=datetime.now(),
            findings=[],
        )
        filtered = filter_new_findings(result, {"/old"})
        assert len(filtered.findings) == 0
