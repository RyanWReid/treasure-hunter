"""Tests for the streaming JSONL reporter."""

import json
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest

from treasure_hunter.reporter import StreamingReporter
from treasure_hunter.models import (
    Finding, ScanResult, Severity, Signal, FindingCategory,
)


def _finding(path="/test/file", score=100):
    return Finding(
        file_path=path,
        severity=Severity.HIGH,
        total_score=score,
        signals=[Signal(category=FindingCategory.EXTENSION, description="test", score=score)],
    )


class TestStreamingReporter:
    def test_start_creates_file_with_header(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.jsonl"
            reporter = StreamingReporter(str(path), "scan-001", ["/target"])
            reporter.start()

            # Give background thread a moment
            time.sleep(0.1)

            result = ScanResult(
                scan_id="scan-001",
                target_paths=["/target"],
                started_at=datetime.now(),
                completed_at=datetime.now(),
                findings=[],
            )
            reporter.stop(result)

            content = path.read_text()
            lines = [json.loads(line) for line in content.strip().split("\n") if line]
            assert lines[0]["type"] == "scan_start"
            assert lines[-1]["type"] == "scan_complete"

    def test_emit_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.jsonl"
            reporter = StreamingReporter(str(path), "scan-001", ["/target"])
            reporter.start()

            reporter.emit_finding(_finding("/etc/passwd", 200))
            reporter.emit_finding(_finding("/etc/shadow", 300))

            time.sleep(0.2)

            result = ScanResult(
                scan_id="scan-001",
                target_paths=["/target"],
                started_at=datetime.now(),
                completed_at=datetime.now(),
                findings=[],
            )
            reporter.stop(result)

            content = path.read_text()
            lines = [json.loads(line) for line in content.strip().split("\n")]
            finding_lines = [l for l in lines if l.get("type") == "finding"]
            assert len(finding_lines) == 2

    def test_emit_credential(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.jsonl"
            reporter = StreamingReporter(str(path), "scan-001", ["/target"])
            reporter.start()

            reporter.emit_credential({
                "source_module": "browser",
                "credential_type": "password",
                "target_application": "Chrome",
                "username": "admin",
            })

            time.sleep(0.2)

            result = ScanResult(
                scan_id="scan-001",
                target_paths=["/target"],
                started_at=datetime.now(),
                completed_at=datetime.now(),
                findings=[],
            )
            reporter.stop(result)

            content = path.read_text()
            lines = [json.loads(line) for line in content.strip().split("\n")]
            cred_lines = [l for l in lines if l.get("type") == "credential"]
            assert len(cred_lines) == 1

    def test_emit_lateral_methods(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.jsonl"
            reporter = StreamingReporter(str(path), "scan-001", ["/target"])
            reporter.start()

            reporter.emit_lateral_attempt({"host": "10.0.0.5", "status": "failed"})
            reporter.emit_lateral_success({"host": "10.0.0.5", "share": "C$"})
            reporter.emit_lateral_summary({"targets_discovered": 1})

            time.sleep(0.2)

            result = ScanResult(
                scan_id="scan-001",
                target_paths=["/target"],
                started_at=datetime.now(),
                completed_at=datetime.now(),
                findings=[],
            )
            reporter.stop(result)

            content = path.read_text()
            lines = [json.loads(line) for line in content.strip().split("\n")]
            types = {l["type"] for l in lines}
            assert "lateral_attempt" in types
            assert "lateral_success" in types
            assert "lateral_summary" in types

    def test_concurrent_writes(self):
        """Ensure thread safety under concurrent emit calls."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.jsonl"
            reporter = StreamingReporter(str(path), "scan-001", ["/target"])
            reporter.start()

            def emit_batch(start):
                for i in range(50):
                    reporter.emit_finding(_finding(f"/file/{start + i}"))

            threads = [threading.Thread(target=emit_batch, args=(i * 50,)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            time.sleep(0.5)

            result = ScanResult(
                scan_id="scan-001",
                target_paths=["/target"],
                started_at=datetime.now(),
                completed_at=datetime.now(),
                findings=[],
            )
            reporter.stop(result)

            content = path.read_text()
            lines = content.strip().split("\n")
            # 1 header + 200 findings + 1 summary = 202
            finding_count = sum(1 for l in lines if '"type": "finding"' in l or '"type":"finding"' in l)
            assert finding_count == 200

    def test_no_crash_when_not_started(self):
        reporter = StreamingReporter("/dev/null", "test", [])
        # Should not raise
        reporter.emit_finding(_finding())
        reporter.emit_credential({"test": True})
        reporter.emit_lateral_attempt({"test": True})
