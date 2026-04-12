"""Tests for scanner engine — deduplication, scoring, metadata, phases."""

import tempfile
from pathlib import Path

from treasure_hunter.models import FileMetadata, FindingCategory, compute_severity, Severity
from treasure_hunter.scanner import FileAnalyzer, ScanContext, TreasureScanner


class TestScanContext:
    def test_deduplication(self):
        ctx = ScanContext(['/tmp'])
        assert ctx.mark_seen('/a/file.txt') is False  # first time
        assert ctx.mark_seen('/a/file.txt') is True   # duplicate
        assert ctx.mark_seen('/b/other.txt') is False  # different file

    def test_time_limit_none(self):
        ctx = ScanContext(['/tmp'], time_limit=None)
        assert ctx.should_terminate() is False

    def test_time_limit_zero(self):
        ctx = ScanContext(['/tmp'], time_limit=0)
        assert ctx.should_terminate() is True

    def test_extra_kwargs_accepted(self):
        """Profile kwargs like target_extensions shouldn't crash."""
        ctx = ScanContext(['/tmp'], target_extensions={'.kdbx'}, custom_flag=True)
        assert ctx.max_threads == 8  # default still works

    def test_thread_safe_counters(self):
        ctx = ScanContext(['/tmp'])
        ctx.increment_counters(files=5, dirs=2)
        ctx.increment_counters(files=3)
        assert ctx.files_scanned == 8
        assert ctx.dirs_scanned == 2


class TestFileAnalyzer:
    def _make_context(self, **kwargs):
        defaults = dict(target_paths=['/tmp'], max_threads=1, min_score_threshold=1)
        defaults.update(kwargs)
        return ScanContext(**defaults)

    def test_skip_empty_file(self):
        ctx = self._make_context()
        analyzer = FileAnalyzer(ctx)
        metadata = FileMetadata(path='/test/empty.txt', size_bytes=0, extension='.txt')
        assert analyzer.analyze_file('/test/empty.txt', metadata) is None

    def test_skip_oversized_file(self):
        ctx = self._make_context(max_file_size=100)
        analyzer = FileAnalyzer(ctx)
        metadata = FileMetadata(path='/test/huge.bin', size_bytes=1000, extension='.bin')
        assert analyzer.analyze_file('/test/huge.bin', metadata) is None

    def test_kdbx_scores_high(self):
        ctx = self._make_context()
        analyzer = FileAnalyzer(ctx)
        metadata = FileMetadata(path='/docs/passwords.kdbx', size_bytes=1024, extension='.kdbx')
        finding = analyzer.analyze_file('/docs/passwords.kdbx', metadata)
        assert finding is not None
        assert finding.total_score >= 75  # extension + keyword
        assert any(s.category == FindingCategory.EXTENSION for s in finding.signals)
        assert any(s.category == FindingCategory.KEYWORD for s in finding.signals)

    def test_env_file_scores(self):
        ctx = self._make_context()
        analyzer = FileAnalyzer(ctx)
        metadata = FileMetadata(path='/app/.env', size_bytes=256, extension='.env')
        finding = analyzer.analyze_file('/app/.env', metadata)
        assert finding is not None
        assert any(s.category == FindingCategory.EXTENSION for s in finding.signals)

    def test_plain_txt_no_finding(self):
        ctx = self._make_context(min_score_threshold=25)
        analyzer = FileAnalyzer(ctx)
        metadata = FileMetadata(path='/docs/readme.txt', size_bytes=100, extension='.txt')
        finding = analyzer.analyze_file('/docs/readme.txt', metadata)
        assert finding is None  # no signals → below threshold


class TestTreasureScanner:
    def test_full_scan_with_temp_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create test files
            (Path(tmp) / 'secret.env').write_text('PASSWORD=hunter2')
            (Path(tmp) / 'notes.txt').write_text('Nothing interesting here')
            (Path(tmp) / 'admin.kdbx').write_bytes(b'\x03\xd9\xa2\x9a' + b'\x00' * 100)

            ctx = ScanContext(
                [tmp], max_threads=2, time_limit=10, min_score_threshold=20
            )
            scanner = TreasureScanner(ctx)
            results = scanner.scan()

            assert results.total_files_scanned >= 2
            assert len(results.findings) >= 1  # at least .env or .kdbx

            # Verify no duplicates
            paths = [f.file_path for f in results.findings]
            assert len(paths) == len(set(paths))

    def test_no_findings_for_boring_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'readme.txt').write_text('Hello world')
            (Path(tmp) / 'notes.md').write_text('Just some notes')

            ctx = ScanContext(
                [tmp], max_threads=1, time_limit=5, min_score_threshold=50,
                grabbers_enabled=False,
            )
            scanner = TreasureScanner(ctx)
            results = scanner.scan()

            assert len(results.findings) == 0

    def test_streaming_output(self):
        """Verify real-time JSONL output is written."""
        import json

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'vault.kdbx').write_bytes(b'\x00' * 50)
            output_path = str(Path(tmp) / 'results.jsonl')

            ctx = ScanContext(
                [tmp], max_threads=1, time_limit=5,
                min_score_threshold=20, output_path=output_path
            )
            scanner = TreasureScanner(ctx)
            scanner.scan()

            # Verify JSONL was written
            with open(output_path) as f:
                lines = [json.loads(line) for line in f]

            types = [l['type'] for l in lines]
            assert 'scan_start' in types
            assert 'scan_complete' in types


class TestComputeSeverity:
    def test_critical(self):
        assert compute_severity(200) == Severity.CRITICAL
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
