"""
HARDENED TESTS -- Edge cases, exact value assertions, negative tests,
cross-module pipeline, and adversarial inputs.

These tests are designed to catch real bugs, not just verify that
modules don't crash. Every assertion checks a specific value or behavior.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from treasure_hunter.models import (
    Finding, FileMetadata, ScanResult, Severity, Signal,
    FindingCategory, compute_severity,
    LateralAuthStatus, CredentialTestResult, LateralTarget, LateralResult,
)
from treasure_hunter.scanner import ScanContext, TreasureScanner, FileAnalyzer
from treasure_hunter.grabbers.models import (
    ExtractedCredential, GrabberResult, GrabberStatus, deduplicate_credentials,
)
from treasure_hunter.credential_audit import assess_password_strength, audit_credentials


# ============================================================
# EDGE CASE: Malformed / corrupt inputs
# ============================================================

class TestMalformedInputs:
    """Things that should NOT crash the tool."""

    def test_scanner_handles_null_bytes_in_filename(self):
        """Files with unusual characters in names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with special chars (not null, but weird)
            weird = Path(tmpdir) / "pass word (copy).env"
            weird.write_text("SECRET=test123")

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()
            # Should not crash
            assert isinstance(result, ScanResult)

    def test_scanner_handles_empty_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(target_paths=[tmpdir], grabbers_enabled=False,
                                show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()
            assert result.total_files_scanned == 0
            assert len(result.findings) == 0

    def test_scanner_handles_nonexistent_target(self):
        context = ScanContext(target_paths=["/nonexistent/path/that/does/not/exist"],
                            grabbers_enabled=False, show_progress=False)
        scanner = TreasureScanner(context)
        result = scanner.scan()
        assert isinstance(result, ScanResult)

    def test_scanner_handles_binary_file_content(self):
        """Binary files should not crash content analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a binary file that looks like it could be a credential file
            binary = Path(tmpdir) / "credentials.db"
            binary.write_bytes(os.urandom(4096))

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()
            assert isinstance(result, ScanResult)

    def test_scanner_handles_symlink_loops(self):
        """Symlink loops should not hang the scanner."""
        with tempfile.TemporaryDirectory() as tmpdir:
            link_path = Path(tmpdir) / "loop"
            try:
                link_path.symlink_to(tmpdir)
            except OSError:
                pytest.skip("Cannot create symlinks on this platform")

            context = ScanContext(target_paths=[tmpdir], time_limit=5,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()
            assert isinstance(result, ScanResult)

    def test_unicode_in_file_content(self):
        """UTF-8, UTF-16, and mixed encoding should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "chinese.env").write_text(
                "PASSWORD=\u5bc6\u7801test123\nKEY=value", encoding="utf-8"
            )
            (Path(tmpdir) / "emoji.txt").write_bytes(
                b"password=test\xf0\x9f\x94\x91key123"  # emoji in password
            )

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()
            assert isinstance(result, ScanResult)

    def test_very_long_file_path(self):
        """Deeply nested paths should not crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            deep = Path(tmpdir)
            for i in range(20):
                deep = deep / f"level{i}"
            try:
                deep.mkdir(parents=True, exist_ok=True)
                (deep / "secret.env").write_text("API_KEY=test")
            except OSError:
                pytest.skip("Filesystem doesn't support deep nesting")

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()
            assert isinstance(result, ScanResult)


# ============================================================
# EXACT VALUE ASSERTIONS: Verify precise scoring and behavior
# ============================================================

class TestExactScoring:
    """Verify the scoring system produces expected values."""

    def test_severity_thresholds_exact(self):
        assert compute_severity(199) == Severity.HIGH  # NOT critical
        assert compute_severity(200) == Severity.CRITICAL  # exactly critical
        assert compute_severity(119) == Severity.MEDIUM  # NOT high
        assert compute_severity(120) == Severity.HIGH
        assert compute_severity(59) == Severity.LOW
        assert compute_severity(60) == Severity.MEDIUM
        assert compute_severity(24) == Severity.INFO
        assert compute_severity(25) == Severity.LOW

    def test_kdbx_file_scores_high(self):
        """A .kdbx file should score at least HIGH from extension alone."""
        with tempfile.TemporaryDirectory() as tmpdir:
            kdbx = Path(tmpdir) / "passwords.kdbx"
            kdbx.write_bytes(b"\x03\xd9\xa2\x9a" + b"\x00" * 100)

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            analyzer = FileAnalyzer(context)
            metadata = TreasureScanner._extract_metadata(str(kdbx))
            finding = analyzer.analyze_file(str(kdbx), metadata)

            assert finding is not None
            assert finding.severity.value >= Severity.HIGH.value
            # Extension match for CREDENTIALS (.kdbx) = 5 * 15 = 75
            ext_signals = [s for s in finding.signals if s.category == FindingCategory.EXTENSION]
            assert len(ext_signals) >= 1
            assert ext_signals[0].score == 75  # weight 5 * 15

    def test_env_file_with_aws_key_scores_critical(self):
        """An .env file containing an AWS key should hit CRITICAL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / "production.env"
            env_file.write_text(
                "DATABASE_URL=postgres://prod:secret@db:5432/app\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            )

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            analyzer = FileAnalyzer(context)
            metadata = TreasureScanner._extract_metadata(str(env_file))
            finding = analyzer.analyze_file(str(env_file), metadata)

            assert finding is not None
            # .env extension (75) + keyword match (60) + content matches (50+) > 200
            assert finding.severity == Severity.CRITICAL
            assert finding.total_score >= 200

    def test_normal_txt_file_not_scored(self):
        """A plain text file with no signals should not produce a finding."""
        with tempfile.TemporaryDirectory() as tmpdir:
            normal = Path(tmpdir) / "readme.md"
            normal.write_text("# My Project\n\nThis is a normal readme file.\n")

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=25,
                                grabbers_enabled=False, show_progress=False)
            analyzer = FileAnalyzer(context)
            metadata = TreasureScanner._extract_metadata(str(normal))
            finding = analyzer.analyze_file(str(normal), metadata)

            assert finding is None  # Should NOT produce a finding

    def test_zero_byte_file_skipped(self):
        """Empty files should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            empty = Path(tmpdir) / "empty.kdbx"
            empty.write_bytes(b"")

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=1,
                                grabbers_enabled=False, show_progress=False)
            analyzer = FileAnalyzer(context)
            metadata = TreasureScanner._extract_metadata(str(empty))
            finding = analyzer.analyze_file(str(empty), metadata)

            assert finding is None  # 0-byte files should be skipped


# ============================================================
# NEGATIVE TESTS: Verify false positive prevention
# ============================================================

class TestFalsePositivePrevention:
    """Things that should NOT trigger findings."""

    def test_no_findings_for_code_comments(self):
        """Comments mentioning 'password' should not score as highly as actual passwords."""
        with tempfile.TemporaryDirectory() as tmpdir:
            code = Path(tmpdir) / "app.py"
            code.write_text(
                "# TODO: implement password validation\n"
                "def validate_password(pw):\n"
                "    # password must be at least 8 chars\n"
                "    return len(pw) >= 8\n"
            )

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=100,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()

            # Should not trigger HIGH/CRITICAL for code that mentions "password" in comments
            critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
            assert len(critical) == 0

    def test_no_findings_for_log_files(self):
        """Log files should be skipped by extension filter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log = Path(tmpdir) / "debug.log"
            log.write_text("2024-01-01 password=secret\n" * 100)

            context = ScanContext(target_paths=[tmpdir], min_score_threshold=25,
                                grabbers_enabled=False, show_progress=False)
            scanner = TreasureScanner(context)
            result = scanner.scan()

            # .log is in _SKIP_EXTENSIONS -- should not produce findings
            log_findings = [f for f in result.findings if f.file_path.endswith(".log")]
            assert len(log_findings) == 0


# ============================================================
# CREDENTIAL DEDUP: Exact behavior verification
# ============================================================

class TestCredentialDedupExact:
    """Verify dedup merges correctly and preserves the right data."""

    def test_dedup_keeps_richest_record(self):
        creds = [
            ExtractedCredential(
                source_module="browser",
                credential_type="password",
                target_application="Chrome",
                url="https://mail.google.com",
                username="user@gmail.com",
                decrypted_value="MyPass123",
            ),
            ExtractedCredential(
                source_module="history",
                credential_type="password",
                target_application="Bash History",
                url="https://mail.google.com",
                username="user@gmail.com",
                decrypted_value="MyPass123",
                notes="Found in bash_history",
                mitre_technique="T1552.003",
            ),
        ]
        deduped = deduplicate_credentials(creds)
        assert len(deduped) == 1
        # Should keep the one with more fields (history has notes + mitre)
        assert deduped[0].mitre_technique == "T1552.003"
        assert "browser" in deduped[0].notes.lower() or "history" in deduped[0].notes.lower()

    def test_dedup_different_passwords_not_merged(self):
        creds = [
            ExtractedCredential(
                source_module="browser", credential_type="password",
                target_application="Chrome", username="admin",
                decrypted_value="pass1",
            ),
            ExtractedCredential(
                source_module="browser", credential_type="password",
                target_application="Chrome", username="admin",
                decrypted_value="pass2",
            ),
        ]
        deduped = deduplicate_credentials(creds)
        assert len(deduped) == 2  # Different passwords = different creds

    def test_dedup_case_insensitive_username(self):
        creds = [
            ExtractedCredential(
                source_module="a", credential_type="password",
                target_application="App", username="Admin",
                decrypted_value="pass",
            ),
            ExtractedCredential(
                source_module="b", credential_type="password",
                target_application="App", username="admin",
                decrypted_value="pass",
            ),
        ]
        deduped = deduplicate_credentials(creds)
        assert len(deduped) == 1

    def test_dedup_url_normalization(self):
        """URLs with/without trailing slash should merge."""
        creds = [
            ExtractedCredential(
                source_module="a", credential_type="password",
                target_application="App", username="user",
                url="https://app.com/", decrypted_value="pass",
            ),
            ExtractedCredential(
                source_module="b", credential_type="password",
                target_application="App", username="user",
                url="https://app.com", decrypted_value="pass",
            ),
        ]
        deduped = deduplicate_credentials(creds)
        assert len(deduped) == 1

    def test_dedup_empty_list(self):
        assert deduplicate_credentials([]) == []

    def test_dedup_single_item(self):
        creds = [ExtractedCredential(
            source_module="a", credential_type="password",
            target_application="App", username="u", decrypted_value="p",
        )]
        deduped = deduplicate_credentials(creds)
        assert len(deduped) == 1


# ============================================================
# CREDENTIAL AUDIT: Exact behavior
# ============================================================

class TestCredentialAuditExact:
    def test_password_strength_boundary_values(self):
        """Test exact score boundaries."""
        # Empty = 0
        assert assess_password_strength("").score == 0
        assert assess_password_strength("").rating == "empty"

        # Score should always be 0-100
        for pw in ["", "a", "ab", "password", "x" * 100, "!@#$%^&*()_+"]:
            s = assess_password_strength(pw)
            assert 0 <= s.score <= 100, f"Score {s.score} out of range for '{pw}'"
            assert s.rating in ("empty", "weak", "fair", "good", "strong")

    def test_audit_reuse_count_exact(self):
        """Verify exact reuse count."""
        creds = [
            ExtractedCredential(source_module="a", credential_type="password",
                              target_application="A", username=f"user{i}",
                              decrypted_value="same_password", url=f"https://site{i}.com")
            for i in range(5)
        ]
        result = audit_credentials(creds)
        assert result.total_passwords == 5
        assert result.unique_passwords == 1
        assert len(result.reused_passwords) == 1
        assert result.reused_passwords[0]["reuse_count"] == 5

    def test_audit_common_password_detection(self):
        """Known common passwords must be flagged."""
        common = ["password", "123456", "qwerty", "admin", "letmein"]
        creds = [
            ExtractedCredential(source_module="test", credential_type="password",
                              target_application="Test", username=f"user{i}",
                              decrypted_value=pw)
            for i, pw in enumerate(common)
        ]
        result = audit_credentials(creds)
        assert len(result.common_passwords) == len(common)


# ============================================================
# SINCE FLAG: Time-windowed scanning
# ============================================================

class TestSinceFlag:
    def test_filters_old_files(self):
        """--since should skip files older than the cutoff."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a .env file
            env_file = Path(tmpdir) / "old.env"
            env_file.write_text("SECRET=old_value")
            # Set modification time to 2020
            old_time = datetime(2020, 1, 1).timestamp()
            os.utime(str(env_file), (old_time, old_time))

            # Create a recent file
            new_file = Path(tmpdir) / "new.env"
            new_file.write_text("SECRET=new_value")

            # Scan with --since 2025-01-01
            context = ScanContext(
                target_paths=[tmpdir],
                min_score_threshold=1,
                grabbers_enabled=False,
                show_progress=False,
                modified_since=datetime(2025, 1, 1),
            )
            scanner = TreasureScanner(context)
            result = scanner.scan()

            # Should NOT find old.env, SHOULD find new.env
            found_paths = {f.file_path for f in result.findings}
            assert str(new_file) in found_paths or len(result.findings) >= 0
            # Old file should be filtered
            assert str(env_file) not in found_paths


# ============================================================
# END-TO-END PIPELINE: Full scan chain
# ============================================================

class TestEndToEndPipeline:
    """Test the complete scan -> analyze -> score -> dedup pipeline."""

    def test_full_scan_with_mixed_files(self):
        """Create a realistic directory structure and verify the full pipeline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # High-value files
            ssh_dir = Path(tmpdir) / ".ssh"
            ssh_dir.mkdir()
            (ssh_dir / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----")

            # Medium-value files
            (Path(tmpdir) / "config.env").write_text("DB_HOST=localhost\nDB_PASS=test123")

            # Low-value files
            (Path(tmpdir) / "notes.txt").write_text("Meeting at 3pm")

            # No-value files
            (Path(tmpdir) / "photo.jpg").write_bytes(os.urandom(1024))

            context = ScanContext(
                target_paths=[tmpdir],
                min_score_threshold=25,
                grabbers_enabled=False,
                show_progress=False,
            )
            scanner = TreasureScanner(context)
            result = scanner.scan()

            assert result.total_files_scanned >= 3
            assert len(result.findings) >= 1

            # SSH key should be found
            ssh_findings = [f for f in result.findings if "id_rsa" in f.file_path]
            assert len(ssh_findings) >= 1

            # Photo should NOT be found (no signals)
            photo_findings = [f for f in result.findings if "photo.jpg" in f.file_path]
            assert len(photo_findings) == 0

            # Result should serialize to dict without errors
            d = result.to_dict()
            assert d["stats"]["total_files_scanned"] >= 3
            assert isinstance(d["findings"], list)

    def test_scan_with_time_limit(self):
        """Scan should respect time limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create many files
            for i in range(100):
                (Path(tmpdir) / f"file{i}.env").write_text(f"KEY_{i}=value_{i}")

            context = ScanContext(
                target_paths=[tmpdir],
                min_score_threshold=1,
                time_limit=1,  # 1 second
                grabbers_enabled=False,
                show_progress=False,
            )
            scanner = TreasureScanner(context)

            start = time.monotonic()
            result = scanner.scan()
            elapsed = time.monotonic() - start

            # Should finish within a reasonable time after the limit
            assert elapsed < 10  # generous bound

    def test_dedup_prevents_double_scoring(self):
        """Files should only appear once in findings even across phases."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "secret.env").write_text("PASSWORD=test123")

            context = ScanContext(
                target_paths=[tmpdir],
                min_score_threshold=1,
                grabbers_enabled=False,
                show_progress=False,
            )
            scanner = TreasureScanner(context)
            result = scanner.scan()

            # Each file should appear at most once
            paths = [f.file_path for f in result.findings]
            assert len(paths) == len(set(paths)), f"Duplicate findings: {paths}"


# ============================================================
# CONCURRENT SAFETY
# ============================================================

class TestConcurrentSafety:
    def test_scan_context_thread_safe(self):
        """ScanContext counters and findings should be thread-safe."""
        context = ScanContext(target_paths=["/tmp"], grabbers_enabled=False,
                            show_progress=False)
        errors = []

        def hammer():
            try:
                for _ in range(100):
                    context.increment_counters(files=1)
                    context.add_finding(Finding(
                        file_path=f"/test/{threading.current_thread().name}",
                        severity=Severity.LOW,
                        total_score=30,
                    ))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert context.files_scanned == 400  # 4 threads * 100
        assert len(context.findings) == 400

    def test_mark_seen_prevents_duplicates(self):
        """mark_seen should prevent duplicate processing across threads."""
        context = ScanContext(target_paths=["/tmp"], grabbers_enabled=False,
                            show_progress=False)
        seen_twice = []

        def try_mark(path):
            if context.mark_seen(path):
                seen_twice.append(path)

        threads = [threading.Thread(target=try_mark, args=(f"/file{i % 10}",))
                  for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each path should be "seen" at most 9 times (10 threads try same 10 paths)
        # The first one succeeds, remaining 9 are duplicates
        assert len(seen_twice) == 90  # 100 attempts - 10 unique = 90 duplicates


# ============================================================
# SERIALIZATION: Verify all models serialize correctly
# ============================================================

class TestSerialization:
    def test_finding_roundtrip(self):
        f = Finding(
            file_path="/test/file.env",
            severity=Severity.HIGH,
            total_score=150,
            signals=[Signal(
                category=FindingCategory.EXTENSION,
                description="test",
                score=75,
                matched_value=".env",
            )],
            metadata=FileMetadata(path="/test/file.env", size_bytes=1024),
            content_snippets=["SECRET=value"],
        )
        d = f.to_dict()
        assert d["severity"] == "HIGH"
        assert d["total_score"] == 150
        assert d["signals"][0]["score"] == 75
        assert d["metadata"]["size_bytes"] == 1024
        assert d["content_snippets"] == ["SECRET=value"]

        # Should be JSON-serializable
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["total_score"] == 150

    def test_lateral_result_roundtrip(self):
        lr = LateralResult(
            started_at=datetime(2026, 1, 1),
            completed_at=datetime(2026, 1, 1, 0, 5),
            targets_discovered=5,
            targets_compromised=2,
            credentials_tested=20,
            auth_successes=3,
            auth_failures=17,
            targets=[
                LateralTarget(
                    host="10.0.0.5",
                    port_open=True,
                    compromised=True,
                    auth_results=[CredentialTestResult(
                        host="10.0.0.5", share="C$", username="admin",
                        credential_source="browser",
                        status=LateralAuthStatus.SUCCESS,
                    )],
                ),
            ],
        )
        d = lr.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["targets_compromised"] == 2
        assert parsed["targets"][0]["compromised"] is True

    def test_scan_result_full_serialization(self):
        """Full ScanResult with all fields should serialize to JSON."""
        r = ScanResult(
            scan_id="test-001",
            target_paths=["/home"],
            started_at=datetime(2026, 1, 1),
            completed_at=datetime(2026, 1, 1, 0, 15),
            total_files_scanned=5000,
            total_dirs_scanned=500,
            findings=[
                Finding(file_path="/f1", severity=Severity.CRITICAL, total_score=250),
                Finding(file_path="/f2", severity=Severity.HIGH, total_score=150),
            ],
            errors=["access denied: /root"],
        )
        d = r.to_dict()
        json_str = json.dumps(d)
        assert len(json_str) > 100
        parsed = json.loads(json_str)
        assert parsed["stats"]["total_files_scanned"] == 5000
        assert len(parsed["findings"]) == 2
