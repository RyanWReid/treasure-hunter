"""
SCANNING ENGINE — Core file discovery and analysis

This is the heart of treasure-hunter. It orchestrates the three-phase scan:
1. RECON: Quick metadata sweep to build priority queues
2. TARGETED: Deep analysis of high-value paths and recent files
3. SWEEP: Comprehensive scan of remaining locations

The engine is designed for speed and OPSEC:
- Uses os.scandir() for fast directory traversal
- Threading pool for I/O-bound operations
- Early termination for time-limited engagements
- Minimal disk writes (JSONL streaming only)
- Graceful error handling to avoid crashes
"""

from __future__ import annotations

import logging
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from queue import PriorityQueue
from typing import Any

from .entropy import (
    BINARY_HIGH_ENTROPY,
    STRING_SECRET_ENTROPY,
    TEXT_HIGH_ENTROPY,
    find_high_entropy_strings,
    shannon_entropy,
)
from .models import Finding, FileMetadata, FindingCategory, Signal, ScanResult, Severity, compute_severity
from .reporter import StreamingReporter
from .rules.value_taxonomy import ALL_CATEGORIES, ValueCategory

logger = logging.getLogger(__name__)


def _compile_category_patterns(categories: list[ValueCategory]) -> dict[str, list[re.Pattern]]:
    """Pre-compile all regex patterns from value categories at import time."""
    compiled = {}
    for cat in categories:
        compiled[cat.name] = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in cat.content_patterns
        ]
    return compiled


def _compile_path_patterns(categories: list[ValueCategory]) -> dict[str, list[re.Pattern]]:
    """Pre-compile path glob patterns converted to regex."""
    compiled = {}
    for cat in categories:
        compiled[cat.name] = [
            re.compile(
                pattern.replace('*', '.*').replace('\\', '\\\\'),
                re.IGNORECASE
            )
            for pattern in cat.path_patterns
        ]
    return compiled


# Build extension sets for O(1) lookup instead of O(n) list scan
_EXTENSION_SETS: dict[str, set[str]] = {
    cat.name: set(cat.extensions) for cat in ALL_CATEGORIES
}

# Pre-compile all regex patterns once at module load
_COMPILED_CONTENT: dict[str, list[re.Pattern]] = _compile_category_patterns(ALL_CATEGORIES)
_COMPILED_PATHS: dict[str, list[re.Pattern]] = _compile_path_patterns(ALL_CATEGORIES)

# Constant sets hoisted out of hot-path methods
_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    '.tmp', '.temp', '.cache', '.log', '.bak~', '.swp',
    '.thumbs.db', '.ds_store', '.desktop.ini',
})

_TEXT_EXTENSIONS: frozenset[str] = frozenset({
    '.txt', '.md', '.csv', '.json', '.xml', '.yml', '.yaml',
    '.ini', '.cfg', '.conf', '.config', '.env', '.log',
    '.sql', '.py', '.js', '.ts', '.cs', '.java', '.go',
    '.rb', '.php', '.ps1', '.sh', '.bat', '.cmd',
    '.htpasswd', '.netrc', '.npmrc', '.pypirc',
    '.rdp', '.ovpn', '.vpn', '.properties', '.toml',
    '.tf', '.tfvars', '.hcl',
})

_HIGH_VALUE_EXTENSIONS: frozenset[str] = frozenset({
    # Password managers
    '.kdbx', '.kdb',
    # Crypto keys & certificates
    '.pem', '.key', '.ppk', '.env', '.pfx', '.p12', '.jks', '.keystore',
    # Remote access
    '.rdp', '.ovpn',
    # Email archives
    '.pst', '.ost',
    # Databases & dumps
    '.sqlite', '.sqlite3', '.db', '.sql', '.bak', '.dump',
    # Infrastructure state
    '.tfstate',
    # Database password files
    '.pgpass', '.mylogin.cnf',
})


class ScanContext:
    """Shared state and configuration for the entire scan operation."""

    def __init__(self,
                 target_paths: list[str],
                 max_threads: int = 8,
                 max_file_size: int = 100 * 1024 * 1024,  # 100MB
                 content_sample_size: int = 8192,  # 8KB
                 time_limit: int | None = None,  # seconds
                 min_score_threshold: int = 25,
                 output_path: str | None = None,
                 grabbers_enabled: bool = True,
                 enabled_grabbers: list[str] | None = None,
                 **_extra: Any):  # Accept extra profile kwargs gracefully
        self.target_paths = target_paths
        self.max_threads = max_threads
        self.max_file_size = max_file_size
        self.content_sample_size = content_sample_size
        self.time_limit = time_limit
        self.min_score_threshold = min_score_threshold
        self.output_path = output_path
        self.grabbers_enabled = grabbers_enabled
        self.enabled_grabbers = enabled_grabbers  # None = all default-enabled

        # Scan state
        self.start_time = datetime.now()
        self.files_scanned = 0
        self.dirs_scanned = 0
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.skipped_paths: list[str] = []

        # Deduplication — tracks files already analyzed to prevent double-scoring
        self._seen_files: set[str] = set()

        # Threading
        self._lock = threading.Lock()

        # Priority path patterns — pre-compiled for performance
        _raw_patterns = [
            r"*\Documents\*",
            r"*\Desktop\*",
            r"*\Downloads\*",
            r"*\.ssh\*",
            r"*\.aws\*",
            r"*\AppData\Roaming\Microsoft\Credentials\*",
            r"*\AppData\Local\Google\Chrome\User Data\*",
            r"*\AppData\Roaming\Mozilla\Firefox\Profiles\*",
            r"*\OneDrive*\*",
        ]
        self.priority_patterns = [
            re.compile(p.replace('*', '.*').replace('\\', '\\\\'), re.IGNORECASE)
            for p in _raw_patterns
        ]

    def should_terminate(self) -> bool:
        """Check if scan should terminate due to time limit."""
        if self.time_limit is None:
            return False
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return elapsed >= self.time_limit

    def mark_seen(self, file_path: str) -> bool:
        """Mark a file as seen. Returns True if already seen (duplicate)."""
        with self._lock:
            if file_path in self._seen_files:
                return True
            self._seen_files.add(file_path)
            return False

    def add_finding(self, finding: Finding) -> None:
        """Thread-safe finding addition."""
        with self._lock:
            self.findings.append(finding)

    def add_error(self, error: str) -> None:
        """Thread-safe error logging."""
        with self._lock:
            self.errors.append(error)
            logger.warning(f"Scan error: {error}")

    def increment_counters(self, files: int = 0, dirs: int = 0) -> None:
        """Thread-safe counter updates."""
        with self._lock:
            self.files_scanned += files
            self.dirs_scanned += dirs


class FileAnalyzer:
    """Analyzes individual files against the value taxonomy."""

    def __init__(self, context: ScanContext):
        self.context = context

    def analyze_file(self, file_path: str, metadata: FileMetadata) -> Finding | None:
        """Analyze a single file and return a Finding if it scores above threshold."""
        signals = []
        total_score = 0

        # Quick rejection for obviously uninteresting files
        if self._should_skip_file(file_path, metadata):
            return None

        # Analyze against each value category
        for category in ALL_CATEGORIES:
            category_signals = self._analyze_category(file_path, metadata, category)
            signals.extend(category_signals)
            total_score += sum(s.score for s in category_signals)

        # Add recency bonus (files modified in last 30 days get extra points)
        if metadata.modified and metadata.modified > datetime.now() - timedelta(days=30):
            recency_signal = Signal(
                category=FindingCategory.RECENCY,
                description="Recently modified file",
                score=10 + (5 if metadata.modified > datetime.now() - timedelta(days=7) else 0),
                matched_value=metadata.modified.strftime("%Y-%m-%d")
            )
            signals.append(recency_signal)
            total_score += recency_signal.score

        # Only create finding if above threshold
        if total_score < self.context.min_score_threshold:
            return None

        # Content analysis — contributes to score AND extracts snippets
        content_snippets = []
        if total_score >= 50 and metadata.size_bytes <= self.context.max_file_size:
            content_signals, content_snippets = self._analyze_content(file_path, metadata)
            signals.extend(content_signals)
            total_score += sum(s.score for s in content_signals)

        # Re-check threshold after content analysis
        if total_score < self.context.min_score_threshold:
            return None

        severity = compute_severity(total_score)

        return Finding(
            file_path=file_path,
            severity=severity,
            total_score=total_score,
            signals=signals,
            metadata=metadata,
            content_snippets=content_snippets
        )

    def _should_skip_file(self, file_path: str, metadata: FileMetadata) -> bool:
        """Quick filtering to skip obviously uninteresting files."""
        if metadata.size_bytes == 0:
            return True
        if metadata.size_bytes > self.context.max_file_size:
            return True
        if metadata.extension.lower() in _SKIP_EXTENSIONS:
            return True
        return False

    def _analyze_category(self, file_path: str, metadata: FileMetadata,
                         category: ValueCategory) -> list[Signal]:
        """Analyze file against a specific value category."""
        signals = []

        # Extension matching — O(1) set lookup
        if metadata.extension.lower() in _EXTENSION_SETS[category.name]:
            signals.append(Signal(
                category=FindingCategory.EXTENSION,
                description=f"{category.name}: {metadata.extension} file",
                score=category.base_weight * 15,
                matched_value=metadata.extension
            ))

        # Filename keyword matching
        filename_lower = Path(file_path).stem.lower()
        for keyword in category.filename_keywords:
            if keyword.lower() in filename_lower:
                signals.append(Signal(
                    category=FindingCategory.KEYWORD,
                    description=f"{category.name}: filename contains '{keyword}'",
                    score=category.base_weight * 12,
                    matched_value=keyword
                ))
                break  # Only score once per category

        # Path pattern matching — pre-compiled regex
        for compiled_re in _COMPILED_PATHS[category.name]:
            if compiled_re.search(file_path):
                signals.append(Signal(
                    category=FindingCategory.METADATA,
                    description=f"{category.name}: located in high-value path",
                    score=category.base_weight * 20,
                    matched_value=compiled_re.pattern
                ))
                break

        return signals

    def _analyze_content(self, file_path: str, metadata: FileMetadata) -> tuple[list[Signal], list[str]]:
        """Analyze file content for pattern matches and entropy. Returns (signals, snippets)."""
        signals: list[Signal] = []
        snippets: list[str] = []

        is_text = self._is_text_file(metadata.extension)

        # Binary entropy check for non-text files (encrypted/compressed detection)
        if not is_text:
            try:
                with open(file_path, 'rb') as f:
                    sample = f.read(min(4096, metadata.size_bytes))
                ent = shannon_entropy(sample)
                if ent >= BINARY_HIGH_ENTROPY:
                    signals.append(Signal(
                        category=FindingCategory.ENTROPY,
                        description=f"High binary entropy ({ent:.2f}) — likely encrypted/compressed",
                        score=20,
                        matched_value=f"entropy={ent:.2f}"
                    ))
            except OSError:
                pass
            return signals, snippets

        # Text content analysis
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(self.context.content_sample_size)
        except OSError as e:
            logger.debug(f"Content read failed for {file_path}: {e}")
            return signals, snippets

        # Regex pattern matching against value taxonomy
        categories_matched: set[str] = set()
        for category in ALL_CATEGORIES:
            for compiled_re in _COMPILED_CONTENT[category.name]:
                match = compiled_re.search(content)
                if match:
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    snippet = content[start:end].strip()
                    if snippet and len(snippet) > 10:
                        snippets.append(snippet)

                    if category.name not in categories_matched:
                        categories_matched.add(category.name)
                        signals.append(Signal(
                            category=FindingCategory.CONTENT,
                            description=f"{category.name}: content pattern match",
                            score=category.base_weight * 10,
                            matched_value=snippet[:80] if snippet else ""
                        ))

                if len(snippets) >= 5:
                    return signals, snippets

        # Entropy analysis — find high-entropy strings (likely secrets/keys)
        high_entropy_strings = find_high_entropy_strings(
            content,
            threshold=STRING_SECRET_ENTROPY,
            max_results=3
        )
        for secret_str, ent in high_entropy_strings:
            signals.append(Signal(
                category=FindingCategory.ENTROPY,
                description=f"High-entropy string ({ent:.2f}) — potential secret",
                score=15,
                matched_value=secret_str[:60]
            ))
            snippets.append(secret_str[:80])

        return signals, snippets

    @staticmethod
    def _is_text_file(extension: str) -> bool:
        """Check if file extension suggests text content."""
        return extension.lower() in _TEXT_EXTENSIONS


class TreasureScanner:
    """Main scanning engine that orchestrates the three-phase scan."""

    def __init__(self, context: ScanContext):
        self.context = context
        self.analyzer = FileAnalyzer(context)
        self._priority_counter = 0  # Tiebreaker for PriorityQueue comparison

    def scan(self) -> ScanResult:
        """Execute the complete three-phase scan."""
        scan_id = f"scan_{int(datetime.now().timestamp())}"

        logger.info(f"Starting treasure scan {scan_id}")
        logger.info(f"Targets: {self.context.target_paths}")
        logger.info(f"Time limit: {self.context.time_limit}s" if self.context.time_limit else "No time limit")

        # Start real-time streaming reporter if output path is configured
        if self.context.output_path:
            self._reporter = StreamingReporter(
                self.context.output_path, scan_id, self.context.target_paths
            )
            self._reporter.start()
        else:
            self._reporter = None

        self._grabber_context = None

        try:
            # Phase 1: Recon - build priority queues
            priority_files = self._recon_phase()

            # Phase 2: Targeted - analyze high-value paths first
            if not self.context.should_terminate():
                self._targeted_phase(priority_files)

            # Phase 2.5: Grabber extraction (credential harvesting)
            if not self.context.should_terminate() and self.context.grabbers_enabled:
                self._grabber_phase()

            # Phase 3: Sweep - comprehensive scan of remaining paths
            if not self.context.should_terminate():
                self._sweep_phase()

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.context.add_error(f"Critical scan failure: {e}")

        completed_at = datetime.now()

        # Collect grabber results
        grabber_results = []
        if self._grabber_context:
            grabber_results = getattr(self, "_grabber_results", [])

        result = ScanResult(
            scan_id=scan_id,
            target_paths=self.context.target_paths,
            started_at=self.context.start_time,
            completed_at=completed_at,
            total_files_scanned=self.context.files_scanned,
            total_dirs_scanned=self.context.dirs_scanned,
            findings=self.context.findings,
            errors=self.context.errors,
            skipped_paths=self.context.skipped_paths,
            grabber_results=grabber_results,
        )

        # Finalize streaming output
        if self._reporter:
            self._reporter.stop(result)

        return result

    def _recon_phase(self) -> PriorityQueue:
        """Phase 1: Quick metadata sweep to identify high-value targets."""
        logger.info("Phase 1: Reconnaissance")

        priority_queue = PriorityQueue()

        with ThreadPoolExecutor(max_workers=self.context.max_threads) as executor:
            futures = []

            for target_path in self.context.target_paths:
                if os.path.exists(target_path):
                    future = executor.submit(self._recon_directory, target_path, priority_queue)
                    futures.append(future)

            # Wait for all recon tasks to complete
            for future in as_completed(futures):
                if self.context.should_terminate():
                    break
                try:
                    future.result()
                except Exception as e:
                    self.context.add_error(f"Recon failed: {e}")

        logger.info(f"Recon complete: {priority_queue.qsize()} priority files identified")
        return priority_queue

    def _recon_directory(self, dir_path: str, priority_queue: PriorityQueue) -> None:
        """Recursively scan directory for high-value file metadata."""
        try:
            with os.scandir(dir_path) as entries:
                for entry in entries:
                    if self.context.should_terminate():
                        break

                    try:
                        if entry.is_file(follow_symlinks=False):
                            metadata = self._extract_metadata(entry.path)
                            priority_score = self._calculate_priority(entry.path, metadata)
                            if priority_score > 0:
                                # (neg_score, counter, path, metadata) — counter breaks ties
                                self._priority_counter += 1
                                priority_queue.put((-priority_score, self._priority_counter, entry.path, metadata))

                        elif entry.is_dir(follow_symlinks=False):
                            self.context.increment_counters(dirs=1)
                            # Recurse into subdirectory
                            self._recon_directory(entry.path, priority_queue)

                    except (PermissionError, OSError) as e:
                        logger.debug(f"Skipping {entry.path}: {e}")
                        continue

        except (PermissionError, OSError) as e:
            self.context.add_error(f"Cannot access directory {dir_path}: {e}")

    def _targeted_phase(self, priority_files: PriorityQueue) -> None:
        """Phase 2: Analyze high-priority files in parallel."""
        logger.info("Phase 2: Targeted Analysis")

        with ThreadPoolExecutor(max_workers=self.context.max_threads) as executor:
            futures = []

            # Process priority files first
            while not priority_files.empty() and not self.context.should_terminate():
                try:
                    priority_score, _counter, file_path, metadata = priority_files.get_nowait()
                    future = executor.submit(self._analyze_and_store, file_path, metadata)
                    futures.append(future)

                    # Limit concurrent analysis to prevent memory issues
                    if len(futures) >= self.context.max_threads * 2:
                        self._wait_for_completion(futures[:self.context.max_threads])
                        futures = futures[self.context.max_threads:]

                except Exception as e:
                    logger.debug(f"Priority analysis error: {e}")
                    continue

            # Wait for remaining analyses to complete
            self._wait_for_completion(futures)

    def _grabber_phase(self) -> None:
        """Phase 2.5: Execute grabber modules to extract credential data."""
        from .grabbers import GrabberContext, GrabberRegistry

        logger.info("Phase 2.5: Grabber Extraction")

        self._grabber_context = GrabberContext.from_scan_context(self.context)
        registry = GrabberRegistry()
        modules = registry.get_enabled_modules(
            self._grabber_context,
            enabled_names=self.context.enabled_grabbers,
        )

        if not modules:
            logger.info("No grabber modules available for this platform/context")
            return

        logger.info(f"Running {len(modules)} grabber modules")
        self._grabber_results = []

        for module in modules:
            if self.context.should_terminate():
                break

            logger.info(f"Running grabber: {module.name}")
            result = module.run(self._grabber_context)
            self._grabber_results.append(result)

            # Feed grabber findings into the main findings pipeline
            for finding in result.findings:
                if not self.context.mark_seen(finding.file_path):
                    self.context.add_finding(finding)
                    if self._reporter:
                        self._reporter.emit_finding(finding)

            # Stream extracted credentials
            for cred in result.credentials:
                self._grabber_context.add_credentials([cred])
                if self._reporter:
                    self._reporter.emit_credential(cred.to_dict())

            if result.errors:
                for error in result.errors:
                    self.context.add_error(f"[{module.name}] {error}")

        total_creds = len(self._grabber_context.all_credentials)
        logger.info(f"Grabber phase complete: {total_creds} credentials extracted")

    def _sweep_phase(self) -> None:
        """Phase 3: Comprehensive scan of all remaining locations."""
        logger.info("Phase 3: Comprehensive Sweep")

        with ThreadPoolExecutor(max_workers=self.context.max_threads) as executor:
            futures = []
            for target_path in self.context.target_paths:
                if self.context.should_terminate():
                    break

                if os.path.exists(target_path):
                    futures.append(executor.submit(self._sweep_directory, target_path))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.context.add_error(f"Sweep task failed: {e}")

    def _sweep_directory(self, dir_path: str) -> None:
        """Comprehensively scan directory for any missed files."""
        try:
            with os.scandir(dir_path) as entries:
                for entry in entries:
                    if self.context.should_terminate():
                        break

                    try:
                        if entry.is_file(follow_symlinks=False):
                            metadata = self._extract_metadata(entry.path)
                            self._analyze_and_store(entry.path, metadata)

                        elif entry.is_dir(follow_symlinks=False):
                            self._sweep_directory(entry.path)

                    except (PermissionError, OSError):
                        continue

        except (PermissionError, OSError) as e:
            self.context.add_error(f"Sweep failed for {dir_path}: {e}")

    def _analyze_and_store(self, file_path: str, metadata: FileMetadata) -> None:
        """Analyze file and store finding if significant. Skips duplicates."""
        try:
            if self.context.mark_seen(file_path):
                return

            self.context.increment_counters(files=1)

            finding = self.analyzer.analyze_file(file_path, metadata)
            if finding:
                self.context.add_finding(finding)
                # Stream to disk in real-time for crash resilience
                if self._reporter:
                    self._reporter.emit_finding(finding)
                logger.debug(f"Finding: {file_path} (score: {finding.total_score})")

        except Exception as e:
            self.context.add_error(f"Analysis failed for {file_path}: {e}")

    @staticmethod
    def _extract_metadata(file_path: str) -> FileMetadata:
        """Extract file metadata efficiently with platform-aware owner/hidden detection."""
        try:
            stat_info = os.stat(file_path)
            path_obj = Path(file_path)
            name = path_obj.name

            # Platform-aware hidden file detection
            is_hidden = name.startswith('.')
            if os.name == 'nt':
                try:
                    import ctypes
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
                    if attrs != -1:
                        is_hidden = bool(attrs & 0x2)  # FILE_ATTRIBUTE_HIDDEN
                except (AttributeError, OSError):
                    pass

            # Platform-aware owner
            owner = ""
            if os.name == 'nt':
                # On Windows, try to get the file owner via SID
                try:
                    import ctypes
                    import ctypes.wintypes
                    # Simplified — full SID resolution is expensive; just note the UID
                    owner = f"sid:{stat_info.st_uid}" if hasattr(stat_info, 'st_uid') else ""
                except (ImportError, AttributeError):
                    pass
            else:
                owner = f"{stat_info.st_uid}:{stat_info.st_gid}"

            return FileMetadata(
                path=file_path,
                size_bytes=stat_info.st_size,
                created=datetime.fromtimestamp(stat_info.st_ctime),
                modified=datetime.fromtimestamp(stat_info.st_mtime),
                accessed=datetime.fromtimestamp(stat_info.st_atime),
                owner=owner,
                is_hidden=is_hidden,
                extension=path_obj.suffix
            )

        except OSError:
            return FileMetadata(
                path=file_path,
                extension=Path(file_path).suffix
            )

    def _calculate_priority(self, file_path: str, metadata: FileMetadata) -> int:
        """Calculate priority score for file during recon phase."""
        score = 0

        if metadata.extension.lower() in _HIGH_VALUE_EXTENSIONS:
            score += 100

        # Priority path patterns (pre-compiled)
        for compiled_re in self.context.priority_patterns:
            if compiled_re.search(file_path):
                score += 50
                break

        # Recent files get priority
        if metadata.modified and metadata.modified > datetime.now() - timedelta(days=7):
            score += 25

        return score

    def _wait_for_completion(self, futures: list) -> None:
        """Wait for futures to complete."""
        for future in as_completed(futures):
            if self.context.should_terminate():
                break
            try:
                future.result()
            except Exception as e:
                logger.debug(f"Analysis task failed: {e}")