"""
REPORTER — Real-time JSONL streaming output

Writes findings to disk as they're discovered, not just at completion.
This provides crash resilience: if the scan is interrupted, all findings
discovered up to that point are preserved in the output file.

The reporter uses a background thread to batch writes and minimize
disk I/O impact on scan performance.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue

from .models import Finding, ScanResult

logger = logging.getLogger(__name__)


class StreamingReporter:
    """Writes findings to JSONL as they arrive, with flush batching."""

    def __init__(self, output_path: str, scan_id: str, target_paths: list[str]):
        self.output_path = Path(output_path)
        self.scan_id = scan_id
        self.target_paths = target_paths

        self._queue: Queue[dict | None] = Queue()
        self._thread: threading.Thread | None = None
        self._started = False
        self._finding_count = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the streaming writer and emit the scan header."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write header synchronously before starting the background thread
        header = {
            'type': 'scan_start',
            'scan_id': self.scan_id,
            'started_at': datetime.now().isoformat(),
            'target_paths': self.target_paths,
        }
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(header) + '\n')

        self._started = True
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()

    def emit_finding(self, finding: Finding) -> None:
        """Queue a finding for writing. Thread-safe."""
        if not self._started:
            return

        with self._lock:
            self._finding_count += 1

        self._queue.put({
            'type': 'finding',
            **finding.to_dict()
        })

    def emit_credential(self, credential_dict: dict) -> None:
        """Queue an extracted credential for writing. Thread-safe."""
        if not self._started:
            return

        self._queue.put({
            'type': 'credential',
            **credential_dict
        })

    def emit_lateral_attempt(self, attempt_dict: dict) -> None:
        """Queue a lateral movement auth attempt for writing. Thread-safe."""
        if not self._started:
            return

        self._queue.put({
            'type': 'lateral_attempt',
            **attempt_dict,
        })

    def emit_lateral_success(self, success_dict: dict) -> None:
        """Queue a lateral movement success event for writing. Thread-safe."""
        if not self._started:
            return

        self._queue.put({
            'type': 'lateral_success',
            **success_dict,
        })

    def emit_lateral_summary(self, summary_dict: dict) -> None:
        """Queue the lateral movement phase summary for writing. Thread-safe."""
        if not self._started:
            return

        self._queue.put({
            'type': 'lateral_summary',
            **summary_dict,
        })

    def stop(self, results: ScanResult) -> None:
        """Flush remaining findings and write the final summary."""
        if not self._started:
            return

        # Signal the writer thread to stop
        self._queue.put(None)
        if self._thread:
            self._thread.join(timeout=10)

        # Write final summary
        summary = {
            'type': 'scan_complete',
            'scan_id': self.scan_id,
            'completed_at': results.completed_at.isoformat() if results.completed_at else None,
            'stats': {
                'total_files_scanned': results.total_files_scanned,
                'total_dirs_scanned': results.total_dirs_scanned,
                'total_findings': len(results.findings),
                'critical': len([f for f in results.findings if f.severity.value >= 5]),
                'high': len([f for f in results.findings if f.severity.value >= 4]),
                'medium': len([f for f in results.findings if f.severity.value >= 3]),
                'low': len([f for f in results.findings if f.severity.value >= 2]),
            },
            'errors': results.errors[:50] if results.errors else [],
        }

        try:
            with open(self.output_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(summary) + '\n')
        except OSError as e:
            logger.error(f"Failed to write scan summary: {e}")

        self._started = False

    def _writer_loop(self) -> None:
        """Background thread that drains the queue and writes to disk."""
        try:
            with open(self.output_path, 'a', encoding='utf-8') as f:
                while True:
                    try:
                        item = self._queue.get(timeout=1.0)
                    except Empty:
                        continue

                    if item is None:
                        # Poison pill — flush and exit
                        f.flush()
                        break

                    f.write(json.dumps(item) + '\n')

                    # Flush periodically (every 10 findings)
                    if self._queue.empty() or self._finding_count % 10 == 0:
                        f.flush()

        except OSError as e:
            logger.error(f"Streaming writer failed: {e}")
