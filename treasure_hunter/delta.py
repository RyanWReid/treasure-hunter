"""
DELTA SCANNING — Only report new/changed findings on re-scans

Loads a previous JSONL results file as a baseline and filters out
findings that were already reported. Useful for persistent access
scenarios where operators re-scan periodically.

Usage:
    treasure-hunter -p full --baseline previous-results.jsonl
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .models import Finding, ScanResult

logger = logging.getLogger(__name__)


def load_baseline(baseline_path: str) -> set[str]:
    """Load a previous JSONL results file and extract file paths of all findings.

    Returns a set of file paths that were already reported.
    """
    seen_paths: set[str] = set()

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("type") == "finding":
                        file_path = record.get("file_path", "")
                        if file_path:
                            seen_paths.add(file_path)
                    elif record.get("type") == "credential":
                        # Also track credentials by source+app+username
                        key = f"{record.get('source_module', '')}:{record.get('target_application', '')}:{record.get('username', '')}"
                        seen_paths.add(key)
                except json.JSONDecodeError:
                    continue
    except (OSError, ValueError) as e:
        logger.error(f"Failed to load baseline: {e}")

    logger.info(f"Loaded baseline: {len(seen_paths)} known findings")
    return seen_paths


def filter_new_findings(results: ScanResult, baseline: set[str]) -> ScanResult:
    """Filter scan results to only include findings not in the baseline.

    Returns a new ScanResult with only the delta findings.
    """
    new_findings = [
        f for f in results.findings
        if f.file_path not in baseline
    ]

    removed = len(results.findings) - len(new_findings)
    logger.info(f"Delta filter: {len(new_findings)} new findings ({removed} already known)")

    # Create a new ScanResult with filtered findings
    return ScanResult(
        scan_id=results.scan_id + "_delta",
        target_paths=results.target_paths,
        started_at=results.started_at,
        completed_at=results.completed_at,
        total_files_scanned=results.total_files_scanned,
        total_dirs_scanned=results.total_dirs_scanned,
        findings=new_findings,
        errors=results.errors,
        skipped_paths=results.skipped_paths,
        grabber_results=results.grabber_results,
    )
