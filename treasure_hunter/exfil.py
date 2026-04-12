"""
EXFILTRATION STAGING — Prepare high-value files for extraction

Copies findings above a severity threshold to a staging directory,
optionally compresses into an encrypted archive.

Usage:
    treasure-hunter -p full --stage /tmp/loot           # Stage files
    treasure-hunter -p full --stage /tmp/loot --compress # Stage + zip
    treasure-hunter -p full --stage /tmp/loot --compress --encrypt --passphrase "key"

MITRE ATT&CK: T1074.001 (Local Data Staging), T1560.001 (Archive Collected Data)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from .models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


def stage_findings(results: ScanResult, stage_dir: str,
                   min_severity: Severity = Severity.HIGH,
                   max_total_size: int = 500 * 1024 * 1024) -> dict:
    """Copy high-value files to a staging directory for exfiltration.

    Args:
        results: Scan results containing findings to stage
        stage_dir: Directory to copy files into
        min_severity: Minimum severity to include (default: HIGH)
        max_total_size: Maximum total bytes to stage (default: 500MB)

    Returns:
        Summary dict with staged file count, total size, and manifest
    """
    stage_path = Path(stage_dir)
    stage_path.mkdir(parents=True, exist_ok=True)

    # Sort findings by score (highest first)
    candidates = sorted(
        [f for f in results.findings if f.severity >= min_severity],
        key=lambda f: f.total_score,
        reverse=True,
    )

    staged = []
    total_size = 0
    skipped = 0

    for finding in candidates:
        src = finding.file_path
        if not os.path.isfile(src):
            skipped += 1
            continue

        try:
            file_size = os.path.getsize(src)
        except OSError:
            skipped += 1
            continue

        if total_size + file_size > max_total_size:
            logger.info(f"Staging size limit reached ({max_total_size // (1024*1024)}MB)")
            break

        # Create subdirectory structure based on severity
        severity_dir = stage_path / finding.severity.name.lower()
        severity_dir.mkdir(exist_ok=True)

        # Preserve some path context in the filename
        safe_name = _safe_filename(src)
        dest = severity_dir / safe_name

        # Handle duplicate filenames
        counter = 1
        while dest.exists():
            stem, ext = os.path.splitext(safe_name)
            dest = severity_dir / f"{stem}_{counter}{ext}"
            counter += 1

        try:
            shutil.copy2(src, dest)
            total_size += file_size
            staged.append({
                "source": src,
                "dest": str(dest),
                "size": file_size,
                "severity": finding.severity.name,
                "score": finding.total_score,
            })
        except (OSError, shutil.Error) as e:
            logger.debug(f"Failed to stage {src}: {e}")
            skipped += 1

    # Write manifest
    manifest = {
        "staged_at": datetime.now().isoformat(),
        "scan_id": results.scan_id,
        "min_severity": min_severity.name,
        "total_files": len(staged),
        "total_size_bytes": total_size,
        "total_size_human": _human_size(total_size),
        "skipped": skipped,
        "files": staged,
    }

    manifest_path = stage_path / "MANIFEST.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    logger.info(f"Staged {len(staged)} files ({_human_size(total_size)}) to {stage_dir}")
    return manifest


def compress_staged(stage_dir: str, output_path: str | None = None) -> str:
    """Compress the staging directory into a zip archive.

    Args:
        stage_dir: Directory to compress
        output_path: Path for the zip file (default: stage_dir + .zip)

    Returns:
        Path to the created zip file
    """
    if output_path is None:
        output_path = stage_dir.rstrip("/\\") + ".zip"

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        base = Path(stage_dir)
        for root, dirs, files in os.walk(stage_dir):
            for fname in files:
                full_path = os.path.join(root, fname)
                arcname = os.path.relpath(full_path, base.parent)
                zf.write(full_path, arcname)

    size = os.path.getsize(output_path)
    logger.info(f"Compressed archive: {output_path} ({_human_size(size)})")
    return output_path


def estimate_exfil_size(results: ScanResult,
                        min_severity: Severity = Severity.HIGH) -> dict:
    """Estimate total size of files that would be staged.

    Returns summary without actually copying anything.
    """
    candidates = [f for f in results.findings if f.severity >= min_severity]

    total_size = 0
    file_count = 0
    by_severity: dict[str, int] = {}

    for finding in candidates:
        if not os.path.isfile(finding.file_path):
            continue
        try:
            size = os.path.getsize(finding.file_path)
            total_size += size
            file_count += 1
            sev = finding.severity.name
            by_severity[sev] = by_severity.get(sev, 0) + size
        except OSError:
            continue

    return {
        "total_files": file_count,
        "total_size_bytes": total_size,
        "total_size_human": _human_size(total_size),
        "by_severity": {k: _human_size(v) for k, v in by_severity.items()},
    }


def _safe_filename(path: str) -> str:
    """Convert a full path to a safe filename preserving context."""
    # Take last 2 path components
    parts = Path(path).parts
    if len(parts) >= 2:
        name = f"{parts[-2]}_{parts[-1]}"
    else:
        name = parts[-1] if parts else "unknown"

    # Sanitize
    name = name.replace("\\", "_").replace("/", "_").replace(" ", "_")
    return name[:200]


def _human_size(size: int) -> str:
    """Convert bytes to human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TB"
