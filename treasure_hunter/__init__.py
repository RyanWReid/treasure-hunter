"""
TREASURE-HUNTER — Red Team File Discovery & Credential Extraction Tool

The definitive file discovery tool for red team engagements. Scans target
systems for valuable files, extracts credentials from 16 application types,
and scores findings using 533 detection patterns across 6 value categories.

Key Features:
- 5-phase scanning: Recon -> Targeted -> Grabber -> Lateral Movement -> Sweep
- 16 grabber modules: browser, cloud, remote access, git, dev tools,
  messaging, history, notes, email, wifi, DPAPI, registry, certs,
  clipboard, process memory, session data
- 533 detection patterns across 6 weighted value categories
- Pure-Python AES-CBC/GCM + DPAPI decryption (zero external dependencies)
- Lateral movement: credential reuse against SMB admin shares
- SMB network share discovery and scanning
- Output encryption (AES-256-GCM), exfil staging, delta scanning
- 4 scan profiles: smash (5m), triage (30m), full (2h+), stealth (8h+)
- JSONL streaming output for crash resilience
- Self-contained HTML reports
- Single .exe deployment via Nuitka

Usage:
    from treasure_hunter import TreasureScanner, ScanContext

    context = ScanContext(['C:\\Users'])
    scanner = TreasureScanner(context)
    results = scanner.scan()
"""

from __future__ import annotations

from .cli import main
from .entropy import shannon_entropy, string_entropy, find_high_entropy_strings
from .models import Finding, FileMetadata, ScanResult, Severity, compute_severity
from .reporter import StreamingReporter
from .scanner import ScanContext, TreasureScanner

__version__ = "2.1.0"
__author__ = "treasure-hunter development team"

__all__ = [
    "main",
    "TreasureScanner",
    "ScanContext",
    "StreamingReporter",
    "Finding",
    "FileMetadata",
    "ScanResult",
    "Severity",
    "compute_severity",
    "shannon_entropy",
    "string_entropy",
    "find_high_entropy_strings",
]
