"""
TREASURE-HUNTER — Red Team File Discovery Tool

A comprehensive file analysis tool designed for red team operations.
Discovers and prioritizes valuable files on target systems using
intelligent scoring based on file types, locations, content patterns,
and metadata signals.

Key Features:
- Multi-threaded scanning with configurable profiles
- Windows-focused value taxonomy covering 6 categories
- Three-phase execution (Recon → Targeted → Sweep)
- JSONL streaming output for crash resilience
- Minimal OPSEC footprint with graceful error handling

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

__version__ = "0.1.0"
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
