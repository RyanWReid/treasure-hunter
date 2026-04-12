"""
Minimal LevelDB log file reader — extract string records from .log and .ldb files.

This is NOT a full LevelDB implementation. It reads the raw log/table files
and extracts ASCII/UTF-8 string sequences that match token patterns.
Slack, Discord, and Teams store auth tokens in LevelDB local storage,
and the tokens are stored as plain strings within the binary data.

This approach avoids needing a LevelDB C library binding.
"""

from __future__ import annotations

import os
import re


def extract_strings_from_leveldb(db_dir: str, min_length: int = 20,
                                  patterns: list[re.Pattern] | None = None) -> list[str]:
    """Extract string matches from LevelDB log and table files.

    Args:
        db_dir: Path to the LevelDB directory (contains .log, .ldb, .sst files)
        min_length: Minimum string length to extract
        patterns: If provided, only return strings matching one of these patterns.
                  If None, return all strings >= min_length.

    Returns: List of matched strings (deduplicated).
    """
    if not os.path.isdir(db_dir):
        return []

    results: list[str] = []
    seen: set[str] = set()

    # Read all LevelDB data files
    for entry in os.scandir(db_dir):
        if not entry.is_file():
            continue
        if not entry.name.endswith((".log", ".ldb", ".sst")):
            continue

        try:
            with open(entry.path, "rb") as f:
                data = f.read(10 * 1024 * 1024)  # 10MB cap per file
        except OSError:
            continue

        # Extract printable ASCII sequences
        for match in re.finditer(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}", data):
            try:
                string = match.group().decode("ascii")
            except UnicodeDecodeError:
                continue

            if string in seen:
                continue

            if patterns:
                for pattern in patterns:
                    if pattern.search(string):
                        seen.add(string)
                        results.append(string)
                        break
            else:
                seen.add(string)
                results.append(string)

    return results
