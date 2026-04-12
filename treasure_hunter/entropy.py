"""
ENTROPY ANALYSIS — Detect high-entropy data indicating secrets or encryption

Shannon entropy measures randomness in data. High entropy (>5.5 for text,
>7.0 for binary) indicates:
- Encrypted files or containers
- Base64-encoded secrets embedded in configs
- Compressed data (archives, packed executables)
- Cryptographic keys / tokens

This module provides both file-level and line-level entropy analysis:
- File-level: quick triage to flag potentially encrypted/compressed files
- Line-level: find individual high-entropy strings in text files (secrets)
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of raw bytes. Returns 0.0-8.0."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def string_entropy(text: str) -> float:
    """Calculate Shannon entropy of a text string. Returns 0.0-~6.5 for ASCII."""
    if not text:
        return 0.0

    length = len(text)
    counts = Counter(text)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def find_high_entropy_strings(content: str,
                               min_length: int = 20,
                               threshold: float = 4.5,
                               max_results: int = 5) -> list[tuple[str, float]]:
    """Find high-entropy substrings in text content.

    Scans each line for tokens that look like secrets:
    - API keys, tokens, passwords assigned in config files
    - Base64-encoded blobs
    - Hex-encoded data

    Returns list of (string, entropy) tuples sorted by entropy descending.
    """
    results = []
    seen: set[str] = set()

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue

        for token in _extract_tokens(line):
            if len(token) < min_length:
                continue
            if token in seen:
                continue

            entropy = string_entropy(token)
            if entropy >= threshold:
                seen.add(token)
                results.append((token[:120], entropy))

            if len(results) >= max_results:
                break

        if len(results) >= max_results:
            break

    results.sort(key=lambda x: x[1], reverse=True)
    return results


def _extract_tokens(line: str) -> list[str]:
    """Extract potential secret tokens from a line of text."""
    tokens = []

    # Split on assignment operators and whitespace
    for delimiter in ['=', ':', '"', "'", ' ', '\t']:
        parts = line.split(delimiter)
        for part in parts:
            part = part.strip().strip('"').strip("'").strip(',').strip(';')
            if len(part) >= 16:
                tokens.append(part)

    return tokens


# Entropy thresholds for different file types
BINARY_HIGH_ENTROPY = 7.0   # Encrypted or compressed binary
TEXT_HIGH_ENTROPY = 5.5      # Unusual for plain text — likely encoded data
STRING_SECRET_ENTROPY = 4.5  # Individual string looks like a secret/key
