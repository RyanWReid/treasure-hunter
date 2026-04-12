"""
DETECTION RULES — Value taxonomy and scoring logic

This package contains the core intelligence that defines what makes a file
"valuable" from a red team perspective. The rules are based on real-world
operational experience and focus on Windows corporate environments.

The value taxonomy covers six categories:
1. CREDENTIALS & SECRETS (weight: 5) - Immediate access value
2. INFRASTRUCTURE INTEL (weight: 4) - Lateral movement fuel
3. SENSITIVE DOCUMENTS (weight: 3) - High exfil value
4. SOURCE CODE (weight: 3) - Proprietary IP
5. UNRELEASED SOFTWARE (weight: 4) - Competitive intel
6. BACKUPS & ARCHIVES (weight: 4) - Often contain everything

Each category defines multiple signal types:
- File extensions (e.g., .kdbx, .pem, .rdp)
- Filename keywords (e.g., "password", "credential", "vpn")
- Path patterns (Windows-specific locations)
- Content patterns (regex for file contents)

The scoring is additive - files hitting multiple categories stack scores.
"""

from __future__ import annotations

from .value_taxonomy import (
    ALL_CATEGORIES,
    BACKUPS,
    CATEGORY_MAP,
    CREDENTIALS,
    INFRASTRUCTURE,
    SENSITIVE_DOCUMENTS,
    SOURCE_CODE,
    UNRELEASED_SOFTWARE,
    ValueCategory,
)

__all__ = [
    "ValueCategory",
    "ALL_CATEGORIES",
    "CATEGORY_MAP",
    "CREDENTIALS",
    "INFRASTRUCTURE",
    "SENSITIVE_DOCUMENTS",
    "SOURCE_CODE",
    "UNRELEASED_SOFTWARE",
    "BACKUPS",
]