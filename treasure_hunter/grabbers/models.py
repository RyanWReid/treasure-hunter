"""Data models for grabber module results."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding


class PrivilegeLevel(enum.Enum):
    """Minimum privilege required to run a grabber module."""

    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"


class GrabberStatus(enum.Enum):
    """Outcome status of a grabber module execution."""

    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class ExtractedCredential:
    """Rich credential data extracted by a grabber module.

    Goes beyond what Finding captures — includes usernames, URLs,
    encrypted blobs for offline cracking, and decrypted cleartext.
    """

    source_module: str
    credential_type: str  # "password", "token", "cookie", "key", "certificate", "credit_card", "pii"
    target_application: str  # "Chrome", "AWS", "FileZilla", etc.
    url: str = ""
    username: str = ""
    encrypted_value: bytes = b""  # raw blob for offline cracking
    decrypted_value: str = ""  # cleartext if decryption succeeded
    notes: str = ""
    mitre_technique: str = ""  # e.g. "T1555.003"
    source_file: str = ""  # file path where credential was found

    @property
    def fingerprint(self) -> str:
        """Content-based hash for deduplication."""
        key = f"{self.username.lower()}:{self.decrypted_value}:{self.url.lower().rstrip('/')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_module": self.source_module,
            "credential_type": self.credential_type,
            "target_application": self.target_application,
            "url": self.url,
            "username": self.username,
            "has_encrypted_value": len(self.encrypted_value) > 0,
            "has_decrypted_value": len(self.decrypted_value) > 0,
            "notes": self.notes,
            "mitre_technique": self.mitre_technique,
            "source_file": self.source_file,
        }


@dataclass
class GrabberResult:
    """Outcome from a single grabber module execution."""

    module_name: str
    status: GrabberStatus = GrabberStatus.COMPLETED
    findings: list[Finding] = field(default_factory=list)
    credentials: list[ExtractedCredential] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "module_name": self.module_name,
            "status": self.status.value,
            "findings_count": len(self.findings),
            "credentials_count": len(self.credentials),
            "credentials": [c.to_dict() for c in self.credentials],
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


def deduplicate_credentials(
    creds: list[ExtractedCredential],
) -> list[ExtractedCredential]:
    """Merge duplicate credentials, preserving the richest record.

    Groups by fingerprint (username + decrypted_value + url). Keeps the
    record with the most populated fields and annotates notes with all
    source modules where the credential was found.
    """
    groups: dict[str, list[ExtractedCredential]] = {}
    for cred in creds:
        fp = cred.fingerprint
        groups.setdefault(fp, []).append(cred)

    deduped: list[ExtractedCredential] = []
    for fp, group in groups.items():
        # Pick the richest record (most non-empty fields)
        def richness(c: ExtractedCredential) -> int:
            return sum(1 for v in (c.url, c.username, c.decrypted_value,
                                   c.notes, c.mitre_technique, c.source_file) if v)
        best = max(group, key=richness)

        # Annotate with all sources
        if len(group) > 1:
            sources = sorted({c.source_module for c in group})
            source_note = f"Found in: {', '.join(sources)}"
            if best.notes:
                best.notes = f"{best.notes}; {source_note}"
            else:
                best.notes = source_note

        deduped.append(best)

    return deduped
