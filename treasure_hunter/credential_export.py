"""
CREDENTIAL EXPORT -- Export credentials in operator-friendly formats

Supports:
- CSV (spreadsheet-ready with all fields)
- NetExec format (domain/user:pass@host -- paste into nxc/cme)
- Plaintext user:pass pairs (for hashcat/hydra wordlists)
- JSON (structured, machine-readable)

Usage:
  treasure-hunter -p full --export csv --export-file creds.csv
  treasure-hunter -p full --export netexec --export-file targets.txt
  treasure-hunter -p full --export plaintext --export-file wordlist.txt
"""

from __future__ import annotations

import csv
import json
import os
from io import StringIO
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .grabbers.models import ExtractedCredential


def export_credentials(
    credentials: list[ExtractedCredential],
    format: str,
    output_path: str | None = None,
) -> str:
    """Export credentials in the specified format.

    Returns the formatted string. If output_path is given, also writes to file.
    """
    formatters = {
        "csv": _format_csv,
        "netexec": _format_netexec,
        "nxc": _format_netexec,
        "cme": _format_netexec,
        "plaintext": _format_plaintext,
        "userpass": _format_plaintext,
        "json": _format_json,
    }

    formatter = formatters.get(format.lower())
    if not formatter:
        raise ValueError(f"Unknown format: {format}. Use: csv, netexec, plaintext, json")

    output = formatter(credentials)

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)

    return output


def _format_csv(credentials: list[ExtractedCredential]) -> str:
    """Export as CSV with all fields."""
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "source", "type", "application", "url", "username",
        "password", "has_encrypted", "notes", "mitre", "source_file",
    ])
    for cred in credentials:
        writer.writerow([
            cred.source_module,
            cred.credential_type,
            cred.target_application,
            cred.url,
            cred.username,
            cred.decrypted_value,
            "yes" if cred.encrypted_value else "no",
            cred.notes,
            cred.mitre_technique,
            getattr(cred, "source_file", ""),
        ])
    return buf.getvalue()


def _format_netexec(credentials: list[ExtractedCredential]) -> str:
    """Export in NetExec/CrackMapExec compatible format.

    Format: domain/username:password (one per line)
    Only includes password-type credentials with decrypted values.
    """
    lines = []
    seen = set()

    for cred in credentials:
        if cred.credential_type != "password" or not cred.decrypted_value:
            continue
        if not cred.username:
            continue

        username = cred.username
        password = cred.decrypted_value

        # Parse domain\user format
        if "\\" in username:
            domain, user = username.split("\\", 1)
            entry = f"{domain}/{user}:{password}"
        elif "@" in username:
            entry = f"{username}:{password}"
        else:
            entry = f"{username}:{password}"

        if entry not in seen:
            seen.add(entry)
            lines.append(entry)

    return "\n".join(lines) + "\n" if lines else ""


def _format_plaintext(credentials: list[ExtractedCredential]) -> str:
    """Export as simple user:pass pairs (for wordlists).

    Only includes password-type credentials with decrypted values.
    """
    lines = []
    seen = set()

    for cred in credentials:
        if cred.credential_type != "password" or not cred.decrypted_value:
            continue

        username = cred.username or "unknown"
        password = cred.decrypted_value
        entry = f"{username}:{password}"

        if entry not in seen:
            seen.add(entry)
            lines.append(entry)

    return "\n".join(lines) + "\n" if lines else ""


def _format_json(credentials: list[ExtractedCredential]) -> str:
    """Export as structured JSON array."""
    data = [cred.to_dict() for cred in credentials]
    return json.dumps(data, indent=2) + "\n"
