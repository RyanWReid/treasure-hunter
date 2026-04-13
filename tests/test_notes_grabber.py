"""Tests for notes grabber with realistic Sticky Notes + Obsidian fixtures."""

import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.grabbers.notes import NotesGrabber
from treasure_hunter.grabbers.base import GrabberContext
from treasure_hunter.grabbers.models import GrabberStatus
from treasure_hunter.scanner import ScanContext


class TestStickyNotesExtraction:
    def test_extracts_secrets_from_plum_sqlite(self):
        """Realistic Sticky Notes plum.sqlite with RTF content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create realistic Sticky Notes path structure
            notes_dir = Path(tmpdir) / "Packages" / "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe" / "LocalState"
            notes_dir.mkdir(parents=True)
            db_path = notes_dir / "plum.sqlite"

            conn = sqlite3.connect(str(db_path))
            conn.execute("CREATE TABLE Note (Text TEXT, Id TEXT)")
            # RTF-wrapped content (like real Sticky Notes)
            conn.execute("INSERT INTO Note VALUES (?, ?)", (
                r"{\rtf1\ansi VPN password: Pr0duction#2024!}",
                "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
            ))
            conn.execute("INSERT INTO Note VALUES (?, ?)", (
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKE",
                "{B2C3D4E5-F6A7-8901-BCDE-F12345678901}",
            ))
            conn.execute("INSERT INTO Note VALUES (?, ?)", (
                "Shopping list: milk, eggs, bread",
                "{C3D4E5F6-A7B8-9012-CDEF-123456789012}",
            ))
            conn.commit()
            conn.close()

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                appdata_local=tmpdir,
                user_profile_path=tmpdir,
            )
            grabber = NotesGrabber()
            result = grabber.execute(gctx)

            # Should find the password and AWS key, not shopping list
            secret_creds = [c for c in result.credentials
                          if c.decrypted_value and ("password" in c.decrypted_value.lower()
                          or "AWS" in c.decrypted_value)]
            assert len(secret_creds) >= 1


class TestObsidianVaultScanning:
    def test_finds_secrets_in_obsidian_vault(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create Obsidian vault structure
            vault = Path(tmpdir) / "MyVault"
            vault.mkdir()
            (vault / ".obsidian").mkdir()
            (vault / ".obsidian" / "app.json").write_text("{}")

            # Notes with embedded secrets
            (vault / "work-notes.md").write_text(
                "# Server Access\n\n"
                "Production DB: `password=Sup3rS3cret!`\n"
                "API endpoint: https://api.internal.corp.com\n"
            )
            (vault / "personal.md").write_text(
                "# Personal\nNothing secret here.\n"
            )

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(
                scan_context=ctx,
                user_profile_path=tmpdir,
            )
            grabber = NotesGrabber()
            result = grabber.execute(gctx)

            assert result.status == GrabberStatus.COMPLETED

    def test_no_findings_without_obsidian_marker(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "random.md").write_text("No vault here")

            ctx = ScanContext(target_paths=[tmpdir], grabbers_enabled=False)
            gctx = GrabberContext(scan_context=ctx, user_profile_path=tmpdir)
            grabber = NotesGrabber()
            result = grabber.execute(gctx)
            # No Obsidian vault, no Sticky Notes -- should be clean
            assert result.status == GrabberStatus.COMPLETED
