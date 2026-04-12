"""Tests for grabber utility functions."""

import sqlite3
import tempfile
from pathlib import Path

from treasure_hunter.grabbers.utils import (
    safe_read_binary,
    safe_read_text,
    safe_sqlite_close,
    safe_sqlite_read,
)


class TestSafeSqliteRead:
    def test_reads_unlocked_db(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "test.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE test (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'hello')")
            conn.commit()
            conn.close()

            result = safe_sqlite_read(db_path)
            assert result is not None
            read_conn, tmp_path = result

            rows = read_conn.execute("SELECT * FROM test").fetchall()
            assert len(rows) == 1
            assert rows[0]["name"] == "hello"

            safe_sqlite_close(read_conn, tmp_path)

    def test_returns_none_for_missing_file(self):
        result = safe_sqlite_read("/nonexistent/path/db.sqlite")
        assert result is None

    def test_temp_file_cleaned_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "test.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE t (x INT)")
            conn.commit()
            conn.close()

            result = safe_sqlite_read(db_path)
            assert result is not None
            read_conn, tmp_path = result

            safe_sqlite_close(read_conn, tmp_path)

            # Temp file should be deleted
            assert not Path(tmp_path).exists()

    def test_row_factory_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = str(Path(tmp) / "test.db")
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE t (name TEXT, value TEXT)")
            conn.execute("INSERT INTO t VALUES ('key', 'secret')")
            conn.commit()
            conn.close()

            result = safe_sqlite_read(db_path)
            read_conn, tmp_path = result
            row = read_conn.execute("SELECT * FROM t").fetchone()
            assert row["name"] == "key"
            assert row["value"] == "secret"
            safe_sqlite_close(read_conn, tmp_path)


class TestSafeReadText:
    def test_reads_text_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("hello world")
            path = f.name

        result = safe_read_text(path)
        assert result == "hello world"

        Path(path).unlink()

    def test_returns_none_for_missing(self):
        assert safe_read_text("/nonexistent/file.txt") is None

    def test_respects_max_size(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("x" * 1000)
            path = f.name

        result = safe_read_text(path, max_size=100)
        assert result is None  # File exceeds max_size

        Path(path).unlink()


class TestSafeReadBinary:
    def test_reads_binary_file(self):
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
            f.write(b"\x00\x01\x02\x03")
            path = f.name

        result = safe_read_binary(path)
        assert result == b"\x00\x01\x02\x03"

        Path(path).unlink()

    def test_returns_none_for_missing(self):
        assert safe_read_binary("/nonexistent/file.bin") is None
