"""Tests for output encryption/decryption (AES-256-GCM + PBKDF2)."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from treasure_hunter.crypto import derive_key, encrypt_file, decrypt_file


class TestKeyDerivation:
    def test_derives_32_byte_key(self):
        salt = os.urandom(16)
        key = derive_key("my-passphrase", salt)
        assert len(key) == 32

    def test_same_passphrase_same_salt_same_key(self):
        salt = os.urandom(16)
        key1 = derive_key("test", salt)
        key2 = derive_key("test", salt)
        assert key1 == key2

    def test_different_passphrase_different_key(self):
        salt = os.urandom(16)
        key1 = derive_key("passphrase-a", salt)
        key2 = derive_key("passphrase-b", salt)
        assert key1 != key2

    def test_different_salt_different_key(self):
        salt1 = os.urandom(16)
        salt2 = os.urandom(16)
        key1 = derive_key("same-pass", salt1)
        key2 = derive_key("same-pass", salt2)
        assert key1 != key2


class TestEncryptDecrypt:
    def test_roundtrip_small_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plain_path = Path(tmpdir) / "results.jsonl"
            enc_path = Path(tmpdir) / "results.jsonl.enc"
            dec_path = Path(tmpdir) / "results.jsonl.dec"

            content = '{"type":"finding","severity":"HIGH"}\n'
            plain_path.write_text(content)

            encrypt_file(str(plain_path), str(enc_path), "test-passphrase")
            assert enc_path.exists()
            assert enc_path.stat().st_size > 0
            assert enc_path.read_bytes() != content.encode()

            result = decrypt_file(str(enc_path), str(dec_path), "test-passphrase")
            assert result is True
            assert dec_path.read_text() == content

    def test_roundtrip_larger_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plain_path = Path(tmpdir) / "large.jsonl"
            enc_path = Path(tmpdir) / "large.jsonl.enc"
            dec_path = Path(tmpdir) / "large.jsonl.dec"

            line = json.dumps({"type": "finding", "data": "x" * 200}) + "\n"
            content = line * 500  # ~100KB
            plain_path.write_text(content)

            encrypt_file(str(plain_path), str(enc_path), "big-passphrase")
            result = decrypt_file(str(enc_path), str(dec_path), "big-passphrase")
            assert result is True
            assert dec_path.read_text() == content

    def test_wrong_passphrase_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plain_path = Path(tmpdir) / "secret.txt"
            enc_path = Path(tmpdir) / "secret.enc"
            dec_path = Path(tmpdir) / "secret.dec"

            plain_path.write_text("top secret data")
            encrypt_file(str(plain_path), str(enc_path), "correct-pass")

            result = decrypt_file(str(enc_path), str(dec_path), "wrong-pass")
            assert result is False

    def test_encrypt_nonexistent_file(self):
        with pytest.raises((FileNotFoundError, OSError)):
            encrypt_file("/nonexistent/file.txt", "/tmp/out.enc", "pass")
