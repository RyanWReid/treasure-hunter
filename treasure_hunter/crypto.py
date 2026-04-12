"""
OUTPUT ENCRYPTION — Protect scan results at rest

Encrypts JSONL output with AES-256-GCM using a passphrase-derived key.
If the operator's USB or workstation is seized, the results file is
protected without the passphrase.

Key derivation: PBKDF2-HMAC-SHA256 (600,000 iterations)
Encryption: AES-256-GCM (from grabbers/_crypto.py)
File format: 16-byte salt + 12-byte nonce + ciphertext + 16-byte tag

Usage:
    # Encrypt during scan
    treasure-hunter --encrypt --passphrase "my secret"

    # Decrypt results later
    treasure-hunter --decrypt results.jsonl.enc --passphrase "my secret"
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

from .grabbers._crypto import aes_gcm_decrypt

# We need AES-GCM encrypt (not just decrypt) — add a minimal wrapper
from .grabbers._crypto import _key_expansion, _aes_encrypt_block, _ghash_multiply, _bytes_to_int, _int_to_bytes, _inc32


def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (ciphertext, tag).

    This is the encrypt counterpart to grabbers/_crypto.aes_gcm_decrypt.
    """
    import hmac as _hmac

    round_keys = _key_expansion(key)

    # H = AES_K(0^128)
    h = _bytes_to_int(_aes_encrypt_block(b"\x00" * 16, round_keys))

    # Initial counter J0 (nonce || 0x00000001)
    j0 = nonce + b"\x00\x00\x00\x01"

    # Encrypt: CTR mode starting from J0+1
    counter = j0
    ciphertext = bytearray()
    for i in range(0, len(plaintext), 16):
        counter = _inc32(counter)
        keystream = _aes_encrypt_block(counter, round_keys)
        block = plaintext[i:i + 16]
        ciphertext.extend(bytes(a ^ b for a, b in zip(block, keystream)))
    ciphertext = bytes(ciphertext[:len(plaintext)])

    # GHASH for tag
    ghash_val = 0
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        ghash_val = _ghash_multiply(ghash_val ^ _bytes_to_int(block), h)

    len_block = struct.pack(">QQ", 0, len(ciphertext) * 8)
    ghash_val = _ghash_multiply(ghash_val ^ _bytes_to_int(len_block), h)

    s = _aes_encrypt_block(j0, round_keys)
    tag = _int_to_bytes(ghash_val ^ _bytes_to_int(s))

    return ciphertext, tag


def derive_key(passphrase: str, salt: bytes, iterations: int = 600_000) -> bytes:
    """Derive a 256-bit key from a passphrase using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)


def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:
    """Encrypt a file with AES-256-GCM using a passphrase.

    Output format: salt(16) + nonce(12) + ciphertext(N) + tag(16)
    """
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext, tag = _aes_gcm_encrypt(key, nonce, plaintext)

    with open(output_path, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)
        f.write(tag)


def decrypt_file(input_path: str, output_path: str, passphrase: str) -> bool:
    """Decrypt a file encrypted with encrypt_file().

    Returns True on success, False on bad passphrase/corrupt file.
    """
    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) < 44:  # 16 salt + 12 nonce + 0 ciphertext + 16 tag minimum
        return False

    salt = data[:16]
    nonce = data[16:28]
    tag = data[-16:]
    ciphertext = data[28:-16]

    key = derive_key(passphrase, salt)
    plaintext = aes_gcm_decrypt(key, nonce, ciphertext, tag)

    if plaintext is None:
        return False

    with open(output_path, "wb") as f:
        f.write(plaintext)

    return True


def encrypt_and_shred(input_path: str, passphrase: str) -> str:
    """Encrypt file in-place and delete the plaintext version.

    Returns the path to the encrypted file (.enc suffix).
    """
    enc_path = input_path + ".enc"
    encrypt_file(input_path, enc_path, passphrase)

    # Overwrite original before deleting (basic anti-forensics)
    try:
        size = os.path.getsize(input_path)
        with open(input_path, "wb") as f:
            f.write(os.urandom(size))
        os.unlink(input_path)
    except OSError:
        # Fallback: just delete
        try:
            os.unlink(input_path)
        except OSError:
            pass

    return enc_path
