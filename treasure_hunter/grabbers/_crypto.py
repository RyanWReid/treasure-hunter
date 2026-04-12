"""
Vendored cryptographic primitives — zero external dependencies.

Provides:
- AES-CBC decrypt (for mRemoteNG, WinSCP)
- AES-GCM decrypt (for Chrome 80+ passwords)
- DPAPI CryptUnprotectData wrapper (Windows only, via ctypes)
- PKCS7 unpadding

These are intentionally minimal implementations optimized for correctness
over performance. Chrome password DBs are small (<500 entries), so
pure-Python crypto is fast enough.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AES S-Box and helpers (shared by CBC and GCM)
# ---------------------------------------------------------------------------

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_INV_SBOX = tuple(_SBOX.index(i) for i in range(256))

_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _mix_column(col: list[int]) -> list[int]:
    t = col[0] ^ col[1] ^ col[2] ^ col[3]
    u = col[0]
    col[0] ^= _xtime(col[0] ^ col[1]) ^ t
    col[1] ^= _xtime(col[1] ^ col[2]) ^ t
    col[2] ^= _xtime(col[2] ^ col[3]) ^ t
    col[3] ^= _xtime(col[3] ^ u) ^ t
    return col


def _inv_mix_column(col: list[int]) -> list[int]:
    u = _xtime(_xtime(col[0] ^ col[2]))
    v = _xtime(_xtime(col[1] ^ col[3]))
    col[0] ^= u
    col[1] ^= v
    col[2] ^= u
    col[3] ^= v
    return _mix_column(col)


def _key_expansion(key: bytes) -> list[list[int]]:
    nk = len(key) // 4
    nr = nk + 6
    w: list[list[int]] = []
    for i in range(nk):
        w.append(list(key[4 * i:4 * i + 4]))
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = [_SBOX[temp[1]] ^ _RCON[i // nk - 1], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w


def _aes_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    nr = len(round_keys) // 4 - 1
    state = [list(block[i:i + 4]) for i in range(0, 16, 4)]

    # AddRoundKey
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_keys[i][j]

    for rnd in range(1, nr + 1):
        # SubBytes
        for i in range(4):
            for j in range(4):
                state[i][j] = _SBOX[state[i][j]]

        # ShiftRows
        for i in range(1, 4):
            state[i] = state[i][i:] + state[i][:i]

        # MixColumns (skip last round)
        if rnd < nr:
            for i in range(4):
                col = [state[j][i] for j in range(4)]
                col = _mix_column(col)
                for j in range(4):
                    state[j][i] = col[j]

        # AddRoundKey
        rk_offset = rnd * 4
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_keys[rk_offset + i][j]

    result = bytearray(16)
    for i in range(4):
        for j in range(4):
            result[i + j * 4] = state[i][j]
    return bytes(result)


def _aes_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    nr = len(round_keys) // 4 - 1
    # Convert block to state (column-major)
    state = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = block[i + j * 4]

    # AddRoundKey (last round key)
    rk_offset = nr * 4
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_keys[rk_offset + i][j]

    for rnd in range(nr - 1, -1, -1):
        # InvShiftRows
        for i in range(1, 4):
            state[i] = state[i][4 - i:] + state[i][:4 - i]

        # InvSubBytes
        for i in range(4):
            for j in range(4):
                state[i][j] = _INV_SBOX[state[i][j]]

        # AddRoundKey
        rk_offset = rnd * 4
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_keys[rk_offset + i][j]

        # InvMixColumns (skip round 0)
        if rnd > 0:
            for i in range(4):
                col = [state[j][i] for j in range(4)]
                col = _inv_mix_column(col)
                for j in range(4):
                    state[j][i] = col[j]

    result = bytearray(16)
    for i in range(4):
        for j in range(4):
            result[i + j * 4] = state[i][j]
    return bytes(result)


# ---------------------------------------------------------------------------
# PKCS7 padding
# ---------------------------------------------------------------------------

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding. Raises ValueError on bad padding."""
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Bad padding: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# AES-CBC
# ---------------------------------------------------------------------------

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-CBC with PKCS7 unpadding. Key must be 16/24/32 bytes."""
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Invalid key length: {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"Invalid IV length: {len(iv)}")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext not block-aligned")

    round_keys = _key_expansion(key)
    plaintext = bytearray()
    prev = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted = _aes_decrypt_block(block, round_keys)
        plaintext.extend(bytes(a ^ b for a, b in zip(decrypted, prev)))
        prev = block

    return pkcs7_unpad(bytes(plaintext))


# ---------------------------------------------------------------------------
# AES-GCM (for Chrome 80+ password decryption)
# ---------------------------------------------------------------------------

def _ghash_multiply(x: int, y: int) -> int:
    """GF(2^128) multiplication for GHASH."""
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        if x & 1:
            x = (x >> 1) ^ (0xE1 << 120)
        else:
            x >>= 1
    return z


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(n: int, length: int = 16) -> bytes:
    return n.to_bytes(length, "big")


def _inc32(counter: bytes) -> bytes:
    """Increment the rightmost 32 bits of a 128-bit counter."""
    prefix = counter[:12]
    ctr = int.from_bytes(counter[12:], "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
    """Decrypt AES-256-GCM. Returns plaintext or None if tag verification fails.

    Args:
        key: 16/32 byte AES key
        nonce: 12 byte nonce (IV)
        ciphertext: encrypted data (without tag)
        tag: 16 byte authentication tag
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Invalid key length: {len(key)}")
    if len(nonce) != 12:
        raise ValueError(f"Invalid nonce length: {len(nonce)}")
    if len(tag) != 16:
        raise ValueError(f"Invalid tag length: {len(tag)}")

    round_keys = _key_expansion(key)

    # H = AES_K(0^128)
    h = _bytes_to_int(_aes_encrypt_block(b"\x00" * 16, round_keys))

    # Initial counter J0 (nonce || 0x00000001)
    j0 = nonce + b"\x00\x00\x00\x01"

    # Decrypt: CTR mode starting from J0+1
    counter = j0
    plaintext = bytearray()
    for i in range(0, len(ciphertext), 16):
        counter = _inc32(counter)
        keystream = _aes_encrypt_block(counter, round_keys)
        block = ciphertext[i:i + 16]
        plaintext.extend(bytes(a ^ b for a, b in zip(block, keystream)))
    plaintext = bytes(plaintext[:len(ciphertext)])

    # GHASH for tag verification
    # GHASH(H, A, C) where A = "" (no additional data), C = ciphertext
    ghash_val = 0
    # Process ciphertext blocks
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        ghash_val = _ghash_multiply(ghash_val ^ _bytes_to_int(block), h)

    # Length block: len(A) || len(C) in bits
    len_block = struct.pack(">QQ", 0, len(ciphertext) * 8)
    ghash_val = _ghash_multiply(ghash_val ^ _bytes_to_int(len_block), h)

    # T = GHASH XOR AES_K(J0)
    s = _aes_encrypt_block(j0, round_keys)
    computed_tag = _int_to_bytes(ghash_val ^ _bytes_to_int(s))

    # Constant-time tag comparison
    if not hmac.compare_digest(computed_tag, tag):
        logger.debug("AES-GCM tag mismatch — data may be corrupt")
        return None

    return plaintext


# ---------------------------------------------------------------------------
# DPAPI wrapper (Windows only)
# ---------------------------------------------------------------------------

def dpapi_decrypt(encrypted: bytes) -> bytes | None:
    """Decrypt DPAPI-protected data in current user context (Windows only).

    Uses CryptUnprotectData via ctypes. Returns None on failure or non-Windows.
    """
    if os.name != "nt":
        return None

    try:
        import ctypes
        import ctypes.wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char)),
            ]

        blob_in = DATA_BLOB(
            len(encrypted),
            ctypes.create_string_buffer(encrypted, len(encrypted)),
        )
        blob_out = DATA_BLOB()

        result = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in),
            None,  # description
            None,  # optional entropy
            None,  # reserved
            None,  # prompt struct
            0,     # flags
            ctypes.byref(blob_out),
        )

        if result:
            data = ctypes.string_at(blob_out.pbData, blob_out.cbData)
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            return data

        return None

    except (AttributeError, OSError) as e:
        logger.debug(f"DPAPI decrypt failed: {e}")
        return None
