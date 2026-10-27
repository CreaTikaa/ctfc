"""TEA and XTEA: tiny block ciphers, written by hand (pycryptodome has neither).

Both work on a 64-bit block (8 bytes) with a 128-bit key (16 bytes), and run 32
rounds built around the magic constant delta = 0x9E3779B9 (the "golden ratio"
constant, a good fingerprint when you see it in a binary). They are popular in
CTF challenges because the whole cipher fits in ten lines of C.

The 8-byte block is read as two 32-bit words. **Byte order matters**: the
reference C code uses the machine's native order (little-endian on x86), while
many Python/Java implementations use big-endian. We cannot know which one the
challenge used, so every function takes `endian` and the solver tries both.
"""

from __future__ import annotations

import struct

DELTA = 0x9E3779B9
ROUNDS = 32
MASK = 0xFFFFFFFF


def _words(block: bytes, endian: str) -> tuple[int, int]:
    return struct.unpack(">II" if endian == "big" else "<II", block)


def _bytes(v0: int, v1: int, endian: str) -> bytes:
    return struct.pack(">II" if endian == "big" else "<II", v0, v1)


def _key_words(key: bytes, endian: str) -> tuple[int, int, int, int]:
    if len(key) != 16:
        raise ValueError("TEA/XTEA keys are 16 bytes")
    return struct.unpack(">4I" if endian == "big" else "<4I", key)


def tea_decrypt_block(block: bytes, key: bytes, endian: str = "big") -> bytes:
    """Undo one TEA block: the rounds of the encryption, run backwards."""
    v0, v1 = _words(block, endian)
    k0, k1, k2, k3 = _key_words(key, endian)
    total = (DELTA * ROUNDS) & MASK  # the encryption ends with this sum
    for _ in range(ROUNDS):
        v1 = (v1 - ((((v0 << 4) & MASK) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK
        v0 = (v0 - ((((v1 << 4) & MASK) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK
        total = (total - DELTA) & MASK
    return _bytes(v0, v1, endian)


def tea_encrypt_block(block: bytes, key: bytes, endian: str = "big") -> bytes:
    """One TEA block, forwards (used by the tests to build fixtures)."""
    v0, v1 = _words(block, endian)
    k0, k1, k2, k3 = _key_words(key, endian)
    total = 0
    for _ in range(ROUNDS):
        total = (total + DELTA) & MASK
        v0 = (v0 + ((((v1 << 4) & MASK) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & MASK
        v1 = (v1 + ((((v0 << 4) & MASK) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & MASK
    return _bytes(v0, v1, endian)


def xtea_decrypt_block(block: bytes, key: bytes, endian: str = "big") -> bytes:
    """Undo one XTEA block. XTEA mixes the key words in a different order than TEA."""
    v0, v1 = _words(block, endian)
    key_words = _key_words(key, endian)
    total = (DELTA * ROUNDS) & MASK
    for _ in range(ROUNDS):
        v1 = (
            v1 - (((((v0 << 4) ^ (v0 >> 5)) & MASK) + v0) ^ (total + key_words[(total >> 11) & 3]))
        ) & MASK  # noqa: E501
        total = (total - DELTA) & MASK
        v0 = (
            v0 - (((((v1 << 4) ^ (v1 >> 5)) & MASK) + v1) ^ (total + key_words[total & 3]))
        ) & MASK  # noqa: E501
    return _bytes(v0, v1, endian)


def xtea_encrypt_block(block: bytes, key: bytes, endian: str = "big") -> bytes:
    """One XTEA block, forwards (used by the tests to build fixtures)."""
    v0, v1 = _words(block, endian)
    key_words = _key_words(key, endian)
    total = 0
    for _ in range(ROUNDS):
        v0 = (
            v0 + (((((v1 << 4) ^ (v1 >> 5)) & MASK) + v1) ^ (total + key_words[total & 3]))
        ) & MASK  # noqa: E501
        total = (total + DELTA) & MASK
        v1 = (
            v1 + (((((v0 << 4) ^ (v0 >> 5)) & MASK) + v0) ^ (total + key_words[(total >> 11) & 3]))
        ) & MASK  # noqa: E501
    return _bytes(v0, v1, endian)


# The code that goes into generated scripts (see codegen.py). Kept as text so the
# snippet stays standalone: it must run without ctfc installed.
TEA_HELPER = '''
def tea_decrypt_block(block, key, endian=">"):
    """One TEA block, decrypted (32 rounds, delta = 0x9E3779B9)."""
    mask, delta = 0xFFFFFFFF, 0x9E3779B9
    v0, v1 = struct.unpack(endian + "II", block)
    k0, k1, k2, k3 = struct.unpack(endian + "4I", key)
    total = (delta * 32) & mask
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) & mask) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & mask
        v0 = (v0 - ((((v1 << 4) & mask) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & mask
        total = (total - delta) & mask
    return struct.pack(endian + "II", v0, v1)
'''

XTEA_HELPER = '''
def xtea_decrypt_block(block, key, endian=">"):
    """One XTEA block, decrypted (32 rounds, delta = 0x9E3779B9)."""
    mask, delta = 0xFFFFFFFF, 0x9E3779B9
    v0, v1 = struct.unpack(endian + "II", block)
    kw = struct.unpack(endian + "4I", key)
    total = (delta * 32) & mask
    for _ in range(32):
        mix = (((v0 << 4) ^ (v0 >> 5)) & mask) + v0
        v1 = (v1 - (mix ^ (total + kw[(total >> 11) & 3]))) & mask
        total = (total - delta) & mask
        mix = (((v1 << 4) ^ (v1 >> 5)) & mask) + v1
        v0 = (v0 - (mix ^ (total + kw[total & 3]))) & mask
    return struct.pack(endian + "II", v0, v1)
'''

ECB_HELPER = '''
def decrypt_blocks_ecb(data, key, block_decrypt, endian=">"):
    """ECB: every 8-byte block is decrypted on its own."""
    out = b""
    for i in range(0, len(data) - len(data) % 8, 8):
        out += block_decrypt(data[i : i + 8], key, endian)
    return out
'''

CBC_HELPER = '''
def decrypt_blocks_cbc(data, key, iv, block_decrypt, endian=">"):
    """CBC: each decrypted block is XORed with the previous ciphertext block."""
    out, previous = b"", iv
    for i in range(0, len(data) - len(data) % 8, 8):
        block = data[i : i + 8]
        clear = block_decrypt(block, key, endian)
        out += bytes(a ^ b for a, b in zip(clear, previous))
        previous = block
    return out
'''
