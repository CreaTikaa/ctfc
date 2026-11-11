"""MD4 (RFC 1320), in pure Python.

Why this exists: NTLM, the hash in every Windows SAM dump, is MD4 of the
password in UTF-16LE. Modern OpenSSL builds drop MD4 (it is broken), so
`hashlib.new("md4")` raises on many machines - and then ctfc could identify an
NTLM hash but never crack one, which is the whole point of pulling it out of a
SAM. This implementation needs no OpenSSL and no dependency.

Checked against the RFC 1320 test vectors in tests/test_md4.py.
"""

from __future__ import annotations

import struct


def _left_rotate(value: int, amount: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def md4(message: bytes) -> bytes:
    """Return the 16-byte MD4 digest of `message`."""
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    padded = bytearray(message)
    bit_length = (8 * len(message)) & 0xFFFFFFFFFFFFFFFF
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded += struct.pack("<Q", bit_length)

    for offset in range(0, len(padded), 64):
        x = list(struct.unpack("<16I", padded[offset : offset + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1: F(x,y,z) = (x & y) | (~x & z)
        for i in (0, 4, 8, 12):
            a = _left_rotate(a + ((b & c) | (~b & d)) + x[i], 3)
            d = _left_rotate(d + ((a & b) | (~a & c)) + x[i + 1], 7)
            c = _left_rotate(c + ((d & a) | (~d & b)) + x[i + 2], 11)
            b = _left_rotate(b + ((c & d) | (~c & a)) + x[i + 3], 19)

        # Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z), constant 0x5A827999
        for i in (0, 1, 2, 3):
            a = _left_rotate(a + ((b & c) | (b & d) | (c & d)) + x[i] + 0x5A827999, 3)
            d = _left_rotate(d + ((a & b) | (a & c) | (b & c)) + x[i + 4] + 0x5A827999, 5)
            c = _left_rotate(c + ((d & a) | (d & b) | (a & b)) + x[i + 8] + 0x5A827999, 9)
            b = _left_rotate(b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5A827999, 13)

        # Round 3: H(x,y,z) = x ^ y ^ z, constant 0x6ED9EBA1
        for i in (0, 2, 1, 3):
            a = _left_rotate(a + (b ^ c ^ d) + x[i] + 0x6ED9EBA1, 3)
            d = _left_rotate(d + (a ^ b ^ c) + x[i + 8] + 0x6ED9EBA1, 9)
            c = _left_rotate(c + (d ^ a ^ b) + x[i + 4] + 0x6ED9EBA1, 11)
            b = _left_rotate(b + (c ^ d ^ a) + x[i + 12] + 0x6ED9EBA1, 15)

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack("<4I", a, b, c, d)


def ntlm(password: str) -> str:
    """The NTLM hash (hex) of a password: MD4 of its UTF-16LE encoding."""
    return md4(password.encode("utf-16-le")).hex()
