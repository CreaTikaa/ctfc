"""ZipCrypto: the traditional PKWARE cipher of password-protected ZIP files.

The crypto concept: a **stream cipher** whose state is three 32-bit numbers.
The password is fed into the state one byte at a time, then every byte of the
entry is XORed with one keystream byte - and the state is stirred again by the
*plaintext* byte just produced. The entry starts with a 12-byte random header
whose last byte is a known "check" value (the top byte of the CRC-32, or of the
file time): decrypting just those 12 bytes rejects 255 wrong passwords out of
256, which is why a dictionary attack on ZipCrypto is cheap.

This module is used to test passwords against a zip2john `$pkzip2$` hash (the
hash carries the encrypted bytes themselves, see `pkzip2.py`). Opening real ZIP
files stays with the standard `zipfile` module, which also knows ZipCrypto -
and is what the tests check this code against.
"""

from __future__ import annotations

# The three initial key values, fixed by the PKWARE APPNOTE (section 6.1.5).
INITIAL_KEYS = (0x12345678, 0x23456789, 0x34567890)


def _crc_table() -> list[int]:
    """The CRC-32 table (polynomial 0xEDB88320), the one zlib uses too."""
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ 0xEDB88320 if value & 1 else value >> 1
        table.append(value)
    return table


CRC_TABLE = _crc_table()


def _crc_step(crc: int, byte: int) -> int:
    """One byte of CRC-32 (without the final inversion): APPNOTE's crc32(k, b)."""
    return (crc >> 8) ^ CRC_TABLE[(crc ^ byte) & 0xFF]


def keys_for(password: bytes) -> tuple[int, int, int]:
    """The cipher state after the password has been fed in."""
    k0, k1, k2 = INITIAL_KEYS
    for byte in password:
        k0 = _crc_step(k0, byte)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc_step(k2, k1 >> 24)
    return k0, k1, k2


def decrypt(data: bytes, keys: tuple[int, int, int]) -> bytes:
    """Decrypt `data` (header included) starting from the state `keys`."""
    k0, k1, k2 = keys
    out = bytearray(len(data))
    for index, byte in enumerate(data):
        temp = (k2 | 2) & 0xFFFF
        plain = byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF)
        out[index] = plain
        # The state is stirred by the plaintext byte, not the ciphertext one.
        k0 = _crc_step(k0, plain)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc_step(k2, k1 >> 24)
    return bytes(out)


def header_matches(header: bytes, password: bytes, checks: tuple[bytes, ...]) -> bool:
    """Does `password` decrypt the 12-byte header so that it ends with a check value?

    `checks` are the accepted endings: one byte (the usual case) or two (very
    old PKZIP). Only 12 bytes are decrypted, so this is the fast filter; a hit
    is then confirmed by decrypting the whole entry and checking its CRC-32.
    """
    plain = decrypt(header[:12], keys_for(password))
    return any(plain.endswith(check) for check in checks)
