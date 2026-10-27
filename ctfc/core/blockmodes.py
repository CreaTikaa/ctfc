"""Block cipher *modes*, written by hand, for the cases pycryptodome does not cover.

A block cipher only knows how to transform one block (8 or 16 bytes). A *mode*
says how to chain the blocks:

- **ECB**: each block on its own. Equal plaintext blocks give equal ciphertext
  blocks, which is why ECB leaks (see `detect`).
- **CBC**: before encryption each plaintext block is XORed with the previous
  *ciphertext* block (the first one with the IV). Decryption therefore needs the
  previous ciphertext block, which we have, so a wrong IV only breaks block 1.
- **CBC-CTS** (ciphertext stealing): CBC for data whose length is not a multiple
  of the block size, without adding padding. The last short block "steals" the
  bytes it is missing from the previous ciphertext block, so the ciphertext has
  exactly the length of the plaintext.

These functions take a `block_decrypt(block, key, endian) -> bytes` callable, so
they work with TEA/XTEA from `tea.py` as well as with AES.
"""

from __future__ import annotations

from collections.abc import Callable

BlockDecrypt = Callable[[bytes, bytes, str], bytes]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings, cut to the shorter one."""
    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def ecb_decrypt(
    data: bytes, key: bytes, block_decrypt: BlockDecrypt, block_size: int, endian: str = "big"
) -> bytes:
    """ECB: decrypt every block independently (trailing partial block is ignored)."""
    out = bytearray()
    for offset in range(0, len(data) - len(data) % block_size, block_size):
        out += block_decrypt(data[offset : offset + block_size], key, endian)
    return bytes(out)


def cbc_decrypt(
    data: bytes,
    key: bytes,
    iv: bytes,
    block_decrypt: BlockDecrypt,
    block_size: int,
    endian: str = "big",
) -> bytes:
    """CBC: decrypt each block, then XOR it with the previous ciphertext block."""
    out = bytearray()
    previous = iv
    for offset in range(0, len(data) - len(data) % block_size, block_size):
        block = data[offset : offset + block_size]
        out += xor_bytes(block_decrypt(block, key, endian), previous)
        previous = block
    return bytes(out)


def cbc_cts_decrypt(
    data: bytes,
    key: bytes,
    iv: bytes,
    block_decrypt: BlockDecrypt,
    block_size: int,
    swapped: bool = True,
    endian: str = "big",
) -> bytes:
    """CBC with ciphertext stealing. `swapped` picks the layout of the last two blocks.

    The encryption produced, for a plaintext ending with a short block of `tail` bytes:
        ... C[n-2] , C[n-1] (full, but only its first `tail` bytes are kept) , C[n] (full)
    and the two final pieces are sent either in that order (CS1, `swapped=False`)
    or the other way round (CS2/CS3, `swapped=True`, what Kerberos and .NET use).

    The trick on decryption: D(C[n]) gives us the bytes of C[n-1] that were dropped,
    so the full C[n-1] can be rebuilt and the last two plaintext blocks recovered.
    """
    tail = len(data) % block_size
    if tail == 0:
        # Nothing was stolen: CTS and plain CBC are the same thing here.
        return cbc_decrypt(data, key, iv, block_decrypt, block_size, endian)
    if len(data) < block_size + tail:
        raise ValueError("ciphertext too short for ciphertext stealing")

    head = data[: -(block_size + tail)]
    if swapped:
        # CS2/CS3: the full block comes first, the truncated one last.
        full, short = data[-(block_size + tail) : -tail], data[-tail:]
    else:
        # CS1: the truncated block comes first, the full one last.
        short, full = data[-(block_size + tail) : -block_size], data[-block_size:]

    out = bytearray()
    previous = iv
    for offset in range(0, len(head), block_size):
        block = head[offset : offset + block_size]
        out += xor_bytes(block_decrypt(block, key, endian), previous)
        previous = block

    decrypted = block_decrypt(full, key, endian)
    # The bytes of C[n-1] that were replaced by the short block are still readable here.
    rebuilt = short + decrypted[tail:]
    last_plain = xor_bytes(decrypted[:tail], short)
    out += xor_bytes(block_decrypt(rebuilt, key, endian), previous)
    out += last_plain
    return bytes(out)


# ---------------------------------------------------------------------------
# The same code as text, to paste into generated standalone scripts.
# ---------------------------------------------------------------------------

ECB_HELPER = '''
def ecb_decrypt(data, key, block_decrypt, block_size):
    """ECB: every block is decrypted on its own."""
    out = b""
    for i in range(0, len(data) - len(data) % block_size, block_size):
        out += block_decrypt(data[i : i + block_size], key)
    return out
'''

CBC_HELPER = '''
def cbc_decrypt(data, key, iv, block_decrypt, block_size):
    """CBC: each decrypted block is XORed with the previous ciphertext block."""
    out, previous = b"", iv
    for i in range(0, len(data) - len(data) % block_size, block_size):
        block = data[i : i + block_size]
        out += bytes(a ^ b for a, b in zip(block_decrypt(block, key), previous))
        previous = block
    return out
'''

CTS_HELPER = '''
def cbc_cts_decrypt(data, key, iv, block_decrypt, block_size, swapped=True):
    """CBC with ciphertext stealing: the short last block stole bytes from C[n-1]."""
    tail = len(data) % block_size
    if tail == 0:
        return cbc_decrypt(data, key, iv, block_decrypt, block_size)
    head = data[: -(block_size + tail)]
    if swapped:
        full, short = data[-(block_size + tail) : -tail], data[-tail:]
    else:
        short, full = data[-(block_size + tail) : -block_size], data[-block_size:]
    out, previous = b"", iv
    for i in range(0, len(head), block_size):
        block = head[i : i + block_size]
        out += bytes(a ^ b for a, b in zip(block_decrypt(block, key), previous))
        previous = block
    decrypted = block_decrypt(full, key)
    rebuilt = short + decrypted[tail:]
    last_plain = bytes(a ^ b for a, b in zip(decrypted[:tail], short))
    out += bytes(a ^ b for a, b in zip(block_decrypt(rebuilt, key), previous))
    return out + last_plain
'''
