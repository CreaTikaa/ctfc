"""LUKS: check a master key found in memory against the volume's own header.

The forensics case (an encrypted disk image + a RAM dump of the running machine):
`aeskeyfind` - or `ctfc keys` - finds AES keys in memory, and one of them, or two
glued together, is the LUKS master key. People then try `cryptsetup open
--master-key-file` with every combination, as root, by hand.

No need: the header stores everything required to CHECK a candidate offline.

- the key size (LUKS1 `key-bytes`, LUKS2 `keyslots.*.key_size`), so only
  combinations of that size are worth building: aes-xts with a 512-bit key is
  two AES-256 keys, `key1 || key2` or `key2 || key1`;
- a digest of the master key: PBKDF2(master key, salt, iterations) with the
  header's hash. A candidate that gives the same digest IS the master key.

Nothing here guesses a passphrase or attacks the volume: it only confirms keys
already recovered from memory, then prints the `cryptsetup` command to open it.

LUKS1 header (big-endian, offsets in bytes): magic 0, version 6, cipher-name 8,
cipher-mode 40, hash-spec 72, payload-offset 104, key-bytes 108, mk-digest 112
(20 bytes), mk-digest-salt 132 (32), mk-digest-iter 164.
LUKS2: a binary header whose `hdr_size` (offset 8) bounds a JSON area at 4096.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import itertools
import json
from dataclasses import dataclass

MAGIC = b"LUKS\xba\xbe"
SEARCH_LIMIT = 256 * 1024 * 1024  # a raw disk image: look for a LUKS partition this far
MAX_CANDIDATES = 400  # pairs of keys: n * (n - 1), keep it bounded


@dataclass
class LuksHeader:
    """What a LUKS header says about its master key."""

    version: int
    offset: int  # where the header starts in the data (a partition inside an image)
    cipher: str  # "aes-xts-plain64"
    key_bytes: int
    digest_hash: str
    digest_salt: bytes
    digest_iterations: int
    digest: bytes

    def describe(self) -> str:
        return (
            f"LUKS{self.version} at offset {self.offset}: {self.cipher}, "
            f"{self.key_bytes * 8}-bit master key, digest PBKDF2-{self.digest_hash} "
            f"x{self.digest_iterations}"
        )

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "offset": self.offset,
            "cipher": self.cipher,
            "key_bits": self.key_bytes * 8,
            "digest_hash": self.digest_hash,
            "digest_iterations": self.digest_iterations,
        }


def _text(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")


def parse_header(data: bytes, offset: int = 0) -> LuksHeader | None:
    """Read the LUKS1 or LUKS2 header at `offset`, or None if there is none."""
    head = data[offset:]
    if head[:6] != MAGIC or len(head) < 592:
        return None
    version = int.from_bytes(head[6:8], "big")
    if version == 1:
        return LuksHeader(
            version=1,
            offset=offset,
            cipher=f"{_text(head[8:40])}-{_text(head[40:72])}",
            key_bytes=int.from_bytes(head[108:112], "big"),
            digest_hash=_text(head[72:104]).lower(),
            digest_salt=head[132:164],
            digest_iterations=int.from_bytes(head[164:168], "big"),
            digest=head[112:132],
        )
    if version == 2:
        return _parse_luks2(head, offset)
    return None


def _parse_luks2(head: bytes, offset: int) -> LuksHeader | None:
    """LUKS2: the facts live in the JSON area that follows the 4096-byte binary header."""
    size = int.from_bytes(head[8:16], "big")
    area = head[4096:size].split(b"\x00", 1)[0]
    try:
        meta = json.loads(area)
        digest = next(iter(meta["digests"].values()))
        keyslot = next(iter(meta["keyslots"].values()))
        segment = next(iter(meta["segments"].values()))
        if digest.get("type") != "pbkdf2":
            return None
        return LuksHeader(
            version=2,
            offset=offset,
            cipher=segment.get("encryption", "?"),
            key_bytes=int(keyslot["key_size"]),
            digest_hash=digest["hash"].lower(),
            digest_salt=base64.b64decode(digest["salt"]),
            digest_iterations=int(digest["iterations"]),
            digest=base64.b64decode(digest["digest"]),
        )
    except (ValueError, KeyError, StopIteration, TypeError, binascii.Error):
        return None


def find_header(data: bytes, limit: int = SEARCH_LIMIT) -> LuksHeader | None:
    """The LUKS header at the start, or of a partition inside a raw disk image.

    Partitions start on a sector boundary, so only 512-aligned hits count.
    """
    position = data.find(MAGIC, 0, limit)
    while position != -1:
        if position % 512 == 0:
            header = parse_header(data, position)
            if header is not None:
                return header
        position = data.find(MAGIC, position + 1, limit)
    return None


def is_master_key(header: LuksHeader, key: bytes) -> bool:
    """The header's own test: PBKDF2(key, salt, iterations) == the stored digest."""
    if len(key) != header.key_bytes:
        return False
    computed = hashlib.pbkdf2_hmac(
        header.digest_hash, key, header.digest_salt, header.digest_iterations, len(header.digest)
    )
    return computed == header.digest


def candidates(keys: list[tuple[bytes, str]], size: int) -> list[tuple[bytes, str]]:
    """Master keys of `size` bytes built from the keys found: alone, or two glued.

    aes-xts uses two keys (data + tweak): a 512-bit master key is two AES-256
    keys, and memory gives no clue about their order, so both orders are tried.
    """
    built: list[tuple[bytes, str]] = []
    seen: set[bytes] = set()
    for key, where in keys:
        if len(key) == size and key not in seen:
            seen.add(key)
            built.append((key, where))
    # Strongest keys first: pairs among the first keys come before pairs that
    # involve a weak one, so A||B and B||A are tried right away.
    pairs = sorted(itertools.permutations(range(len(keys)), 2), key=lambda ij: (max(ij), ij))
    for i, j in pairs:
        (first, where1), (second, where2) = keys[i], keys[j]
        if len(built) >= MAX_CANDIDATES:
            break
        joined = first + second
        if len(joined) == size and joined not in seen and first != second:
            seen.add(joined)
            built.append((joined, f"{where1} || {where2}"))
    return built


def find_master_key(header: LuksHeader, keys: list[tuple[bytes, str]]) -> tuple[bytes, str] | None:
    """The candidate the header confirms, with how it was built, or None."""
    for key, how in candidates(keys, header.key_bytes):
        if is_master_key(header, key):
            return key, how
    return None


def open_commands(key: bytes, image: str = "<image>") -> list[str]:
    """How to use the confirmed key (cryptsetup needs root to map the volume)."""
    return [
        f"echo -n {key.hex()} | xxd -r -p > master.key",
        f"sudo cryptsetup open --volume-key-file master.key {image} recovered",
        "sudo mount /dev/mapper/recovered /mnt   # then look around, and umount + cryptsetup close",
    ]
