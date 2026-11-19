"""Known-prefix crib search: look for the flag prefix under every cheap disguise.

The decoders go forward: decode a layer, then look for a flag. This goes
backward. The flag format is known (`CYBN{`, or the one set with
`ctfc config --flag`), so each simple transform of `CYBN{` is computed once
and searched for in the raw bytes - including big binaries, dumps and
captures where the flag is a few bytes in the middle of noise, which a
whole-file decoder never sees at the right offset.

Disguises searched (each one for every configured prefix):

* XOR with a repeating key of period 1 to len(prefix) - 4. The key is unknown,
  but XOR cancels it out between two bytes one period apart:
  data[i] ^ data[i+L] == prefix[i] ^ prefix[i+L]. So one pass per period finds
  the offset, whatever the key; the key is then read off the prefix. (Period 1
  is single-byte XOR. With `CYBN{` (5 characters) only period 1 is possible: a
  longer key needs a longer known prefix to be told apart from chance.)
* adding a constant to every byte (a "Caesar" over bytes: c = p + k mod 256),
  found the same way with differences instead of XOR;
* ROT-N of the letters (1..25) and Atbash, plain in the bytes;
* hex (lower or upper case, with or without a separator), and decimal codes.

A hit is decoded from that offset up to the closing `}`, and kept only when
what comes out is a plausible flag. Nothing here is a guess over the whole
file: the prefix fixes the transform, and the body must then read as a flag.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass

# Bytes searched at most (a whole disk image is searched by the plain search only).
MAX_BYTES = 16 * 1024 * 1024
# The add-a-constant search builds one shifted copy per constant: smaller cap.
MAX_SHIFT_BYTES = 512 * 1024
MAX_BODY = 120  # characters between the prefix and the closing brace
MAX_HITS_PER_FORM = 20


@dataclass
class CribHit:
    flag: str
    how: str  # "xor key 5a (single byte)", "rot13", "hex", ...
    offset: int


def _diff_xor(data: bytes, period: int) -> bytes:
    """data[i] ^ data[i+period], for every i (big-integer XOR: fast)."""
    size = len(data) - period
    left = int.from_bytes(data[:size], "big")
    right = int.from_bytes(data[period:], "big")
    return (left ^ right).to_bytes(size, "big")


def _finds(haystack: bytes, needle: bytes, limit: int = MAX_HITS_PER_FORM) -> list[int]:
    out: list[int] = []
    start = haystack.find(needle)
    while start >= 0 and len(out) < limit:
        out.append(start)
        start = haystack.find(needle, start + 1)
    return out


def _until_brace(decoded: bytes, prefix: bytes) -> str | None:
    """The flag that starts the decoded window, or None if it does not close."""
    if not decoded.startswith(prefix):
        return None
    end = decoded.find(b"}", len(prefix))
    if end < 0 or end - len(prefix) > MAX_BODY or end == len(prefix):
        return None
    body = decoded[len(prefix) : end]
    if not all(32 <= byte < 127 for byte in body):
        return None
    return decoded[: end + 1].decode("ascii")


def _xor_hits(data: bytes, prefix: bytes) -> list[CribHit]:
    hits: list[CribHit] = []
    for period in range(1, max(1, len(prefix) - 4) + 1):
        if len(data) <= period + len(prefix):
            break
        crib = bytes(prefix[i] ^ prefix[i + period] for i in range(len(prefix) - period))
        diff = _diff_xor(data, period)
        for offset in _finds(diff, crib):
            key = bytes(data[offset + i] ^ prefix[i] for i in range(period))
            if not any(key) or key == b" " * period:
                continue  # the plain text, or a mere case flip
            window = data[offset : offset + len(prefix) + MAX_BODY + 1]
            decoded = bytes(byte ^ key[i % period] for i, byte in enumerate(window))
            flag = _until_brace(decoded, prefix)
            if flag:
                kind = "single byte" if period == 1 else f"{period}-byte key"
                hits.append(CribHit(flag, f"xor key {key.hex()} ({kind})", offset))
    return hits


def _shift_hits(data: bytes, prefix: bytes) -> list[CribHit]:
    """c = p + k (mod 256): the differences between neighbours do not depend on k."""
    if len(data) > MAX_SHIFT_BYTES or len(data) < len(prefix):
        return []
    crib = bytes((prefix[i + 1] - prefix[i]) % 256 for i in range(len(prefix) - 1))
    diff = bytes((data[i + 1] - data[i]) % 256 for i in range(len(data) - 1))
    hits: list[CribHit] = []
    for offset in _finds(diff, crib):
        shift = (data[offset] - prefix[0]) % 256
        if shift == 0:
            continue
        window = data[offset : offset + len(prefix) + MAX_BODY + 1]
        decoded = bytes((byte - shift) % 256 for byte in window)
        flag = _until_brace(decoded, prefix)
        if flag:
            hits.append(CribHit(flag, f"every byte + {shift} (mod 256)", offset))
    return hits


def _rot_table(shift: int) -> bytes:
    lower, upper = string.ascii_lowercase, string.ascii_uppercase
    table = bytearray(range(256))
    for i in range(26):
        table[ord(lower[i])] = ord(lower[(i + shift) % 26])
        table[ord(upper[i])] = ord(upper[(i + shift) % 26])
    return bytes(table)


_ATBASH = bytes.maketrans(
    (string.ascii_lowercase + string.ascii_uppercase).encode(),
    (string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1]).encode(),
)


def _letter_hits(data: bytes, prefix: bytes) -> list[CribHit]:
    hits: list[CribHit] = []
    forms = [(f"rot{shift}", _rot_table(shift), _rot_table(26 - shift)) for shift in range(1, 26)]
    forms.append(("atbash", _ATBASH, _ATBASH))
    for how, encode, decode in forms:
        disguised = prefix.translate(encode)
        if disguised == prefix:
            continue
        for offset in _finds(data, disguised):
            window = data[offset : offset + len(prefix) + MAX_BODY + 1]
            flag = _until_brace(window.translate(decode), prefix)
            if flag:
                hits.append(CribHit(flag, how, offset))
    return hits


_HEX_PAIR = re.compile(rb"[0-9a-fA-F]{2}")


def _hex_hits(data: bytes, prefix: bytes) -> list[CribHit]:
    hits: list[CribHit] = []
    for separator in (b"", b" ", b":", b",", b"\\x", b"0x", b", 0x", b"-", b"%"):
        for case in (str.lower, str.upper):
            pairs = [case(f"{byte:02x}").encode() for byte in prefix]
            if separator in (b"\\x", b"%"):
                disguised = b"".join(separator + pair for pair in pairs)
            else:
                disguised = separator.join(pairs)
            for offset in _finds(data, disguised):
                window = data[
                    offset : offset + (len(prefix) + MAX_BODY + 1) * (2 + len(separator) + 2)
                ]
                values = bytes(
                    int(pair, 16) for pair in _HEX_PAIR.findall(window.replace(b"0x", b" "))
                )
                flag = _until_brace(values, prefix)
                if flag:
                    hits.append(CribHit(flag, "hex", offset))
    return hits


_NUMBER = re.compile(rb"\d{2,3}")


def _decimal_hits(data: bytes, prefix: bytes) -> list[CribHit]:
    hits: list[CribHit] = []
    for separator in (b" ", b",", b", ", b";"):
        disguised = separator.join(str(byte).encode() for byte in prefix)
        for offset in _finds(data, disguised):
            window = data[offset : offset + (len(prefix) + MAX_BODY + 1) * 5]
            numbers = [int(number) for number in _NUMBER.findall(window)]
            values = bytes(number for number in numbers if number < 256)
            flag = _until_brace(values, prefix)
            if flag:
                hits.append(CribHit(flag, "decimal codes", offset))
    return hits


def search(data: bytes, prefixes: list[str]) -> list[CribHit]:
    """Every flag found under one of the disguises, for each known prefix."""
    if len(data) > MAX_BYTES:
        data = data[:MAX_BYTES]
    hits: list[CribHit] = []
    seen: set[str] = set()
    for text in prefixes:
        prefix = text.encode("utf-8")
        if len(prefix) < 4:
            continue
        for found in (
            _xor_hits(data, prefix)
            + _shift_hits(data, prefix)
            + _letter_hits(data, prefix)
            + _hex_hits(data, prefix)
            + _decimal_hits(data, prefix)
        ):
            if found.flag not in seen:
                seen.add(found.flag)
                hits.append(found)
    return hits
