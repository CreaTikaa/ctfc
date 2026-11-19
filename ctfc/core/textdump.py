"""Turn a text hex dump back into the bytes it shows (`xxd -r`, for every dialect).

A challenge often ships a binary as a dump instead of the file: `xxd file`,
`hexdump -C file`, `od -A x -t x1z file`, or plain `hexdump` / `od -x` (16-bit
little-endian words). Each line is an offset, then the bytes in hex, then
(sometimes) an ASCII column. Reading only the hex columns gives the file back,
so the readers and the decoders see the real thing (a gzip, a PNG...).

Supported, tried in this order (the first dialect that reads every line wins):

    xxd          00000010: 0300 3e00 0100 0000  ..>.....
    hexdump -C   00000010  03 00 3e 00 01 00 00 00  |..>.....|
    od -t x1     0000010 03 00 3e 00 01 00 00 00  >..>.....<
    hexdump      0000010 0003 003e 0001 0000          (LE 16-bit words)

`*` on a line of its own (hexdump, od) means "the previous line, repeated until
the next offset", and is expanded.
"""

from __future__ import annotations

import re

_XXD = re.compile(r"^([0-9a-fA-F]{6,16}):\s((?:[0-9a-fA-F]{2,4}\s?){1,16})(?:\s{2,}.*)?$")
_CANONICAL = re.compile(
    r"^([0-9a-fA-F]{6,16})\s{1,2}((?:[0-9a-fA-F]{2}\s{1,2}){1,16})\s*(?:\|.*\|)?\s*$"
)
_OD_BYTES = re.compile(r"^([0-9a-fA-F]{6,16})((?:\s[0-9a-fA-F]{2}){1,16})\s*(?:>.*<)?\s*$")
_WORDS = re.compile(r"^([0-9a-fA-F]{6,16})((?:\s[0-9a-fA-F]{4}){1,8})\s*$")
_END = re.compile(r"^([0-9a-fA-F]{6,16})\s*$")

DIALECTS = (
    ("xxd", _XXD),
    ("hexdump -C", _CANONICAL),
    ("hexdump (16-bit little-endian words)", _WORDS),
    ("od -t x1", _OD_BYTES),
)
MAX_TEXT = 64 * 1024 * 1024


def _read(lines: list[str], dialect: str, pattern: re.Pattern[str]) -> bytes | None:
    """The bytes, if every line matches this dialect; else None."""
    out = bytearray()
    previous = b""
    repeat = False
    for line in lines:
        if line.strip() == "*":
            repeat = True
            continue
        end = _END.match(line)
        match = pattern.match(line)
        if match is None:
            if end is None:
                return None
            # The last line of hexdump/od: the final offset, nothing after it.
            offset = int(end.group(1), 16)
            if repeat and previous:
                while len(out) < offset:
                    out += previous
            # The final offset is the file's length: it also cuts the padding
            # byte of an odd-length file shown as 16-bit words.
            del out[offset:]
            break
        offset = int(match.group(1), 16)
        if repeat and previous:
            while len(out) < offset:
                out += previous
            repeat = False
        if offset != len(out):
            return None  # not a contiguous dump: some other text
        hex_part = match.group(2).split()
        if dialect.startswith("hexdump (16"):
            row = b"".join(bytes.fromhex(word)[::-1] for word in hex_part)
        else:
            row = bytes.fromhex("".join(hex_part))
        out += row
        previous = row
    return bytes(out) if out else None


def revert(data: bytes) -> tuple[bytes, str] | None:
    """(the bytes, the dialect's name) when `data` is a text hex dump, else None."""
    if len(data) > MAX_TEXT or b"\x00" in data[:4096]:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    lines = [line.rstrip("\r") for line in text.splitlines() if line.strip()]
    if not lines or len(lines) == 1 and not _XXD.match(lines[0]):
        return None  # one line is enough only for xxd's distinctive "offset:" form
    for dialect, pattern in DIALECTS:
        result = _read(lines, dialect, pattern)
        if result:
            return result, dialect
    return None


def looks_like_dump(data: bytes) -> bool:
    """Cheap test on the first lines, before the full revert."""
    head = data[:2048]
    try:
        lines = [line for line in head.decode("ascii").splitlines() if line.strip()][:4]
    except UnicodeDecodeError:
        return False
    if len(lines) == 1:
        return bool(_XXD.match(lines[0]))
    body = lines[:-1]  # the last line may be a bare final offset
    return any(all(p.match(line) or line.strip() == "*" for line in body) for _, p in DIALECTS)
