"""Read a tar archive by hand, including the things `tar tvf` quietly skips.

A tar file is the simplest archive there is: a 512-byte header block naming one
file, then that file's bytes padded to a multiple of 512, then the next header,
and so on until two blocks of zeros say "the end". Everything is ASCII, and the
sizes are written in **octal**, which is the one surprise.

It is read here rather than with `tarfile` for three reasons, and each of them
is a challenge that has been set at least once:

- **data after the end-of-archive marker.** `tarfile` stops at the two zero
  blocks and never tells you that 40 KB follow. Appending a second archive, or
  a whole different file, is invisible to every normal tool.
- **a header that lies.** The name field is 100 bytes; longer names are carried
  in a GNU `L` entry or a PAX record that precedes the real one. A file can
  therefore show one name through one reader and another through the next.
- **the fields nobody reads**: the user/group names, the link target, the mtime,
  and a path that escapes the extraction folder with `../`.

Nothing here is executed and nothing is written: it returns the entry list and
hands the bytes of a member back on request.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core.errors import FormatError

BLOCK = 512
# Type flags, by the character stored at offset 156.
TYPES = {
    "0": "file",
    "\x00": "file",
    "1": "hard link",
    "2": "symlink",
    "3": "character device",
    "4": "block device",
    "5": "directory",
    "6": "fifo",
    "7": "contiguous file",
    "g": "pax global header",
    "x": "pax header",
    "L": "GNU long name",
    "K": "GNU long link name",
}
MAX_ENTRIES = 100_000


class TarError(FormatError):
    """The data is not a tar we can read."""


@dataclass
class TarEntry:
    """One member of the archive."""

    name: str
    size: int
    offset: int  # where the member's bytes start in the file
    mode: int = 0
    uid: int = 0
    gid: int = 0
    mtime: int = 0
    kind: str = "file"
    link: str = ""
    uname: str = ""
    gname: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def is_file(self) -> bool:
        return self.kind in ("file", "contiguous file")


def _text(raw: bytes) -> str:
    """A NUL-padded fixed field, as text."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def _octal(raw: bytes) -> int:
    """A tar size/mode field: octal digits, possibly padded with spaces or NULs.

    GNU tar switches to a binary big-endian form (high bit of the first byte set)
    for anything that does not fit in the octal field, so that is handled too.
    """
    if raw and raw[0] & 0x80:
        return int.from_bytes(bytes([raw[0] & 0x7F]) + raw[1:], "big")
    cleaned = raw.split(b"\x00", 1)[0].strip()
    if not cleaned:
        return 0
    try:
        return int(cleaned, 8)
    except ValueError as exc:
        raise TarError(f"field {cleaned!r} is not an octal number: the header is damaged") from exc


def checksum_ok(block: bytes) -> bool:
    """A header's own checksum: the sum of its bytes, with the field read as spaces."""
    if len(block) < BLOCK:
        return False
    stored = block[148:156]
    try:
        expected = _octal(stored)
    except TarError:
        return False
    body = block[:148] + b" " * 8 + block[156:BLOCK]
    # Some very old tars summed the header as *signed* chars, so a header with a
    # high byte in it checks out one way or the other. Both sums are computed as
    # plain integers: building a bytes() out of the signed values would raise.
    signed = sum(value - 256 if value > 127 else value for value in body)
    return expected in (sum(body), signed)


def looks_like_tar(data: bytes) -> bool:
    """Is this a tar? The `ustar` magic, or a first header whose checksum works."""
    if len(data) < BLOCK:
        return False
    if data[257:262] == b"ustar":
        return True
    return checksum_ok(data[:BLOCK])


def read_entries(data: bytes) -> tuple[list[TarEntry], int]:
    """Every member, plus the offset where the archive ends (the zero blocks).

    The second value is what makes the "something is appended" case visible: any
    bytes past it are not part of the archive.
    """
    if not looks_like_tar(data):
        raise TarError(
            "not a tar archive: no 'ustar' magic at offset 257 and the first "
            "header's checksum does not add up"
        )
    entries: list[TarEntry] = []
    position = 0
    end = len(data)
    # GNU long names and PAX records describe the *next* header, so they are
    # kept here until it is read.
    pending_name = ""
    pending_link = ""
    pax: dict[str, str] = {}

    while position + BLOCK <= len(data):
        block = data[position : position + BLOCK]
        if block == b"\x00" * BLOCK:
            end = position
            break
        if not checksum_ok(block):
            raise TarError(
                f"the header at offset {position} has a bad checksum: the archive is "
                "damaged, or something else was concatenated here"
            )
        size = _octal(block[124:136])
        flag = chr(block[156]) if block[156] else "0"
        entry = TarEntry(
            name=_text(block[0:100]),
            size=size,
            offset=position + BLOCK,
            mode=_octal(block[100:108]),
            uid=_octal(block[108:116]),
            gid=_octal(block[116:124]),
            mtime=_octal(block[136:148]),
            kind=TYPES.get(flag, f"type {flag!r}"),
            link=_text(block[157:257]),
            uname=_text(block[265:297]),
            gname=_text(block[297:329]),
        )
        prefix = _text(block[345:500]) if block[257:262] == b"ustar" else ""
        if prefix:
            entry.name = f"{prefix}/{entry.name}"
        body = data[entry.offset : entry.offset + size]
        position = entry.offset + size + (-size % BLOCK)

        if flag == "L":  # GNU long name: the body is the real name
            pending_name = _text(body)
            continue
        if flag == "K":
            pending_link = _text(body)
            continue
        if flag in ("x", "g"):  # PAX: "<len> key=value\n" records
            pax = _parse_pax(body)
            continue

        if pending_name:
            entry.name, pending_name = pending_name, ""
        if pending_link:
            entry.link, pending_link = pending_link, ""
        if "path" in pax:
            entry.name = pax.pop("path")
        if "size" in pax:
            try:
                entry.size = int(pax["size"])
            except ValueError:
                pass
        pax = {}

        if entry.name.startswith("/") or ".." in entry.name.replace("\\", "/").split("/"):
            entry.problems.append("the path escapes the extraction folder")
        entries.append(entry)
        if len(entries) > MAX_ENTRIES:
            raise TarError("more than 100000 entries: this is not a normal archive")
    else:
        end = len(data)
    if not entries:
        raise TarError("a tar with no entries: only the end-of-archive blocks")
    return entries, end


def _parse_pax(body: bytes) -> dict[str, str]:
    """PAX extended records: `<length> <key>=<value>\\n`, repeated."""
    records: dict[str, str] = {}
    position = 0
    while position < len(body):
        space = body.find(b" ", position)
        if space < 0:
            break
        try:
            length = int(body[position:space])
        except ValueError:
            break
        if length <= 0 or position + length > len(body):
            break
        record = body[space + 1 : position + length].rstrip(b"\n")
        key, _, value = record.partition(b"=")
        records[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
        position += length
    return records


def member(data: bytes, entry: TarEntry) -> bytes:
    """The bytes of one member."""
    return data[entry.offset : entry.offset + entry.size]


def trailing_after_end(data: bytes, end: int) -> bytes:
    """Whatever follows the end-of-archive marker, ignoring the zero padding.

    tar pads the file out with zero blocks, so "trailing data" means the first
    non-zero byte after the marker - which is where an appended file starts.
    """
    tail = data[end:]
    stripped = tail.lstrip(b"\x00")
    return stripped
