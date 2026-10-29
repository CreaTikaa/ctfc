"""Read an OLE2 / Compound File Binary container (a .doc, .xls, .msi, vbaProject.bin).

An OLE2 file is a FAT filesystem in a file. That is the whole idea, and knowing it
makes the rest obvious:

- the file is cut into **sectors** (512 bytes, or 4096 in the newer version);
- a **FAT** says, for each sector, which sector comes next - so a stream is a
  linked list of sectors, exactly like a file on a floppy disk;
- a **directory** of 128-byte entries names the streams and storages (files and
  folders) and says which sector each stream starts at;
- streams smaller than 4096 bytes are packed together in one "mini stream" with
  its own mini FAT, so that a 200-byte stream does not waste a whole sector.

Why ctfc needs it: the macro of a malicious Office document lives in a stream
called `VBA/<ModuleName>` inside such a container, and the container is also what
a `.docm` hides in its `vbaProject.bin`. Nothing here interprets the content - it
only hands the streams over, and nothing is ever executed.

Reading is deliberately defensive: these files come from samples, so every offset
is checked and a malformed one raises `CfbError` rather than reading wild memory
or looping forever.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# Special FAT values (MS-CFB 2.2).
MAXREGSECT = 0xFFFFFFFA
DIFSECT = 0xFFFFFFFC
FATSECT = 0xFFFFFFFD
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF
# Directory entry object types.
TYPE_STORAGE = 1
TYPE_STREAM = 2
TYPE_ROOT = 5
DIR_ENTRY_SIZE = 128
# Guards against a crafted file: a chain longer than this is a loop or a bomb.
MAX_CHAIN = 1_000_000
MAX_ENTRIES = 20_000


class CfbError(Exception):
    """The data is not a usable compound file."""


def is_cfb(data: bytes) -> bool:
    """Does this start with the OLE2 signature?"""
    return data[:8] == SIGNATURE


@dataclass
class Entry:
    """One directory entry: a stream (file) or a storage (folder)."""

    name: str
    kind: int  # TYPE_STORAGE | TYPE_STREAM | TYPE_ROOT
    size: int
    start: int  # first sector of the stream
    left: int
    right: int
    child: int

    @property
    def is_stream(self) -> bool:
        return self.kind == TYPE_STREAM


@dataclass
class CfbFile:
    """A parsed container. `streams` maps "Storage/name" to the stream's bytes."""

    streams: dict[str, bytes] = field(default_factory=dict)
    names: list[str] = field(default_factory=list)  # every entry name, in file order

    def find(self, suffix: str) -> list[str]:
        """Stream paths whose last component matches `suffix`, case-insensitively."""
        wanted = suffix.lower()
        return [path for path in self.streams if path.rsplit("/", 1)[-1].lower() == wanted]


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def read(data: bytes) -> CfbFile:
    """Parse the container and return every stream it holds."""
    if not is_cfb(data):
        raise CfbError("not an OLE2 compound file (signature d0cf11e0a1b11ae1 missing)")
    if len(data) < 512:
        raise CfbError(f"truncated: {len(data)} bytes, the header alone is 512")

    sector_shift = _u16(data, 30)
    if sector_shift not in (9, 12):
        raise CfbError(f"unsupported sector size 2^{sector_shift}")
    sector_size = 1 << sector_shift
    mini_shift = _u16(data, 32)
    if not 2 <= mini_shift <= sector_shift:
        raise CfbError(f"unsupported mini sector size 2^{mini_shift}")
    mini_size = 1 << mini_shift
    mini_cutoff = _u32(data, 56)
    first_dir = _u32(data, 48)
    first_mini_fat = _u32(data, 60)
    mini_fat_count = _u32(data, 64)
    first_difat = _u32(data, 68)
    difat_count = _u32(data, 72)

    def sector(number: int) -> bytes:
        """The bytes of sector `number` (sector 0 starts right after the header)."""
        start = (number + 1) * sector_size
        if number > MAXREGSECT or start + sector_size > len(data):
            raise CfbError(f"sector {number} is outside the file")
        return data[start : start + sector_size]

    # --- The FAT. Its own sector numbers are listed in the DIFAT: 109 entries in
    # the header, then more in a chain of DIFAT sectors for large files.
    fat_sectors = [_u32(data, 76 + 4 * index) for index in range(109)]
    next_difat = first_difat
    seen_difat = 0
    while next_difat != ENDOFCHAIN and next_difat <= MAXREGSECT and seen_difat <= difat_count:
        block = sector(next_difat)
        per_sector = sector_size // 4
        fat_sectors += [_u32(block, 4 * index) for index in range(per_sector - 1)]
        next_difat = _u32(block, 4 * (per_sector - 1))
        seen_difat += 1
        if seen_difat > MAX_CHAIN:
            raise CfbError("DIFAT chain loops")

    fat: list[int] = []
    for number in fat_sectors:
        if number > MAXREGSECT:
            continue  # FREESECT padding
        block = sector(number)
        fat += [_u32(block, offset) for offset in range(0, len(block), 4)]
    if not fat:
        raise CfbError("the FAT is empty: the file is corrupt")

    def chain(start: int, limit: int = MAX_CHAIN) -> list[int]:
        """The list of sectors of a stream, following the FAT from `start`."""
        out: list[int] = []
        current = start
        seen: set[int] = set()
        while current != ENDOFCHAIN and current <= MAXREGSECT:
            if current in seen or len(out) >= limit:
                raise CfbError(f"sector chain from {start} loops")
            seen.add(current)
            out.append(current)
            if current >= len(fat):
                raise CfbError(f"sector {current} is outside the FAT")
            current = fat[current]
        return out

    def read_chain(start: int, size: int) -> bytes:
        out = bytearray()
        for number in chain(start):
            out += sector(number)
            if len(out) >= size:
                break
        return bytes(out[:size])

    # --- The directory, as a flat array of 128-byte entries.
    entries: list[Entry] = []
    directory = b"".join(sector(number) for number in chain(first_dir))
    for offset in range(0, len(directory) - DIR_ENTRY_SIZE + 1, DIR_ENTRY_SIZE):
        raw = directory[offset : offset + DIR_ENTRY_SIZE]
        name_length = _u16(raw, 64)
        kind = raw[66]
        if kind not in (TYPE_STORAGE, TYPE_STREAM, TYPE_ROOT):
            entries.append(Entry("", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM))
            continue
        # The name is UTF-16LE and includes its NUL terminator in the length.
        name = raw[: max(0, min(name_length, 64) - 2)].decode("utf-16-le", "replace")
        entries.append(
            Entry(
                name=name,
                kind=kind,
                size=int.from_bytes(raw[120:128], "little"),
                start=_u32(raw, 116),
                left=_u32(raw, 68),
                right=_u32(raw, 72),
                child=_u32(raw, 76),
            )
        )
        if len(entries) > MAX_ENTRIES:
            raise CfbError("too many directory entries")
    if not entries or entries[0].kind != TYPE_ROOT:
        raise CfbError("no root directory entry")

    # --- The mini stream: small streams are packed inside the root entry's stream.
    root = entries[0]
    mini_stream = read_chain(root.start, root.size) if root.size else b""
    mini_fat: list[int] = []
    if mini_fat_count and first_mini_fat <= MAXREGSECT:
        for number in chain(first_mini_fat, limit=mini_fat_count + 1):
            block = sector(number)
            mini_fat += [_u32(block, offset) for offset in range(0, len(block), 4)]

    def read_mini(start: int, size: int) -> bytes:
        out = bytearray()
        current = start
        seen: set[int] = set()
        while current != ENDOFCHAIN and current <= MAXREGSECT and len(out) < size:
            if current in seen:
                raise CfbError(f"mini chain from {start} loops")
            seen.add(current)
            begin = current * mini_size
            out += mini_stream[begin : begin + mini_size]
            if current >= len(mini_fat):
                break
            current = mini_fat[current]
        return bytes(out[:size])

    # --- Walk the tree so each stream gets its full "Storage/name" path. The
    # directory is a red-black tree: `child` opens a storage, left/right are
    # siblings within it.
    result = CfbFile(names=[entry.name for entry in entries if entry.name])

    def walk(index: int, prefix: str, depth: int = 0) -> None:
        if index == NOSTREAM or index >= len(entries) or depth > 50:
            return
        entry = entries[index]
        walk(entry.left, prefix, depth + 1)
        if entry.is_stream and entry.name:
            path = f"{prefix}{entry.name}"
            if entry.size < mini_cutoff:
                result.streams[path] = read_mini(entry.start, entry.size)
            else:
                result.streams[path] = read_chain(entry.start, entry.size)
        elif entry.kind == TYPE_STORAGE and entry.name:
            walk(entry.child, f"{prefix}{entry.name}/", depth + 1)
        walk(entry.right, prefix, depth + 1)

    walk(root.child, "")
    return result
