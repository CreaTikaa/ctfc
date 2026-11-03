"""Read a Microsoft cabinet (.cab) and pull its files out without cabextract.

A CAB is three lists bolted together, and once that is clear it is an easy
format:

- a **header** (`MSCF`) counting the folders and the files;
- one **CFFOLDER** per compression unit, saying where its data blocks start and
  which compression was used for all of them;
- one **CFFILE** per file: its size, its *offset inside the uncompressed folder*,
  and its name;
- then the **CFDATA** blocks, each holding up to 32 KB of compressed bytes.

So a file is not stored on its own: it is a slice of the folder's decompressed
stream. Everything in one folder has to be decompressed to reach the last file,
which is why a corrupt block loses the files after it and not just its own.

Why ctfc reads it: a cabinet is what a `.msi` carries its payload in, what
`expand.exe` and some droppers use, and what a Windows challenge hands you when
it does not want to hand you a ZIP. Two compressions are decoded here - stored
and **MSZIP**, which is deflate with the previous block as the dictionary. LZX
and Quantum are named and handed over to `cabextract`, because reimplementing
LZX is a project of its own and `cabextract` does it well.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core.errors import FormatError

SIGNATURE = b"MSCF"
COMPRESSION = {0: "stored", 1: "MSZIP", 2: "Quantum", 3: "LZX"}
# Header flags.
PREV_CABINET = 0x0001
NEXT_CABINET = 0x0002
RESERVE_PRESENT = 0x0004
# A file whose name is UTF-8 rather than the local code page.
ATTR_NAME_IS_UTF = 0x80
MAX_FILES = 100_000
MAX_BLOCK = 0x8000  # a CFDATA never decompresses to more than 32 KB


class CabError(FormatError):
    """The data is not a cabinet we can read."""


@dataclass
class CabFile:
    """One file listed in the cabinet."""

    name: str
    size: int
    folder: int
    offset: int  # offset inside the folder's *uncompressed* stream
    attributes: int
    date: int
    time: int
    data: bytes | None = None  # filled when the folder could be decompressed

    @property
    def dos_timestamp(self) -> str:
        """The MS-DOS date/time pair, as text. Two seconds of resolution, by design."""
        year = 1980 + ((self.date >> 9) & 0x7F)
        month = (self.date >> 5) & 0x0F
        day = self.date & 0x1F
        hour = (self.time >> 11) & 0x1F
        minute = (self.time >> 5) & 0x3F
        second = (self.time & 0x1F) * 2
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"


@dataclass
class CabFolder:
    """One compression unit: where its blocks start, and how they are compressed."""

    start: int
    blocks: int
    compression: int

    @property
    def method(self) -> str:
        return COMPRESSION.get(self.compression & 0x000F, f"type {self.compression}")


@dataclass
class Cabinet:
    """A parsed cabinet."""

    files: list[CabFile] = field(default_factory=list)
    folders: list[CabFolder] = field(default_factory=list)
    size: int = 0  # cbCabinet, as the header claims
    previous: str = ""  # a cabinet set: this one continues from that file
    following: str = ""
    notes: list[str] = field(default_factory=list)


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise CabError(f"the cabinet stops at {len(data)} bytes, a field at {offset} does not fit")
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise CabError(f"the cabinet stops at {len(data)} bytes, a field at {offset} does not fit")
    return int.from_bytes(data[offset : offset + 4], "little")


def _cstring(data: bytes, offset: int, utf8: bool = False) -> tuple[str, int]:
    """A NUL-terminated name, and the offset just past it."""
    end = data.find(b"\x00", offset)
    if end < 0:
        raise CabError(f"a name starting at {offset} is not terminated")
    raw = data[offset:end]
    encoding = "utf-8" if utf8 else "cp1252"
    return raw.decode(encoding, "replace"), end + 1


def is_cab(data: bytes) -> bool:
    return data[:4] == SIGNATURE


def read(data: bytes) -> Cabinet:
    """Parse the header, the folders and the file list."""
    if not is_cab(data):
        raise CabError("not a cabinet (the four bytes MSCF are missing)")
    if len(data) < 36:
        raise CabError(f"truncated: {len(data)} bytes, the header alone is 36")

    cabinet = Cabinet(size=_u32(data, 8))
    files_offset = _u32(data, 16)
    folder_count = _u16(data, 26)
    file_count = _u16(data, 28)
    flags = _u16(data, 30)

    position = 36
    folder_reserve = 0
    data_reserve = 0
    if flags & RESERVE_PRESENT:
        header_reserve = _u16(data, 36)
        folder_reserve = data[38]
        data_reserve = data[39]
        position = 40 + header_reserve
    if flags & PREV_CABINET:
        cabinet.previous, position = _cstring(data, position)
        _disk, position = _cstring(data, position)
    if flags & NEXT_CABINET:
        cabinet.following, position = _cstring(data, position)
        _disk, position = _cstring(data, position)

    if folder_count == 0 or file_count == 0:
        raise CabError(f"the header counts {folder_count} folder(s) and {file_count} file(s)")
    if folder_count > MAX_FILES or file_count > MAX_FILES:
        raise CabError("the header counts more folders/files than any real cabinet has")

    for index in range(folder_count):
        at = position + index * (8 + folder_reserve)
        cabinet.folders.append(
            CabFolder(
                start=_u32(data, at), blocks=_u16(data, at + 4), compression=_u16(data, at + 6)
            )
        )

    at = files_offset
    for _ in range(file_count):
        size = _u32(data, at)
        offset = _u32(data, at + 4)
        folder = _u16(data, at + 8)
        date = _u16(data, at + 10)
        clock = _u16(data, at + 12)
        attributes = _u16(data, at + 14)
        name, at = _cstring(data, at + 16, utf8=bool(attributes & ATTR_NAME_IS_UTF))
        cabinet.files.append(
            CabFile(
                name=name.replace("\\", "/"),
                size=size,
                folder=folder,
                offset=offset,
                attributes=attributes,
                date=date,
                time=clock,
            )
        )

    cabinet.notes.extend(_structural_notes(cabinet, data, data_reserve))
    return cabinet


def _structural_notes(cabinet: Cabinet, data: bytes, data_reserve: int) -> list[str]:
    """The oddities worth saying out loud before anything is decompressed."""
    notes: list[str] = []
    if cabinet.size and cabinet.size != len(data):
        notes.append(
            f"the header says the cabinet is {cabinet.size} bytes but the file is "
            f"{len(data)}: {'truncated' if len(data) < cabinet.size else 'something is appended'}"
        )
    if cabinet.previous or cabinet.following:
        notes.append(
            "this cabinet is part of a set"
            + (f", continuing {cabinet.previous!r}" if cabinet.previous else "")
            + (f", continued by {cabinet.following!r}" if cabinet.following else "")
            + ": a file split across two cabinets needs both"
        )
    if data_reserve:
        notes.append(f"each data block carries {data_reserve} reserved byte(s)")
    for file in cabinet.files:
        if file.name.startswith("/") or ".." in file.name.split("/"):
            notes.append(f"{file.name!r} escapes the extraction folder")
    return notes


def folder_stream(data: bytes, folder: CabFolder, reserve: int = 0, limit: int = 64 << 20) -> bytes:
    """Decompress one folder's data blocks into its uncompressed stream.

    MSZIP is raw deflate per block, each block using the previous block's output
    as its dictionary - that is what the two bytes `CK` in front of every block
    announce. Stored folders are concatenated as is.
    """
    import zlib

    method = folder.compression & 0x000F
    if method not in (0, 1):
        raise CabError(
            f"folder compressed with {folder.method}, which ctfc does not decode: "
            "use `cabextract -F <name> <file>`"
        )
    out = bytearray()
    position = folder.start
    history = b""
    for index in range(folder.blocks):
        if position + 8 > len(data):
            raise CabError(f"data block {index} starts past the end of the file")
        compressed_size = _u16(data, position + 4)
        uncompressed_size = _u16(data, position + 6)
        body = data[position + 8 + reserve : position + 8 + reserve + compressed_size]
        if len(body) < compressed_size:
            raise CabError(f"data block {index} is cut short")
        position += 8 + reserve + compressed_size
        if uncompressed_size > MAX_BLOCK:
            raise CabError(
                f"data block {index} claims {uncompressed_size} bytes, the limit is 32768"
            )
        if method == 0:
            chunk = body[:uncompressed_size] if uncompressed_size else body
        else:
            if body[:2] != b"CK":
                raise CabError(f"MSZIP block {index} does not start with 'CK': it is not MSZIP")
            try:
                decompressor = (
                    zlib.decompressobj(wbits=-15, zdict=history)
                    if history
                    else zlib.decompressobj(wbits=-15)
                )
                chunk = decompressor.decompress(body[2:], uncompressed_size or MAX_BLOCK)
            except zlib.error as exc:
                raise CabError(f"MSZIP block {index} does not inflate: {exc}") from exc
            history = (history + chunk)[-MAX_BLOCK:]
        out += chunk
        if len(out) > limit:
            raise CabError(f"the folder decompresses to more than {limit} bytes: stopping")
    return bytes(out)


def extract(data: bytes, cabinet: Cabinet | None = None, limit: int = 64 << 20) -> Cabinet:
    """Fill in `CabFile.data` for every file whose folder could be decompressed."""
    cabinet = cabinet or read(data)
    reserve = data[39] if _u16(data, 30) & RESERVE_PRESENT else 0
    for index, folder in enumerate(cabinet.folders):
        try:
            stream = folder_stream(data, folder, reserve, limit)
        except CabError as exc:
            cabinet.notes.append(f"folder {index}: {exc}")
            continue
        for file in cabinet.files:
            if file.folder != index:
                continue
            chunk = stream[file.offset : file.offset + file.size]
            if len(chunk) < file.size:
                cabinet.notes.append(
                    f"{file.name}: only {len(chunk)} of {file.size} bytes were in the folder"
                )
            file.data = chunk
    return cabinet
