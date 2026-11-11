"""Read an ISO 9660 disk image (a .iso, the stock "it's a CD/USB image" challenge).

An ISO 9660 image is how a bootable disc or a USB stick is handed over. The flag
is a file inside it, and the usual answer is "mount it" (needs root) or "7z x".
This reads the file tree without either.

The format, in brief:

- the image is a sequence of 2048-byte **logical sectors**;
- sector 16 (offset 0x8000) holds the **Primary Volume Descriptor** (PVD): the
  bytes `0x01 "CD001" 0x01`, and at offset 156 a 34-byte record pointing at the
  **root directory**;
- a **directory** is itself stored in some sectors, as a list of variable-length
  **records**: a length byte, the extent's sector number and byte length (each
  written both little- and big-endian; we read the little-endian copy), a flags
  byte (bit 1 = "this is a directory"), and the name;
- a file's bytes are simply `sector * 2048`, for its length.

Joliet (a second descriptor with UCS-2 names, what ImgBurn writes) and Rock
Ridge are handled lightly: the primary tree is read, and a file identifier's
`;1` version suffix is stripped. Pure functions on bytes; nothing is mounted.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SECTOR = 2048
PVD_SECTOR = 16
ISO_SIGNATURE = b"\x01CD001\x01"  # type 1 (primary), identifier, version
# A directory tree deeper or wider than this is almost certainly a parser that
# lost its way in a malformed image, not a real disc.
MAX_FILES = 10_000
MAX_DEPTH = 32
MAX_TOTAL = 512 * 1024 * 1024


class IsoError(ValueError):
    """The data is not an ISO 9660 image we can read."""


@dataclass
class IsoFile:
    """One file inside the image."""

    path: str
    data: bytes


@dataclass
class IsoReport:
    """What the image holds."""

    volume_id: str = ""
    files: list[IsoFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "volume_id": self.volume_id,
            "files": [{"path": f.path, "size": len(f.data)} for f in self.files],
            "notes": list(self.notes),
        }


def looks_like_iso(data: bytes) -> bool:
    """True when sector 16 begins an ISO 9660 primary volume descriptor.

    Some images carry a 16- or 24-byte-per-sector sync header (a raw .bin/.cue
    rip); the plain .iso we handle has the descriptor exactly at 0x8000.
    """
    offset = PVD_SECTOR * SECTOR
    return len(data) > offset + 7 and data[offset : offset + 7] == ISO_SIGNATURE


def _clean_name(raw: bytes) -> str:
    """A directory record's file identifier, without its `;1` version suffix."""
    name = raw.decode("latin-1")
    return name.split(";", 1)[0]


def _records(block: bytes):
    """Yield the directory records in a directory's data block."""
    offset = 0
    while offset < len(block):
        length = block[offset]
        if length == 0:
            # A record never spans a sector boundary: the rest of this sector is
            # padding, so jump to the next one.
            offset = (offset // SECTOR + 1) * SECTOR
            if offset >= len(block):
                return
            continue
        yield block[offset : offset + length]
        offset += length


def _walk(data: bytes, extent: int, length: int, prefix: str, report: IsoReport, depth: int):
    """Walk one directory extent, recursing into subdirectories."""
    if depth > MAX_DEPTH or len(report.files) >= MAX_FILES:
        return
    start = extent * SECTOR
    block = data[start : start + length]
    for record in _records(block):
        if len(record) < 33:
            continue
        child_extent = struct.unpack("<I", record[2:6])[0]
        child_length = struct.unpack("<I", record[10:14])[0]
        flags = record[25]
        name_len = record[32]
        name_raw = record[33 : 33 + name_len]
        # The first two records of every directory are "." (0x00) and ".." (0x01).
        if name_len == 1 and name_raw in (b"\x00", b"\x01"):
            continue
        if flags & 0x02:  # a subdirectory
            folder = f"{prefix}{_clean_name(name_raw)}/"
            _walk(data, child_extent, child_length, folder, report, depth + 1)
        else:
            file_start = child_extent * SECTOR
            payload = data[file_start : file_start + child_length]
            if len(payload) != child_length:
                report.notes.append(f"{prefix}{_clean_name(name_raw)} is truncated in the image")
            report.files.append(IsoFile(path=prefix + _clean_name(name_raw), data=payload))
            if len(report.files) >= MAX_FILES:
                return


def read(data: bytes) -> IsoReport:
    """Read an ISO 9660 image into its volume name and file tree."""
    if not looks_like_iso(data):
        raise IsoError("no ISO 9660 primary volume descriptor at sector 16 (offset 0x8000)")
    pvd = data[PVD_SECTOR * SECTOR : PVD_SECTOR * SECTOR + SECTOR]
    report = IsoReport(volume_id=pvd[40:72].decode("latin-1").strip())
    root_record = pvd[156:190]
    extent = struct.unpack("<I", root_record[2:6])[0]
    length = struct.unpack("<I", root_record[10:14])[0]
    _walk(data, extent, length, "", report, 0)
    if not report.files:
        report.notes.append("the image parsed but held no files (it may use Joliet-only names)")
    return report
