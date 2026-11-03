"""Read a RAR archive's headers: what is inside, and which encryption guards it.

RAR comes in two incompatible shapes and the first bytes say which:

    52 61 72 21 1A 07 00        "Rar!" + 1A 07 00     -> RAR 4 and earlier
    52 61 72 21 1A 07 01 00     "Rar!" + 1A 07 01 00  -> RAR 5

Both are a chain of blocks, each announcing its own size, so walking an archive
is a loop over "read the header, skip its data, repeat". RAR 4 writes fixed
little-endian fields; RAR 5 writes **vints** (7 bits per byte, high bit = "one
more byte follows"), which is the only thing that needs care.

What a CTF actually wants from this file:

- **the names**, when they are readable at all;
- **which encryption**. RAR encrypts in two ways, and the difference decides
  everything. `rar a -p` encrypts the *files* but leaves the names in clear, so
  you can see what you are missing. `rar a -hp` encrypts the *headers* too: the
  listing itself needs the password, which is why `unrar l` asks for one. In
  RAR 5 both are AES-256 with a PBKDF2-HMAC-SHA256 key whose iteration count is
  stored as a power of two, and that count is part of the hash `rar2john` emits.
- **no known-plaintext shortcut exists**, unlike ZipCrypto. The password has to
  be cracked, so the useful answer is the exact hashcat/john command.

Nothing is decompressed: RAR's compression is proprietary and unrar does it
well. This reads the headers, which is where the answers are.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core.errors import FormatError

RAR4_SIGNATURE = b"Rar!\x1a\x07\x00"
RAR5_SIGNATURE = b"Rar!\x1a\x07\x01\x00"

# --- RAR 4 -----------------------------------------------------------------
R4_MARKER = 0x72
R4_ARCHIVE = 0x73
R4_FILE = 0x74
R4_END = 0x7B
R4_ADD_SIZE = 0x8000  # the header is followed by that many bytes of data
R4_FILE_ENCRYPTED = 0x0004
R4_FILE_SOLID = 0x0010
R4_FILE_LARGE = 0x0100
R4_FILE_UNICODE = 0x0200
R4_FILE_SALT = 0x0400
R4_ARCHIVE_ENCRYPTED_HEADERS = 0x0080
R4_METHODS = {
    0x30: "stored",
    0x31: "fastest",
    0x32: "fast",
    0x33: "normal",
    0x34: "good",
    0x35: "best",
}

# --- RAR 5 -----------------------------------------------------------------
R5_MAIN = 1
R5_FILE = 2
R5_SERVICE = 3
R5_ENCRYPTION = 4
R5_END = 5
R5_EXTRA_AREA = 0x0001
R5_DATA_AREA = 0x0002
R5_FILE_DIRECTORY = 0x0001
R5_FILE_MTIME = 0x0002
R5_FILE_CRC = 0x0004
R5_FILE_UNKNOWN_SIZE = 0x0008
R5_EXTRA_ENCRYPTION = 1
R5_METHODS = {0: "stored", 1: "fastest", 2: "fast", 3: "normal", 4: "good", 5: "best"}
MAX_ENTRIES = 100_000


class RarError(FormatError):
    """The data is not a RAR we can read."""


@dataclass
class RarEntry:
    """One file, as its header describes it."""

    name: str
    size: int  # unpacked
    packed: int
    method: str = "?"
    encrypted: bool = False
    directory: bool = False
    crc: int = 0
    solid: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class RarArchive:
    """A parsed archive."""

    version: int  # 4 or 5
    entries: list[RarEntry] = field(default_factory=list)
    encrypted_headers: bool = False  # the listing itself needs the password
    kdf_count: int = 0  # RAR 5: PBKDF2 iterations are 2**kdf_count
    salt: bytes = b""
    notes: list[str] = field(default_factory=list)

    @property
    def any_encrypted(self) -> bool:
        return self.encrypted_headers or any(entry.encrypted for entry in self.entries)


def version_of(data: bytes) -> int:
    """4, 5, or 0 when this is not a RAR at all."""
    if data[:8] == RAR5_SIGNATURE:
        return 5
    if data[:7] == RAR4_SIGNATURE:
        return 4
    return 0


def _u16(data: bytes, offset: int) -> int:
    if offset + 2 > len(data):
        raise RarError(f"a 2-byte field at {offset} is past the end of the file")
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise RarError(f"a 4-byte field at {offset} is past the end of the file")
    return int.from_bytes(data[offset : offset + 4], "little")


def read_vint(data: bytes, offset: int) -> tuple[int, int]:
    """A RAR 5 variable-length integer: 7 bits per byte, little end first.

    Returns the value and the offset after it. Ten bytes is already more than
    64 bits, so anything longer is a crafted file.
    """
    if offset < 0:
        # A header whose declared extra area is bigger than the header itself
        # produces a negative offset, and a negative index reads the *end* of
        # the file instead of failing. Refuse it here, once, for every caller.
        raise RarError(f"a vint was asked for at offset {offset}: the header is corrupt")
    value = 0
    shift = 0
    for step in range(10):
        if offset + step >= len(data):
            raise RarError(f"a vint starting at {offset} runs off the end of the file")
        byte = data[offset + step]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset + step + 1
        shift += 7
    raise RarError(f"the vint at {offset} is longer than ten bytes: the file is corrupt")


# ---------------------------------------------------------------------------
# RAR 4
# ---------------------------------------------------------------------------


def _decode_rar4_name(raw: bytes) -> str:
    """A RAR 4 name: ASCII, or the odd two-part Unicode encoding after a NUL.

    With the Unicode flag set, the field is "ascii name \\0 compressed utf-16".
    The compressed part is rarely needed - the ASCII half is the same name for
    anything a challenge uses - so it is used when it is there and the raw bytes
    are decoded otherwise.
    """
    if b"\x00" in raw:
        ascii_part = raw.split(b"\x00", 1)[0]
        if ascii_part:
            return ascii_part.decode("utf-8", "replace")
    return raw.decode("utf-8", "replace")


def read_rar4(data: bytes) -> RarArchive:
    """Walk the block chain of a RAR 4 archive."""
    archive = RarArchive(version=4)
    position = len(RAR4_SIGNATURE)
    while position + 7 <= len(data):
        kind = data[position + 2]
        flags = _u16(data, position + 3)
        header_size = _u16(data, position + 5)
        if header_size < 7:
            raise RarError(f"the block at {position} says its header is {header_size} bytes")
        data_size = _u32(data, position + 7) if flags & R4_ADD_SIZE else 0

        if kind == R4_ARCHIVE:
            if flags & R4_ARCHIVE_ENCRYPTED_HEADERS:
                archive.encrypted_headers = True
                archive.notes.append(
                    "the archive header says the block headers are encrypted (rar -hp): "
                    "even the file names need the password, so nothing can be listed"
                )
                break
        elif kind == R4_FILE:
            archive.entries.append(_read_rar4_file(data, position, flags, header_size))
            if len(archive.entries) > MAX_ENTRIES:
                raise RarError("more entries than any real archive has")
        elif kind == R4_END:
            break

        step = header_size + data_size
        if step <= 0:
            raise RarError(f"the block at {position} does not advance: the chain loops")
        position += step
    if not archive.entries and not archive.encrypted_headers:
        raise RarError("no file header found in the RAR 4 block chain")
    return archive


def _read_rar4_file(data: bytes, position: int, flags: int, header_size: int) -> RarEntry:
    """One RAR 4 file header, from the fixed fields on."""
    packed = _u32(data, position + 7)
    unpacked = _u32(data, position + 11)
    crc = _u32(data, position + 16)
    method = data[position + 25] if position + 25 < len(data) else 0
    name_size = _u16(data, position + 26)
    attributes = _u32(data, position + 28)
    at = position + 32
    if flags & R4_FILE_LARGE:  # 64-bit sizes, split in two halves
        packed |= _u32(data, at) << 32
        unpacked |= _u32(data, at + 4) << 32
        at += 8
    if at + name_size > len(data) or at + name_size > position + header_size:
        raise RarError(f"the name of the entry at {position} does not fit in its header")
    entry = RarEntry(
        name=_decode_rar4_name(data[at : at + name_size]).replace("\\", "/"),
        size=unpacked,
        packed=packed,
        method=R4_METHODS.get(method, f"method {method:#x}"),
        encrypted=bool(flags & R4_FILE_ENCRYPTED),
        # A directory is marked twice over: the DOS attribute, and the dictionary
        # bits of the flags set to all ones (RAR 4's LHD_DIRECTORY).
        directory=bool(attributes & 0x10) or (flags & 0xE0) == 0xE0,
        crc=crc,
        solid=bool(flags & R4_FILE_SOLID),
    )
    if flags & R4_FILE_SALT:
        entry.notes.append("the header carries an 8-byte password salt")
    if flags & 0x0003:  # continued from, or into, another volume
        entry.notes.append("split across volumes: every part is needed to unpack it")
    return entry


# ---------------------------------------------------------------------------
# RAR 5
# ---------------------------------------------------------------------------


def read_rar5(data: bytes) -> RarArchive:
    """Walk the block chain of a RAR 5 archive."""
    archive = RarArchive(version=5)
    position = len(RAR5_SIGNATURE)
    while position + 4 < len(data):
        header_size, after_size = read_vint(data, position + 4)
        if header_size == 0:
            raise RarError(f"the block at {position} says its header is empty")
        header_end = after_size + header_size
        if header_end > len(data):
            # The last block of a truncated archive: say so and stop.
            archive.notes.append(
                f"the block at {position} claims {header_size} bytes of header but only "
                f"{len(data) - after_size} are left: the archive is truncated"
            )
            break
        kind, at = read_vint(data, after_size)
        flags, at = read_vint(data, at)
        extra_size = 0
        data_size = 0
        if flags & R5_EXTRA_AREA:
            extra_size, at = read_vint(data, at)
        if flags & R5_DATA_AREA:
            data_size, at = read_vint(data, at)

        if kind == R5_ENCRYPTION:
            _read_rar5_encryption(archive, data, at)
            break  # every header after this one is AES-encrypted
        if kind in (R5_FILE, R5_SERVICE):
            entry = _read_rar5_file(data, at, data_size, header_end, extra_size)
            if kind == R5_FILE:
                archive.entries.append(entry)
            elif entry.name == "CMT":
                archive.notes.append("the archive carries a comment (unrar lb prints it)")
            if len(archive.entries) > MAX_ENTRIES:
                raise RarError("more entries than any real archive has")
        elif kind == R5_END:
            break

        position = header_end + data_size
    if not archive.entries and not archive.encrypted_headers:
        raise RarError("no file header found in the RAR 5 block chain")
    return archive


def _read_rar5_encryption(archive: RarArchive, data: bytes, at: int) -> None:
    """The RAR 5 encryption block, which means the whole listing is encrypted."""
    archive.encrypted_headers = True
    version, at = read_vint(data, at)
    flags, at = read_vint(data, at)
    if at < len(data):
        archive.kdf_count = data[at]
        archive.salt = data[at + 1 : at + 17]
    iterations = 1 << archive.kdf_count if archive.kdf_count else 0
    archive.notes.append(
        f"headers encrypted with AES-256 (rar -hp), key = PBKDF2-HMAC-SHA256 with "
        f"2^{archive.kdf_count} = {iterations} iterations"
        + (f", salt {archive.salt.hex()}" if archive.salt else "")
        + ": the file names cannot be listed without the password"
    )
    if version != 0:
        archive.notes.append(f"encryption version {version} is not the AES-256 one ctfc knows")


def _read_rar5_file(
    data: bytes, at: int, data_size: int, header_end: int, extra_size: int
) -> RarEntry:
    """One RAR 5 file (or service) header."""
    file_flags, at = read_vint(data, at)
    unpacked, at = read_vint(data, at)
    _attributes, at = read_vint(data, at)
    if file_flags & R5_FILE_MTIME:
        at += 4
    crc = 0
    if file_flags & R5_FILE_CRC:
        crc = _u32(data, at)
        at += 4
    compression, at = read_vint(data, at)
    _host_os, at = read_vint(data, at)
    name_size, at = read_vint(data, at)
    if at + name_size > len(data):
        raise RarError("a RAR 5 entry name runs past the end of the file")
    entry = RarEntry(
        name=data[at : at + name_size].decode("utf-8", "replace").replace("\\", "/"),
        size=unpacked,
        packed=data_size,
        method=R5_METHODS.get((compression >> 7) & 0x07, "?"),
        directory=bool(file_flags & R5_FILE_DIRECTORY),
        crc=crc,
        solid=bool(compression & 0x40),
    )
    # The extra area sits at the end of the header and holds, among other
    # records, the per-file encryption one (`rar -p`: names stay in clear).
    # Each record is "vint size, vint type, body", and `size` counts everything
    # after the size field itself.
    extra_at = header_end - extra_size
    while 0 <= extra_at < header_end and extra_size:
        record_size, after_size = read_vint(data, extra_at)
        if record_size <= 0 or after_size + record_size > header_end:
            break
        record_type, cursor = read_vint(data, after_size)
        if record_type == R5_EXTRA_ENCRYPTION:
            entry.encrypted = True
            _version, cursor = read_vint(data, cursor)
            _flags, cursor = read_vint(data, cursor)
            if cursor < len(data):
                count = data[cursor]
                entry.notes.append(
                    f"AES-256, PBKDF2-HMAC-SHA256 with 2^{count} = {1 << count} iterations"
                )
        extra_at = after_size + record_size
    if file_flags & R5_FILE_UNKNOWN_SIZE:
        entry.notes.append("the header does not state the unpacked size (written as a stream)")
    return entry


def read(data: bytes) -> RarArchive:
    """Parse whichever RAR this is."""
    version = version_of(data)
    if version == 5:
        return read_rar5(data)
    if version == 4:
        return read_rar4(data)
    raise RarError("not a RAR archive (no Rar!\\x1a\\x07\\x00 or Rar!\\x1a\\x07\\x01\\x00 marker)")
