"""zip2john's `$pkzip2$` hash: read it, crack it, and get the file back out of it.

The crypto concept: `zip2john` does not hash anything. For a ZipCrypto entry
(see `zipcrypto.py`) it copies the **encrypted bytes themselves** into the
line, with the CRC-32 of the plaintext. So a password that decrypts those bytes
into data whose CRC-32 matches is *the* password - and the decrypted bytes are
the file. When the whole entry fits in the line ("data type 2"), the archive is
not even needed: the hash is the archive (BuckeyeCTF 2025 "zip2john2zip").

The line, as john documents it (`pkzip_fmt_plug.c`), all numbers in hex:

    $pkzip2$C*B*DT*MT*CL*UL*CR*OF*OX*CT*DL*CS*TC*DA*$/pkzip2$
      C  how many entries follow (each one is DT..DA)
      B  how many check bytes the 12-byte header ends with (1, or 2 for Info-ZIP)
      DT 1 = only the start of the data, 2 = all of it
      MT a "magic" hint for john (0 = none)
      CL UL CR OF OX   only when DT is not 1: compressed size (with the
                       12-byte header), real size, CRC-32, offsets in the zip
      CT compression: 0 stored, 8 deflate
      DL DA  the data length and the data (hex)
      CS TC  the two possible check values: from the CRC, or from the file time

Nothing here is run or executed: the bytes are decrypted and inflated, that is all.
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field

from ctfc.core import zipcrypto
from ctfc.core.budget import Budget

HASH_RE = re.compile(r"\$pkzip2?\$(.*?)\*\$/pkzip2?\$")
# zip2john prints "archive.zip/name.txt:$pkzip2$...$/pkzip2$:name.txt:archive.zip::archive.zip"
NAME_AFTER_RE = re.compile(r"\$/pkzip2?\$:([^:]+)")
NAME_BEFORE_RE = re.compile(r"^[^:$]*?/([^:/$]+):\$pkzip")


@dataclass
class PkzipEntry:
    """One encrypted ZIP entry, as zip2john copied it."""

    full: bool  # DT == 2: every encrypted byte is in the line
    compression: int  # 0 stored, 8 deflate
    data: bytes  # the encrypted bytes, 12-byte header first
    check: int  # CS: the top 16 bits of the CRC-32, normally
    time_check: int  # TC: the same from the file time (data-descriptor zips)
    crc: int | None = None  # CRC-32 of the plaintext (full entries only)
    size: int | None = None  # uncompressed size (full entries only)

    def checks(self, check_bytes: int) -> tuple[bytes, ...]:
        """The values the decrypted header may end with (CS or TC, 1 or 2 bytes)."""
        values = []
        for value in (self.check, self.time_check):
            pair = struct.pack("<H", value)  # header[10], header[11]
            values.append(pair if check_bytes == 2 else pair[1:])
        return tuple(dict.fromkeys(values))


@dataclass
class PkzipHash:
    """A whole `$pkzip2$` line."""

    check_bytes: int
    entries: list[PkzipEntry]
    name: str = "file.bin"  # the entry's file name, when zip2john printed it
    notes: list[str] = field(default_factory=list)


@dataclass
class Cracked:
    """The password, and what it decrypts the entry to."""

    password: bytes
    plaintext: bytes | None  # None when the line holds only part of the data
    tried: int


def parse(text: str) -> PkzipHash | None:
    """Read a `$pkzip2$` line; None if it is not one, or is malformed."""
    match = HASH_RE.search(text.strip())
    if match is None:
        return None
    fields = match.group(1).split("*")
    try:
        count, check_bytes = int(fields[0], 16), int(fields[1], 16)
        position = 2
        entries = []
        for _ in range(count):
            data_type = int(fields[position], 16)
            position += 2  # DT and MT
            crc = size = None
            if data_type != 1:
                size = int(fields[position + 1], 16)
                crc = int(fields[position + 2], 16)
                position += 5  # CL UL CR OF OX
            compression = int(fields[position], 16)
            length = int(fields[position + 1], 16)
            check = int(fields[position + 2], 16)
            time_check = int(fields[position + 3], 16)
            data = bytes.fromhex(fields[position + 4])
            position += 5
            if data_type == 3 or len(data) != length or len(data) < 12:
                return None  # DT 3 = "read the zip from disk": the bytes are not here
            entries.append(
                PkzipEntry(
                    full=data_type == 2,
                    compression=compression,
                    data=data,
                    check=check,
                    time_check=time_check,
                    crc=crc,
                    size=size,
                )
            )
    except (IndexError, ValueError):
        return None
    if not entries:
        return None
    parsed = PkzipHash(check_bytes=check_bytes, entries=entries)
    name = NAME_AFTER_RE.search(text) or NAME_BEFORE_RE.search(text.strip())
    if name:
        parsed.name = name.group(1)
    if not any(entry.full for entry in entries):
        parsed.notes.append(
            "the line holds only the start of the data (data type 1): a password can be "
            "found, but the file cannot be rebuilt from the hash alone"
        )
    return parsed


def hashcat_mode(parsed: PkzipHash) -> int:
    """hashcat's mode for this line: 17210 stored, 17200 deflated, 17220/17225 several files."""
    if len(parsed.entries) > 1:
        return 17225 if any(entry.compression == 8 for entry in parsed.entries) else 17220
    return 17200 if parsed.entries[0].compression == 8 else 17210


def _open(entry: PkzipEntry, password: bytes) -> bytes | None:
    """Decrypt and inflate a full entry; the plaintext if its CRC-32 matches."""
    plain = zipcrypto.decrypt(entry.data, zipcrypto.keys_for(password))[12:]
    if entry.compression == 8:
        try:
            plain = zlib.decompress(plain, -zlib.MAX_WBITS)
        except zlib.error:
            return None
    elif entry.compression != 0:
        return None
    return plain if zlib.crc32(plain) & 0xFFFFFFFF == entry.crc else None


def crack(parsed: PkzipHash, passwords, budget: Budget | None = None) -> Cracked | None:
    """Try each password: the 12-byte header filter first, then the CRC-32.

    A password must pass the header check of every entry in the line (that is
    what makes a false hit rare when there are several), and decrypt a full
    entry to the right CRC-32. With only partial entries, passing the header
    checks is all there is: said so in `parsed.notes`.
    """
    checks = [entry.checks(parsed.check_bytes) for entry in parsed.entries]
    full = next((entry for entry in parsed.entries if entry.full), None)
    tried = 0
    for password in passwords:
        if budget is not None and not budget.spend():
            break
        tried += 1
        if not all(
            zipcrypto.header_matches(entry.data, password, entry_checks)
            for entry, entry_checks in zip(parsed.entries, checks, strict=True)
        ):
            continue
        if full is None:
            return Cracked(password=password, plaintext=None, tried=tried)
        plaintext = _open(full, password)
        if plaintext is not None:
            return Cracked(password=password, plaintext=plaintext, tried=tried)
    return None


def rebuild_zip(parsed: PkzipHash) -> bytes | None:
    """The one-entry encrypted ZIP the line came from (the "2zip" of zip2john2zip).

    Any ZIP tool opens it with the password (7z, unzip, Python's zipfile). The
    header's check byte comes from the CRC (CS) unless CS does not match the
    CRC: then the zip used a data descriptor, and the check comes from the file
    time (TC), which ZIP marks with general-purpose bit 3.
    """
    entry = next((entry for entry in parsed.entries if entry.full), None)
    if entry is None or entry.crc is None or entry.size is None:
        return None
    name = parsed.name.encode("utf-8", errors="replace")
    flags = 0x0001  # bit 0: encrypted
    mod_time = 0
    if entry.check != entry.crc >> 16:
        flags |= 0x0008  # bit 3: the check byte is the top of the file time
        mod_time = entry.time_check
    sizes = (entry.crc, len(entry.data), entry.size)
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, entry.compression, mod_time, 0, *sizes, len(name), 0
    )
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20,
        20,
        flags,
        entry.compression,
        mod_time,
        0,
        *sizes,
        len(name),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    body = local + name + entry.data
    directory = central + name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(directory), len(body), 0)
    return body + directory + end
