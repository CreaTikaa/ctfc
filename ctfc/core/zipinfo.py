"""Look closely at a ZIP: how it is encrypted, what it hides, and the tiny files.

`unzip -l` tells you the names. The things that decide a challenge are the ones
it does not show:

- **which encryption**. Bit 0 of an entry's flags means "encrypted", but there
  are two completely different schemes behind it. The traditional PKWARE cipher
  (*ZipCrypto*) falls to a known-plaintext attack with no password at all;
  WinZip **AES** (method 99) does not, and has to be cracked through a hash. The
  attack to reach for is the opposite in each case, so naming it matters.
- **the CRC32 of a very short file**. The CRC is of the *plaintext*, and it is
  stored in clear even for an encrypted entry. For a file of a few bytes, there
  is effectively one string with that CRC, so the content can be recovered
  **without the password**. Challenge authors hide one-word flags this way.
- **a local header that disagrees with the central directory**. Unzip trusts the
  central directory; many tools trust the local header. A file can therefore
  show one name or size and extract as another.
- **the archive comment**, which `unzip -l` prints at the bottom and everyone
  scrolls past.
- **a path that escapes the folder** (`../`), and an entry whose compression
  ratio makes it a bomb.

Everything is read by hand rather than through `zipfile`, because the point is to
see the disagreements a well-behaved reader hides.
"""

from __future__ import annotations

import string
import zlib
from dataclasses import dataclass, field

from ctfc.core.budget import Budget

LOCAL_HEADER = b"PK\x03\x04"
CENTRAL_HEADER = b"PK\x01\x02"
END_OF_CENTRAL = b"PK\x05\x06"
ZIP64_END = b"PK\x06\x06"
AES_EXTRA = 0x9901
ZIP64_EXTRA = 0x0001
AES_METHOD = 99
# Compression methods, by the number stored in the header.
METHODS = {
    0: "stored",
    1: "shrunk",
    6: "imploded",
    8: "deflate",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
    95: "xz",
    98: "ppmd",
    99: "WinZip AES",
}
AES_STRENGTH = {1: "AES-128", 2: "AES-192", 3: "AES-256"}
# Recovering a short plaintext from its CRC32. 256**2 is instant; three bytes is
# 16.7 million checks, so that pass is limited to the characters a flag uses.
CRC_FULL_MAX = 2
CRC_TEXT_MAX = 3
CRC_ALPHABET = (string.ascii_letters + string.digits + "_-{}!?.,: @#$%&*+=/\\\n\r\t").encode()
BOMB_RATIO = 200  # an entry that expands more than this is worth a warning


class ZipError(Exception):
    """The data is not a ZIP we can read."""


@dataclass
class Entry:
    """One entry, as the central directory describes it."""

    name: str
    method: int
    flags: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    comment: str = ""
    aes_strength: str = ""
    real_method: int | None = None  # the method hidden behind WinZip AES
    recovered: bytes | None = None  # plaintext recovered from the CRC32
    problems: list[str] = field(default_factory=list)

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def zipcrypto(self) -> bool:
        """Encrypted with the traditional PKWARE cipher, which bkcrack breaks."""
        return self.encrypted and self.method != AES_METHOD

    @property
    def method_name(self) -> str:
        name = METHODS.get(self.method, f"method {self.method}")
        if self.method == AES_METHOD and self.real_method is not None:
            inner = METHODS.get(self.real_method, str(self.real_method))
            return f"{self.aes_strength or name} over {inner}"
        return name

    @property
    def ratio(self) -> float:
        return self.uncompressed_size / self.compressed_size if self.compressed_size else 0.0


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def find_end_of_central(data: bytes) -> int:
    """The offset of the end-of-central-directory record, searched from the end."""
    # The record is 22 bytes plus a comment of at most 65535.
    window = max(0, len(data) - (22 + 0xFFFF))
    position = data.rfind(END_OF_CENTRAL, window)
    if position < 0:
        raise ZipError(
            "no end-of-central-directory record (PK\\x05\\x06): the archive is "
            "truncated, or it is a ZIP fragment rather than a whole file"
        )
    return position


def _parse_extra(entry: Entry, extra: bytes) -> None:
    """Read the extra fields we care about: WinZip AES, and Zip64 sizes."""
    position = 0
    while position + 4 <= len(extra):
        tag = _u16(extra, position)
        size = _u16(extra, position + 2)
        body = extra[position + 4 : position + 4 + size]
        position += 4 + size
        if tag == AES_EXTRA and len(body) >= 7:
            entry.aes_strength = AES_STRENGTH.get(body[4], f"AES strength {body[4]}")
            entry.real_method = _u16(body, 5)
        elif tag == ZIP64_EXTRA and len(body) >= 8:
            # Zip64 replaces the 32-bit sizes when they were written as 0xFFFFFFFF.
            if entry.uncompressed_size == 0xFFFFFFFF:
                entry.uncompressed_size = int.from_bytes(body[0:8], "little")
            if entry.compressed_size == 0xFFFFFFFF and len(body) >= 16:
                entry.compressed_size = int.from_bytes(body[8:16], "little")


def read_central_directory(data: bytes) -> tuple[list[Entry], str]:
    """Every entry from the central directory, plus the archive comment."""
    end = find_end_of_central(data)
    total = _u16(data, end + 10)
    # The directory's own size (end + 12) is not used: entries are followed until
    # the PK\x01\x02 signatures run out, which also survives a wrong size field.
    offset = _u32(data, end + 16)
    comment_length = _u16(data, end + 20)
    comment = data[end + 22 : end + 22 + comment_length].decode("utf-8", "replace")

    if offset == 0xFFFFFFFF or total == 0xFFFF:
        # Zip64: the real directory offset lives in the Zip64 end record.
        locator = data.rfind(ZIP64_END, 0, end)
        if locator >= 0:
            total = int.from_bytes(data[locator + 32 : locator + 40], "little")
            offset = int.from_bytes(data[locator + 48 : locator + 56], "little")

    entries: list[Entry] = []
    position = offset
    if position + 46 > len(data) or data[position : position + 4] != CENTRAL_HEADER:
        # A self-extracting or concatenated archive: find the directory ourselves.
        position = data.find(CENTRAL_HEADER)
        if position < 0:
            raise ZipError("the central directory offset is wrong and no PK\\x01\\x02 was found")
    while position + 46 <= len(data) and data[position : position + 4] == CENTRAL_HEADER:
        name_length = _u16(data, position + 28)
        extra_length = _u16(data, position + 30)
        comment_len = _u16(data, position + 32)
        entry = Entry(
            name=data[position + 46 : position + 46 + name_length].decode("utf-8", "replace"),
            flags=_u16(data, position + 8),
            method=_u16(data, position + 10),
            crc=_u32(data, position + 16),
            compressed_size=_u32(data, position + 20),
            uncompressed_size=_u32(data, position + 24),
            local_offset=_u32(data, position + 42),
        )
        extra_at = position + 46 + name_length
        _parse_extra(entry, data[extra_at : extra_at + extra_length])
        entry.comment = data[
            extra_at + extra_length : extra_at + extra_length + comment_len
        ].decode("utf-8", "replace")
        entries.append(entry)
        position = extra_at + extra_length + comment_len
        if len(entries) > 100_000:
            break
    if not entries and total:
        raise ZipError(f"the directory says {total} entries but none could be read")
    return entries, comment


def compare_with_local(data: bytes, entry: Entry) -> list[str]:
    """Disagreements between the local header and the central directory.

    Unzip believes the central directory; plenty of other tools believe the local
    header. A file that reads differently through each is hiding something.
    """
    problems: list[str] = []
    offset = entry.local_offset
    if offset + 30 > len(data) or data[offset : offset + 4] != LOCAL_HEADER:
        problems.append(f"no local header at offset {offset}: the directory points nowhere")
        return problems
    name_length = _u16(data, offset + 26)
    local_name = data[offset + 30 : offset + 30 + name_length].decode("utf-8", "replace")
    if local_name != entry.name:
        problems.append(
            f"the local header calls it {local_name!r}, the directory {entry.name!r}: "
            "different tools will show different names"
        )
    local_method = _u16(data, offset + 8)
    if local_method != entry.method:
        problems.append(
            f"method differs: {METHODS.get(local_method, local_method)} locally, "
            f"{entry.method_name} in the directory"
        )
    local_crc = _u32(data, offset + 14)
    # A streamed entry (bit 3) legitimately writes zeros here and a data descriptor after.
    if local_crc != entry.crc and not (entry.flags & 0x0008 and local_crc == 0):
        problems.append(f"CRC differs: {local_crc:08x} locally, {entry.crc:08x} in the directory")
    return problems


def recover_from_crc(crc: int, size: int, budget: Budget | None = None) -> bytes | None:
    """Recover a very short plaintext from its CRC32.

    For a file of one or two bytes every possibility is tried. For three, only
    the characters a flag or a word is made of - the full 16.7 million is slow in
    Python and almost never needed. The CRC is stored in clear even when the
    entry is encrypted, so this works with no password.
    """
    if size <= 0 or size > CRC_TEXT_MAX:
        return None
    budget = budget or Budget(max_attempts=20_000_000, max_seconds=30)
    alphabet = range(256) if size <= CRC_FULL_MAX else CRC_ALPHABET

    def search(prefix: bytes) -> bytes | None:
        if len(prefix) == size:
            return prefix if zlib.crc32(prefix) == crc else None
        for byte in alphabet:
            if not budget.spend():
                return None
            found = search(prefix + bytes([byte]))
            if found is not None:
                return found
        return None

    return search(b"")


@dataclass
class ZipReport:
    """What the archive holds and how to get into it."""

    entries: list[Entry] = field(default_factory=list)
    comment: str = ""
    trailing: int = 0
    notes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "comment": self.comment,
            "trailing": self.trailing,
            "entries": [
                {
                    "name": entry.name,
                    "method": entry.method_name,
                    "encrypted": entry.encrypted,
                    "zipcrypto": entry.zipcrypto,
                    "crc": f"{entry.crc:08x}",
                    "compressed_size": entry.compressed_size,
                    "uncompressed_size": entry.uncompressed_size,
                    "comment": entry.comment,
                    "recovered": None
                    if entry.recovered is None
                    else entry.recovered.decode("utf-8", "replace"),
                    "problems": list(entry.problems),
                }
                for entry in self.entries
            ],
            "notes": list(self.notes),
            "commands": list(self.commands),
        }


def analyse(data: bytes, path: str = "archive.zip", budget: Budget | None = None) -> ZipReport:
    """Read the archive and say what to do with it."""
    if data[:4] not in (LOCAL_HEADER, CENTRAL_HEADER) and END_OF_CENTRAL not in data[-65557:]:
        raise ZipError("not a ZIP archive (no PK\\x03\\x04 and no end-of-directory record)")
    entries, comment = read_central_directory(data)
    report = ZipReport(entries=entries, comment=comment)

    if comment.strip():
        report.notes.append(f"archive comment: {comment.strip()[:300]}")
    for entry in entries:
        entry.problems = compare_with_local(data, entry)
        if entry.comment.strip():
            report.notes.append(f"{entry.name}: entry comment: {entry.comment.strip()[:200]}")
        if entry.name.startswith("/") or ".." in entry.name.replace("\\", "/").split("/"):
            report.notes.append(
                f"{entry.name!r} escapes the extraction folder: extract it with "
                "`unzip -j` or into a throwaway directory"
            )
        if entry.ratio > BOMB_RATIO:
            report.notes.append(
                f"{entry.name} expands {entry.ratio:.0f}x "
                f"({entry.compressed_size} -> {entry.uncompressed_size} bytes): "
                "check the size before extracting it"
            )
        # The CRC is the plaintext's, and it is in clear even when encrypted.
        if 0 < entry.uncompressed_size <= CRC_TEXT_MAX and entry.crc:
            entry.recovered = recover_from_crc(entry.crc, entry.uncompressed_size, budget)
            if entry.recovered is not None:
                report.notes.append(
                    f"{entry.name} is {entry.uncompressed_size} bytes, so its CRC32 gives "
                    f"the content away without the password: {entry.recovered!r}"
                )

    encrypted = [entry for entry in entries if entry.encrypted]
    zipcrypto = [entry for entry in encrypted if entry.zipcrypto]
    aes = [entry for entry in encrypted if not entry.zipcrypto]
    if not encrypted:
        report.notes.append("nothing is encrypted: just extract it")
    if zipcrypto:
        report.notes.append(
            f"{len(zipcrypto)} entry/entries use ZipCrypto (the traditional cipher). "
            "It falls to a known-plaintext attack with no password at all: if you can "
            "guess any 8+ bytes of one file, bkcrack recovers the keys for the whole archive"
        )
        report.commands.append(f"ctfc tools {path}   # prints the bkcrack command, filled in")
        report.commands.append(f"zip2john {path} > zip.hash && ctfc hash <that line>")
    if aes:
        strengths = {entry.aes_strength or "AES" for entry in aes}
        report.notes.append(
            f"{len(aes)} entry/entries use WinZip {'/'.join(sorted(strengths))}. There is no "
            "known-plaintext attack on this one: the password has to be cracked"
        )
        if all(entry.crc == 0 for entry in aes):
            report.notes.append(
                "their CRC fields are zero, which is normal for WinZip AE-2 - and it is why "
                "the short-file CRC trick cannot work on an AES archive"
            )
        report.commands.append(f"zip2john {path} > zip.hash && hashcat -m 13600 zip.hash wordlist")

    end = find_end_of_central(data)
    report.trailing = len(data) - (end + 22 + _u16(data, end + 20))
    if report.trailing > 0:
        report.notes.append(
            f"{report.trailing} byte(s) after the end of the archive: another file may be "
            "appended. `ctfc detect` the whole thing"
        )
    return report
