"""Repair and carve files whose header was broken on purpose.

A whole family of forensics challenges is built on the same three tricks, often
stacked in one file (the "Pixel Rehab" shape):

1. **one byte of the magic is wrong** - `88 50 4E 47` instead of `89 50 4E 47`,
   so `file` says "data" and every tool refuses to open it;
2. **something is appended after the end marker** of the container (a 7z after a
   PNG's IEND chunk, a ZIP after `%%EOF`);
3. **a header is pasted over the hidden file's own magic**, to make the appended
   bytes look like the container again.

None of this needs guessing: a signature table answers all three.

- A magic that differs from a known one by **a single byte** is a corruption, not
  a coincidence: 4 bytes agreeing out of 5 happens by chance once in 4 billion.
- Bytes after the end marker are already reported by `magic.find_trailing_data`.
- A file that starts with a **proper prefix** of a known magic but not the whole
  magic (`89 50 4E 47 0D 0A` - the first 6 bytes of a PNG signature, then not
  `1A 0A`) cannot be that format: those bytes were written over something else.
  The length of the pasted prefix says what fits underneath - 6 bytes is exactly
  the size of the 7z magic.

Everything here is a pure function on bytes: nothing is executed, nothing is
written unless the CLI is asked to.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

from ctfc.core.magic import Signature, find_trailing_data, load_signatures, match_signature

MIN_MAGIC = 4  # shorter magics give too many coincidences
# What to do with a carved file, by extension (printed, never run).
NEXT_COMMAND = {
    "7z": "7z x {file}",
    "zip": "unzip {file}   (password-protected? zip2john {file} > zip.hash)",
    "rar": "unrar x {file}",
    "gz": "gunzip -k {file}",
    "xz": "unxz -k {file}",
    "bz2": "bunzip2 -k {file}",
    "tar": "tar xvf {file}",
    "png": "ctfc detect {file}   (then zsteg / exiftool)",
    "jpg": "ctfc detect {file}   (then steghide / exiftool)",
    "pdf": "pdfdetach -saveall {file}; pdftotext {file} -",
    "elf": "ctfc detect {file}; diec {file}",
    "exe": "ctfc detect {file}; diec {file}",
}
MIN_CARVE = 16  # ignore carved pieces smaller than this
MAX_FITS = 8  # a pasted header is a deduction only when few formats fit underneath


@dataclass
class Fix:
    """One byte-level repair, with the reason to trust it."""

    offset: int
    old: bytes
    new: bytes
    why: str

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "old_hex": self.old.hex(),
            "new_hex": self.new.hex(),
            "why": self.why,
        }

    def command(self, path: str = "<file>") -> str:
        """The one-liner that applies this fix to a copy of the file."""
        escaped = "".join(f"\\x{byte:02x}" for byte in self.new)
        return f"printf '{escaped}' | dd of={path} bs=1 seek={self.offset} conv=notrunc"


@dataclass
class Carved:
    """A file found inside another one."""

    offset: int
    name: str  # "PNG image"
    ext: str  # "png"
    data: bytes = field(repr=False, default=b"")
    why: str = ""

    def filename(self, index: int) -> str:
        return f"carved_{index:02d}_0x{self.offset:x}.{self.ext}"

    def next_command(self, path: str) -> str:
        """What to run on this piece once written to `path`."""
        template = NEXT_COMMAND.get(self.ext, "ctfc detect {file}")
        return template.format(file=path)

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "offset_hex": f"0x{self.offset:x}",
            "name": self.name,
            "ext": self.ext,
            "size": len(self.data),
            "why": self.why,
        }


@dataclass
class RepairReport:
    """What was wrong with the file, and what came out of it."""

    fixes: list[Fix] = field(default_factory=list)
    carved: list[Carved] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    repaired: bytes = field(repr=False, default=b"")

    @property
    def changed(self) -> bool:
        return bool(self.fixes or self.carved)

    def to_dict(self) -> dict:
        return {
            "fixes": [fix.to_dict() for fix in self.fixes],
            "carved": [item.to_dict() for item in self.carved],
            "notes": list(self.notes),
            "repaired_size": len(self.repaired),
        }


# ---------------------------------------------------------------------------
# Is this really a <format>? Cheap structural checks, beyond the magic bytes
# ---------------------------------------------------------------------------
#
# A magic is 4 to 8 bytes, so when several formats could sit under a pasted
# header, the magic alone cannot choose. The bytes that FOLLOW it can: a 7z
# stores the CRC32 of its own start header, a PNG must have IHDR as its first
# chunk, a ZIP a sane compression method. One check that passes where the others
# fail turns a list of guesses into an answer.
#
# Each validator reads only the first bytes and returns True / False. Only STRONG
# checks belong here: a stored CRC, or several constraints that random bytes meet
# less than once in a million. A check that passes by chance one time in ten (a
# non-zero GIF canvas size) would "confirm" garbage, so formats without a strong
# check have no validator and are never confirmed (None).


def _check_7z(data: bytes) -> bool:
    """7z: magic (6), version (2), then the CRC32 of the 20-byte start header."""
    if len(data) < 32:
        return False
    return zlib.crc32(data[12:32]) == int.from_bytes(data[8:12], "little")


def _check_xz(data: bytes) -> bool:
    """xz: magic (6), stream flags (2: 0x00 + check type), CRC32 of those 2 bytes."""
    if len(data) < 12:
        return False
    flags = data[6:8]
    return (
        flags[0] == 0
        and flags[1] in (0, 1, 4, 10)
        and (zlib.crc32(flags) == int.from_bytes(data[8:12], "little"))
    )


def _check_png(data: bytes) -> bool:
    """PNG: the first chunk is IHDR (13 bytes), and its CRC32 is right."""
    if len(data) < 33 or data[8:16] != b"\x00\x00\x00\rIHDR":
        return False
    return zlib.crc32(data[12:29]) == int.from_bytes(data[29:33], "big")


def _check_zip(data: bytes) -> bool:
    """ZIP local header: a version, a known method, a printable file name of that length."""
    if len(data) < 30:
        return False
    version = int.from_bytes(data[4:6], "little")
    method = int.from_bytes(data[8:10], "little")
    name_length = int.from_bytes(data[26:28], "little")
    name = data[30 : 30 + name_length]
    return (
        version <= 63
        and method in (0, 1, 6, 8, 9, 12, 14, 93, 95, 98)
        and 0 < name_length < 1024
        and len(name) == name_length
        and all(32 <= byte < 127 for byte in name)
    )


def _check_elf(data: bytes) -> bool:
    """ELF: class, byte order, ident version, and e_version = 1 in that byte order."""
    if len(data) < 24 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        return False
    order = "little" if data[5] == 1 else "big"
    return int.from_bytes(data[20:24], order) == 1


def _check_luks(data: bytes) -> bool:
    """LUKS1: version 1 and a printable, NUL-padded cipher name (e.g. "aes")."""
    if len(data) < 40 or int.from_bytes(data[6:8], "big") != 1:
        return False
    name = data[8:40].rstrip(b"\x00")
    return 2 <= len(name) <= 31 and all(32 < byte < 127 for byte in name)


VALIDATORS = {
    "7z": _check_7z,
    "xz": _check_xz,
    "png": _check_png,
    "zip": _check_zip,
    "elf": _check_elf,
    "luks": _check_luks,
}


def validate(data: bytes, sig: Signature) -> bool | None:
    """Does `data` look like a real `sig` file beyond its magic?

    True / False when a check exists for that format, None when none does.
    """
    checker = VALIDATORS.get(sig.ext)
    return checker(data) if checker is not None else None


def _candidates() -> list[Signature]:
    """Signatures worth matching at offset 0: long enough, and not the weak ones."""
    return [
        sig
        for sig in load_signatures()
        if sig.offset == 0 and not sig.weak and len(sig.magic) >= MIN_MAGIC
    ]


def near_miss(data: bytes) -> tuple[Signature, int, int] | None:
    """A magic that is one byte away from a known one: (signature, offset, actual byte).

    Returns None when the file already matches a signature, or when nothing is
    close enough. Only ONE differing byte is accepted - two would be a guess.
    """
    if match_signature(data) is not None:
        return None
    for sig in _candidates():
        head = data[: len(sig.magic)]
        if len(head) < len(sig.magic):
            continue
        wrong = [index for index, (a, b) in enumerate(zip(head, sig.magic, strict=True)) if a != b]
        if len(wrong) == 1:
            return sig, wrong[0], head[wrong[0]]
    return None


def pasted_header(data: bytes) -> tuple[Signature, list[Signature]] | None:
    """Bytes that start with *part* of a known magic: a header pasted over something.

    Returns (the signature that was pasted, the formats whose magic has exactly
    that length and could be underneath).
    """
    best: tuple[Signature, list[Signature]] | None = None
    best_length = 0
    for sig in _candidates():
        magic = sig.magic
        if data[: len(magic)] == magic:
            continue
        # The LONGEST matching prefix is the one that was pasted: 6 bytes of a PNG
        # signature is a deliberate paste, its first 4 bytes are just a consequence.
        for length in range(len(magic) - 1, MIN_MAGIC - 1, -1):
            if data[:length] != magic[:length]:
                continue
            if length > best_length:
                fits = [other for other in _candidates() if len(other.magic) == length]
                # Dozens of formats share the commonest magic length: that is no
                # longer a deduction, so only a short list is worth showing.
                if len(fits) <= MAX_FITS:
                    best, best_length = (sig, fits), length
            break
    return best


def carve(data: bytes, limit: int = 8) -> list[Carved]:
    """Files hidden inside `data`, found by their signature (offset > 0).

    Each carved piece runs to the start of the next one, or to the end of the
    data: a signature says where a file *starts*, not where it ends, and cutting
    short would be worse than cutting long (most parsers ignore trailing bytes).
    """
    hits: list[tuple[int, Signature]] = []
    for sig in _candidates():
        position = data.find(sig.magic, 1)
        while position != -1 and len(hits) < limit * 4:
            hits.append((position, sig))
            position = data.find(sig.magic, position + 1)
    hits.sort(key=lambda item: item[0])
    # One file per offset (several signatures can share a prefix).
    unique: list[tuple[int, Signature]] = []
    for offset, sig in hits:
        if not unique or unique[-1][0] != offset:
            unique.append((offset, sig))

    carved = []
    for index, (offset, sig) in enumerate(unique[:limit]):
        end = unique[index + 1][0] if index + 1 < len(unique) else len(data)
        piece = data[offset:end]
        if len(piece) < MIN_CARVE:
            continue
        carved.append(
            Carved(
                offset=offset,
                name=sig.name,
                ext=sig.ext,
                data=piece,
                why=f"{sig.name} signature at offset 0x{offset:x}",
            )
        )
    return carved


def repair(data: bytes) -> RepairReport:
    """Fix what can be fixed, then carve what the file was hiding."""
    report = RepairReport(repaired=data)

    miss = near_miss(data)
    if miss is not None:
        sig, offset, actual = miss
        fixed = bytearray(data)
        fixed[offset] = sig.magic[offset]
        report.repaired = bytes(fixed)
        report.fixes.append(
            Fix(
                offset=offset,
                old=bytes([actual]),
                new=bytes([sig.magic[offset]]),
                why=f"byte {offset} is 0x{actual:02x} where a {sig.name} has "
                f"0x{sig.magic[offset]:02x}: every other byte of the signature matches",
            )
        )
        report.notes.append(f"the file is a {sig.name} with one corrupted byte")

    data = report.repaired
    trailing = find_trailing_data(data)
    if trailing is not None:
        extra = data[trailing.end_offset :]
        report.notes.append(
            f"{trailing.size} bytes sit after the end of the {trailing.after} "
            f"(offset 0x{trailing.end_offset:x})"
            + (f": looks like a {trailing.looks_like}" if trailing.looks_like else "")
        )
        _study_trailing(extra, trailing.end_offset, report)

    for item in carve(data):
        if all(item.offset != done.offset for done in report.carved):
            report.carved.append(item)
    if not report.changed:
        report.notes.append(
            "nothing to repair: the magic bytes are intact and nothing follows the end of the file"
        )
    return report


def _study_trailing(extra: bytes, base: int, report: RepairReport) -> None:
    """What are the appended bytes? A known file, or a file wearing a fake hat?"""
    inner = match_signature(extra)
    if inner is not None and not inner.weak:
        report.carved.append(
            Carved(
                base, inner.name, inner.ext, extra, f"appended after the end marker, a {inner.name}"
            )
        )
        return

    pasted = pasted_header(extra)
    if pasted is None:
        report.carved.append(
            Carved(base, "unknown data", "bin", extra, "appended after the end marker")
        )
        return

    worn, fits = pasted
    length = max(
        size for size in range(MIN_MAGIC, len(worn.magic)) if extra[:size] == worn.magic[:size]
    )
    report.notes.append(
        f"the appended bytes start with the first {length} bytes of a {worn.name} "
        f"signature but not the rest of it: those {length} bytes were pasted over "
        "the real header"
    )
    # Several formats have a magic of that length; the bytes that follow decide.
    confirmed = [sig for sig in fits if validate(sig.magic + extra[length:], sig)]
    chosen = confirmed or fits
    for sig in chosen:
        candidate = sig.magic + extra[length:]
        if confirmed:
            why = (
                f"the pasted {length}-byte header replaced by the {sig.name} magic "
                f"({sig.magic.hex()}): what follows it is a valid {sig.name} header, "
                "which is not true of the other formats of that magic length"
            )
        else:
            why = (
                f"the pasted {length}-byte header replaced by the {sig.name} magic "
                f"({sig.magic.hex()}), one of the {len(fits)} formats whose magic is "
                f"{length} bytes long (nothing confirms it: check them all)"
            )
        report.carved.append(Carved(base, sig.name, sig.ext, candidate, why))
        report.fixes.append(
            Fix(
                offset=base,
                old=extra[:length],
                new=sig.magic,
                why=f"restores the {sig.name} magic under the pasted header"
                + (", confirmed by the header that follows" if confirmed else ""),
            )
        )
    if confirmed:
        report.notes.append(
            f"under the pasted header: {', '.join(sig.name for sig in confirmed)} "
            "(confirmed by a structure check, not just by the magic length)"
        )
    if not fits:
        report.carved.append(
            Carved(base, "unknown data", "bin", extra, "appended, with a pasted header")
        )


# ---------------------------------------------------------------------------
# ZipCrypto known-plaintext (the bkcrack setup)
# ---------------------------------------------------------------------------
#
# A ZIP encrypted with the traditional PKWARE cipher ("ZipCrypto") is broken by a
# known-plaintext attack (bkcrack) given >= 8 bytes of plaintext at a known offset
# in the ciphertext stream. We never run the attack; we only work out the three
# arguments bkcrack needs, which is the fiddly part:
#
#   - WHICH entry: the first encrypted one whose name says what it is (a .png...).
#   - WHICH plaintext: that file type's own magic bytes (a PNG always starts the
#     same way), so the plaintext is known without ever seeing the file.
#   - AT WHICH offset in the ciphertext: a *stored* entry (method 0) is the raw
#     file, so the magic is at offset 0. A *deflated* entry (method 8) of already
#     compressed data (a PNG) becomes one uncompressed deflate block, whose 5-byte
#     block header sits before the data, so the magic is at offset 5.
#
# AES-encrypted ZIPs (method 99, WinZip AES) are NOT vulnerable and are skipped.

LOCAL_FILE_HEADER = b"PK\x03\x04"
# The best-known opening bytes of a file type, longer than its bare magic when the
# bytes that follow are just as predictable (a PNG's IHDR length and chunk name).
PLAINTEXT_PREFIXES = {
    "png": bytes.fromhex("89504e470d0a1a0a0000000d49484452"),  # signature + IHDR length + "IHDR"
}
MIN_PLAINTEXT = 8  # bkcrack needs at least this many known bytes


@dataclass
class ZipPlaintext:
    """Everything bkcrack needs for one ZipCrypto entry (nothing is run here)."""

    entry: str  # the inner file name, e.g. "flag.png"
    offset: int  # byte offset of the known plaintext in the ciphertext stream
    plaintext: bytes  # the known bytes themselves
    method: int  # 0 = stored, 8 = deflated

    @property
    def plaintext_hex(self) -> str:
        return self.plaintext.hex()


def _ext_magics() -> dict[str, bytes]:
    """extension -> opening bytes, from the signature table, for strong (>=8 byte) magics."""
    magics: dict[str, bytes] = {}
    for sig in load_signatures():
        if sig.offset == 0 and not sig.weak and len(sig.magic) >= MIN_PLAINTEXT:
            magics.setdefault(sig.ext, sig.magic)
    magics.update(PLAINTEXT_PREFIXES)  # a longer, hand-picked prefix wins
    return magics


def zipcrypto_known_plaintext(data: bytes) -> ZipPlaintext | None:
    """Find a ZipCrypto entry whose plaintext is guessable from its file extension.

    Returns the bkcrack parameters for the first such entry, or None when the ZIP
    has no encrypted entry we can guess a long-enough plaintext for.
    """
    if not data.startswith(LOCAL_FILE_HEADER):
        return None
    magics = _ext_magics()
    position = 0
    while True:
        position = data.find(LOCAL_FILE_HEADER, position)
        if position < 0 or position + 30 > len(data):
            return None
        flag = int.from_bytes(data[position + 6 : position + 8], "little")
        method = int.from_bytes(data[position + 8 : position + 10], "little")
        name_length = int.from_bytes(data[position + 26 : position + 28], "little")
        name = data[position + 30 : position + 30 + name_length]
        position += 4  # keep scanning for the next header even if this one is unusable
        encrypted = bool(flag & 0x1)
        if not encrypted or method not in (0, 8) or not name:
            continue  # method 99 = WinZip AES: not a ZipCrypto target
        ext = name.rsplit(b".", 1)[-1].decode("ascii", "replace").lower()
        magic = magics.get(ext)
        if magic is None or len(magic) < MIN_PLAINTEXT:
            continue
        offset = 5 if method == 8 else 0  # deflate stored-block header is 5 bytes
        return ZipPlaintext(
            entry=name.decode("utf-8", "replace"),
            offset=offset,
            plaintext=magic,
            method=method,
        )
