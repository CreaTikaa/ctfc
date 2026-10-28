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

from dataclasses import dataclass, field

from ctfc.core.magic import Signature, find_trailing_data, load_signatures, match_signature

MIN_MAGIC = 4  # shorter magics give too many coincidences
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
    for sig in fits:
        candidate = sig.magic + extra[length:]
        report.carved.append(
            Carved(
                base,
                sig.name,
                sig.ext,
                candidate,
                f"the pasted {length}-byte header replaced by the {sig.name} magic "
                f"({sig.magic.hex()}), the only {length}-byte signature that fits",
            )
        )
        report.fixes.append(
            Fix(
                offset=base,
                old=extra[:length],
                new=sig.magic,
                why=f"restores the {sig.name} magic under the pasted header",
            )
        )
    if not fits:
        report.carved.append(
            Carved(base, "unknown data", "bin", extra, "appended, with a pasted header")
        )
