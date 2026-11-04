"""PNG surgery: the shrunk height, the wrong CRC, the chunk that lies.

The stock challenge: a PNG whose IHDR says the image is 200 pixels tall when
the pixel data holds 600 rows. Every viewer draws the first 200 and the flag,
written across the bottom, is never shown. Nothing is encrypted, nothing is
hidden - the header simply lies.

The fix needs no image decoding at all, only arithmetic. A PNG stores its
pixels as `height` scanlines, each one `1 + ceil(width * channels * depth / 8)`
bytes long (the extra byte is the filter type). So once the IDAT stream is
inflated, the real height is the inflated size divided by that row length. If
that number is not the one in IHDR, the header was edited - and the proof is
that the division comes out exact.

Three more things are checked while the chunks are being walked, because they
are the other ways a PNG is tampered with in a challenge:

- a **chunk CRC that does not match** its own data (the usual way to break a
  file "just enough" for a viewer to refuse it);
- a **bit depth / colour type pair** no encoder would emit;
- the **text chunks**, which is where an author leaves a note.

Every change is reported the way `ctfc repair` reports: offset, the bytes that
were there, the bytes that replace them, and why. Nothing is "fixed" silently,
because a file that was never broken must come back unchanged.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

MAGIC = b"\x89PNG\r\n\x1a\n"
# Colour type -> samples per pixel. 3 is a palette index, so one sample.
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
COLOUR_NAMES = {
    0: "greyscale",
    2: "truecolour",
    3: "palette",
    4: "greyscale + alpha",
    6: "truecolour + alpha",
}
# What the spec allows, per colour type.
ALLOWED_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
# A height is only accepted if it stays sane: a 2-pixel-wide image that claims
# a million rows is a decompression bomb, not a challenge.
MAX_HEIGHT = 1_000_000


@dataclass
class Chunk:
    """One PNG chunk, with where it is and whether its CRC agrees."""

    kind: str
    offset: int  # of the length field
    length: int
    payload: bytes = field(repr=False, default=b"")
    declared_crc: int = 0
    actual_crc: int = 0

    @property
    def crc_ok(self) -> bool:
        return self.declared_crc == self.actual_crc

    @property
    def crc_offset(self) -> int:
        return self.offset + 8 + self.length


@dataclass
class PngReport:
    """What is wrong with this PNG, and what the corrected bytes are."""

    width: int = 0
    height: int = 0
    real_height: int = 0  # what the pixel data actually holds, 0 when unknown
    depth: int = 0
    colour: int = 0
    interlaced: bool = False
    chunks: list[Chunk] = field(default_factory=list)
    texts: list[tuple[str, str]] = field(default_factory=list)
    # (offset, old bytes, new bytes, why) - the shape `ctfc repair` prints.
    fixes: list[tuple[int, bytes, bytes, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    repaired: bytes = field(repr=False, default=b"")

    @property
    def changed(self) -> bool:
        return bool(self.fixes)

    def to_dict(self) -> dict:
        return {
            "width": self.width,
            "height": self.height,
            "real_height": self.real_height,
            "depth": self.depth,
            "colour": COLOUR_NAMES.get(self.colour, str(self.colour)),
            "interlaced": self.interlaced,
            "chunks": [
                {
                    "kind": chunk.kind,
                    "offset": chunk.offset,
                    "length": chunk.length,
                    "crc_ok": chunk.crc_ok,
                }
                for chunk in self.chunks
            ],
            "texts": [{"keyword": key, "text": text} for key, text in self.texts],
            "fixes": [
                {"offset": offset, "was": old.hex(), "is_now": new.hex(), "why": why}
                for offset, old, new, why in self.fixes
            ],
            "notes": list(self.notes),
        }


def looks_like_png(data: bytes) -> bool:
    return data[:8] == MAGIC


def read_chunks(data: bytes) -> list[Chunk]:
    """Walk the chunks, checking each CRC. Stops where the file stops making sense."""
    chunks: list[Chunk] = []
    offset = len(MAGIC)
    while offset + 12 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8]
        end = offset + 8 + length
        if length > len(data) or end + 4 > len(data):
            break  # truncated: what we have is what we report
        payload = data[offset + 8 : end]
        chunks.append(
            Chunk(
                kind=kind.decode("latin-1"),
                offset=offset,
                length=length,
                payload=payload,
                declared_crc=int.from_bytes(data[end : end + 4], "big"),
                actual_crc=zlib.crc32(kind + payload) & 0xFFFFFFFF,
            )
        )
        offset = end + 4
        if kind == b"IEND":
            break
    return chunks


def _row_bytes(width: int, channels: int, depth: int) -> int:
    """The length of one scanline, filter byte included."""
    bits = width * channels * depth
    return 1 + (bits + 7) // 8


def _inflate_idat(chunks: list[Chunk]) -> tuple[bytes, str]:
    """The decompressed pixel data, and a note when it ended badly."""
    stream = b"".join(chunk.payload for chunk in chunks if chunk.kind == "IDAT")
    if not stream:
        return b"", "no IDAT chunk: there are no pixels in this file"
    decompressor = zlib.decompressobj()
    try:
        # decompressobj, not zlib.decompress: a truncated stream still gives
        # back everything that did inflate, which is what a damaged PNG needs.
        raw = decompressor.decompress(stream, 64 * 1024 * 1024)
    except zlib.error as exc:
        return b"", f"the IDAT stream does not inflate ({exc})"
    if not decompressor.eof:
        return raw, "the IDAT stream is truncated: the rows that did inflate are used"
    return raw, ""


def analyse(data: bytes) -> PngReport:
    """Read the chunks, check them, and work out the real height."""
    report = PngReport(repaired=data)
    if not looks_like_png(data):
        report.notes.append("not a PNG: the 8 magic bytes do not match")
        return report

    report.chunks = read_chunks(data)
    if not report.chunks:
        report.notes.append("no readable chunk after the PNG signature")
        return report

    header = next((chunk for chunk in report.chunks if chunk.kind == "IHDR"), None)
    if header is None or header.length < 13:
        report.notes.append("no usable IHDR chunk")
        return report

    report.width = int.from_bytes(header.payload[0:4], "big")
    report.height = int.from_bytes(header.payload[4:8], "big")
    report.depth = header.payload[8]
    report.colour = header.payload[9]
    report.interlaced = bool(header.payload[12])
    report.texts = _texts(report.chunks)

    _check_header(report)
    _check_crcs(report, header)
    _check_height(report, header)

    if not report.fixes and not report.notes:
        report.notes.append(
            f"{report.width}x{report.height}, "
            f"{COLOUR_NAMES.get(report.colour, report.colour)} {report.depth}-bit: "
            "every chunk CRC matches and the pixel data fills exactly the height "
            "the header declares"
        )
    return report


def _texts(chunks: list[Chunk]) -> list[tuple[str, str]]:
    """The tEXt / zTXt / iTXt chunks, as (keyword, text)."""
    found: list[tuple[str, str]] = []
    for chunk in chunks:
        if chunk.kind not in ("tEXt", "zTXt", "iTXt"):
            continue
        keyword, _, rest = chunk.payload.partition(b"\x00")
        name = keyword.decode("latin-1", "replace")
        if chunk.kind == "tEXt":
            found.append((name, rest.decode("latin-1", "replace")))
        elif chunk.kind == "zTXt":
            try:
                found.append((name, zlib.decompress(rest[1:]).decode("utf-8", "replace")))
            except zlib.error:
                found.append((name, "<the zTXt payload does not inflate>"))
        else:  # iTXt: compression flag, method, language, translated keyword
            try:
                flag = rest[0]
                body = rest[3:].split(b"\x00", 2)[-1]
                text = zlib.decompress(body) if flag else body
                found.append((name, text.decode("utf-8", "replace")))
            except (IndexError, zlib.error):
                found.append((name, "<the iTXt payload cannot be read>"))
    return found


def _check_header(report: PngReport) -> None:
    """A colour type / bit depth pair no encoder would write."""
    if report.colour not in CHANNELS:
        report.notes.append(
            f"colour type {report.colour} does not exist (0, 2, 3, 4 and 6 do): "
            "the IHDR has been edited"
        )
        return
    allowed = ALLOWED_DEPTHS[report.colour]
    if report.depth not in allowed:
        report.notes.append(
            f"bit depth {report.depth} is not allowed for a "
            f"{COLOUR_NAMES[report.colour]} image (only {', '.join(map(str, allowed))}): "
            "the IHDR has been edited"
        )
    if report.interlaced:
        report.notes.append(
            "the image is interlaced (Adam7): the height arithmetic below does not "
            "apply to interlaced data, so the height is reported, not corrected"
        )


def _check_crcs(report: PngReport, header: Chunk) -> None:
    """Every chunk's CRC, and the correction when one is wrong."""
    for chunk in report.chunks:
        if chunk.crc_ok or chunk is header:
            # IHDR is handled with the height, so that one fix carries both.
            continue
        report.fixes.append(
            (
                chunk.crc_offset,
                chunk.declared_crc.to_bytes(4, "big"),
                chunk.actual_crc.to_bytes(4, "big"),
                f"the {chunk.kind} chunk's CRC32 does not match its data "
                f"(declared {chunk.declared_crc:08x}, computed {chunk.actual_crc:08x})",
            )
        )
    report.repaired = _apply(report.repaired, report.fixes)


def _check_height(report: PngReport, header: Chunk) -> None:
    """The heart of it: does the pixel data hold more rows than IHDR admits?"""
    if report.colour not in CHANNELS or report.interlaced or not report.width:
        return
    raw, note = _inflate_idat(report.chunks)
    if note:
        report.notes.append(note)
    if not raw:
        return

    row = _row_bytes(report.width, CHANNELS[report.colour], report.depth)
    real = len(raw) // row
    report.real_height = real
    leftover = len(raw) % row

    if real == report.height:
        if leftover:
            report.notes.append(
                f"{leftover} byte(s) of pixel data past the last complete row: "
                "the IDAT stream is slightly longer than the image needs"
            )
        return
    if real < report.height:
        report.notes.append(
            f"the header declares {report.height} rows but only {real} inflated: "
            "the IDAT stream is truncated, not the header shrunk"
        )
        return
    if leftover:
        report.notes.append(
            f"the pixel data holds {real} full rows plus {leftover} byte(s), where the "
            f"header says {report.height}: the arithmetic does not come out exact, so the "
            "width may have been edited too - try `ctfc stego` and a hex editor"
        )
        return
    if real > MAX_HEIGHT:
        report.notes.append(f"a computed height of {real} is not plausible; left alone")
        return

    # The division is exact: the file really holds `real` rows. Fix the height
    # field, then the IHDR CRC that the change invalidates.
    payload = bytearray(header.payload)
    payload[4:8] = real.to_bytes(4, "big")
    new_crc = zlib.crc32(b"IHDR" + bytes(payload)) & 0xFFFFFFFF
    fixes = [
        (
            header.offset + 8 + 4,
            header.payload[4:8],
            real.to_bytes(4, "big"),
            f"the IDAT stream inflates to {len(raw)} bytes, which is exactly {real} rows "
            f"of {row} bytes - the header says {report.height}, so the image was cropped "
            "by editing its height",
        ),
    ]
    if new_crc == header.declared_crc:
        # The stored CRC is the CRC of the *restored* header: whoever shrunk
        # the height did not recompute it. That is not a problem to fix, it is
        # proof of the edit - and the reason most viewers still open the file.
        report.notes.append(
            "the IHDR CRC32 already matches the restored height: the height was edited "
            "without recomputing the checksum, which is the proof that it was edited"
        )
    else:
        fixes.append(
            (
                header.crc_offset,
                header.declared_crc.to_bytes(4, "big"),
                new_crc.to_bytes(4, "big"),
                "the IHDR CRC32, recomputed after the height was put back",
            )
        )
    report.fixes += fixes
    report.repaired = _apply(report.repaired, fixes)
    report.notes.append(
        f"the image is really {report.width}x{real}, not {report.width}x{report.height}: "
        f"{real - report.height} row(s) were never drawn"
    )


def _apply(data: bytes, fixes: list[tuple[int, bytes, bytes, str]]) -> bytes:
    """Write the corrections into the bytes, in place."""
    out = bytearray(data)
    for offset, old, new, _why in fixes:
        if out[offset : offset + len(old)] == old:
            out[offset : offset + len(new)] = new
    return bytes(out)
