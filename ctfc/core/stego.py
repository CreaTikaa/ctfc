"""Find data hidden in the pixels of a PNG or BMP.

`zsteg` is the usual answer here, and CLAUDE.md says not to vendor it but to
reimplement the idea - the same decision as for xortool. The idea is small: a
pixel's lowest bit can be changed without anyone seeing it, so a message is
written one bit per colour sample. Recovering it means guessing four things:

1. **which bit** of each sample carries the message (bit 0 almost always);
2. **which samples**, and in which order - only the red channel? all three, RGB?
   BGR, because the author used a library that stores it that way?
3. **which direction** the pixels were walked: along rows (the obvious way) or
   down columns (what you get from a transposed array);
4. **which way round the bits go** inside each reconstructed byte, MSB or LSB
   first.

So there is no clever algorithm, only a few hundred combinations - and the real
work is deciding which output is the message, which `scoring.py` already does.
Every candidate therefore comes back with the combination that produced it, so
the result can be reproduced by hand.

Decoding the image comes first, and is most of the code: a PNG's pixels are
zlib-compressed and each scanline is "filtered" against its neighbours, so the
five filter types have to be undone before a single bit can be read.

Nothing is executed; the image is only ever read as data.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field

from ctfc.core.budget import Budget
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
BMP_MAGIC = b"BM"
# Channels per pixel, by PNG colour type (3 = palette index, expanded to RGB).
PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
CHANNEL_NAMES = "rgba"
MAX_PIXELS = 40_000_000  # refuse a decompression bomb
# How many bytes of a candidate are enough to tell a message from noise.
PROBE_BYTES = 2048


class StegoError(Exception):
    """The data is not an image we can read."""


# ---------------------------------------------------------------------------
# PNG
# ---------------------------------------------------------------------------


def png_chunks(data: bytes):
    """Yield (type, payload) for each chunk, stopping at the end of the data."""
    offset = len(PNG_MAGIC)
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8]
        start = offset + 8
        if length > len(data) or start + length > len(data):
            break  # truncated: keep what we have
        yield kind, data[start : start + length]
        offset = start + length + 4  # skip the CRC
        if kind == b"IEND":
            break


def _paeth(left: int, above: int, upper_left: int) -> int:
    """PNG's Paeth predictor: whichever neighbour the gradient points at."""
    estimate = left + above - upper_left
    distances = (abs(estimate - left), abs(estimate - above), abs(estimate - upper_left))
    return (left, above, upper_left)[distances.index(min(distances))]


def _defilter(raw: bytes, width: int, height: int, channels: int, depth: int) -> bytes:
    """Undo the per-scanline filter. Returns width*height*channels bytes."""
    sample_bytes = max(1, depth // 8)
    stride = width * channels * sample_bytes
    step = channels * sample_bytes  # distance to the pixel on the left
    out = bytearray()
    previous = bytearray(stride)
    position = 0
    for _ in range(height):
        if position >= len(raw):
            break
        filter_type = raw[position]
        position += 1
        line = bytearray(raw[position : position + stride])
        if len(line) < stride:
            line += bytes(stride - len(line))  # truncated image: pad with black
        position += stride
        if filter_type == 1:  # Sub
            for index in range(step, stride):
                line[index] = (line[index] + line[index - step]) & 0xFF
        elif filter_type == 2:  # Up
            for index in range(stride):
                line[index] = (line[index] + previous[index]) & 0xFF
        elif filter_type == 3:  # Average
            for index in range(stride):
                left = line[index - step] if index >= step else 0
                line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif filter_type == 4:  # Paeth
            for index in range(stride):
                left = line[index - step] if index >= step else 0
                upper_left = previous[index - step] if index >= step else 0
                line[index] = (line[index] + _paeth(left, previous[index], upper_left)) & 0xFF
        elif filter_type != 0:
            raise StegoError(f"unknown PNG filter type {filter_type}")
        out += line
        previous = line
    # 16-bit samples: keep the high byte, which is where a visible change lives.
    if sample_bytes == 2:
        out = bytearray(out[index] for index in range(0, len(out), 2))
    return bytes(out)


@dataclass
class Image:
    """Decoded pixels, row-major, one byte per sample."""

    width: int
    height: int
    channels: int
    data: bytes
    kind: str = ""
    # The letter of each sample index, in storage order: a PNG keeps R,G,B but a
    # BMP keeps B,G,R, so index 0 does not mean the same colour in both.
    channel_names: str = "rgba"
    texts: list[tuple[str, str]] = field(default_factory=list)  # PNG text chunks
    notes: list[str] = field(default_factory=list)

    def sample(self, x: int, y: int, channel: int) -> int:
        return self.data[(y * self.width + x) * self.channels + channel]


def load_png(data: bytes) -> Image:
    """Decode a non-interlaced PNG to one byte per sample."""
    header: bytes | None = None
    idat = bytearray()
    palette = b""
    texts: list[tuple[str, str]] = []
    notes: list[str] = []
    for kind, payload in png_chunks(data):
        if kind == b"IHDR":
            header = payload
        elif kind == b"IDAT":
            idat += payload
        elif kind == b"PLTE":
            palette = payload
        elif kind in (b"tEXt", b"zTXt", b"iTXt"):
            texts.append(_png_text(kind, payload))
    if header is None or len(header) < 13:
        raise StegoError("no IHDR chunk: not a readable PNG")
    width = int.from_bytes(header[0:4], "big")
    height = int.from_bytes(header[4:8], "big")
    depth = header[8]
    colour = header[9]
    interlace = header[12]
    if width * height > MAX_PIXELS or not width or not height:
        raise StegoError(f"implausible image size {width}x{height}")
    if interlace:
        raise StegoError("interlaced PNG (Adam7) is not supported: convert it first")
    if colour not in PNG_CHANNELS:
        raise StegoError(f"unknown PNG colour type {colour}")
    if depth not in (8, 16):
        raise StegoError(
            f"bit depth {depth} is not supported (only 8 and 16): LSB stego needs 8-bit samples"
        )
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error as exc:
        raise StegoError(f"the IDAT stream does not inflate: {exc}") from exc
    channels = PNG_CHANNELS[colour]
    pixels = _defilter(raw, width, height, channels, depth)
    if colour == 3:  # palette: expand each index to its RGB entry
        if not palette:
            raise StegoError("palette image without a PLTE chunk")
        expanded = bytearray()
        for index in pixels:
            base = index * 3
            expanded += palette[base : base + 3] or b"\x00\x00\x00"
        pixels = bytes(expanded)
        channels = 3
        notes.append(
            "palette image: the bits live in the PLTE entries, not the pixels - "
            "the palette was expanded, so LSB results here are about the colours used"
        )
    return Image(
        width,
        height,
        channels,
        pixels,
        kind="png",
        texts=texts,
        notes=notes,
    )


def _png_text(kind: bytes, payload: bytes) -> tuple[str, str]:
    """Read a tEXt / zTXt / iTXt chunk as (keyword, text)."""
    keyword, _, rest = payload.partition(b"\x00")
    name = keyword.decode("latin-1", "replace")
    if kind == b"zTXt":
        # one compression-method byte, then a zlib stream
        try:
            return name, zlib.decompress(rest[1:]).decode("utf-8", "replace")
        except zlib.error:
            return name, "<unreadable zTXt>"
    if kind == b"iTXt":
        # compression flag, method, language tag, translated keyword, then text
        if len(rest) < 2:
            return name, ""
        compressed = rest[0] == 1
        body = rest[2:].split(b"\x00", 2)[-1]
        if compressed:
            try:
                return name, zlib.decompress(body).decode("utf-8", "replace")
            except zlib.error:
                return name, "<unreadable iTXt>"
        return name, body.decode("utf-8", "replace")
    return name, rest.decode("latin-1", "replace")


# ---------------------------------------------------------------------------
# BMP
# ---------------------------------------------------------------------------


def load_bmp(data: bytes) -> Image:
    """Decode an uncompressed 24- or 32-bit BMP."""
    if len(data) < 54:
        raise StegoError("truncated BMP header")
    offset = int.from_bytes(data[10:14], "little")
    header_size = int.from_bytes(data[14:18], "little")
    if header_size < 40:
        raise StegoError(f"unsupported BMP header size {header_size} (BITMAPCOREHEADER?)")
    width = int.from_bytes(data[18:22], "little", signed=True)
    height = int.from_bytes(data[22:26], "little", signed=True)
    bits = int.from_bytes(data[28:30], "little")
    compression = int.from_bytes(data[30:34], "little")
    if compression != 0:
        raise StegoError(f"compressed BMP (compression {compression}) is not supported")
    if bits not in (24, 32):
        raise StegoError(f"{bits}-bit BMP is not supported (only 24 and 32)")
    channels = bits // 8
    bottom_up = height > 0
    height = abs(height)
    if width <= 0 or not height or width * height > MAX_PIXELS:
        raise StegoError(f"implausible image size {width}x{height}")
    stride = ((width * channels + 3) // 4) * 4  # rows are padded to 4 bytes
    rows = []
    for row in range(height):
        start = offset + row * stride
        line = data[start : start + width * channels]
        if len(line) < width * channels:
            line += bytes(width * channels - len(line))
        rows.append(line)
    if bottom_up:
        rows.reverse()  # a positive height means the first row is the bottom one
    return Image(
        width,
        height,
        channels,
        b"".join(rows),
        kind="bmp",
        channel_names="bgra",  # a BMP stores blue first
        notes=["BMP stores its samples B,G,R, so index 0 is blue: the labels below say so"],
    )


def load(data: bytes) -> Image:
    """Decode a PNG or BMP into samples."""
    if data[:8] == PNG_MAGIC:
        return load_png(data)
    if data[:2] == BMP_MAGIC:
        return load_bmp(data)
    raise StegoError("not a PNG or BMP: LSB extraction needs raw pixels")


# ---------------------------------------------------------------------------
# LSB extraction
# ---------------------------------------------------------------------------

# The sample orders worth trying, as indices into a pixel. They are named from
# `Image.channel_names` rather than hard-coded, because index 0 is red in a PNG
# but blue in a BMP - calling both "r" would make the label a lie.
CHANNEL_ORDERS = (
    (0, 1, 2),
    (2, 1, 0),
    (0,),
    (1,),
    (2,),
    (0, 1, 2, 3),
    (3,),
)
BIT_PLANES = (0, 1, 2, 7)  # 0 is the LSB; 7 is the visible one, used by sloppy tools


def extract_bits(
    image: Image,
    channels: tuple[int, ...],
    plane: int,
    column_major: bool,
    msb_first: bool,
    limit: int,
) -> bytes:
    """Read one bit per sample and rebuild bytes, for one combination."""
    out = bytearray()
    accumulator = 0
    count = 0
    coordinates = (
        ((x, y) for x in range(image.width) for y in range(image.height))
        if column_major
        else ((x, y) for y in range(image.height) for x in range(image.width))
    )
    for x, y in coordinates:
        for channel in channels:
            bit = (image.sample(x, y, channel) >> plane) & 1
            if msb_first:
                accumulator = (accumulator << 1) | bit
            else:
                accumulator |= bit << count
            count += 1
            if count == 8:
                out.append(accumulator)
                accumulator = 0
                count = 0
                if len(out) >= limit:
                    return bytes(out)
    return bytes(out)


def lsb_candidates(
    image: Image, flagset=None, budget: Budget | None = None, top_n: int = 5
) -> list[Candidate]:
    """Try the plausible LSB combinations and keep the ones that read as something."""
    budget = budget or Budget(max_attempts=2000, max_seconds=20)
    results: list[Candidate] = []
    for plane in BIT_PLANES:
        for channels in CHANNEL_ORDERS:
            if max(channels) >= image.channels:
                continue  # this image has no such channel
            name = "".join(image.channel_names[index] for index in channels)
            for column_major in (False, True):
                for msb_first in (True, False):
                    if not budget.spend():
                        break
                    probe = extract_bits(
                        image, channels, plane, column_major, msb_first, PROBE_BYTES
                    )
                    if len(probe) < 8:
                        continue
                    # A smooth gradient read one bit at a time produces a short
                    # repeating cycle ("333333..."), which scores as printable
                    # text without being a message. Real payloads - text or a
                    # whole file - use far more than a handful of byte values.
                    if len(set(probe[:64])) < 4:
                        continue
                    value, reasons = score(probe, flagset)
                    if value < 0.45:
                        continue
                    order = "column-major" if column_major else "row-major"
                    bits = "MSB first" if msb_first else "LSB first"
                    label = f"LSB bit {plane}, channels {name}, {order}, {bits}"
                    results.append(
                        Candidate(
                            label=label,
                            data=probe,
                            score=value,
                            reasons=reasons,
                            params={
                                "plane": plane,
                                "channels": name,
                                "order": order,
                                "bit_order": "msb" if msb_first else "lsb",
                            },
                            python=_snippet(image, name, channels, plane, column_major, msb_first),
                        )
                    )
    results.sort(key=lambda candidate: -candidate.score)
    # The same message often scores well on several near-identical combinations;
    # keep one per distinct output.
    unique: list[Candidate] = []
    seen: set[bytes] = set()
    for candidate in results:
        if candidate.data[:64] in seen:
            continue
        seen.add(candidate.data[:64])
        unique.append(candidate)
    return unique[:top_n]


def _snippet(
    image: Image,
    name: str,
    channels: tuple[int, ...],
    plane: int,
    column_major: bool,
    msb_first: bool,
) -> str:
    """A standalone script reproducing one extraction (teaching layer)."""
    loop = (
        "for x in range(width):\n    for y in range(height):"
        if column_major
        else "for y in range(height):\n    for x in range(width):"
    )
    shift = (
        "            byte = (byte << 1) | bit" if msb_first else "            byte |= bit << count"
    )
    return (
        f"# LSB: bit {plane}, channels {name}, "
        f"{'column' if column_major else 'row'}-major, "
        f"{'MSB' if msb_first else 'LSB'} first.\n"
        "# `pixels` must be the decoded samples, row-major, one byte per sample\n"
        "# (ctfc/core/stego.py load() does the PNG/BMP decoding).\n"
        f"width, height, channels = {image.width}, {image.height}, {image.channels}\n"
        f"order = {list(channels)}\n"
        "out, byte, count = bytearray(), 0, 0\n"
        f"{loop}\n"
        "        for c in order:\n"
        "            bit = (pixels[(y * width + x) * channels + c] >> "
        f"{plane}) & 1\n"
        f"{shift}\n"
        "            count += 1\n"
        "            if count == 8:\n"
        "                out.append(byte); byte, count = 0, 0\n"
        "print(bytes(out)[:200])\n"
    )


@dataclass
class StegoReport:
    """What the image holds."""

    width: int = 0
    height: int = 0
    channels: int = 0
    kind: str = ""
    texts: list[tuple[str, str]] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "width": self.width,
            "height": self.height,
            "channels": self.channels,
            "kind": self.kind,
            "texts": [{"keyword": key, "text": value} for key, value in self.texts],
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "notes": list(self.notes),
        }


def analyse(data: bytes, flagset=None, budget: Budget | None = None, top_n: int = 5) -> StegoReport:
    """Decode the image, read its metadata, and try the LSB combinations."""
    image = load(data)
    report = StegoReport(
        width=image.width,
        height=image.height,
        channels=image.channels,
        kind=image.kind,
        texts=image.texts,
        notes=list(image.notes),
    )
    for keyword, text in image.texts:
        report.notes.append(f"text chunk {keyword!r}: {text[:200]}")
    report.candidates = lsb_candidates(image, flagset, budget, top_n)
    if not report.candidates:
        report.notes.append(
            "no LSB combination produced anything that reads: the data may be in a "
            "channel order we do not try, encrypted, or not in the pixels at all. "
            "Try `ctfc detect` for data appended after the image, and zsteg for "
            "the exotic orders"
        )
    return report
