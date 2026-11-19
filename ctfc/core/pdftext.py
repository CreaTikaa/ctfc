"""The text a PDF page shows, read from its content streams (what `pdftotext` does).

A page does not store "ABCTF{...}" as text: it stores drawing operators. The
characters are the string operands of `Tj` / `TJ` / `'` / `"` inside `BT ... ET`
blocks, and two things hide them from a plain search:

* a TJ array cuts a line into pieces with spacing in between:
  `[(CYB) -20 (N{fl) 15 (ag})] TJ`, so the flag is never one contiguous string;
* an embedded (subset) font numbers its glyphs as it likes: `<0013> Tj` draws
  glyph 0x13, and only the font's /ToUnicode CMap says that 0x13 is "A".

So the string operands are joined in drawing order, and read once as they are
and once through each /ToUnicode CMap of the file (a wrong CMap just gives
garbage, which no flag search matches). Approximate on purpose: positions,
spacing and font changes are ignored - the point is a flag search, not layout.
"""

from __future__ import annotations

import bisect
import re

MAX_STREAM = 4 * 1024 * 1024
MAX_CMAPS = 20
MAX_TEXT = 1024 * 1024

# A font resource name -> its /ToUnicode CMap (None: the font has none, its
# bytes are read as they are).
FontMap = dict[bytes, "dict[bytes, str] | None"]

_TEXT_OPERATORS = re.compile(rb"(?:Tj|TJ|'|\")(?![A-Za-z])")
_HEX = re.compile(rb"<([0-9A-Fa-f\s]*)>")


def _hex_bytes(digits: bytes) -> bytes:
    cleaned = re.sub(rb"\s", b"", digits)
    if len(cleaned) % 2:
        cleaned += b"0"
    try:
        return bytes.fromhex(cleaned.decode("ascii"))
    except ValueError:
        return b""


def parse_cmap(stream: bytes) -> dict[bytes, str]:
    """A /ToUnicode CMap: glyph code (bytes) -> the Unicode text it stands for."""
    mapping: dict[bytes, str] = {}

    def text_of(hex_digits: bytes) -> str:
        return _hex_bytes(hex_digits).decode("utf-16-be", "replace")

    for block in re.findall(rb"beginbfchar(.*?)endbfchar", stream, re.S):
        for source, target in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", block):
            mapping[_hex_bytes(source)] = text_of(target)
    for block in re.findall(rb"beginbfrange(.*?)endbfrange", stream, re.S):
        pattern = rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])"
        for low, high, target in re.findall(pattern, block):
            start, end = int(low, 16), int(high, 16)
            width = len(low) // 2
            if end - start > 65535 or end < start:
                continue
            if target.startswith(b"["):
                targets = [text_of(item) for item in _HEX.findall(target)]
                for offset, value in enumerate(targets[: end - start + 1]):
                    mapping[(start + offset).to_bytes(width, "big")] = value
                continue
            first = _hex_bytes(target[1:-1])
            if not first:
                continue
            base = int.from_bytes(first, "big")
            for offset in range(end - start + 1):
                value = (base + offset).to_bytes(len(first), "big")
                mapping[(start + offset).to_bytes(width, "big")] = value.decode(
                    "utf-16-be", "replace"
                )
    return mapping


def _string_operands(block: bytes) -> list[tuple[int, bytes]]:
    """Every string operand of one BT...ET block, in order: (offset, bytes)."""
    from ctfc.core.pdf import _balanced_literal, _unescape  # pdf imports pdftext

    found: list[tuple[int, bytes]] = []
    index = 0
    while index < len(block):
        byte = block[index : index + 1]
        if byte == b"(":
            raw = _balanced_literal(block, index + 1)
            found.append((index, _unescape(raw)))
            index += len(raw) + 2
        elif byte == b"<" and block[index + 1 : index + 2] != b"<":
            end = block.find(b">", index)
            if end < 0:
                break
            found.append((index, _hex_bytes(block[index + 1 : end])))
            index = end + 1
        elif byte == b"%":  # a comment runs to the end of the line
            newline = block.find(b"\n", index)
            index = len(block) if newline < 0 else newline + 1
        else:
            index += 1
    return found


# A reading with fewer unknown glyphs than this is taken as the right one.
GOOD_ENOUGH = 0.02


def unknown_ratio(text: str) -> float:
    """The share of characters that are unknown glyphs ("?") or unprintable."""
    if not text:
        return 1.0
    bad = len(text) - sum(ch.isprintable() for ch in text) - text.count("\n") - text.count("\t")
    return (bad + text.count("?")) / len(text)


def _decode_one(item: bytes, cmap: dict[bytes, str] | None, widths: dict[int, int]) -> str:
    """One string operand as text. `widths` caches each CMap's code width for
    the length of one call (keyed by id(), so it must not outlive the CMaps)."""
    if cmap is None:
        return item.decode("latin-1")
    width = widths.get(id(cmap))
    if width is None:
        width = widths[id(cmap)] = max((len(code) for code in cmap), default=1)
    return "".join(cmap.get(item[i : i + width], "?") for i in range(0, len(item), width))


# "/F2 12 Tf": select font F2. It stays selected across BT blocks (it is part
# of the graphics state), so it is tracked over the whole stream.
_SET_FONT = re.compile(rb"/([^\s/<>\[\]()%]+)\s+[-+\d.]+\s+Tf(?![A-Za-z])")
_BLOCK = re.compile(rb"(?<![A-Za-z])BT(?![A-Za-z])(.*?)(?<![A-Za-z])ET(?![A-Za-z])", re.S)


def content_text(
    stream: bytes,
    cmaps: list[dict[bytes, str]],
    font_cmaps: FontMap | None = None,
    precise: bool = False,
) -> list[str]:
    """The text of one content stream, in several readings.

    1. each string through the /ToUnicode CMap of the font selected by `Tf`
       at that point (`font_cmaps`: resource name -> CMap), raw when the font
       has none - the faithful one, when the fonts could be resolved;
    2. as it is (raw bytes), and through each CMap of the file in turn - the
       fallbacks, for a stream whose fonts could not be resolved.
    """
    if len(stream) > MAX_STREAM or b"BT" not in stream or not _TEXT_OPERATORS.search(stream):
        return []
    blocks = []
    for match in _BLOCK.finditer(stream):
        operands = [
            (match.start(1) + offset, item) for offset, item in _string_operands(match.group(1))
        ]
        if operands:
            blocks.append(operands)
    if not blocks:
        return []
    readings = []
    widths: dict[int, int] = {}
    if font_cmaps:
        fonts = [(m.start(), m.group(1)) for m in _SET_FONT.finditer(stream)]
        positions = [position for position, _name in fonts]
        lines = []
        for operands in blocks:
            line = []
            for offset, item in operands:
                # The last Tf before this string (binary search: a big page has
                # thousands of both).
                index = bisect.bisect_right(positions, offset) - 1
                current = fonts[index][1] if index >= 0 else b""
                line.append(_decode_one(item, font_cmaps.get(current), widths))
            lines.append("".join(line))
        faithful = "\n".join(lines)[:MAX_TEXT]
        readings.append(faithful)
        every_font_known = all(name in font_cmaps for _position, name in fonts)
        if precise and every_font_known and faithful and unknown_ratio(faithful) < GOOD_ENOUGH:
            # Every font resolved and read: the fallbacks would only cost time
            # (a 500-page PDF with 20 CMaps is 10 000 extra readings).
            return [
                *readings,
                "\n".join("".join(i.decode("latin-1") for _o, i in ops) for ops in blocks)[
                    :MAX_TEXT
                ],
            ]
    for cmap in [None, *cmaps]:
        text = "\n".join(
            "".join(_decode_one(item, cmap, widths) for _o, item in ops) for ops in blocks
        )
        readings.append(text[:MAX_TEXT])
    return readings


_TO_UNICODE = re.compile(rb"/ToUnicode\s+(\d{1,10})\s+\d{1,5}\s+R")
_FONT_DICT = re.compile(rb"/Font\s*<<(.*?)>>", re.S)
_FONT_REF = re.compile(rb"/Font\s+(\d{1,10})\s+\d{1,5}\s+R")
_NAME_REF = re.compile(rb"/([^\s/<>\[\]()%]+)\s+(\d{1,10})\s+\d{1,5}\s+R")


_PAGE = re.compile(rb"/Type\s*/Page(?![A-Za-z])")
_RESOURCES_REF = re.compile(rb"/Resources\s+(\d{1,10})\s+\d{1,5}\s+R")
_CONTENTS_REF = re.compile(rb"/Contents\s+(\d{1,10})\s+\d{1,5}\s+R")
_CONTENTS_ARRAY = re.compile(rb"/Contents\s*\[([^\]]*)\]")
_REF = re.compile(rb"(\d{1,10})\s+\d{1,5}\s+R")


def font_maps(objects) -> tuple[FontMap, dict[int, FontMap]]:
    """Which /ToUnicode CMap each font name means: (whole file, per content stream).

    A /Resources << /Font << /F2 12 0 R >> >> names font 12, whose dictionary
    says /ToUnicode 30 0 R, a CMap stream. Names are per page ("F1" is often a
    different font on every page), so each page's own resources are mapped to
    its /Contents streams, and a Form XObject to itself. The whole-file map
    (first meaning of a name wins) is the fallback for anything else.
    A font with no /ToUnicode maps to None: its bytes are read as they are.
    """
    by_number = {obj.number: obj for obj in objects}
    cmap_of: dict[int, dict[bytes, str]] = {}

    def cmap_for(font_number: int):
        font = by_number.get(font_number)
        if font is None:
            return None
        reference = _TO_UNICODE.search(font.dictionary)
        if reference is None:
            return None
        number = int(reference.group(1))
        if number not in cmap_of:
            stream = getattr(by_number.get(number), "stream", None) or b""
            cmap_of[number] = parse_cmap(stream)
        return cmap_of[number] or None

    def names_in(dictionary: bytes, depth: int = 0) -> FontMap:
        bodies = [match.group(1) for match in _FONT_DICT.finditer(dictionary)]
        for match in _FONT_REF.finditer(dictionary):
            target = by_number.get(int(match.group(1)))
            if target is not None:
                bodies.append(target.dictionary)
        if not bodies and depth == 0:
            reference = _RESOURCES_REF.search(dictionary)
            target = by_number.get(int(reference.group(1))) if reference else None
            if target is not None:
                return names_in(target.dictionary, 1)
        found: FontMap = {}
        for body in bodies:
            for name, number in _NAME_REF.findall(body):
                found.setdefault(name, cmap_for(int(number)))
        return found

    whole: FontMap = {}
    per_stream: dict[int, FontMap] = {}
    for obj in objects:
        names = names_in(obj.dictionary)
        for name, cmap in names.items():
            if cmap is not None:
                whole.setdefault(name, cmap)
        if not names:
            continue
        if _PAGE.search(obj.dictionary):
            references = [int(m.group(1)) for m in _CONTENTS_REF.finditer(obj.dictionary)]
            for array in _CONTENTS_ARRAY.finditer(obj.dictionary):
                references += [int(number) for number in _REF.findall(array.group(1))]
            for number in references:
                per_stream[number] = names
        elif obj.stream is not None and b"/Form" in obj.dictionary:
            per_stream[obj.number] = names
    return whole, per_stream


def file_cmaps(streams: list[bytes]) -> list[dict[bytes, str]]:
    """Every /ToUnicode CMap among the decoded streams of a file."""
    cmaps = []
    for stream in streams:
        if b"begincmap" in stream and (b"bfchar" in stream or b"bfrange" in stream):
            mapping = parse_cmap(stream)
            if mapping:
                cmaps.append(mapping)
        if len(cmaps) >= MAX_CMAPS:
            break
    return cmaps
