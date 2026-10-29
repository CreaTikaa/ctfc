"""Static analysis of a PDF: what it would do when opened, and what it hides.

A PDF is not a document so much as a little object database with an interpreter
attached, which is why it shows up so often in forensics. The things worth finding
are always the same:

- an **action that fires on open** (`/OpenAction`, `/AA`) - usually running
  JavaScript, sometimes launching a program (`/Launch`);
- **JavaScript**, which is where the obfuscated payload lives;
- an **embedded file** (`/EmbeddedFile`): the real artefact, carried inside;
- **earlier revisions**. A PDF can be updated incrementally, so the file keeps
  every previous version. Text that was "removed" or a black box drawn over a
  password is still in the bytes before the first `%%EOF`.

Streams are compressed, so they have to be decoded before any of that is visible:
`/FlateDecode` mostly, and the four other filters a real file may use.

The parser is deliberately **tolerant, not correct**: challenge PDFs are hand-
edited and frequently violate the spec (wrong `/Length`, broken xref, missing
`endobj`). So objects are found by scanning for `N G obj` rather than by trusting
the cross-reference table, which is exactly what a damaged file needs.

Nothing is executed: JavaScript is extracted as text for Code Lens to read.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass, field

HEADER = re.compile(rb"%PDF-(\d+\.\d+)")
OBJECT = re.compile(rb"(\d{1,10})\s+(\d{1,5})\s+obj\b")
STREAM_START = re.compile(rb"stream\r\n|stream\n|stream\r")
# /Filter /FlateDecode   or   /Filter [/ASCII85Decode /FlateDecode]
FILTER = re.compile(rb"/Filter\s*(\[[^\]]{0,200}\]|/\w+)")
FILTER_NAME = re.compile(rb"/(\w+)")
# JavaScript written straight into a dictionary: /JS (code) or /JS <hex>
JS_LITERAL = re.compile(rb"/JS\s*\(", re.DOTALL)
JS_HEX = re.compile(rb"/JS\s*<([0-9A-Fa-f\s]{4,})>")
# The name of an embedded file, from the file specification next to it.
FILE_NAME = re.compile(rb"/(?:UF|F)\s*\(([^)]{1,200})\)")
MAX_STREAM = 16 * 1024 * 1024
MAX_OBJECTS = 20_000

# (key, why it matters). Order matters: the most alarming first.
INDICATORS = (
    (b"/OpenAction", "an action runs as soon as the document is opened"),
    (b"/AA", "an additional action fires on an event (page open, field focus...)"),
    (b"/Launch", "launches an external program or command"),
    (b"/JavaScript", "the document carries JavaScript"),
    (b"/JS", "a JavaScript action"),
    (b"/EmbeddedFile", "a file is carried inside this PDF"),
    (b"/RichMedia", "embedded Flash/media, a classic exploit carrier"),
    (b"/SubmitForm", "sends form data to a URL"),
    (b"/GoToR", "jumps into a remote file"),
    (b"/URI", "contains a link"),
    (b"/ObjStm", "objects are packed inside a compressed object stream"),
    (b"/XFA", "XFA form (XML), which can carry script"),
    (b"/AcroForm", "has form fields"),
)


class PdfError(Exception):
    """The data is not a PDF we can read."""


# ---------------------------------------------------------------------------
# Stream filters
# ---------------------------------------------------------------------------


def _flate(data: bytes) -> bytes:
    """/FlateDecode, tolerating a truncated or slightly wrong stream."""
    for wbits in (15, -15):
        try:
            return zlib.decompressobj(wbits).decompress(data, MAX_STREAM)
        except zlib.error:
            continue
    # Some files have junk before the zlib header; find it and retry.
    start = data.find(b"\x78")
    if 0 < start < 64:
        try:
            return zlib.decompressobj().decompress(data[start:], MAX_STREAM)
        except zlib.error:
            pass
    raise PdfError("FlateDecode failed")


def _ascii_hex(data: bytes) -> bytes:
    body = data.split(b">")[0]
    cleaned = re.sub(rb"[^0-9A-Fa-f]", b"", body)
    if len(cleaned) % 2:
        cleaned += b"0"  # the spec pads an odd final digit with zero
    return binascii.unhexlify(cleaned)


def _ascii85(data: bytes) -> bytes:
    body = data.strip()
    if body.startswith(b"<~"):
        body = body[2:]
    body = body.split(b"~>")[0]
    return base64.a85decode(re.sub(rb"\s", b"", body))


def _run_length(data: bytes) -> bytes:
    out = bytearray()
    index = 0
    while index < len(data):
        length = data[index]
        index += 1
        if length == 128:
            break  # end-of-data marker
        if length < 128:
            out += data[index : index + length + 1]
            index += length + 1
        else:
            if index >= len(data):
                break
            out += bytes([data[index]]) * (257 - length)
            index += 1
    return bytes(out)


def _lzw(data: bytes) -> bytes:
    """/LZWDecode: LZW with 9-to-12-bit codes and the PDF "early change" default."""
    table = [bytes([value]) for value in range(256)] + [b"", b""]
    out = bytearray()
    previous = b""
    width = 9
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= width:
            code = (buffer >> (bits - width)) & ((1 << width) - 1)
            bits -= width
            if code == 256:  # clear table
                table = [bytes([value]) for value in range(256)] + [b"", b""]
                width, previous = 9, b""
                continue
            if code == 257:  # end of data
                return bytes(out)
            if code < len(table):
                entry = table[code]
            elif previous:
                entry = previous + previous[:1]
            else:
                raise PdfError("LZWDecode: code outside the table")
            out += entry
            if previous:
                table.append(previous + entry[:1])
            previous = entry
            # Widen the code before the table is actually full. The +2 is two
            # separate off-by-ones added together: PDF's "early change" widens one
            # code early (+1), and a decoder is always one entry behind the
            # encoder, because it can only add an entry once it has read the
            # *next* code (+1). Getting this wrong only shows up past 512 codes.
            if len(table) + 2 >= (1 << width) and width < 12:
                width += 1
            if len(out) > MAX_STREAM:
                raise PdfError("LZWDecode produced too much data")
    return bytes(out)


FILTERS = {
    b"FlateDecode": _flate,
    b"Fl": _flate,
    b"ASCIIHexDecode": _ascii_hex,
    b"AHx": _ascii_hex,
    b"ASCII85Decode": _ascii85,
    b"A85": _ascii85,
    b"RunLengthDecode": _run_length,
    b"RL": _run_length,
    b"LZWDecode": _lzw,
    b"LZW": _lzw,
}
# Filters that only make the data smaller on disk, not readable - leave them be.
IMAGE_FILTERS = {b"DCTDecode", b"JPXDecode", b"JBIG2Decode", b"CCITTFaxDecode"}


def decode_stream(raw: bytes, dictionary: bytes) -> tuple[bytes, list[str], str]:
    """Apply the stream's /Filter chain. Returns (data, filters applied, note)."""
    match = FILTER.search(dictionary)
    if match is None:
        return raw, [], ""
    names = FILTER_NAME.findall(match.group(1))
    data = raw
    applied: list[str] = []
    for name in names:
        if name in IMAGE_FILTERS:
            return data, applied, f"{name.decode()} is image data: left encoded"
        function = FILTERS.get(name)
        if function is None:
            return data, applied, f"unsupported filter /{name.decode()}"
        try:
            data = function(data)
        except (PdfError, zlib.error, binascii.Error, ValueError) as exc:
            return data, applied, f"/{name.decode()} failed: {exc}"
        applied.append(name.decode())
    return data, applied, ""


# ---------------------------------------------------------------------------
# Objects
# ---------------------------------------------------------------------------


@dataclass
class PdfObject:
    """One `N G obj ... endobj` block."""

    number: int
    generation: int
    offset: int
    dictionary: bytes
    stream: bytes | None = None  # decoded
    filters: list[str] = field(default_factory=list)
    note: str = ""

    @property
    def is_embedded_file(self) -> bool:
        return b"/EmbeddedFile" in self.dictionary

    @property
    def is_object_stream(self) -> bool:
        return b"/ObjStm" in self.dictionary


def parse_objects(data: bytes) -> list[PdfObject]:
    """Every object found by scanning, ignoring the cross-reference table.

    A challenge PDF often has a wrong xref, so scanning is both simpler and more
    reliable. `/Length` is likewise not trusted: the stream runs to `endstream`.
    """
    objects: list[PdfObject] = []
    for match in OBJECT.finditer(data):
        if len(objects) >= MAX_OBJECTS:
            break
        start = match.end()
        end = data.find(b"endobj", start)
        body = data[start : end if end != -1 else min(start + MAX_STREAM, len(data))]
        stream_match = STREAM_START.search(body)
        dictionary = body[: stream_match.start()] if stream_match else body
        obj = PdfObject(
            number=int(match.group(1)),
            generation=int(match.group(2)),
            offset=match.start(),
            dictionary=dictionary,
        )
        if stream_match:
            stream_end = body.find(b"endstream", stream_match.end())
            raw = body[stream_match.end() : stream_end if stream_end != -1 else len(body)]
            # A stream often ends with the EOL that precedes `endstream`.
            raw = raw.rstrip(b"\r\n") if stream_end != -1 else raw
            decoded, applied, note = decode_stream(raw, dictionary)
            obj.stream = decoded
            obj.filters = applied
            obj.note = note
        objects.append(obj)
    return objects


def _unescape(literal: bytes) -> bytes:
    r"""Undo a PDF literal string's backslash escapes (\n, \(, \251, \\)."""
    out = bytearray()
    index = 0
    simple = {b"n": 10, b"r": 13, b"t": 9, b"b": 8, b"f": 12}
    while index < len(literal):
        byte = literal[index : index + 1]
        if byte != b"\\":
            out += byte
            index += 1
            continue
        index += 1
        if index >= len(literal):
            break
        nxt = literal[index : index + 1]
        if nxt in simple:
            out.append(simple[nxt])
            index += 1
        elif b"0" <= nxt <= b"7":
            # Up to three octal digits: \251 is one byte.
            digits = b""
            while (
                len(digits) < 3
                and index < len(literal)
                and b"0" <= literal[index : index + 1] <= b"7"
            ):
                digits += literal[index : index + 1]
                index += 1
            out.append(int(digits, 8) & 0xFF)
        else:
            out += nxt
            index += 1
    return bytes(out)


def _balanced_literal(data: bytes, start: int) -> bytes:
    """Read a PDF literal string starting just after its `(`, honouring nesting."""
    depth = 1
    index = start
    out = bytearray()
    while index < len(data) and depth:
        byte = data[index]
        if byte == 0x5C:  # backslash: the next byte is escaped
            out += data[index : index + 2]
            index += 2
            continue
        if byte == 0x28:
            depth += 1
        elif byte == 0x29:
            depth -= 1
            if not depth:
                break
        out.append(byte)
        index += 1
    return bytes(out)


def find_javascript(objects: list[PdfObject]) -> list[tuple[int, str]]:
    """JavaScript held in a dictionary, or in the stream of a /JavaScript object."""
    found: list[tuple[int, str]] = []
    for obj in objects:
        for match in JS_LITERAL.finditer(obj.dictionary):
            code = _unescape(_balanced_literal(obj.dictionary, match.end()))
            if len(code) > 4:
                found.append((obj.number, code.decode("latin-1")))
        for match in JS_HEX.finditer(obj.dictionary):
            cleaned = re.sub(rb"\s", b"", match.group(1))
            try:
                code = binascii.unhexlify(cleaned[: len(cleaned) // 2 * 2])
            except binascii.Error:
                continue
            if len(code) > 4:
                found.append((obj.number, code.decode("latin-1")))
        if obj.stream and (b"/JavaScript" in obj.dictionary or b"/JS" in obj.dictionary):
            text = obj.stream.decode("latin-1")
            if len(text) > 4:
                found.append((obj.number, text))
    return found


# `/EF << /F 6 0 R >>` inside a file specification: which object holds the bytes.
EF_REFERENCE = re.compile(rb"/EF\s*<<[^>]{0,200}?/(?:UF|F|DOS|Mac|Unix)\s+(\d{1,10})\s+\d{1,5}\s+R")


def _embedded_names(objects: list[PdfObject]) -> dict[int, str]:
    """Map an /EmbeddedFile object number to the file name its /Filespec gives it."""
    names: dict[int, str] = {}
    for obj in objects:
        if b"/EF" not in obj.dictionary:
            continue
        reference = EF_REFERENCE.search(obj.dictionary)
        name = FILE_NAME.search(obj.dictionary)
        if reference and name:
            names[int(reference.group(1))] = name.group(1).decode("latin-1")
    return names


@dataclass
class PdfReport:
    """Everything worth knowing about the file."""

    version: str = ""
    objects: list[PdfObject] = field(default_factory=list)
    revisions: int = 1
    encrypted: bool = False
    indicators: list[str] = field(default_factory=list)
    javascript: list[tuple[int, str]] = field(default_factory=list)
    embedded: list[tuple[str, bytes]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    flags: list[tuple[int, str]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "object_count": len(self.objects),
            "revisions": self.revisions,
            "encrypted": self.encrypted,
            "indicators": list(self.indicators),
            "javascript": [{"object": number, "code": code} for number, code in self.javascript],
            "embedded": [
                {"name": name, "size": len(blob), "hex": blob[:64].hex()}
                for name, blob in self.embedded
            ],
            "streams_decoded": sum(1 for obj in self.objects if obj.filters),
            "flags": [{"object": number, "text": text} for number, text in self.flags],
            "notes": list(self.notes),
        }


def analyse(data: bytes, flagset=None) -> PdfReport:
    """Read the PDF and report what it would do and what it carries."""
    header = HEADER.search(data[:1024])
    if header is None:
        raise PdfError("no %PDF- header in the first 1024 bytes: this is not a PDF")
    report = PdfReport(version=header.group(1).decode())
    report.objects = parse_objects(data)
    if not report.objects:
        report.notes.append("no object found: the file is truncated or not really a PDF")

    # Objects packed inside a compressed /ObjStm are invisible to a plain scan:
    # parse the decoded stream too, so their dictionaries are searched as well.
    for obj in list(report.objects):
        if obj.is_object_stream and obj.stream:
            inner = parse_objects(obj.stream)
            if inner:
                report.objects += inner
            else:
                # An /ObjStm holds bare dictionaries, without "N G obj" wrappers.
                report.objects.append(
                    PdfObject(
                        number=obj.number,
                        generation=0,
                        offset=obj.offset,
                        dictionary=obj.stream[:MAX_STREAM],
                        note="unpacked from an object stream",
                    )
                )

    report.revisions = max(1, data.count(b"%%EOF"))
    if report.revisions > 1:
        report.notes.append(
            f"{report.revisions} revisions: this PDF was updated incrementally, so earlier "
            "versions are still in the file. Content that looks removed or redacted is "
            "often readable in the first one - cut the file at the first %%EOF and reopen it"
        )
    report.encrypted = any(b"/Encrypt" in obj.dictionary for obj in report.objects) or (
        b"/Encrypt" in data[-2048:]
    )
    if report.encrypted:
        report.notes.append(
            "encrypted (/Encrypt): pdf2john.pl <file> > h, then `ctfc hash` on that line. "
            "An empty user password still allows reading in most viewers"
        )

    searchable = b"".join(obj.dictionary for obj in report.objects)
    for key, why in INDICATORS:
        if re.search(re.escape(key) + rb"[^A-Za-z]", searchable):
            report.indicators.append(f"{key.decode()}: {why}")

    report.javascript = find_javascript(report.objects)
    if report.javascript:
        report.notes.append(
            f"{len(report.javascript)} JavaScript block(s): shown below and read by Code Lens"
        )
    # The embedded file's name lives in the /Filespec object that points at it
    # (`/F (payload.txt) /EF << /F 6 0 R >>`), not in the stream's own dictionary.
    names = _embedded_names(report.objects)
    for obj in report.objects:
        if obj.is_embedded_file and obj.stream:
            own = FILE_NAME.search(obj.dictionary)
            label = names.get(obj.number) or (
                own.group(1).decode("latin-1") if own else f"object_{obj.number}.bin"
            )
            report.embedded.append((label, obj.stream))
    if report.embedded:
        report.notes.append(
            f"{len(report.embedded)} embedded file(s): extract them and run `ctfc scan`"
        )
    # A flag sitting in a decoded stream (page text, an old revision's content)
    # would otherwise need a second command to find, so say it here.
    report.flags = _flags_in_streams(report.objects, flagset)
    for number, hit in report.flags:
        report.notes.append(f"flag pattern in the stream of object {number}: {hit}")

    broken = [obj.note for obj in report.objects if obj.note and "unpacked" not in obj.note]
    for note in dict.fromkeys(broken):
        report.notes.append(f"stream decoding: {note}")
    return report


def _flags_in_streams(objects: list[PdfObject], flagset) -> list[tuple[int, str]]:
    """Flag matches inside the decoded streams, with the object they came from."""
    from ctfc.core.flags import default_flagset, find_flags

    flagset = flagset or default_flagset()
    found: list[tuple[int, str]] = []
    seen: set[str] = set()
    for obj in objects:
        if not obj.stream:
            continue
        for hit in find_flags(obj.stream, flagset):
            if hit.text not in seen:
                seen.add(hit.text)
                found.append((obj.number, hit.text))
    return found
