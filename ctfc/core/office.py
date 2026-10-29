"""Pull the VBA macros out of an Office document, statically.

The malicious-attachment shape: a `.doc` or `.docm` arrives by mail, a macro runs
on open, it decodes a blob and drops a payload. `olevba` is the usual answer; this
does the same reading without needing it installed, and hands the recovered source
straight to Code Lens, which already knows how to read VBS-flavoured crypto.

Two containers, one payload:

- **`.doc` / `.xls` (OLE2)**: the macro lives in a stream named `VBA/<Module>`
  inside the compound file (see `core/cfb.py`).
- **`.docm` / `.xlsm` (OOXML)**: the file is a ZIP, and the whole OLE2 container
  above is stored inside it as `word/vbaProject.bin`.

In both cases the source is not plain text: it is wrapped in a *compressed
container* (MS-OVBA 2.4.1), a simple LZ77 variant with 4096-byte chunks. That is
implemented below, because it is the only reason the macro looks like binary.

Nothing is executed and nothing is written: the document is parsed as data. A
macro is returned as text for the user and for Code Lens to look at.
"""

from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

from ctfc.core import cfb

CONTAINER_SIGNATURE = 0x01  # first byte of a compressed container
CHUNK_SIGNATURE = 0b011  # bits 12-14 of a chunk header
MAX_DECOMPRESSED = 8 * 1024 * 1024
MIN_SOURCE = 24  # shorter than this is not a module worth reporting

# Names that make a macro run on its own, which is what makes a document malicious
# rather than merely unusual.
AUTO_RUN = (
    "AutoOpen",
    "Auto_Open",
    "AutoExec",
    "AutoClose",
    "Auto_Close",
    "Document_Open",
    "Document_Close",
    "DocumentOpen",
    "Workbook_Open",
    "Workbook_Activate",
    "Worksheet_Activate",
)
# Things a macro does that are worth pointing at. (needle, why)
SUSPICIOUS = (
    ("Shell", "runs a command"),
    ("WScript.Shell", "runs a command through the Windows scripting host"),
    ("CreateObject", "instantiates a COM object (Shell, XMLHTTP, ADODB...)"),
    ("powershell", "launches PowerShell"),
    ("cmd.exe", "launches a command prompt"),
    ("URLDownloadToFile", "downloads a file"),
    ("XMLHTTP", "makes an HTTP request"),
    ("WinHttp", "makes an HTTP request"),
    ("ADODB.Stream", "writes a file to disk"),
    ("SaveToFile", "writes a file to disk"),
    ("Environ", "reads environment variables (often %TEMP%)"),
    ("StrReverse", "reverses a string: an obfuscation step"),
    ("Chr(", "builds a string from character codes: an obfuscation step"),
    ("Xor", "XORs data: there is a key in here"),
    ("Base64", "decodes base64"),
    ("CallByName", "calls a method by name, to hide it"),
    ("GetObject", "binds to a COM object"),
    ("VBA.CreateObject", "instantiates a COM object"),
)
# An external relationship target in an OOXML part: remote template injection.
EXTERNAL_TARGET = re.compile(rb'Target="(https?://[^"]{4,400})"[^>]*TargetMode="External"')
EXTERNAL_TARGET_ALT = re.compile(rb'TargetMode="External"[^>]*Target="(https?://[^"]{4,400})"')


class OfficeError(Exception):
    """The file is not an Office document we can read."""


def decompress_container(data: bytes, start: int = 0) -> bytes:
    """Undo the MS-OVBA "compressed container" that wraps VBA source.

    The format is LZ77 in 4096-byte chunks. Each chunk header gives its size and
    says whether it is compressed; a compressed chunk is a series of groups of
    eight tokens, preceded by a flag byte saying which of the eight are literal
    bytes and which are (offset, length) copies from what was already produced.

    The clever/annoying part is that the number of bits used for the offset grows
    with how much has been decompressed *in the current chunk*, so the split of a
    2-byte copy token between offset and length changes as it goes.
    """
    if start >= len(data) or data[start] != CONTAINER_SIGNATURE:
        raise OfficeError("not a compressed container (it must start with 0x01)")
    out = bytearray()
    position = start + 1
    while position + 2 <= len(data):
        header = int.from_bytes(data[position : position + 2], "little")
        position += 2
        size = (header & 0x0FFF) + 3
        signature = (header >> 12) & 0x07
        compressed = bool(header >> 15)
        if signature != CHUNK_SIGNATURE:
            break  # not a chunk header any more: the container ended here
        end = position + size - 2
        if end > len(data):
            end = len(data)  # truncated sample: keep what is there
        if not compressed:
            out += data[position:end]
            position = end
            continue
        chunk_start = len(out)
        while position < end:
            flags = data[position]
            position += 1
            for bit in range(8):
                if position >= end:
                    break
                if not (flags >> bit) & 1:
                    out.append(data[position])
                    position += 1
                    continue
                if position + 2 > end:
                    position = end
                    break
                token = int.from_bytes(data[position : position + 2], "little")
                position += 2
                difference = len(out) - chunk_start
                # ceil(log2(difference)), at least 4 bits for the offset.
                bit_count = max(4, (difference - 1).bit_length() if difference else 0)
                length_mask = 0xFFFF >> bit_count
                length = (token & length_mask) + 3
                offset = ((token & ~length_mask & 0xFFFF) >> (16 - bit_count)) + 1
                if offset > len(out) - chunk_start:
                    raise OfficeError("copy token points before the chunk: corrupt container")
                for _ in range(length):
                    # Byte by byte: a copy may overlap what it is producing.
                    out.append(out[len(out) - offset])
        if len(out) > MAX_DECOMPRESSED:
            raise OfficeError("decompressed container is implausibly large")
    return bytes(out)


def _looks_like_source(text: str) -> bool:
    """Is this VBA source rather than a lucky decompression of binary?"""
    if len(text) < MIN_SOURCE:
        return False
    printable = sum(1 for char in text if " " <= char < "\x7f" or char in "\r\n\t")
    if printable < 0.9 * len(text):
        return False
    lowered = text.lower()
    return any(word in lowered for word in ("sub ", "function ", "dim ", "attribute ", "end sub"))


@dataclass
class Macro:
    """One VBA module recovered from the document."""

    module: str  # the stream path it came from
    code: str
    offset: int  # where the compressed container started in that stream


@dataclass
class OfficeReport:
    """What the document holds."""

    container: str = ""  # "ole2" | "ooxml"
    macros: list[Macro] = field(default_factory=list)
    streams: list[str] = field(default_factory=list)
    externals: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def source(self) -> str:
        """Every module concatenated, for Code Lens to analyse in one go."""
        return "\n\n".join(f"' --- {macro.module} ---\n{macro.code}" for macro in self.macros)

    def to_dict(self) -> dict:
        return {
            "container": self.container,
            "macros": [
                {"module": macro.module, "offset": macro.offset, "code": macro.code}
                for macro in self.macros
            ],
            "streams": list(self.streams),
            "externals": list(self.externals),
            "indicators": list(self.indicators),
            "notes": list(self.notes),
        }


def extract_macros(container: cfb.CfbFile) -> list[Macro]:
    """Find and decompress every VBA module in an OLE2 container.

    A module stream begins with a "performance cache" whose size is only given in
    the (itself compressed) `dir` stream. Rather than depend on that, every offset
    where a compressed container could start is tried and the result is kept when
    it reads as source - which is both simpler and more tolerant of the
    hand-damaged documents a CTF hands you.
    """
    macros = []
    for path, stream in container.streams.items():
        name = path.rsplit("/", 1)[-1]
        if name.lower() in ("dir", "project", "projectwm", "_vba_project"):
            continue  # project metadata, not source
        best: Macro | None = None
        for offset, byte in enumerate(stream):
            if byte != CONTAINER_SIGNATURE:
                continue
            try:
                raw = decompress_container(stream, offset)
            except (OfficeError, IndexError):
                continue
            text = raw.decode("latin-1")
            if _looks_like_source(text) and (best is None or len(text) > len(best.code)):
                best = Macro(module=path, code=text, offset=offset)
        if best is not None:
            macros.append(best)
    return macros


def _indicators(source: str) -> list[str]:
    """Autorun entry points and notable calls found in the recovered source."""
    found = []
    for name in AUTO_RUN:
        if re.search(rf"\b{re.escape(name)}\b", source, re.IGNORECASE):
            found.append(f"{name}: the macro runs by itself when the document is opened")
    lowered = source.lower()
    for needle, why in SUSPICIOUS:
        if needle.lower() in lowered:
            found.append(f"{needle}: {why}")
    return found


def _externals(archive: zipfile.ZipFile) -> list[str]:
    """External relationship targets: a remote template or remote object."""
    targets: list[str] = []
    for item in archive.infolist():
        if not item.filename.endswith(".rels") or item.file_size > 1_000_000:
            continue
        try:
            body = archive.read(item)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            continue
        for pattern in (EXTERNAL_TARGET, EXTERNAL_TARGET_ALT):
            for match in pattern.finditer(body):
                url = match.group(1).decode("latin-1")
                if url not in targets:
                    targets.append(url)
    return targets


def analyse(data: bytes) -> OfficeReport:
    """Read an Office document and report its macros and indicators."""
    report = OfficeReport()
    if cfb.is_cfb(data):
        report.container = "ole2"
        container = cfb.read(data)
        report.streams = sorted(container.streams)
        report.macros = extract_macros(container)
        if any(name.lower() == "objectpool" for name in container.names):
            report.notes.append(
                "an ObjectPool storage is present: the document embeds an object "
                "(another file). Try `ctfc scan` after extracting the streams."
            )
    elif data[:4] == b"PK\x03\x04":
        report.container = "ooxml"
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError) as exc:
            raise OfficeError(f"not a readable OOXML file: {exc}") from exc
        report.streams = sorted(item.filename for item in archive.infolist())
        report.externals = _externals(archive)
        project = [name for name in report.streams if name.lower().endswith("vbaproject.bin")]
        for name in project:
            try:
                inner = cfb.read(archive.read(name))
            except (cfb.CfbError, zipfile.BadZipFile, OSError, RuntimeError) as exc:
                report.notes.append(f"{name} could not be read: {exc}")
                continue
            report.macros += [
                Macro(module=f"{name}:{macro.module}", code=macro.code, offset=macro.offset)
                for macro in extract_macros(inner)
            ]
        if not project:
            report.notes.append(
                "no vbaProject.bin: this document has no VBA macro (a .docx cannot "
                "hold one; a macro-enabled file is .docm / .xlsm)"
            )
    else:
        raise OfficeError(
            "not an Office document: expected an OLE2 compound file (d0cf11e0) "
            "or a ZIP-based OOXML file (PK\\x03\\x04)"
        )

    if report.macros:
        report.indicators = _indicators(report.source)
        report.notes.append(
            f"{len(report.macros)} VBA module(s) recovered: the source is shown below, and "
            "Code Lens read it as VBS to pull the crypto out"
        )
    elif report.container == "ole2":
        report.notes.append("no VBA module found in the streams")
    for url in report.externals:
        report.notes.append(f"external relationship target (remote template injection?): {url}")
    return report
