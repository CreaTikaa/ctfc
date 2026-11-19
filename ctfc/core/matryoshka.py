"""Peel a "matryoshka": a file nested in hundreds of single-member layers.

A classic handout is the flag compressed again and again, mixing formats
(bzip2 -> zip -> xz -> gzip -> ...), often under a misleading name (`flag.txt`
that is really bzip2). Reading it one layer per step of the walk would need a
depth of 1000; here each layer is recognised by its magic bytes and opened in
memory with the standard library, until the data stops being a one-member
container. Nothing is executed and nothing is written to disk.

A layer is followed only while it holds ONE thing: a compressed stream (bzip2,
gzip, xz, lzma, zlib), a ZIP or a tar with a single file. A multi-file archive,
an encrypted ZIP member or anything else stops the peel, and the walk takes
over from there as usual.

Bounded: MAX_LAYERS layers, LAYER_MAX bytes per layer, TOTAL_MAX bytes in all,
and a few seconds.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import time
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field

MAX_LAYERS = 20_000
LAYER_MAX = 256 * 1024 * 1024
TOTAL_MAX = 1024 * 1024 * 1024
SECONDS = 10.0


@dataclass
class Peeled:
    """What was under the layers."""

    data: bytes
    depth: int = 0  # how many layers were removed
    kinds: Counter = field(default_factory=Counter)  # {"bzip2": 75, "zip": 75, ...}
    name: str = ""  # the innermost member name, when a layer gave one
    stopped: str = ""  # why it stopped early, "" when it simply reached the bottom

    def chain(self) -> str:
        """ "bzip2 x75, zip x75, ..." (most frequent first)."""
        return ", ".join(f"{kind} x{count}" for kind, count in self.kinds.most_common())


def _zlib_header(data: bytes) -> bool:
    return (
        len(data) > 2
        and data[0] == 0x78
        and data[1] in (0x01, 0x5E, 0x9C, 0xDA)
        and (data[0] * 256 + data[1]) % 31 == 0
    )


def is_layer(data: bytes) -> bool:
    """Does this start like one of the layers peel() opens? (cheap: magic bytes only)"""
    return (
        data[:3] == b"BZh"
        or data[:2] == b"\x1f\x8b"
        or data[:6] == b"\xfd7zXZ\x00"
        or data[:3] == b"\x5d\x00\x00"
        or data[:4] == b"PK\x03\x04"
        or data[257:262] == b"ustar"
        or _zlib_header(data)
    )


def peel_once(data: bytes) -> tuple[str, bytes, str] | None:
    """Remove one layer: (kind, inner bytes, member name) or None when it is not one."""
    try:
        if data[:3] == b"BZh" and data[3:4].isdigit():
            return "bzip2", bz2.BZ2Decompressor().decompress(data, LAYER_MAX), ""
        if data[:2] == b"\x1f\x8b":
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                return "gzip", stream.read(LAYER_MAX), ""
        if data[:6] == b"\xfd7zXZ\x00":
            return "xz", lzma.LZMADecompressor().decompress(data, LAYER_MAX), ""
        if data[:3] == b"\x5d\x00\x00":
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            return "lzma", decompressor.decompress(data, LAYER_MAX), ""
        if data[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                files = [info for info in archive.infolist() if not info.is_dir()]
                if len(files) != 1 or files[0].flag_bits & 0x1:
                    return None  # several files, or encrypted: the walk's job
                if files[0].file_size > LAYER_MAX:
                    return None
                return "zip", archive.read(files[0]), files[0].filename
        if data[257:262] == b"ustar":
            with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                files = [member for member in archive.getmembers() if member.isfile()]
                if len(files) != 1 or files[0].size > LAYER_MAX:
                    return None
                stream = archive.extractfile(files[0])
                return ("tar", stream.read(), files[0].name) if stream else None
        if _zlib_header(data):
            decompressor = zlib.decompressobj()
            inner = decompressor.decompress(data, LAYER_MAX)
            return ("zlib", inner, "") if decompressor.eof else None
    except (OSError, EOFError, ValueError, lzma.LZMAError, zlib.error, zipfile.BadZipFile,
            tarfile.TarError, NotImplementedError, RuntimeError):  # fmt: skip
        return None
    return None


def peel(data: bytes, seconds: float = SECONDS) -> Peeled:
    """Remove every single-member layer, as deep as it goes (within the bounds)."""
    result = Peeled(data=data)
    total = 0
    deadline = time.monotonic() + seconds
    while result.depth < MAX_LAYERS:
        if time.monotonic() > deadline:
            result.stopped = "time limit"
            break
        layer = peel_once(result.data)
        if layer is None:
            break
        kind, inner, name = layer
        if not inner:
            result.stopped = "empty layer"
            break
        total += len(inner)
        if total > TOTAL_MAX:
            result.stopped = "size limit"
            break
        result.data = inner
        result.depth += 1
        result.kinds[kind] += 1
        result.name = name or result.name
    else:
        result.stopped = "layer limit"
    return result
