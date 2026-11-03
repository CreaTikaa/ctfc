"""Pull the files that are *embedded inside* an OLE2 document back out.

Double-clicking an icon in a Word document opens a file that was never on disk:
it was stored inside the document. Word keeps those in a storage called
`ObjectPool`, one sub-storage per object, and the file itself sits in a stream
whose name depends on how it was embedded:

- **`\\x01Ole10Native`** - the "Package" case, which is what you get when any
  file is dragged in. The stream holds the original file name, the path it came
  from on the author's machine, and then the file's bytes, as they were.
- **`CONTENTS`** or **`Package`** - the same idea with another name, used by some
  producers.
- a nested compound file - an embedded Excel sheet, for instance, which is
  itself a `.xls`.

This is the "the real payload was an embedded object inside the .doc" shape, and
it is also where the path on the author's machine leaks - which is sometimes the
answer all by itself (`C:\\Users\\<name>\\Desktop\\flag.exe`).

Nothing is executed: the bytes are handed back for `ctfc detect` / `ctfc scan`
to look at.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core import cfb
from ctfc.core.errors import FormatError

NATIVE_STREAM = "\x01Ole10Native"
OTHER_STREAMS = ("CONTENTS", "Package", "EmbeddedOdf")
POOL = "objectpool"
MAX_OBJECT = 64 << 20


class EmbeddedError(FormatError):
    """The stream is not an embedded object we can read."""


@dataclass
class EmbeddedObject:
    """One file that was stored inside the document."""

    stream: str  # where it was found
    name: str = ""  # the file name the document shows
    source_path: str = ""  # where it came from on the author's machine
    temp_path: str = ""
    data: bytes = b""
    notes: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)


def _zero_terminated(data: bytes, offset: int) -> tuple[str, int]:
    """One NUL-terminated ANSI string, and the offset after it."""
    end = data.find(b"\x00", offset)
    if end < 0:
        raise EmbeddedError(f"a name starting at {offset} is not terminated")
    return data[offset:end].decode("cp1252", "replace"), end + 1


def parse_ole10native(data: bytes, stream: str = NATIVE_STREAM) -> EmbeddedObject:
    """Read an `\\x01Ole10Native` stream: the names, then the embedded file.

    The layout is a 1990s one, and the only awkward part is the middle: after
    the two names come a couple of fields whose meaning is undocumented, then
    the temporary path, then the real size. Both of the layouts seen in the wild
    are tried and the one whose size field actually fits the stream wins - which
    is a more reliable test than trusting either description.
    """
    if len(data) < 12:
        raise EmbeddedError(f"an Ole10Native stream of {len(data)} bytes holds nothing")
    declared = int.from_bytes(data[0:4], "little")
    if declared and declared + 4 != len(data):
        # Not fatal: a truncated sample still has its names and most of its data.
        note = f"the stream says {declared + 4} bytes but it is {len(data)}"
    else:
        note = ""
    label, position = _zero_terminated(data, 6)
    source, position = _zero_terminated(data, position)

    candidates: list[tuple[str, int, int]] = []  # (temp path, data size, data start)
    for unknown_fields in (2, 1, 0):
        cursor = position + 4 * unknown_fields
        try:
            temp, after = _zero_terminated(data, cursor)
        except EmbeddedError:
            continue
        if after + 4 > len(data):
            continue
        size = int.from_bytes(data[after : after + 4], "little")
        if 0 < size <= len(data) - after - 4 and size <= MAX_OBJECT:
            candidates.append((temp, size, after + 4))
    if not candidates:
        raise EmbeddedError(
            "no plausible size field after the names: this is not an Ole10Native "
            "stream, or it is damaged"
        )
    # Prefer the reading whose data runs to the end of the stream.
    temp, size, start = max(candidates, key=lambda item: item[1] + item[2])
    obj = EmbeddedObject(
        stream=stream,
        name=label,
        source_path=source,
        temp_path=temp,
        data=data[start : start + size],
    )
    if note:
        obj.notes.append(note)
    return obj


def find_objects(container: cfb.CfbFile) -> list[EmbeddedObject]:
    """Every embedded object in a compound file's `ObjectPool`.

    A stream that is not an Ole10Native package is still returned, with its raw
    bytes: an embedded `.xls` or a `CONTENTS` blob is just as interesting, and
    `ctfc detect` is better placed than this function to say what it is.
    """
    objects: list[EmbeddedObject] = []
    for path, payload in container.streams.items():
        parts = path.split("/")
        if len(parts) < 2 or parts[0].lower() != POOL:
            continue
        leaf = parts[-1]
        if leaf == NATIVE_STREAM:
            try:
                obj = parse_ole10native(payload, path)
            except EmbeddedError as exc:
                objects.append(
                    EmbeddedObject(stream=path, data=payload, notes=[f"not readable: {exc}"])
                )
                continue
            objects.append(obj)
        elif leaf in OTHER_STREAMS or cfb.is_cfb(payload):
            objects.append(
                EmbeddedObject(
                    stream=path,
                    name=f"{parts[-2]}/{leaf}",
                    data=payload,
                    notes=[
                        "a nested compound file"
                        if cfb.is_cfb(payload)
                        else "raw object contents (no Package wrapper)"
                    ],
                )
            )
    return objects
