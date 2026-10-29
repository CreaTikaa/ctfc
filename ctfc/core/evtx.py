"""Read a Windows event log (.evtx) down to the record level.

The structure above the records is simple and worth knowing:

    ElfFile\\0   a 4096-byte file header: how many chunks, the next record id
    ElfChnk\\0   chunks of 65536 bytes, each with its own 512-byte header saying
                which record numbers it holds
    2a2a0000    a record: size, record number, an 8-byte FILETIME, then the
                event itself, then the size again so it can be walked backwards

Inside a record the event is **binary XML**: a token stream that refers to
templates and a substitution array, with element and attribute names kept in a
per-chunk string table. Rendering that back into the XML `wevtutil` prints is a
few hundred lines of fiddly work, and there is no genuine .evtx on this machine
to check an implementation against - so this does not pretend to. What it does
instead is the part that is both robust and what a challenge actually needs:

- walk the chunks and records properly, so every record is found with its real
  **record number and timestamp** (including in a file whose header is damaged,
  because records are also located by scanning for their magic);
- pull the **UTF-16LE strings** out of each record. The substitution values - a
  command line, a user name, a path, a script block - are stored as UTF-16LE
  text, so they come out intact even without rendering the XML around them;
- flag the records that hold a flag, a credential, or a PowerShell
  `-EncodedCommand` (through the `psenc` decoder, which already handles the
  UTF-16LE-inside-binary case).

For the full XML, `evtx_dump` or python-evtx renders it properly; the report says
so rather than leaving you to wonder what is missing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
RECORD_HEADER_SIZE = 24  # magic, size, record number, timestamp
MIN_STRING = 4  # shorter UTF-16 runs are noise
MAX_RECORDS = 200_000
MAX_RECORD_SIZE = 4 * 1024 * 1024
# A run of UTF-16LE characters: an ASCII byte followed by a zero, repeated.
UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING)


class EvtxError(Exception):
    """The file is not an event log we can read."""


@dataclass
class Record:
    """One event record, with the strings it carries."""

    number: int
    timestamp: int  # raw FILETIME
    offset: int
    size: int
    strings: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)
    command: str = ""  # a decoded PowerShell -EncodedCommand

    @property
    def when(self) -> str:
        """The timestamp as a date, through the FILETIME reading."""
        from ctfc.core import timestamps

        for reading in timestamps.readings(self.timestamp):
            if reading.epoch == "Windows FILETIME":
                return reading.text
        return ""

    @property
    def text(self) -> str:
        return " | ".join(self.strings)


def read_header(data: bytes) -> tuple[int, int]:
    """(chunk count, next record number) from the file header."""
    if data[:8] != FILE_MAGIC:
        raise EvtxError("not an event log (the file must start with 'ElfFile\\0')")
    if len(data) < FILE_HEADER_SIZE:
        raise EvtxError(f"truncated: {len(data)} bytes, the header alone is {FILE_HEADER_SIZE}")
    chunk_count = int.from_bytes(data[42:44], "little")
    next_record = int.from_bytes(data[24:32], "little")
    return chunk_count, next_record


def chunk_offsets(data: bytes, declared: int) -> list[int]:
    """Where the chunks are.

    The header's count is used when it agrees with the file size, and otherwise
    the chunks are found by their own magic - a log cut out of a disk image or a
    memory dump very often has a stale count.
    """
    by_size = max(0, (len(data) - FILE_HEADER_SIZE) // CHUNK_SIZE)
    if declared and declared == by_size:
        return [FILE_HEADER_SIZE + index * CHUNK_SIZE for index in range(declared)]
    found = []
    position = 0
    while True:
        position = data.find(CHUNK_MAGIC, position)
        if position < 0:
            break
        found.append(position)
        position += len(CHUNK_MAGIC)
    return found or [FILE_HEADER_SIZE + index * CHUNK_SIZE for index in range(by_size)]


def utf16_strings(blob: bytes) -> list[str]:
    """Every readable UTF-16LE run in the record, in order, without duplicates.

    This is where the event's substitution values live - the command line, the
    user, the path - so they are recoverable without rendering the binary XML
    that surrounds them.
    """
    seen: set[str] = set()
    out: list[str] = []
    for match in UTF16_RUN.finditer(blob):
        text = match.group(0).decode("utf-16-le", "replace").strip()
        if len(text) >= MIN_STRING and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def records(data: bytes) -> list[Record]:
    """Every event record, walked through the chunks and then by magic.

    Records are walked inside each chunk using their declared size, which is the
    correct way; any record the walk missed is then picked up by scanning for the
    magic, so a damaged chunk costs one record rather than all of them.
    """
    try:
        declared, _next = read_header(data)
    except EvtxError:
        declared = 0
    found: dict[int, Record] = {}

    for chunk_start in chunk_offsets(data, declared):
        position = chunk_start + CHUNK_HEADER_SIZE
        limit = min(chunk_start + CHUNK_SIZE, len(data))
        while position + RECORD_HEADER_SIZE <= limit:
            if data[position : position + 4] != RECORD_MAGIC:
                break  # the rest of the chunk is free space
            record = _record_at(data, position)
            if record is None:
                break
            found.setdefault(record.offset, record)
            position += record.size
            if len(found) > MAX_RECORDS:
                return sorted(found.values(), key=lambda item: item.number)

    # A second pass by magic, for records the chunk walk could not reach.
    position = 0
    while len(found) <= MAX_RECORDS:
        position = data.find(RECORD_MAGIC, position)
        if position < 0:
            break
        if position not in found:
            record = _record_at(data, position)
            if record is not None:
                found[position] = record
        position += 4
    return sorted(found.values(), key=lambda item: (item.number, item.offset))


def _record_at(data: bytes, position: int) -> Record | None:
    """Read the record header at `position`, or None if it is not one."""
    size = int.from_bytes(data[position + 4 : position + 8], "little")
    if not RECORD_HEADER_SIZE < size <= MAX_RECORD_SIZE or position + size > len(data):
        return None
    # The size is written again at the end of the record; that is the check that
    # tells a real record from four bytes that happen to be 2a 2a 00 00.
    trailing = int.from_bytes(data[position + size - 4 : position + size], "little")
    if trailing != size:
        return None
    number = int.from_bytes(data[position + 8 : position + 16], "little")
    timestamp = int.from_bytes(data[position + 16 : position + 24], "little")
    body = data[position + RECORD_HEADER_SIZE : position + size - 4]
    return Record(
        number=number,
        timestamp=timestamp,
        offset=position,
        size=size,
        strings=utf16_strings(body),
    )


@dataclass
class EvtxReport:
    """What the log holds."""

    chunks: int = 0
    records: list[Record] = field(default_factory=list)
    interesting: list[Record] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "chunks": self.chunks,
            "record_count": len(self.records),
            "records": [
                {
                    "number": record.number,
                    "when": record.when,
                    "offset": record.offset,
                    "strings": list(record.strings),
                    "flags": list(record.flags),
                    "secrets": list(record.secrets),
                    "command": record.command,
                }
                for record in self.records
            ],
            "interesting": [record.number for record in self.interesting],
            "notes": list(self.notes),
        }


def analyse(data: bytes, flagset=None) -> EvtxReport:
    """Read the log and point at the records worth reading."""
    from ctfc.core import secrets as secrets_module
    from ctfc.core.encodings import find_encoded_command
    from ctfc.core.flags import default_flagset, find_flags

    flagset = flagset or default_flagset()
    declared, next_record = read_header(data)
    report = EvtxReport()
    report.records = records(data)
    report.chunks = len(chunk_offsets(data, declared))

    if declared and declared != (len(data) - FILE_HEADER_SIZE) // CHUNK_SIZE:
        report.notes.append(
            f"the header declares {declared} chunk(s) but the file holds "
            f"{(len(data) - FILE_HEADER_SIZE) // CHUNK_SIZE}: the chunks were found by their "
            "own magic instead. A log carved out of an image usually looks like this"
        )
    if next_record and report.records:
        highest = max(record.number for record in report.records)
        missing = next_record - 1 - highest
        if missing > 0:
            report.notes.append(
                f"the header expects records up to {next_record - 1} but the highest found is "
                f"{highest}: {missing} record(s) are missing, so the log is "
                "truncated or was cleared"
            )

    for record in report.records:
        joined = record.text.encode()
        record.flags = [hit.text for hit in find_flags(joined, flagset)]
        as_config = "\n".join(record.strings).encode()
        record.secrets = [
            f"{secret.name} = {secret.value}" for secret in secrets_module.find_secrets(as_config)
        ]
        decoded = find_encoded_command(as_config)
        if decoded is not None:
            record.command = decoded.decode("utf-8", "replace")
            # The flag is usually inside the decoded command, not in the base64
            # that carried it, so search that too.
            for hit in find_flags(decoded, flagset):
                if hit.text not in record.flags:
                    record.flags.append(hit.text)
        if record.flags or record.secrets or record.command:
            report.interesting.append(record)

    report.interesting.sort(key=lambda record: (not record.flags, not record.command))
    if report.interesting:
        report.notes.append(
            f"{len(report.interesting)} record(s) hold a flag, a credential or an encoded "
            "command: they are shown first"
        )
    if not report.records:
        report.notes.append(
            "no record found: the file may be an empty log, or only its header survived"
        )
    report.notes.append(
        "ctfc reads the records and their strings, not the binary XML around them: the "
        "substitution values (command lines, users, paths, script blocks) come out, but the "
        "element names and the EventID do not. For the full XML use `evtx_dump <file>` or "
        "python-evtx"
    )
    return report
