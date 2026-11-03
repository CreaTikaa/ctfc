"""Read a Windows Installer package (`.msi`): its tables, its strings, and what
it carries.

An MSI is two things at once. It is an OLE2 compound file (`core/cfb.py`), and
it is a *relational database* whose tables are stored as streams of that file -
`Property`, `File`, `CustomAction`, `Binary`, `Media`. The payload itself is
either a cabinet embedded as one more stream, or files sitting next to the MSI.

The part that makes an MSI look unreadable is its **stream-name encoding**. Table
names are not stored as text: each character is packed into a private Unicode
range, two 6-bit values per code point, so the `Property` table's stream is a run
of characters around U+3800-U+4800 and `strings` shows nothing useful. Decoding
is a dozen lines (`decode_name` below) and makes the whole file legible:

    4840 3F3F 4443 ...   ->   _StringData
    4840 4842 ...        ->   CustomAction

What a CTF wants out of it:

- **the string pool** (`_StringData` + `_StringPool`), which holds every string
  of every table in one place: paths, URLs, registry keys, command lines. Reading
  the pool is both easy and enough for most questions.
- **the `CustomAction` table**, which is where "this installer also runs
  something" lives, and `Binary`, which is where that something is stored.
- **an embedded cabinet**, which `core/cab.py` then opens offline.

The row-level decoding of arbitrary tables (which needs `_Columns` and per-column
types) is deliberately not done: the string pool answers the same questions with
a tenth of the code, and `msidump` is there for the rest. That limit is stated in
the report rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core import cab as cab_module
from ctfc.core import cfb
from ctfc.core.encodings import find_encoded_command
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags

# The 64 characters an encoded name maps onto, in order.
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
BASE = 0x3800
SINGLE = 0x4800
LIMIT = 0x4840
# Streams whose names are these, once decoded, describe the database itself.
POOL_STREAM = "_StringPool"
DATA_STREAM = "_StringData"
TABLES_STREAM = "_Tables"
COLUMNS_STREAM = "_Columns"
# A string long enough to be worth showing, and a cap on how many are reported.
MIN_STRING = 4
MAX_STRINGS = 4000
# Things in the strings that answer a question on their own.
INTERESTING = (
    ("http://", "an http URL"),
    ("https://", "an https URL"),
    ("powershell", "PowerShell is launched"),
    ("cmd.exe", "a command prompt is launched"),
    ("rundll32", "rundll32 is used to run a DLL"),
    ("mshta", "mshta runs an HTA script"),
    ("wscript", "the Windows scripting host is used"),
    ("cscript", "the Windows scripting host is used"),
    ("-enc ", "an encoded PowerShell command"),
    ("-EncodedCommand", "an encoded PowerShell command"),
    ("FromBase64String", "base64 is decoded at install time"),
    ("DownloadString", "something is downloaded at install time"),
    ("\\AppData\\", "a path under AppData"),
    ("%TEMP%", "a path under TEMP"),
)
FLAG_SEARCH_LIMIT = 4 << 20


class MsiError(FormatError):
    """The file is not an installer package we can read."""


def decode_name(name: str) -> str:
    """Undo the MSI stream-name encoding.

    Each code point carries either two 6-bit indexes into `ALPHABET` (the
    U+3800 range) or one (the U+4800 range); anything outside those ranges is a
    literal character. The alphabet's last two entries are `.` and `_`, which is
    why table names come out as `_StringData` rather than mojibake.
    """
    out: list[str] = []
    for character in name:
        value = ord(character)
        if BASE <= value < SINGLE:
            index = value - BASE
            out.append(ALPHABET[index & 0x3F])
            out.append(ALPHABET[(index >> 6) & 0x3F])
        elif SINGLE <= value < LIMIT:
            out.append(ALPHABET[value - SINGLE])
        else:
            out.append(character)
    return "".join(out)


def encode_name(name: str) -> str:
    """The inverse of `decode_name`, used to build the test fixture.

    Kept next to its inverse on purpose: an encoder and a decoder that disagree
    are the easiest bug in the world to write, and the round trip is a test.
    """
    out: list[str] = []
    position = 0
    while position < len(name):
        first = name[position]
        if first not in ALPHABET:
            out.append(first)
            position += 1
            continue
        low = ALPHABET.index(first)
        second = name[position + 1] if position + 1 < len(name) else ""
        if second and second in ALPHABET:
            out.append(chr(BASE + low + (ALPHABET.index(second) << 6)))
            position += 2
        else:
            out.append(chr(SINGLE + low))
            position += 1
    return "".join(out)


@dataclass
class MsiReport:
    """What the package is made of."""

    streams: list[str] = field(default_factory=list)  # every stream name, decoded
    strings: list[str] = field(default_factory=list)  # the string pool
    cabinets: list[tuple[str, int]] = field(default_factory=list)  # (stream, files)
    binaries: list[tuple[str, int]] = field(default_factory=list)  # (stream, size)
    cabinet_files: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)  # decoded PowerShell -enc payloads
    summary: dict[str, str] = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "streams": list(self.streams),
            "strings": self.strings[:MAX_STRINGS],
            "cabinets": [{"stream": name, "files": count} for name, count in self.cabinets],
            "binaries": [{"stream": name, "size": size} for name, size in self.binaries],
            "cabinet_files": list(self.cabinet_files),
            "commands": list(self.commands),
            "summary": dict(self.summary),
            "flags": list(self.flags),
            "indicators": list(self.indicators),
            "notes": list(self.notes),
        }


def looks_like_msi(data: bytes) -> bool:
    """A compound file whose stream names decode to the MSI tables."""
    if not cfb.is_cfb(data):
        return False
    try:
        container = cfb.read(data)
    except cfb.CfbError:
        return False
    return is_msi_container(container)


def is_msi_container(container: cfb.CfbFile) -> bool:
    decoded = {decode_name(name) for name in container.streams}
    return bool(decoded & {DATA_STREAM, POOL_STREAM, TABLES_STREAM})


def read_string_pool(data: bytes, pool: bytes, codepage: str = "utf-8") -> list[str]:
    """The string pool: every string of every table, in one list.

    `_StringPool` is an array of 2-byte pairs - **the length first, then the
    reference count** - and `_StringData` is the strings themselves, end to end,
    with no separators. So a string is found by adding up the lengths before it;
    get the pair order wrong and every string after the first is garbage.

    The first pair is not a string: it carries the code page the data is written
    in. A pair of (0, 0) is a freed slot and still consumes no data. A length of
    zero with a non-zero reference count marks a string longer than 65535, whose
    real length is that count shifted up by 16 plus the next pair's length - rare
    enough that it is read defensively and abandoned if the result does not fit.
    """
    strings: list[str] = []
    position = 4  # skip the code-page pair
    offset = 0
    while position + 4 <= len(pool):
        length = int.from_bytes(pool[position : position + 2], "little")
        refs = int.from_bytes(pool[position + 2 : position + 4], "little")
        position += 4
        if length == 0:
            if refs == 0:
                continue  # a freed slot: it holds no data
            if position + 4 > len(pool):
                break
            length = (refs << 16) + int.from_bytes(pool[position : position + 2], "little")
            position += 4
            if offset + length > len(data):
                break  # not a long string after all: stop rather than invent one
        if offset + length <= len(data):
            strings.append(data[offset : offset + length].decode(codepage, "replace"))
        offset += length
        if len(strings) > MAX_STRINGS * 4:
            break
    return strings


def pool_codepage(pool: bytes) -> str:
    """The code page from the pool's first pair, as a Python codec name."""
    if len(pool) < 2:
        return "utf-8"
    number = int.from_bytes(pool[0:2], "little")
    return {0: "utf-8", 65001: "utf-8", 1252: "cp1252", 1250: "cp1250", 932: "cp932"}.get(
        number, "utf-8"
    )


def analyse(data: bytes, flagset: FlagSet | None = None) -> MsiReport:
    """Read the package: its tables, its strings, and anything it embeds."""
    if not cfb.is_cfb(data):
        raise MsiError(
            "not an installer package: an .msi is an OLE2 compound file and this "
            "does not start with d0cf11e0"
        )
    try:
        container = cfb.read(data)
    except cfb.CfbError as exc:
        raise MsiError(f"not a readable compound file: {exc}") from exc
    if not is_msi_container(container):
        raise MsiError(
            "this is a compound file but none of its streams decode to an MSI table: "
            "it is probably a .doc/.xls (`ctfc office`) or a .msg (`ctfc msg`)"
        )

    report = MsiReport()
    decoded = {decode_name(name): name for name in container.streams}
    report.streams = sorted(decoded)

    pool = container.streams.get(decoded.get(POOL_STREAM, ""), b"")
    pool_data = container.streams.get(decoded.get(DATA_STREAM, ""), b"")
    if pool and pool_data:
        every = read_string_pool(pool_data, pool, pool_codepage(pool))
        report.strings = [text for text in every if len(text) >= MIN_STRING][:MAX_STRINGS]
    elif pool_data:
        report.notes.append(
            "_StringData is there but _StringPool is not, so the strings cannot be "
            "cut apart: the raw stream is still searched for flags"
        )

    for name, payload in container.streams.items():
        pretty = decode_name(name)
        if payload[:4] == cab_module.SIGNATURE:
            try:
                cabinet = cab_module.extract(payload)
            except cab_module.CabError as exc:
                report.notes.append(f"{pretty}: an embedded cabinet that does not read: {exc}")
                continue
            report.cabinets.append((pretty, len(cabinet.files)))
            report.cabinet_files += [file.name for file in cabinet.files]
            for file in cabinet.files:
                if file.data and len(file.data) <= FLAG_SEARCH_LIMIT:
                    report.flags += [hit.text for hit in find_flags(file.data, flagset)]
        elif pretty.startswith("Binary.") or name.startswith("Binary"):
            report.binaries.append((pretty, len(payload)))

    _add_notes(report, container, pool_data, flagset)
    return report


def _add_notes(
    report: MsiReport, container: cfb.CfbFile, pool_data: bytes, flagset: FlagSet | None
) -> None:
    """The indicators, the flags, and what this reader deliberately does not do."""
    haystack = "\n".join(report.strings)
    # An installer that hides its real command line does it the same way a
    # dropper does: `powershell -enc <base64 of UTF-16LE>`. Decode it here so the
    # user does not have to notice it and paste it somewhere else.
    for text in report.strings:
        script = find_encoded_command(text.encode("utf-8", "replace"))
        if script is not None:
            decoded = script.decode("utf-8", "replace")
            if decoded not in report.commands:
                report.commands.append(decoded)
                haystack += "\n" + decoded
    for needle, why in INTERESTING:
        if needle.lower() in haystack.lower():
            report.indicators.append(f"{needle} - {why}")

    found = list(report.flags)
    found += [hit.text for hit in find_flags(haystack.encode("utf-8", "replace"), flagset)]
    if not report.strings and pool_data:
        found += [hit.text for hit in find_flags(pool_data, flagset)]
    seen: list[str] = []
    for text in found:
        if text not in seen:
            seen.append(text)
    report.flags = seen

    if report.commands:
        report.notes.append(
            f"{len(report.commands)} PowerShell -EncodedCommand payload(s) decoded out of "
            "the strings: they are printed in full below"
        )
    if "CustomAction" in report.streams:
        report.notes.append(
            "there is a CustomAction table: this installer runs something of its own. "
            "The command lines are among the strings below; `msidump -t <file>` prints "
            "the table itself"
        )
    if report.cabinets:
        report.notes.append(
            f"{len(report.cabinets)} embedded cabinet(s), {len(report.cabinet_files)} file(s) "
            "inside: ctfc decoded them (--extract writes them out)"
        )
    elif "Media" in report.streams:
        report.notes.append(
            "the Media table says where the payload is; no cabinet is embedded in this "
            "file, so it ships beside the .msi"
        )
    report.notes.append(
        "row-level table decoding is not implemented: the string pool holds the same "
        "paths, URLs and command lines, and `msidump` / `7z l` cover the rest"
    )
