"""The Windows artefacts that answer "what was run, and when".

Four files turn up in every Windows forensics challenge, and they are all small,
documented binary structures. One command reads whichever one you hand it:

- **`.lnk` shortcuts** (`core/lnk.py`): where a file was, on which disk, on which
  machine - and, when the shortcut is really a dropper, what it runs.
- **Prefetch** (`C:\\Windows\\Prefetch\\*.pf`): Windows records, for every
  program started, **when it ran, how many times, and every file it loaded in
  its first ten seconds**. That last list is the reason prefetch wins
  challenges: it names the DLLs, the data files and often the *payload* a
  program touched, long after all of them have been deleted.
- **Jump lists** (`*.automaticDestinations-ms`): a compound file holding one
  embedded `.lnk` per recently-opened document, plus a `DestList` stream
  ordering them. It is the recent-files list, kept per application, and it
  survives clearing the Recent folder.
- **AmCache** (`Amcache.hve`) is a registry hive, so `ctfc hive` already reads
  it; this module recognises it and says so rather than duplicating the reader.

Deliberate limit, stated here and in the report: a modern prefetch file is
**MAM-compressed** (LZXPRESS Huffman) and this module does not decompress it. It
says so and names the tool - that is the honest answer until there is something
real to verify a decompressor against, and `libscca` is installed on this
machine anyway.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core import cfb, lnk
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.timestamps import from_filetime

PREFETCH_SIGNATURE = b"SCCA"
MAM_SIGNATURE = b"MAM\x04"
HIVE_SIGNATURE = b"regf"
# Prefetch format versions, by the number in the first four bytes.
PREFETCH_VERSIONS = {
    17: "Windows XP / 2003",
    23: "Windows Vista / 7",
    26: "Windows 8.1",
    30: "Windows 10 / 11",
    31: "Windows 11",
}
# Where each field lives, per version. The file header is 84 bytes (0x54) and
# the "file information" block follows it; its first nine fields are identical in
# every version, which is why the offsets below only differ for the run count and
# the run times. Those two were not taken from a document but *measured* against
# libscca: a marker was written into every four-byte slot of the block in turn
# and the one libscca then reported as the run count is the offset below. That is
# why Windows 7's run count is at 0x98 and Windows 8.1's at 0xd0.
#   (metrics offset, metrics count, filenames offset, filenames size,
#    volumes offset, run count, run times, how many run times)
LAYOUTS = {
    17: (0x54, 0x58, 0x64, 0x68, 0x6C, 0x90, 0x78, 1),
    23: (0x54, 0x58, 0x64, 0x68, 0x6C, 0x98, 0x80, 1),
    26: (0x54, 0x58, 0x64, 0x68, 0x6C, 0xD0, 0x80, 8),
    30: (0x54, 0x58, 0x64, 0x68, 0x6C, 0xD0, 0x80, 8),
    31: (0x54, 0x58, 0x64, 0x68, 0x6C, 0xD0, 0x80, 8),
}
MAX_FILENAMES = 4000
# Extensions worth pointing at in a prefetch file's loaded-file list: the ones
# that are not just another system DLL.
INTERESTING_EXTENSIONS = (
    ".exe",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".jse",
    ".hta",
    ".lnk",
    ".zip",
    ".rar",
    ".7z",
    ".doc",
    ".docm",
    ".xls",
    ".xlsm",
    ".pdf",
    ".txt",
    ".csv",
    ".key",
    ".pem",
    ".kdbx",
)
# Jump list streams: DestList orders the entries, the numbered ones are shortcuts.
DESTLIST = "destlist"


class ArtifactError(FormatError):
    """The file is not a Windows artefact this module reads."""


@dataclass
class PrefetchRun:
    """One recorded start of the program."""

    when: str


@dataclass
class PrefetchReport:
    """What Windows recorded about one executable."""

    version: int = 0
    version_name: str = ""
    name: str = ""  # the executable's name, as recorded
    hash_value: str = ""  # the path hash in the file name
    run_count: int = 0
    runs: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    interesting: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "version_name": self.version_name,
            "name": self.name,
            "hash": self.hash_value,
            "run_count": self.run_count,
            "runs": list(self.runs),
            "files": list(self.files),
            "volumes": list(self.volumes),
            "interesting": list(self.interesting),
            "notes": list(self.notes),
        }


@dataclass
class JumpListEntry:
    """One recently-opened document, as a jump list records it."""

    stream: str
    path: str = ""
    arguments: str = ""
    machine_id: str = ""
    accessed: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class JumpListReport:
    """A per-application recent-files list."""

    entries: list[JumpListEntry] = field(default_factory=list)
    order: list[str] = field(default_factory=list)  # from the DestList stream
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "entries": [
                {
                    "stream": entry.stream,
                    "path": entry.path,
                    "arguments": entry.arguments,
                    "machine_id": entry.machine_id,
                    "accessed": entry.accessed,
                    "notes": list(entry.notes),
                }
                for entry in self.entries
            ],
            "order": list(self.order),
            "notes": list(self.notes),
        }


@dataclass
class ArtifactReport:
    """Whichever artefact it was, with the right reader's report inside."""

    kind: str = ""  # "lnk" | "prefetch" | "jumplist" | "hive"
    lnk: lnk.LnkReport | None = None
    prefetch: PrefetchReport | None = None
    jumplist: JumpListReport | None = None
    flags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "lnk": None if self.lnk is None else self.lnk.to_dict(),
            "prefetch": None if self.prefetch is None else self.prefetch.to_dict(),
            "jumplist": None if self.jumplist is None else self.jumplist.to_dict(),
            "flags": list(self.flags),
            "notes": list(self.notes),
            "commands": list(self.commands),
        }


def sniff(data: bytes) -> str:
    """Which artefact this is: "lnk", "prefetch", "jumplist", "hive", or ""."""
    if lnk.is_lnk(data):
        return "lnk"
    if data[:4] == MAM_SIGNATURE or data[4:8] == PREFETCH_SIGNATURE:
        return "prefetch"
    if data[:4] == HIVE_SIGNATURE:
        return "hive"
    if cfb.is_cfb(data):
        try:
            container = cfb.read(data)
        except cfb.CfbError:
            return ""
        names = {name.rsplit("/", 1)[-1].lower() for name in container.streams}
        if DESTLIST in names or any(_is_jumplist_stream(name) for name in names):
            return "jumplist"
        return ""
    # A customDestinations-ms file is simply shortcuts end to end.
    if data[:4] == b"\x02\x00\x00\x00" and lnk.CLSID in data[:512]:
        return "jumplist"
    return ""


def _is_jumplist_stream(name: str) -> bool:
    """Jump list entry streams are named with hex digits, like `1`, `a`, `2f`."""
    return 1 <= len(name) <= 8 and all(char in "0123456789abcdef" for char in name)


def analyse(data: bytes, name: str = "", flagset: FlagSet | None = None) -> ArtifactReport:
    """Read whichever Windows artefact this is."""
    kind = sniff(data)
    report = ArtifactReport(kind=kind)
    if kind == "lnk":
        report.lnk = lnk.analyse(data)
        report.commands.append("ctfc lens <the command line>   # if it runs something")
    elif kind == "prefetch":
        report.prefetch = read_prefetch(data, name)
    elif kind == "jumplist":
        report.jumplist = read_jumplist(data)
    elif kind == "hive":
        report.notes.append(
            "this is a registry hive, which `ctfc hive <file>` reads. An Amcache.hve "
            "holds one key per executable ever present, with its SHA-1 and its size, "
            "under Root\\InventoryApplicationFile"
        )
        report.commands.append("ctfc hive <file>")
    else:
        raise ArtifactError(
            "not a Windows artefact this reads: expected a .lnk shortcut, a .pf "
            "prefetch file, a jump list (*.automaticDestinations-ms) or a registry "
            "hive. `ctfc detect <file>` says what it is instead"
        )
    _find_flags(report, flagset)
    return report


def _find_flags(report: ArtifactReport, flagset: FlagSet | None) -> None:
    """Flags in everything that was read, which for a .lnk means the decoded command.

    A path or a command line is where a flag hides in these files - an argument
    with a base64 payload most of all, because the flag only appears once that
    payload is decoded.
    """
    texts: list[str] = []
    if report.lnk is not None:
        texts += [
            report.lnk.command,
            report.lnk.description,
            report.lnk.icon_location,
            *report.lnk.decoded_commands,
            *report.lnk.id_list_names,
        ]
    if report.prefetch is not None:
        texts += [report.prefetch.name, *report.prefetch.files, *report.prefetch.volumes]
    if report.jumplist is not None:
        for entry in report.jumplist.entries:
            texts += [entry.path, entry.arguments]
        texts += report.jumplist.order
    found: list[str] = []
    for text in texts:
        if text:
            found += [hit.text for hit in find_flags(text.encode("utf-8", "replace"), flagset)]
    seen: list[str] = []
    for text in found:
        if text not in seen:
            seen.append(text)
    report.flags = seen


# ---------------------------------------------------------------------------
# Prefetch
# ---------------------------------------------------------------------------


def read_prefetch(data: bytes, name: str = "") -> PrefetchReport:
    """Read a `.pf` file: when the program ran, and what it loaded."""
    report = PrefetchReport()
    if data[:4] == MAM_SIGNATURE:
        size = int.from_bytes(data[4:8], "little")
        report.notes.append(
            f"this prefetch file is MAM-compressed (LZXPRESS Huffman, {size} bytes "
            'uncompressed), which ctfc does not decode. `python3 -c "import pyscca; '
            "f=pyscca.file(); f.open('<file>'); print(f.executable_filename)\"` reads it, "
            "and so does PECmd on Windows"
        )
        report.version_name = "Windows 10 / 11 (compressed)"
        return report
    if data[4:8] != PREFETCH_SIGNATURE:
        raise ArtifactError(
            "not a prefetch file: neither the SCCA signature at offset 4 nor the MAM "
            "compression header is there"
        )
    report.version = int.from_bytes(data[0:4], "little")
    report.version_name = PREFETCH_VERSIONS.get(report.version, f"version {report.version}")
    layout = LAYOUTS.get(report.version)
    if layout is None:
        raise ArtifactError(
            f"prefetch version {report.version} is not one this reads "
            f"({', '.join(str(key) for key in sorted(LAYOUTS))})"
        )
    if len(data) < 0x100:
        raise ArtifactError(f"truncated: {len(data)} bytes, the header alone is 84 + 136")

    # The header holds the executable's name as UTF-16 and the hash that is also
    # in the file name, so a renamed .pf still says what it was.
    report.name = data[0x10:0x4C].decode("utf-16-le", "replace").split("\x00")[0]
    report.hash_value = f"{int.from_bytes(data[0x4C:0x50], 'little'):08X}"

    (
        _metrics_offset,
        _metrics_count,
        filenames_offset_at,
        filenames_size_at,
        volumes_offset_at,
        run_count_at,
        run_times_at,
        run_times_count,
    ) = layout
    report.run_count = int.from_bytes(data[run_count_at : run_count_at + 4], "little")
    for index in range(run_times_count):
        at = run_times_at + index * 8
        if at + 8 > len(data):
            break
        when = from_filetime(int.from_bytes(data[at : at + 8], "little"))
        if when:
            report.runs.append(when)

    filenames_offset = int.from_bytes(data[filenames_offset_at : filenames_offset_at + 4], "little")
    filenames_size = int.from_bytes(data[filenames_size_at : filenames_size_at + 4], "little")
    if 0 < filenames_offset < len(data) and filenames_size:
        block = data[filenames_offset : filenames_offset + filenames_size]
        for piece in block.decode("utf-16-le", "replace").split("\x00"):
            if len(piece) > 3:
                report.files.append(piece)
            if len(report.files) >= MAX_FILENAMES:
                report.notes.append(f"only the first {MAX_FILENAMES} file names are listed")
                break

    volumes_offset = int.from_bytes(data[volumes_offset_at : volumes_offset_at + 4], "little")
    if 0 < volumes_offset + 0x10 <= len(data):
        path_offset = int.from_bytes(data[volumes_offset : volumes_offset + 4], "little")
        path_length = int.from_bytes(data[volumes_offset + 4 : volumes_offset + 8], "little")
        serial = int.from_bytes(data[volumes_offset + 16 : volumes_offset + 20], "little")
        start = volumes_offset + path_offset
        if 0 < path_length < 1000 and start + path_length * 2 <= len(data):
            device = data[start : start + path_length * 2].decode("utf-16-le", "replace")
            report.volumes.append(f"{device.rstrip(chr(0))} (serial {serial:08x})")

    _prefetch_notes(report)
    return report


def _prefetch_notes(report: PrefetchReport) -> None:
    """Point at the files in the list that are not just another system DLL."""
    for path in report.files:
        lowered = path.lower()
        if lowered.endswith(INTERESTING_EXTENSIONS) and "\\windows\\" not in lowered:
            report.interesting.append(path)
    if report.runs:
        report.notes.append(
            f"{report.name or 'this program'} ran {report.run_count} time(s); the last "
            f"{len(report.runs)} start(s) are listed, most recent first"
        )
    if report.interesting:
        report.notes.append(
            f"{len(report.interesting)} of the {len(report.files)} loaded files are not "
            "system DLLs: those are the ones the program actually worked on, and they "
            "are listed even if the files are gone"
        )
    if not report.files:
        report.notes.append(
            "no file name list: either the file is truncated, or its version stores the "
            "list somewhere this reader does not look"
        )


# ---------------------------------------------------------------------------
# Jump lists
# ---------------------------------------------------------------------------


def read_jumplist(data: bytes) -> JumpListReport:
    """Read a jump list: one embedded shortcut per recently-opened document."""
    report = JumpListReport()
    if cfb.is_cfb(data):
        try:
            container = cfb.read(data)
        except cfb.CfbError as exc:
            raise ArtifactError(f"not a readable jump list: {exc}") from exc
        for path, payload in sorted(container.streams.items()):
            leaf = path.rsplit("/", 1)[-1]
            if leaf.lower() == DESTLIST:
                report.order = _destlist_names(payload)
                continue
            entry = JumpListEntry(stream=leaf)
            if lnk.is_lnk(payload):
                _fill_from_lnk(entry, payload)
            else:
                entry.notes.append("not a shortcut: the stream holds something else")
            report.entries.append(entry)
        report.notes.append(
            "an automaticDestinations-ms jump list: each numbered stream is a complete "
            ".lnk, so every entry carries its own path, volume and machine id"
        )
    else:
        # customDestinations-ms: shortcuts end to end, with a small header each.
        position = 0
        while True:
            found = data.find(lnk.CLSID, position)
            if found < 4:
                break
            start = found - 4
            entry = JumpListEntry(stream=f"offset {start}")
            _fill_from_lnk(entry, data[start:])
            report.entries.append(entry)
            position = found + 16
        if not report.entries:
            raise ArtifactError("no shortcut found in this file: it is not a jump list")
        report.notes.append(
            "a customDestinations-ms jump list: the shortcuts are simply concatenated, "
            "so they are read where they are found"
        )
    if report.order:
        report.notes.append(
            "the DestList stream orders the entries by how recently they were used; "
            "the paths it names are listed above"
        )
    return report


def _fill_from_lnk(entry: JumpListEntry, payload: bytes) -> None:
    """Read one embedded shortcut into a jump list entry."""
    try:
        inner = lnk.analyse(payload)
    except lnk.LnkError as exc:
        entry.notes.append(f"the embedded shortcut does not read: {exc}")
        return
    entry.path = inner.target
    entry.arguments = inner.arguments
    entry.machine_id = inner.machine_id
    entry.accessed = inner.accessed or inner.written
    entry.notes += inner.indicators


def _destlist_names(payload: bytes) -> list[str]:
    """The paths named in a DestList stream.

    The stream is a header plus one fixed-size entry per destination, and each
    entry ends with a UTF-16 path. The entry size changed between Windows
    versions, so rather than hard-code a stride the UTF-16 runs are lifted out -
    which gives the same answer for every version, in the stored order.
    """
    names: list[str] = []
    text = payload.decode("utf-16-le", "replace")
    current: list[str] = []
    for char in text:
        if char.isprintable() and char != "\x00":
            current.append(char)
            continue
        if len(current) >= 4:
            candidate = "".join(current)
            if candidate not in names and any(ch.isalnum() for ch in candidate):
                names.append(candidate)
        current = []
    if len(current) >= 4:
        names.append("".join(current))
    return names[:200]
