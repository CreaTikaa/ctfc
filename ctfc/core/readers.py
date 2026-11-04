"""Which reader claims a file, and what that reader hands back that is itself a file.

Two questions live here, and only these two:

1. **"whose file is this?"** - the cheap sniff test for each format reader, in a
   fixed order, because several formats share a container (a `.msg`, a `.msi`, a
   jump list and a Word document are all compound files; a `.jar`, an `.apk` and
   a `.docx` are all ZIPs).
2. **"what came out of it that is itself worth reading?"** - the members of an
   archive, a PDF's embedded files, a mail's attachments, a capture's objects,
   the overlay of an executable, the layers of a Docker image.

Question 1 is what the browser's single Files tab asks (`ctfc/web/formats.py`
imports this table rather than keeping its own copy). Question 2 is what
`ctfc solve` asks: it is the whole reason a container can be followed to the
bottom without a human deciding, at each step, which command comes next.

Nothing here parses anything: every opener calls the reader that already exists
and copies out what it found. An opener must never raise - a file that fails to
parse is a note, not a crash - so each one is wrapped by `open_with()`.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field

from ctfc.core import (
    archive,
    cab,
    cfb,
    evtx,
    executable,
    hive,
    msg,
    msi,
    office,
    pcap,
    pdf,
    pe,
    repair,
    sqlitedb,
    stego,
    winartifact,
    zipinfo,
)
from ctfc.core.budget import Budget
from ctfc.core.flags import FlagSet

# A piece smaller than this holds nothing anyone wants; a piece bigger than this
# is a disk image, not a payload, and following it is a different job (`ctfc scan`).
CHILD_MIN_SIZE = 4
CHILD_MAX_SIZE = 8 * 1024 * 1024
# How many children one reader may hand over. A 2000-file tar would otherwise
# turn one command into an afternoon.
CHILD_LIMIT = 120


@dataclass(frozen=True)
class Child:
    """One piece a reader produced: bytes, a name, and where it came from."""

    name: str
    origin: str  # "archive member", "PDF embedded file", "overlay"...
    data: bytes
    # Set only when this one piece is written to disk by a different command
    # than the reader's own --extract (a macro module, say). "" = the reader's.
    extract: str = ""


@dataclass
class Opened:
    """What one reader made of one file."""

    reader: str = ""
    label: str = ""
    command: str = ""  # the terminal command that shows this, with {file}
    detail: str = ""  # one line: the format, the entry count...
    children: list[Child] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # flags the reader found itself
    notes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)  # what the reader suggests next
    # How to put the children on disk, so that a report can print a command the
    # user can actually run. "" when the reader has no --extract.
    extract: str = ""
    error: str = ""


def _keep(children: list[Child]) -> list[Child]:
    """Drop the pieces that are too small, too big, or empty, and cap the count."""
    kept = [
        child
        for child in children
        if child.data and CHILD_MIN_SIZE <= len(child.data) <= CHILD_MAX_SIZE
    ]
    return kept[:CHILD_LIMIT]


def _zip_members(data: bytes, origin: str) -> list[Child]:
    """Every member a plain `zipfile` can read (so: not the encrypted ones)."""
    children: list[Child] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.flag_bits & 0x0001:
                    continue
                if info.file_size > CHILD_MAX_SIZE:
                    continue
                try:
                    children.append(Child(info.filename, origin, zf.read(info)))
                except Exception:  # noqa: BLE001 - one bad member must not lose the rest
                    continue
    except Exception:  # noqa: BLE001 - a damaged ZIP is a note, not a crash
        return children
    return children


# ---------------------------------------------------------------------------
# One opener per reader
# ---------------------------------------------------------------------------


def _open_archive(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = archive.analyse(data, path, flagset=flagset)
    children = [
        Child(entry.name, f"{report.format} member", entry.data)
        for entry in report.entries
        if entry.data
    ]
    if report.trailing:
        children.append(Child("trailing.bin", "appended after the archive", report.trailing))
    if report.docker is not None:
        # A layer is itself a tar, so handing the layer over means the tar reader
        # reads it next - no second implementation of "look inside a layer".
        for layer in report.docker.layers:
            if layer.data:
                children.append(Child(f"layer{layer.index}.tar", "Docker layer", layer.data))
        for deleted in report.docker.deleted:
            if deleted.content:
                children.append(
                    Child(deleted.name, "deleted by a later layer", deleted.content),
                )
    return Opened(
        detail=f"{report.format}, {len(report.entries)} entr(ies)",
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        commands=list(report.commands),
        extract="ctfc archive {file} --extract {dir}",
    )


def _open_zip(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = zipinfo.analyse(data, path)
    children = _zip_members(data, "ZIP member")
    for entry in report.entries:
        if entry.recovered:
            children.append(Child(entry.name, "recovered from the CRC32", entry.recovered))
    encrypted = [entry.name for entry in report.entries if entry.encrypted]
    notes = list(report.notes)
    if encrypted:
        notes.append(
            f"{len(encrypted)} encrypted entr(ies): a password is needed, "
            "and the commands below say which tool breaks this flavour"
        )
    return Opened(
        detail=f"ZIP, {len(report.entries)} entr(ies)",
        children=_keep(children),
        notes=notes,
        commands=list(report.commands),
        # -j flattens the paths, which is what makes the file name printed next
        # to a member the name it actually lands under.
        extract="unzip -j -d {dir} {file}",
    )


def _open_pdf(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = pdf.analyse(data, flagset)
    children = [Child(name, "PDF embedded file", blob) for name, blob in report.embedded]
    for number, code in report.javascript:
        children.append(Child(f"object{number}.js", "PDF JavaScript", code.encode()))
    for obj in report.objects:
        if obj.stream and obj.filters:
            children.append(
                Child(f"object{obj.number}.stream", "decoded PDF stream", obj.stream),
            )
    return Opened(
        detail=f"PDF {report.version}, {len(report.objects)} objects",
        children=_keep(children),
        flags=[text for _number, text in report.flags],
        notes=list(report.indicators) + list(report.notes),
        extract="ctfc pdf {file} --extract {dir}",
    )


def _open_office(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = office.analyse(data)
    children = [
        Child(item.name or item.stream, "embedded object", item.data) for item in report.objects
    ]
    for macro in report.macros:
        # One piece per module, named the way `--save-macros` names it on disk,
        # so the command printed next to it is the command that produces it.
        name = re.sub(r"[^A-Za-z0-9._-]", "_", macro.module) + ".vbs"
        children.append(
            Child(
                name,
                "VBA macro module",
                macro.code.encode(),
                extract="ctfc office {file} --save-macros {dir}",
            )
        )
    if report.container == "ooxml":
        children += _zip_members(data, "document part")
    return Opened(
        detail=f"{report.container}, {len(report.macros)} macro module(s)",
        children=_keep(children),
        notes=list(report.indicators) + list(report.notes),
        extract="ctfc office {file} --extract {dir}",
    )


def _open_msg(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = msg.analyse(data, flagset)
    children = [
        Child(item.name or "attachment.bin", "mail attachment", item.data)
        for item in report.attachments
    ]
    body = report.body or report.html_body
    if body:
        children.append(Child("body.txt", "mail body", body.encode()))
    return Opened(
        detail=f"Outlook message, {len(report.attachments)} attachment(s)",
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        extract="ctfc msg {file} --extract {dir}",
    )


def _open_msi(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = msi.analyse(data, flagset)
    children: list[Child] = []
    try:
        container = cfb.read(data)
    except Exception:  # noqa: BLE001 - the report above is still worth printing
        container = None
    if container is not None:
        for name, payload in container.streams.items():
            pretty = msi.decode_name(name)
            if payload[:4] == cab.SIGNATURE:
                try:
                    cabinet = cab.extract(payload)
                except Exception:  # noqa: BLE001
                    continue
                for file in cabinet.files:
                    if file.data:
                        children.append(Child(file.name, "file in the embedded cabinet", file.data))
            elif pretty.startswith("Binary"):
                children.append(Child(pretty, "MSI Binary stream", payload))
    return Opened(
        detail=f"MSI, {len(report.streams)} streams",
        children=_keep(children),
        notes=list(report.notes),
        extract="ctfc msi {file} --extract {dir}",
    )


def _open_pcap(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = pcap.analyse(data, path)
    children = [Child(item.name, f"capture: {item.kind}", item.data) for item in report.objects]
    return Opened(
        detail=f"{report.format}, {report.packets} packets, {len(report.objects)} object(s)",
        children=_keep(children),
        notes=list(report.notes),
        extract="ctfc pcap {file} --extract {dir}",
    )


def _open_stego(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    budget = Budget(max_attempts=4000, max_seconds=5)
    report = stego.analyse(data, flagset, budget, top_n=3)
    children = [
        Child(f"lsb{index}.bin", f"LSB: {candidate.label}", candidate.data)
        for index, candidate in enumerate(report.candidates)
    ]
    for keyword, text in report.texts:
        children.append(Child(f"{keyword}.txt", "image text chunk", text.encode()))
    return Opened(
        detail=f"{report.kind} {report.width}x{report.height}",
        children=_keep(children),
        notes=list(report.notes),
    )


def _open_pe(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = pe.analyse(data, flagset)
    children: list[Child] = []
    if report.overlay:
        children.append(Child("overlay.bin", "appended after the last section", report.overlay))
    if report.dotnet_literals:
        children.append(
            Child(
                "dotnet_strings.txt",
                ".NET string literals",
                "\n".join(report.dotnet_literals).encode(),
            )
        )
    return Opened(
        detail=f"PE {report.bits}-bit {report.machine}" + (", .NET" if report.is_dotnet else ""),
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        extract="ctfc pe {file} --extract {dir}",
    )


def _open_exe(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = executable.analyse(data, flagset)
    children: list[Child] = []
    if report.elf is not None and report.elf.overlay_bytes:
        children.append(
            Child("overlay.bin", "appended after the last ELF section", report.elf.overlay_bytes)
        )
    if report.kind in ("jar", "dex") and data[:4] == b"PK\x03\x04":
        children += _zip_members(data, f"{report.kind} entry")
    return Opened(
        detail=report.kind,
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        commands=list(report.commands),
        extract="ctfc exe {file} --extract {dir}",
    )


def _open_winartifact(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = winartifact.analyse(data, "", flagset)
    return Opened(
        detail=report.kind,
        flags=list(report.flags),
        notes=list(report.notes),
        commands=list(report.commands),
    )


def _open_evtx(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = evtx.analyse(data, flagset)
    children: list[Child] = []
    flags: list[str] = []
    for record in report.records:
        flags += [hit for hit in record.flags if hit not in flags]
        if record.command:
            # A PowerShell -EncodedCommand the reader already un-base64'd: that
            # decoded script is exactly the next thing to look at.
            children.append(
                Child(f"record{record.number}.ps1", "decoded command", record.command.encode())
            )
    return Opened(
        detail=f"{len(report.records)} record(s) read",
        children=_keep(children),
        flags=flags,
        notes=list(report.notes),
    )


def _open_hive(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = hive.analyse(data)
    children = [
        Child(f"{path}.txt", f"registry value ({why})", "\n".join(values).encode())
        for path, why, values in report.found
    ]
    return Opened(
        detail=f"{report.kind} hive, {report.keys} keys",
        children=_keep(children),
        notes=list(report.notes),
        commands=list(report.commands),
    )


def _open_sqlite(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = sqlitedb.analyse(data, None, flagset)
    rows = [
        " | ".join("NULL" if value is None else str(value) for value in row.values)
        for row in report.deleted
    ]
    children = (
        [Child("deleted_rows.txt", "rows recovered from free space", "\n".join(rows).encode())]
        if rows
        else []
    )
    return Opened(
        detail=f"{len(report.tables)} table(s), {len(report.deleted)} recovered row(s)",
        children=_keep(children),
        notes=list(report.notes),
    )


def _open_repair(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = repair.repair(data)
    # The index starts at 1 because that is how `ctfc repair --out` names the
    # files it writes, and the point is that the printed command is runnable.
    children = [
        Child(item.filename(index), f"carved at {item.offset:#x}: {item.name}", item.data)
        for index, item in enumerate(report.carved, start=1)
    ]
    if report.fixes:
        children.append(Child("repaired.bin", "the file with its header fixed", report.repaired))
    return Opened(
        detail=f"{len(report.fixes)} fix(es), {len(report.carved)} carved",
        children=_keep(children),
        notes=list(report.notes),
        extract="ctfc repair {file} --out {dir}",
    )


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


def office_sniff(data: bytes) -> bool:
    """An OLE2 document or an OOXML one - but not a .msg, an .msi or a jump list.

    Four formats share the compound-file container and two share the ZIP one, so
    this test, not the order of the table, is what keeps them apart: `office`
    claims a compound file the other three readers do not, and a ZIP only when
    it holds the parts of an Office document.
    """
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return (
            not msg.looks_like_msg(data)
            and not msi.looks_like_msi(data)
            and winartifact.sniff(data) != "jumplist"
        )
    if data[:4] == b"PK\x03\x04":
        # An OOXML file names its parts: word/, xl/ or ppt/. A .jar or an .apk
        # does not, and goes to `ctfc exe` or `ctfc zip`.
        head = data[:4096]
        return any(part in head for part in (b"word/", b"xl/", b"ppt/"))
    return False


@dataclass(frozen=True)
class Reader:
    """One format reader: how to recognise its files, and how to open them."""

    name: str  # the id the browser and `ctfc solve` use
    label: str  # what a human sees
    command: str  # the terminal command that does the same thing
    sniff: Callable[[bytes], bool]  # cheap "is this mine?"
    open: Callable[[bytes, FlagSet | None, str], Opened]


READERS: tuple[Reader, ...] = (
    Reader(
        "archive",
        "archive (tar, 7z, RAR, cabinet, Docker image)",
        "ctfc archive",
        lambda data: bool(archive.sniff(data)),
        _open_archive,
    ),
    Reader(
        "office",
        "Office document with macros (.doc, .docm)",
        "ctfc office",
        office_sniff,
        _open_office,
    ),
    Reader("msg", "Outlook message (.msg)", "ctfc msg", msg.looks_like_msg, _open_msg),
    Reader("msi", "Windows Installer package (.msi)", "ctfc msi", msi.looks_like_msi, _open_msi),
    Reader("pdf", "PDF", "ctfc pdf", lambda data: data[:1024].find(b"%PDF-") >= 0, _open_pdf),
    Reader(
        "stego",
        "image, for a message in its low bits",
        "ctfc stego",
        lambda data: data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"BM",
        _open_stego,
    ),
    Reader("pe", "Windows executable (PE)", "ctfc pe", lambda data: data[:2] == b"MZ", _open_pe),
    Reader(
        "exe",
        "ELF, Java class/JAR, Android DEX",
        "ctfc exe",
        lambda data: executable.sniff(data) in ("elf", "class", "jar", "dex"),
        _open_exe,
    ),
    Reader(
        "winartifact",
        "Windows artefact (.lnk, prefetch, jump list)",
        "ctfc winartifact",
        lambda data: winartifact.sniff(data) in ("lnk", "prefetch", "jumplist"),
        _open_winartifact,
    ),
    Reader(
        "evtx",
        "Windows event log (.evtx)",
        "ctfc evtx",
        lambda data: data[:8] == b"ElfFile\x00",
        _open_evtx,
    ),
    Reader(
        "hive",
        "registry hive (SAM, SYSTEM, NTUSER.DAT, Amcache)",
        "ctfc hive",
        lambda data: data[:4] == b"regf",
        _open_hive,
    ),
    Reader(
        "sqlite",
        "SQLite database",
        "ctfc sqlite",
        lambda data: data[:15] == b"SQLite format 3",
        _open_sqlite,
    ),
    Reader(
        "pcap",
        "capture (pcap, pcapng)",
        "ctfc pcap",
        lambda data: (
            data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")
            or data[:4] == b"\x4d\x3c\xb2\xa1"
        ),
        _open_pcap,
    ),
    # Not sniffed: by definition you reach for it when the file is broken.
    Reader(
        "repair",
        "repair a broken file (magic, trailing data, pasted header)",
        "ctfc repair",
        lambda data: False,
        _open_repair,
    ),
    Reader(
        "zip",
        "ZIP archive (also .docx, .jar, .apk)",
        "ctfc zip",
        lambda data: data[:4] in (b"PK\x03\x04", b"PK\x01\x02"),
        _open_zip,
    ),
)
READERS_BY_NAME = {reader.name: reader for reader in READERS}


def sniff(data: bytes) -> str:
    """Which reader claims these bytes, or "" when none does."""
    for reader in READERS:
        try:
            if reader.sniff(data):
                return reader.name
        except Exception:  # noqa: BLE001 - a sniff must never decide the request
            continue
    return ""


def open_with(
    name: str, data: bytes, flagset: FlagSet | None = None, path: str = "{file}"
) -> Opened:
    """Run one reader and copy out what it found. Never raises: errors are reported.

    `path` is only used for display: the readers that print a next command
    (`bkcrack this.zip`, `zip2john that.zip`) need the name of the real file.
    """
    reader = READERS_BY_NAME.get(name)
    if reader is None:
        return Opened(error=f"unknown reader {name!r}")
    try:
        opened = reader.open(data, flagset, path)
    except Exception as exc:  # noqa: BLE001 - a file that will not parse is a note
        opened = Opened(error=f"{type(exc).__name__}: {exc}")
    opened.reader = reader.name
    opened.label = reader.label
    opened.command = reader.command + " {file}"
    return opened
