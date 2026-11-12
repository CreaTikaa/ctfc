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

import bz2
import io
import lzma
import re
import zipfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC

from ctfc.core import (
    archive,
    audio,
    cab,
    cfb,
    disk,
    evtx,
    executable,
    exif,
    hive,
    iso,
    mail,
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
from ctfc.core.flags import FlagSet, find_flags

# A piece smaller than this holds nothing anyone wants. A piece bigger than the
# max is not followed - but it is SAID (a note), never dropped in silence: a 22 MB
# capture inside a ZIP is a normal challenge (HTB Fake Boost), and the old 8 MB
# cap made `solve` answer "nothing came out" about it.
CHILD_MIN_SIZE = 4
CHILD_MAX_SIZE = 256 * 1024 * 1024
# A decompressed stream may be a whole disk image; only a bomb is refused.
DECOMPRESS_MAX = 512 * 1024 * 1024
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


@dataclass(frozen=True)
class Event:
    """One timestamp a reader found, already read as a date.

    `when` is always "YYYY-MM-DD HH:MM:SS UTC", which is both what a human
    wants and a string that sorts chronologically - so `ctfc timeline` can
    merge events from six formats without reparsing anything.
    """

    when: str
    kind: str  # "tar mtime", "prefetch run", "shortcut written"...
    what: str  # the member, the program, the record


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
    events: list[Event] = field(default_factory=list)  # the timestamps it carries
    # How to put the children on disk, so that a report can print a command the
    # user can actually run. "" when the reader has no --extract.
    extract: str = ""
    error: str = ""


def _iso(value: str) -> str:
    """Any date string a format wrote, as "YYYY-MM-DD HH:MM:SS UTC", or "".

    Docker writes RFC 3339, a mail header writes RFC 2822; both are turned into
    the one shape every event uses so that sorting is a string comparison.
    """
    text = value.strip()
    if not text:
        return ""
    from datetime import datetime
    from email.utils import parsedate_to_datetime

    for parse in (
        lambda item: datetime.fromisoformat(item.replace("Z", "+00:00")),
        parsedate_to_datetime,
    ):
        try:
            when = parse(text)
        except (ValueError, TypeError, IndexError):
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        return when.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return ""


def _keep(children: list[Child]) -> list[Child]:
    """Drop the pieces that are too small, too big, or empty, and cap the count."""
    # The count is capped in `open_with` (`_likeliest`), where it can be said.
    return [child for child in children if child.data and CHILD_MIN_SIZE <= len(child.data)]


# Names that say "look at me", then the files a person writes, then containers.
# Images are NOT promoted: an APK carries hundreds of icons.
NAME_RANKS = (
    re.compile(r"flag|secret|key|pass|hidden|cred|token|note|readme|backup", re.IGNORECASE),
    re.compile(
        r"\.(txt|md|json|csv|log|ps1|py|js|sh|bat|vbs|php|conf|cfg|ini|sql|eml)$", re.IGNORECASE
    ),
    re.compile(r"\.(zip|7z|rar|gz|xz|bz2|tar|pdf|docx?|xlsx?|pcapng|pcap)$", re.IGNORECASE),
)


def _rank(child: Child) -> int:
    """0 for the likeliest piece, len(NAME_RANKS) for an ordinary one."""
    for rank, pattern in enumerate(NAME_RANKS):
        if pattern.search(child.name):
            return rank
    return len(NAME_RANKS)


def _likeliest(children: list[Child]) -> tuple[list[Child], list[str]]:
    """At most CHILD_LIMIT pieces, the likeliest first - and a note for the rest.

    Under the limit nothing moves: the readers' own order means something (a
    capture's mail bodies before its UDP noise). Over it, an APK's 772 members
    used to be cut at 120 in ZIP order, and `res/color/flag.txt` (picoCTF Mob
    psycho) never got looked at. So the names that say "flag", "secret", ".txt"
    go first, then the rest in the reader's order.
    """
    if len(children) <= CHILD_LIMIT:
        return children, []
    ranked = sorted(children, key=_rank)  # stable: the reader's order within a rank
    note = (
        f"{len(children)} pieces inside, only {CHILD_LIMIT} followed (names that look "
        "like a flag, a secret or a document first): extract it to see them all"
    )
    return ranked[:CHILD_LIMIT], [note]


def _too_big(children: list[Child]) -> tuple[list[Child], list[str]]:
    """Split off the pieces too big to follow, with a note naming each one."""
    kept = [child for child in children if len(child.data) <= CHILD_MAX_SIZE]
    notes = [
        f"{child.name} ({len(child.data) // (1024 * 1024)} MB) is too big to follow here: "
        "extract it and run `ctfc solve` on it"
        for child in children
        if len(child.data) > CHILD_MAX_SIZE
    ]
    return kept, notes


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
    events = [
        Event(entry.modified, f"{report.format} member modified", entry.name)
        for entry in report.entries
        if entry.modified
    ]
    if report.docker is not None:
        for item in report.docker.config.get("history", [])[:60]:
            when = _iso(str(item.get("created", "")))
            if when:
                step = str(item.get("created_by", ""))[:120]
                events.append(Event(when, "Docker build step", step))
    return Opened(
        detail=f"{report.format}, {len(report.entries)} entr(ies)",
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        commands=list(report.commands),
        events=events,
        extract="ctfc archive {file} --extract {dir}",
    )


# ---------------------------------------------------------------------------
# A compressed stream (gzip, bzip2, xz): one file inside, nothing else
# ---------------------------------------------------------------------------
#
# A .tar.gz is two formats: the gzip stream, then the tar in it. The decoding
# chains of `auto` do decompress it, but a tar is mostly zero bytes and scores
# too low to be followed - so `solve` stopped at "gzip compressed data". As a
# reader, the stream is simply opened and its content walked like any file.

GZIP_MAGIC = b"\x1f\x8b"
BZIP2_MAGIC = b"BZh"
BZIP2_BLOCK = bytes.fromhex("314159265359")  # pi: the start of the first block
XZ_MAGIC = b"\xfd7zXZ\x00"


def _compression_of(data: bytes) -> str:
    """ "gzip", "bzip2", "xz" or "" - from the stream's magic bytes."""
    if data[:2] == GZIP_MAGIC and len(data) > 18:
        return "gzip"
    if (
        data[:3] == BZIP2_MAGIC
        and data[3:4].isdigit()
        and data[4:10] == b"\x31\x41\x59\x26\x53\x59"
    ):
        return "bzip2"
    if data[:6] == XZ_MAGIC:
        return "xz"
    return ""


def _gzip_name(data: bytes) -> str:
    """The original file name a gzip header carries (FNAME, flag bit 3), or ""."""
    if len(data) < 10 or not data[3] & 0x08:
        return ""
    start = 10
    if data[3] & 0x04:  # FEXTRA comes first: two length bytes, then that much
        start += 2 + int.from_bytes(data[10:12], "little")
    end = data.find(b"\x00", start)
    return data[start:end].decode("latin-1") if end > start else ""


def decompress_stream(data: bytes, limit: int = DECOMPRESS_MAX) -> tuple[bytes, str]:
    """Decompress a gzip / bzip2 / xz stream, at most `limit` bytes of output.

    Returns (content, note). The cap is what keeps a decompression bomb (a few
    kB that expand to gigabytes) from filling the memory; the note says when it
    was hit. A truncated stream gives what could be decoded, and a note.
    """
    kind = _compression_of(data)
    if kind == "gzip":
        decoder = zlib.decompressobj(wbits=31)  # 31 = expect a gzip header
    elif kind == "bzip2":
        decoder = bz2.BZ2Decompressor()
    elif kind == "xz":
        decoder = lzma.LZMADecompressor()
    else:
        return b"", "not a gzip, bzip2 or xz stream"
    content = b""
    broken = ""
    try:
        if kind == "gzip":
            content = decoder.decompress(data, limit)
            capped = bool(decoder.unconsumed_tail)
        else:
            content = decoder.decompress(data, max_length=limit)
            capped = not decoder.needs_input and not decoder.eof
    except (zlib.error, OSError, EOFError, lzma.LZMAError) as exc:
        # A truncated or damaged stream: keep whatever was decoded before it
        # broke (the flag is often in the first bytes), and say so.
        content = getattr(decoder, "flush", lambda: b"")() if kind == "gzip" else content
        capped = False
        broken = f"; the stream is damaged and stops early ({exc})"
    note = f"{kind} stream, {len(data)} -> {len(content)} bytes"
    if capped:
        note += f" (stopped at {limit} bytes: the rest was not decompressed)"
    elif broken:
        note += broken
    elif not decoder.eof:
        note += " (the stream is truncated: this is what could be decoded)"
    if not content and broken:
        return b"", f"the {kind} stream does not decompress{broken}"
    return content, note


def _open_compressed(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    kind = _compression_of(data)
    content, note = decompress_stream(data)
    base = path.rsplit("/", 1)[-1]
    name = _gzip_name(data) if kind == "gzip" else ""
    if not name:
        # unknown.tar.gz -> unknown.tar, notes.bz2 -> notes, x.tgz -> x.tar
        for suffix, replacement in ((".tgz", ".tar"), (".gz", ""), (".bz2", ""), (".xz", "")):
            if base.lower().endswith(suffix):
                name = base[: -len(suffix)] + replacement
                break
        else:
            name = f"{base or 'stream'}.out"
    tool = {"gzip": "gzip", "bzip2": "bzip2", "xz": "xz"}.get(kind, "gzip")
    opened = Opened(
        detail=note,
        # Kept whatever its size (a disk image is large on purpose), unlike the
        # 8 MB-capped children of other readers - solve still searches it.
        children=[Child(name, f"{kind} content", content)] if content else [],
        notes=[note],
        extract=f"mkdir -p {{dir}} && {tool} -dc {{file}} > {{dir}}/{safe_child_name(name)}",
    )
    if not content:
        opened.error = note
    return opened


def safe_child_name(name: str) -> str:
    """A name that is safe to print in a shell command (no path, no spaces)."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name.split("/")[-1])
    return cleaned.lstrip(".") or "stream.out"


# ---------------------------------------------------------------------------
# A TLS key log file (what decrypts an HTTPS capture)
# ---------------------------------------------------------------------------
#
# A capture of HTTPS traffic is unreadable without the session keys, and the
# keys are exactly what a browser or an app writes to an SSLKEYLOGFILE. A
# challenge that hands over `sslkeyfile` next to a `.pcap` is handing you the
# key to the whole capture; the one step people forget is the tshark option
# that uses it. This reader recognises the file and prints that command.

KEYLOG_LABELS = (
    b"CLIENT_RANDOM",
    b"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    b"SERVER_HANDSHAKE_TRAFFIC_SECRET",
    b"CLIENT_TRAFFIC_SECRET_0",
    b"SERVER_TRAFFIC_SECRET_0",
    b"CLIENT_EARLY_TRAFFIC_SECRET",
    b"EXPORTER_SECRET",
    b"EARLY_EXPORTER_SECRET",
)


def keylog_sniff(data: bytes) -> bool:
    """True when the file is an NSS TLS key log (SSLKEYLOGFILE)."""
    for line in data[:4096].split(b"\n"):
        line = line.strip()
        if not line or line.startswith(b"#"):
            continue
        label = line.split(b" ", 1)[0]
        return label in KEYLOG_LABELS
    return False


def _open_iso(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = iso.read(data)
    children = [Child(f.path, "ISO 9660 file", f.data) for f in report.files]
    return Opened(
        detail=f"ISO 9660 '{report.volume_id}', {len(report.files)} file(s)",
        children=_keep(children),
        notes=list(report.notes),
        extract="7z x {file} -o{dir}   (or mount it)",
    )


def _open_disk(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    try:
        # A quick pass for solve; `ctfc disk` runs the full extraction itself.
        report = disk.analyse(data, max_files=400, max_seconds=25)
    except disk.DiskError as exc:
        return Opened(error=str(exc))
    children = []
    for item in report.files:
        tag = "deleted file" if item.deleted else "file"
        children.append(Child(item.path, f"disk image {tag}", item.data))
    parts = ", ".join(f"{p.fs_type}" for p in report.partitions)
    return Opened(
        detail=f"disk image ({parts}), {len(report.files)} file(s)",
        children=children,  # a disk's files are kept whatever their size
        notes=list(report.notes),
        extract="fls -r -p {file}  then  icat {file} <inode> > out   (The Sleuth Kit)",
    )


def _open_keylog(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    counts: dict[str, int] = {}
    for line in data.split(b"\n"):
        label = line.strip().split(b" ", 1)[0]
        if label in KEYLOG_LABELS:
            counts[label.decode()] = counts.get(label.decode(), 0) + 1
    total = sum(counts.values())
    notes = [
        f"{total} TLS session secret(s): this decrypts an HTTPS capture taken at the same time. "
        "Give it to Wireshark/tshark with the tls.keylog_file option."
    ]
    base = path.rsplit("/", 1)[-1] or "sslkeyfile"
    commands = [
        f"tshark -r <capture.pcap> -o tls.keylog_file:{base} -Y http --export-objects http,./out",
        f"tshark -r <capture.pcap> -o tls.keylog_file:{base} -z follow,http,ascii,0",
    ]
    return Opened(
        detail=f"TLS key log, {total} secret(s): "
        + ", ".join(f"{k}x{v}" for k, v in counts.items()),
        notes=notes,
        commands=commands,
    )


def _open_zip(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = zipinfo.analyse(data, path)
    children = _zip_members(data, "ZIP member")
    for entry in report.entries:
        if entry.recovered:
            children.append(Child(entry.name, "recovered from the CRC32", entry.recovered))
    encrypted = [entry.name for entry in report.entries if entry.encrypted]
    notes = list(report.notes)
    notes += [
        f"{entry.name} ({entry.uncompressed_size // (1024 * 1024)} MB) is too big to follow "
        "here: extract it and run `ctfc solve` on it"
        for entry in report.entries
        if entry.uncompressed_size > CHILD_MAX_SIZE and not entry.encrypted
    ]
    if encrypted:
        notes.append(
            f"{len(encrypted)} encrypted entr(ies): a password is needed, "
            "and the commands below say which tool breaks this flavour"
        )
    return Opened(
        detail=f"ZIP, {len(report.entries)} entr(ies)",
        children=_keep(children),
        events=[
            Event(entry.modified, "ZIP entry modified (local clock)", entry.name)
            for entry in report.entries
            if entry.modified
        ],
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
    events: list[Event] = []
    for name in ("Date", "date", "Delivery time", "Creation time"):
        when = _iso(report.headers.get(name, ""))
        if when:
            events.append(Event(when, f"mail {name.lower()}", report.headers.get("Subject", "")))
            break
    return Opened(
        events=events,
        detail=f"Outlook message, {len(report.attachments)} attachment(s)",
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        extract="ctfc msg {file} --extract {dir}",
    )


def _open_mail(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    messages = mail.read_file(data)
    children: list[Child] = []
    events: list[Event] = []
    notes: list[str] = []
    for index, message in enumerate(messages):
        label = message.subject or f"message {index + 1}"
        when = _iso(message.headers.get("Date", ""))
        if when:
            events.append(Event(when, "mail date", label))
        header_line = ", ".join(f"{name}: {value}" for name, value in message.headers.items())
        if header_line:
            notes.append(header_line[:300])
        for part in message.parts:
            name = part.filename or ("body.txt" if part.is_body else "part.bin")
            children.append(
                Child(
                    f"{index + 1}_{name}" if len(messages) > 1 else name,
                    "mail body" if part.is_body else f"attachment ({part.content_type})",
                    part.data,
                )
            )
    return Opened(
        detail=f"{len(messages)} message(s), {len(children)} part(s)",
        children=_keep(children),
        notes=notes,
        events=events,
        extract="ctfc mail {file} --extract {dir}",
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


# The order a capture's objects are walked in. A busy capture has thousands of
# them and only CHILD_LIMIT are followed, so the ones a challenge hides things in
# come first: what was typed or sent as a password, mail, HTTP, then DNS
# exfiltration, and only then the raw TCP/UDP payloads, which are mostly noise.
PCAP_KIND_ORDER = {
    "usb-keystrokes": 0,
    "radius-pap": 0,
    "mail-body": 1,
    "mail-attachment": 1,
    "http-body": 2,
    "http-request": 2,
    "dns-exfil": 3,
    "tcp-stream": 4,
    "udp-payload": 5,
}


def _pcap_priority(item: pcap.Extracted) -> tuple[int, int]:
    """Sort key for a capture object: by kind, and the biggest DNS stream first.

    Every domain a browser touched becomes a "dns-exfil" candidate (google.com,
    akamaiedge.net...) with a handful of queries; the real tunnel has thousands.
    Size sorts it to the front of its kind. Other kinds keep capture order.
    """
    rank = PCAP_KIND_ORDER.get(item.kind, 4)
    return (rank, -len(item.data) if item.kind == "dns-exfil" else 0)


def _open_pcap(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = pcap.analyse(data, path)
    objects = sorted(report.objects, key=_pcap_priority)  # sorted() keeps ties in order
    children = [Child(item.name, f"capture: {item.kind}", item.data) for item in objects]
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


def _open_exif(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = exif.read(data)
    events = [
        Event(when, label, report.get("Model") or "the camera")
        for when, label in (
            (_exif_date(report.get("DateTimeOriginal")), "photograph taken"),
            (_exif_date(report.get("DateTime")), "image file written"),
        )
        if when
    ]
    flags = [hit.text for hit in find_flags(exif.text_values(report), flagset)]
    return Opened(
        detail=f"{report.container} EXIF, {len(report.tags)} field(s)"
        + (f", GPS {report.coordinates}" if report.coordinates else ""),
        flags=flags,
        notes=list(report.notes),
        events=events,
    )


def _exif_date(value: str) -> str:
    """EXIF writes "2024:05:17 09:30:00"; every event here is ISO-ish and UTC-labelled.

    EXIF has no time zone (the standard added one only in 2016, and almost
    nothing writes it), so this is the camera's local clock. It is labelled as
    UTC-shaped for sorting and the timeline flags its kind, which is the same
    compromise the ZIP and cabinet stamps get.
    """
    text = value.strip()
    if len(text) < 19 or text[:1] not in "12":
        return ""
    return f"{text[:4]}-{text[5:7]}-{text[8:10]} {text[11:19]} UTC"


def _open_wav(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = audio.analyse(data, flagset, Budget(max_attempts=200, max_seconds=8), top_n=3)
    children = [
        Child(f"lowbits{index}.bin", f"WAV: {candidate.label}", candidate.data)
        for index, candidate in enumerate(report.candidates)
    ]
    for keyword, text in report.texts:
        children.append(Child(f"{keyword}.txt", "WAV metadata chunk", text.encode()))
    return Opened(
        detail=f"{report.channels} channel(s), {report.width * 8}-bit, "
        f"{report.rate} Hz, {report.seconds:.1f} s",
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
    children += _toolchain_child(report.toolchain)
    events = (
        [Event(report.timestamp_text, "PE build stamp", "linked")] if report.timestamp_text else []
    )
    return Opened(
        events=events,
        detail=f"PE {report.bits}-bit {report.machine}" + (", .NET" if report.is_dotnet else ""),
        children=_keep(children),
        flags=list(report.flags),
        notes=list(report.notes),
        extract="ctfc pe {file} --extract {dir}",
    )


def _toolchain_child(found) -> list[Child]:
    """A Go or Rust binary's literals and function names, as one text piece.

    Handed over as a child so that the flag hunt and `ctfc solve` search them:
    the whole point of `core/binstrings.py` is that these strings are invisible
    to a plain scan of the bytes.
    """
    if found is None:
        return []
    lines = [*found.slices, *found.own_functions, *found.sources]
    if not lines:
        return []
    return [
        Child(
            f"{found.toolchain}_strings.txt",
            f"{found.toolchain} literals and function names",
            "\n".join(lines).encode(),
        )
    ]


def _exe_claims(data: bytes) -> bool:
    """Does the executable reader claim this file?

    An APK is a ZIP whose payload is resources and a classes.dex: the ZIP
    reader walks it and reaches res/, assets/, the manifest - where a flag
    usually hides - so it is left to that reader, not dead-ended here. A raw
    .dex, an ELF, a .class or a .jar (read for its class constant pools) are
    ours.
    """
    kind = executable.sniff(data)
    if kind == "dex" and data[:4] == b"PK\x03\x04":
        return False  # an APK: let the zip reader walk it
    return kind in ("elf", "class", "jar", "dex")


def _open_exe(data: bytes, flagset: FlagSet | None, path: str) -> Opened:
    report = executable.analyse(data, flagset)
    children: list[Child] = []
    if report.elf is not None and report.elf.overlay_bytes:
        children.append(
            Child("overlay.bin", "appended after the last ELF section", report.elf.overlay_bytes)
        )
    if report.kind in ("jar", "dex") and data[:4] == b"PK\x03\x04":
        children += _zip_members(data, f"{report.kind} entry")
    children += _toolchain_child(report.toolchain)
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
    events: list[Event] = []
    if report.lnk is not None:
        target = report.lnk.local_path or report.lnk.relative_path or "the target"
        for when, label in (
            (report.lnk.created, "shortcut target created"),
            (report.lnk.written, "shortcut target written"),
            (report.lnk.accessed, "shortcut target accessed"),
        ):
            if when:
                events.append(Event(when, label, target))
    if report.prefetch is not None:
        for run in report.prefetch.runs:
            if run.when:
                events.append(Event(run.when, "program run (prefetch)", report.prefetch.name))
    if report.jumplist is not None:
        for entry in report.jumplist.entries:
            if entry.accessed:
                events.append(Event(entry.accessed, "jump list entry opened", entry.path))
    return Opened(
        events=events,
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
        events=[
            Event(record.when, "event log record", f"record {record.number}")
            for record in report.records
            if record.when
        ],
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
    Reader(
        "mail",
        "e-mail file (.eml, .mbox)",
        "ctfc mail",
        mail.looks_like_mail,
        _open_mail,
    ),
    Reader("msi", "Windows Installer package (.msi)", "ctfc msi", msi.looks_like_msi, _open_msi),
    Reader("pdf", "PDF", "ctfc pdf", lambda data: data[:1024].find(b"%PDF-") >= 0, _open_pdf),
    Reader(
        "stego",
        "image, for a message in its low bits",
        "ctfc stego",
        lambda data: data[:8] == b"\x89PNG\r\n\x1a\n" or data[:2] == b"BM",
        _open_stego,
    ),
    Reader(
        "wav",
        "audio (WAV): a message in the low bits of the samples",
        "ctfc stego",
        audio.looks_like_wav,
        _open_wav,
    ),
    Reader(
        "exif",
        "photograph metadata (JPEG / TIFF EXIF, GPS)",
        "ctfc stego",
        lambda data: data[:3] == exif.JPEG_MAGIC or data[:4] in (exif.TIFF_LITTLE, exif.TIFF_BIG),
        _open_exif,
    ),
    Reader("pe", "Windows executable (PE)", "ctfc pe", lambda data: data[:2] == b"MZ", _open_pe),
    Reader(
        "exe",
        "ELF, Java class/JAR, Android DEX",
        "ctfc exe",
        _exe_claims,
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
        "capture (pcap, pcapng, 5View)",
        "ctfc pcap",
        lambda data: (
            data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")
            or data[:4] == b"\x4d\x3c\xb2\xa1"
            or data[:4] == b"\xaa\xaa\xaa\xaa"  # InfoVista 5View
            or pcap.looks_like_recoverable_pcap(data)  # magic smashed, but recoverable
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
        "iso",
        "ISO 9660 disk image (.iso)",
        "ctfc archive",
        iso.looks_like_iso,
        _open_iso,
    ),
    Reader(
        "disk",
        "disk image (ext/FAT/NTFS/..., via The Sleuth Kit)",
        "ctfc disk",
        disk.looks_like_disk_image,
        _open_disk,
    ),
    Reader(
        "keylog",
        "TLS key log (decrypts an HTTPS capture)",
        "ctfc detect",
        keylog_sniff,
        _open_keylog,
    ),
    Reader(
        "compressed",
        "compressed stream (gzip, bzip2, xz)",
        "ctfc auto",
        lambda data: bool(_compression_of(data)),
        _open_compressed,
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
    opened.children, skipped = _too_big(opened.children)
    opened.children, cut = _likeliest(opened.children)
    opened.notes += skipped + cut
    opened.reader = reader.name
    opened.label = reader.label
    opened.command = reader.command + " {file}"
    return opened
