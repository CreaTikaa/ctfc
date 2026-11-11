"""One web endpoint for every file-format reader.

The terminal has a command per format - `ctfc archive`, `ctfc msg`, `ctfc pe`,
`ctfc winartifact`... - because that is how a terminal works: you already know
what you have. The web UI starts from the opposite place: a file has been
dropped into the input box and the question is "what *is* this, and what does it
say?".

So the browser gets **one tab**, and this module answers it: it sniffs which
reader applies, runs it, and turns whatever report comes back into a small
display-agnostic shape - a list of sections, each a facts table, a table or a
block of text, plus the flags, the notes and the commands to run next.

That shape is the point. One JSON contract and one renderer in `app.js` means a
reader added next month shows up in the browser by writing an adapter here, not
by writing another tab. It also keeps the rule from `web/app.py`: the API calls
`ctfc.core` and formats; nothing here parses anything itself.

Every reader is also selectable by hand, because sniffing answers "what is this
file" and sometimes the question is "what does `ctfc repair` make of it".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ctfc.core import (
    archive,
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
    timestamps,
    winartifact,
    zipinfo,
)
from ctfc.core import readers as core_readers
from ctfc.core.budget import Budget
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags

# How much of a long list is sent to the browser. The point of the web view is
# to see what a file holds, not to scroll a thousand rows - the CLI prints the
# rest, and `--json` has all of it.
LIMIT = 300
TEXT_LIMIT = 20_000


# ---------------------------------------------------------------------------
# The display shape
# ---------------------------------------------------------------------------


def facts(title: str, rows: list[tuple[str, object]]) -> dict:
    """A two-column name/value block. Empty values are dropped, not shown blank."""
    kept = [[name, str(value)] for name, value in rows if value not in (None, "", [], 0)]
    return {"kind": "facts", "title": title, "rows": kept}


def table(title: str, columns: list[str], rows: list[list[object]]) -> dict:
    return {
        "kind": "table",
        "title": title,
        "columns": columns,
        "rows": [[str(cell) for cell in row] for row in rows[:LIMIT]],
        "total": len(rows),
    }


def text(title: str, body: str, code: bool = True) -> dict:
    return {"kind": "text", "title": title, "text": body[:TEXT_LIMIT], "code": code}


def _preview(data: bytes, limit: int = 200) -> str:
    return data[:limit].decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# One adapter per reader. Each mirrors what the terminal renderer shows.
# ---------------------------------------------------------------------------


def _archive(data: bytes, flagset: FlagSet | None) -> dict:
    report = archive.analyse(data, "archive", flagset=flagset)
    sections = [
        facts(
            "archive",
            [
                ("format", report.format),
                ("entries", len(report.entries)),
                ("file names encrypted", "yes" if report.encrypted_names else ""),
                ("appended after the end", len(report.trailing)),
            ],
        ),
        table(
            "entries",
            ["name", "method", "size", "read by ctfc", "notes"],
            [
                [
                    entry.name,
                    ("encrypted + " if entry.encrypted else "") + entry.method,
                    "" if entry.directory else entry.size,
                    "yes" if entry.data is not None else "",
                    "; ".join(entry.notes),
                ]
                for entry in report.entries
            ],
        ),
    ]
    if report.docker is not None:
        docker = report.docker
        sections.append(
            facts(
                "Docker image",
                [
                    ("tags", ", ".join(docker.tags)),
                    ("layers", len(docker.layers)),
                    ("runs", " ".join(docker.entrypoint + docker.command)),
                    ("environment", " | ".join(docker.environment[:12])),
                ],
            )
        )
        sections.append(
            table(
                "layers, oldest first",
                ["#", "id", "files", "created by", "deletes"],
                [
                    [
                        layer.index,
                        layer.short[:12],
                        len(layer.files),
                        layer.created_by or "(unknown)",
                        ", ".join(layer.whiteouts[:4]),
                    ]
                    for layer in docker.layers
                ],
            )
        )
        if docker.deleted:
            sections.append(
                table(
                    "files a later layer hides, but the image still carries",
                    ["path", "still in", "deleted by", "content"],
                    [
                        [
                            item.name,
                            f"layer {item.present_in}",
                            f"layer {item.hidden_by}",
                            "" if item.content is None else _preview(item.content),
                        ]
                        for item in docker.deleted
                    ],
                )
            )
    return {
        "sections": sections,
        "flags": report.flags,
        "notes": report.notes,
        "commands": report.commands,
    }


def _zip(data: bytes, flagset: FlagSet | None) -> dict:
    report = zipinfo.analyse(data, "archive.zip", Budget(max_attempts=5_000_000, max_seconds=10))
    return {
        "sections": [
            facts(
                "ZIP",
                [
                    ("entries", len(report.entries)),
                    ("comment", report.comment.strip()),
                    ("bytes after the archive", report.trailing),
                ],
            ),
            table(
                "entries",
                ["name", "method", "size", "crc32", "recovered", "problems"],
                [
                    [
                        entry.name,
                        ("encrypted + " if entry.encrypted else "") + entry.method_name,
                        entry.uncompressed_size,
                        f"{entry.crc:08x}",
                        "" if entry.recovered is None else repr(entry.recovered),
                        "; ".join(entry.problems),
                    ]
                    for entry in report.entries
                ],
            ),
        ],
        "flags": [],
        "notes": report.notes,
        "commands": report.commands,
    }


def _office(data: bytes, flagset: FlagSet | None) -> dict:
    report = office.analyse(data)
    sections = [
        facts(
            "Office document",
            [
                ("container", report.container),
                ("VBA modules", len(report.macros)),
                ("embedded objects", len(report.objects)),
                ("streams / parts", len(report.streams)),
            ],
        )
    ]
    if report.indicators:
        sections.append(
            table("what the macro does", ["indicator"], [[i] for i in report.indicators])
        )
    if report.objects:
        sections.append(
            table(
                "embedded objects (ObjectPool)",
                ["name", "size", "came from", "stream"],
                [
                    [item.name or "(unnamed)", item.size, item.source_path, item.stream]
                    for item in report.objects
                ],
            )
        )
    for macro in report.macros:
        sections.append(text(macro.module, macro.code))
    return {"sections": sections, "flags": [], "notes": report.notes, "commands": []}


def _msg(data: bytes, flagset: FlagSet | None) -> dict:
    report = msg.analyse(data, flagset)
    sections = [
        facts("Outlook message", list(report.headers.items())),
    ]
    if report.recipients:
        sections.append(table("recipients", ["recipient"], [[r] for r in report.recipients]))
    if report.attachments:
        sections.append(
            table(
                "attachments",
                ["name", "size", "type"],
                [[a.name, a.size, a.mime] for a in report.attachments],
            )
        )
    if report.body:
        sections.append(text("body", report.body, code=False))
    elif report.html_body:
        sections.append(text("body (HTML)", report.html_body))
    if report.transport_headers:
        sections.append(text("transport headers", report.transport_headers))
    return {"sections": sections, "flags": report.flags, "notes": report.notes, "commands": []}


def _mail(data: bytes, flagset: FlagSet | None) -> dict:
    from ctfc.core import mail as mail_module

    messages = mail_module.read_file(data)
    sections = [
        facts(
            f"message {index + 1}",
            [(name, value) for name, value in message.headers.items()],
        )
        for index, message in enumerate(messages[:20])
    ]
    rows = []
    flags: list[str] = []
    for index, message in enumerate(messages):
        for part in message.parts:
            rows.append(
                [
                    index + 1,
                    part.filename or ("(body)" if part.is_body else "(part)"),
                    part.content_type,
                    len(part.data),
                    _preview(part.data, 80),
                ]
            )
            flags += [hit.text for hit in find_flags(part.data, flagset)]
    sections.append(table("parts", ["message", "name", "type", "size", "preview"], rows))
    return {
        "sections": sections,
        "flags": flags,
        "notes": [f"{len(messages)} message(s)"],
        "commands": [],
    }


def _msi(data: bytes, flagset: FlagSet | None) -> dict:
    report = msi.analyse(data, flagset)
    sections = [
        facts(
            "installer package",
            [
                ("streams", len(report.streams)),
                ("strings", len(report.strings)),
                ("embedded cabinets", ", ".join(f"{n} ({c})" for n, c in report.cabinets)),
                ("Binary streams", ", ".join(f"{n} ({s} B)" for n, s in report.binaries)),
                ("inside the cabinet", ", ".join(report.cabinet_files)),
            ],
        ),
        table("streams and tables", ["name"], [[name] for name in report.streams]),
    ]
    if report.indicators:
        sections.append(table("indicators", ["what"], [[i] for i in report.indicators]))
    for command in report.commands:
        sections.append(text("decoded PowerShell command", command))
    if report.strings:
        sections.append(text("string pool", "\n".join(report.strings)))
    return {"sections": sections, "flags": report.flags, "notes": report.notes, "commands": []}


def _pdf(data: bytes, flagset: FlagSet | None) -> dict:
    report = pdf.analyse(data, flagset)
    sections = [
        facts(
            "PDF",
            [
                ("version", report.version),
                ("objects", len(report.objects)),
                ("revisions", report.revisions),
                ("encrypted", "yes" if report.encrypted else ""),
                ("embedded files", len(report.embedded)),
            ],
        )
    ]
    if report.indicators:
        sections.append(table("what it would do", ["indicator"], [[i] for i in report.indicators]))
    if report.embedded:
        sections.append(
            table(
                "embedded files",
                ["name", "size"],
                [[name, len(payload)] for name, payload in report.embedded],
            )
        )
    for script in report.javascript:
        sections.append(text("JavaScript", script))
    return {
        "sections": sections,
        "flags": [flag for _number, flag in report.flags],
        "notes": report.notes,
        "commands": [],
    }


def _stego(data: bytes, flagset: FlagSet | None) -> dict:
    report = stego.analyse(data, flagset, Budget(max_attempts=200_000, max_seconds=10))
    sections = [
        facts(
            "image",
            [
                ("kind", report.kind),
                ("size", f"{report.width} x {report.height}"),
                ("channels", report.channels),
            ],
        ),
        table(
            "what came out of the low bits",
            ["score", "how", "text"],
            [
                [f"{candidate.score:.2f}", candidate.label, _preview(candidate.data, 300)]
                for candidate in report.candidates
            ],
        ),
    ]
    if report.texts:
        sections.append(table("text found in the file", ["text"], [[t] for t in report.texts]))
    flags = []
    for candidate in report.candidates:
        flags += [hit.text for hit in find_flags(candidate.data, flagset)]
    return {"sections": sections, "flags": flags, "notes": report.notes, "commands": []}


def _wav(data: bytes, flagset: FlagSet | None) -> dict:
    from ctfc.core import audio as audio_module

    report = audio_module.analyse(data, flagset, Budget(max_attempts=200, max_seconds=10), top_n=5)
    sections = [
        facts(
            "the audio",
            [
                ("channels", report.channels),
                ("bits per sample", report.width * 8),
                ("sample rate", f"{report.rate} Hz"),
                ("length", f"{report.seconds:.2f} s"),
                ("frames", report.frames),
            ],
        )
    ]
    if report.texts:
        sections.append(
            table(
                "metadata chunks", ["chunk", "text"], [[key, value] for key, value in report.texts]
            )
        )
    sections.append(
        table(
            "what the low bits spell",
            ["score", "layout", "output"],
            [
                [f"{candidate.score:.2f}", candidate.label, _preview(candidate.data, 160)]
                for candidate in report.candidates
            ],
        )
    )
    flags: list[str] = []
    for candidate in report.candidates:
        flags += [hit.text for hit in find_flags(candidate.data, flagset)]
    return {"sections": sections, "flags": flags, "notes": report.notes, "commands": []}


def _exif(data: bytes, flagset: FlagSet | None) -> dict:
    from ctfc.core import exif as exif_module

    report = exif_module.read(data)
    sections = [
        facts(
            "the photograph",
            [
                ("container", report.container),
                ("byte order", report.byte_order),
                ("GPS", report.coordinates),
                ("altitude", report.altitude),
                ("camera", f"{report.get('Make')} {report.get('Model')}".strip()),
                ("taken", report.get("DateTimeOriginal")),
            ],
        ),
        table(
            "every field",
            ["where", "tag", "field", "value"],
            [[tag.ifd, f"0x{tag.tag:04x}", tag.name, tag.value] for tag in report.tags],
        ),
    ]
    commands = []
    if report.map_url:
        commands.append(f"# the GPS point, on a map (a third party): {report.map_url}")
    return {
        "sections": sections,
        "flags": [hit.text for hit in find_flags(exif_module.text_values(report), flagset)],
        "notes": list(report.notes),
        "commands": commands,
    }


def _toolchain(found) -> list[dict]:
    """The Go / Rust report, shared by the PE and the ELF adapters.

    Mirrors `render.print_toolchain`: the version, the program's *own*
    functions (not the runtime's), and the string literals cut exactly where
    the compiler ended them - which is the whole point, since `strings` glues
    them into one long run.
    """
    if found is None:
        return []
    sections = [
        facts(
            f"built by {found.toolchain}",
            [
                ("version", found.version or "?"),
                ("module", found.module),
                ("functions", len(found.functions)),
                ("string literals", len(found.slices)),
            ],
        )
    ]
    own = found.own_functions
    if own:
        sections.append(
            table(f"{len(own)} function(s) of this program", ["name"], [[n] for n in own])
        )
    if found.slices:
        sections.append(
            text("string literals (exact, from their length fields)", "\n".join(found.slices))
        )
    if found.sources:
        sections.append(
            table("source paths embedded in the binary", ["path"], [[p] for p in found.sources])
        )
    return sections


def _pe(data: bytes, flagset: FlagSet | None) -> dict:
    report = pe.analyse(data, flagset)
    sections = [
        facts(
            "executable",
            [
                ("format", "PE32+" if report.bits == 64 else "PE32"),
                ("machine", report.machine),
                (
                    "kind",
                    ("DLL" if report.is_dll else "EXE") + (" / .NET" if report.is_dotnet else ""),
                ),
                ("subsystem", report.subsystem),
                ("built", report.timestamp_text),
                ("entry point", f"{report.entry_point:#x}"),
                ("imports", f"{report.import_count} from {len(report.imports)} DLL(s)"),
                ("exports", len(report.exports)),
                ("signed", "yes" if report.signed else ""),
                ("overlay", len(report.overlay)),
            ],
        ),
        table(
            "sections",
            ["name", "flags", "virtual", "on disk", "entropy"],
            [
                [s.name, s.flags, s.virtual_size, s.raw_size, f"{s.entropy:.2f}"]
                for s in report.sections
            ],
        ),
    ]
    if report.notable:
        sections.append(
            table(
                "what its API calls say it does",
                ["import", "meaning"],
                [line.split(": ", 1) if ": " in line else [line, ""] for line in report.notable],
            )
        )
    if report.dotnet_literals:
        sections.append(text(".NET string literals (#US heap)", "\n".join(report.dotnet_literals)))
    sections += _toolchain(report.toolchain)
    return {
        "sections": sections,
        "flags": list(report.flags),
        "notes": report.notes,
        "commands": [],
    }


def _exe(data: bytes, flagset: FlagSet | None) -> dict:
    report = executable.analyse(data, flagset)
    sections: list[dict] = []
    if report.elf is not None:
        elf = report.elf
        sections.append(
            facts(
                "ELF",
                [
                    ("format", f"ELF{elf.bits}, {elf.endian} endian"),
                    ("kind", elf.kind),
                    ("machine", elf.machine),
                    ("entry point", f"{elf.entry:#x}"),
                    ("interpreter", elf.interpreter),
                    ("soname", elf.soname),
                    ("needs", ", ".join(elf.needed)),
                    ("runpath", elf.runpath),
                    ("stripped", "yes" if elf.stripped else ""),
                    ("statically linked", "yes" if elf.static else ""),
                    ("appended after the last section", elf.overlay),
                ],
            )
        )
        sections.append(
            table(
                "segments",
                ["flags", "offset", "in file", "in memory"],
                [
                    [s.permissions, f"{s.offset:#x}", s.file_size, s.memory_size]
                    for s in elf.segments
                ],
            )
        )
        sections.append(
            table(
                "sections",
                ["name", "flags", "address", "size", "entropy"],
                [
                    [s.name, s.permissions, f"{s.address:#x}", s.size, f"{s.entropy:.2f}"]
                    for s in elf.sections
                    if s.name
                ],
            )
        )
        if elf.notable:
            sections.append(
                table(
                    "what its imported symbols say",
                    ["symbol", "meaning"],
                    [line.split(": ", 1) for line in elf.notable],
                )
            )
        if elf.symbols:
            sections.append(text("dynamic symbols", "\n".join(elf.symbols)))
    sections += _toolchain(report.toolchain)
    for item in report.classes[:20]:
        sections.append(
            facts(
                item.name or "(unnamed class)",
                [
                    ("extends", item.superclass),
                    ("version", item.version),
                    ("literals", len(item.strings)),
                    ("types referenced", len(item.classes)),
                ],
            )
        )
        if item.strings:
            sections.append(text("string literals", "\n".join(item.strings)))
        if item.notable:
            sections.append(table("notable APIs", ["what"], [[line] for line in item.notable]))
    if report.dex is not None:
        dex = report.dex
        sections.append(
            facts(
                f"Android DEX (version {dex.version})",
                [
                    ("strings", len(dex.strings)),
                    ("classes", len(dex.classes)),
                    ("header checksum", "matches" if dex.checksum_ok else "stale"),
                ],
            )
        )
        if dex.classes:
            sections.append(table("classes", ["name"], [[name] for name in dex.classes]))
        sections.append(text("strings", "\n".join(dex.strings)))
        if dex.notable:
            sections.append(table("notable APIs", ["what"], [[line] for line in dex.notable]))
    notes = list(report.notes)
    if report.elf is not None:
        notes += report.elf.notes
    for item in report.classes:
        notes += item.notes
    if report.dex is not None:
        notes += report.dex.notes
    sections = [section for section in sections if section.get("rows") or section.get("text")]
    return {
        "sections": sections,
        "flags": report.flags,
        "notes": notes,
        "commands": report.commands,
    }


def _winartifact(data: bytes, flagset: FlagSet | None) -> dict:
    report = winartifact.analyse(data, flagset=flagset)
    sections: list[dict] = []
    if report.lnk is not None:
        link = report.lnk
        sections.append(
            facts(
                "Windows shortcut",
                [
                    ("target", link.target),
                    ("arguments", link.arguments),
                    ("description", link.description),
                    ("working directory", link.working_directory),
                    ("icon", link.icon_location),
                    (
                        "volume",
                        f"{link.drive_type} serial {link.volume_serial} {link.volume_label}"
                        if link.volume_serial
                        else "",
                    ),
                    ("made on machine", link.machine_id),
                    ("target size", link.target_size),
                    ("created", link.created),
                    ("accessed", link.accessed),
                    ("written", link.written),
                ],
            )
        )
        if link.command:
            sections.append(text("command line", link.command))
        for decoded in link.decoded_commands:
            sections.append(text("decoded PowerShell command", decoded))
        if link.indicators:
            sections.append(table("indicators", ["what"], [[line] for line in link.indicators]))
    if report.prefetch is not None:
        prefetch = report.prefetch
        sections.append(
            facts(
                "prefetch",
                [
                    ("format", prefetch.version_name),
                    ("executable", prefetch.name),
                    ("path hash", prefetch.hash_value),
                    ("times run", prefetch.run_count),
                    ("last runs", ", ".join(prefetch.runs)),
                    ("volume", ", ".join(prefetch.volumes)),
                ],
            )
        )
        if prefetch.interesting:
            sections.append(
                table(
                    "files it loaded that are not system DLLs",
                    ["path"],
                    [[path] for path in prefetch.interesting],
                )
            )
        if prefetch.files:
            sections.append(text("every file it loaded", "\n".join(prefetch.files)))
    if report.jumplist is not None:
        sections.append(
            table(
                "jump list entries",
                ["stream", "path", "accessed", "machine"],
                [
                    [
                        entry.stream,
                        entry.path or "; ".join(entry.notes),
                        entry.accessed,
                        entry.machine_id,
                    ]
                    for entry in report.jumplist.entries
                ],
            )
        )
    notes = list(report.notes)
    for part in (report.lnk, report.prefetch, report.jumplist):
        if part is not None:
            notes += part.notes
    return {
        "sections": sections,
        "flags": report.flags,
        "notes": notes,
        "commands": report.commands,
    }


def _evtx(data: bytes, flagset: FlagSet | None) -> dict:
    report = evtx.analyse(data, flagset)
    sections = [
        facts("Windows event log", [("chunks", report.chunks), ("records", len(report.records))]),
    ]
    rows = report.interesting or report.records[:LIMIT]
    sections.append(
        table(
            "records",
            ["#", "written", "what it says"],
            [[record.number, record.when, _preview(record.text.encode(), 300)] for record in rows],
        )
    )
    for record in rows:
        if record.command:
            sections.append(text(f"record {record.number}: decoded command", record.command))
    return {"sections": sections, "flags": [], "notes": report.notes, "commands": []}


def _hive(data: bytes, flagset: FlagSet | None) -> dict:
    report = hive.analyse(data)
    sections = [
        facts(
            "registry hive",
            [
                ("file name inside", report.name),
                ("looks like", report.kind),
                ("keys", report.keys),
                ("boot key", report.boot_key.hex() if report.boot_key else ""),
            ],
        )
    ]
    for path, why, values in report.found:
        sections.append(text(f"{path}  ({why})", "\n".join(values)))
    return {"sections": sections, "flags": [], "notes": report.notes, "commands": report.commands}


def _sqlite(data: bytes, flagset: FlagSet | None) -> dict:
    report = sqlitedb.analyse(data, None, flagset)
    sections = [
        facts(
            "SQLite database",
            [
                ("page size", report.page_size),
                ("pages", report.pages),
                ("free pages", len(report.freelist)),
                ("tables", len(report.tables)),
                ("rows recovered from free space", len(report.deleted)),
            ],
        ),
        table("tables", ["table"], [[str(item)] for item in report.tables]),
    ]
    if report.deleted:
        sections.append(
            table(
                "rows recovered from free space",
                ["where", "rowid", "values"],
                [
                    [
                        row.where,
                        row.rowid if row.rowid is not None else "",
                        " | ".join("NULL" if value is None else str(value) for value in row.values),
                    ]
                    for row in report.deleted
                ],
            )
        )
    return {"sections": sections, "flags": [], "notes": report.notes, "commands": []}


def _pcap(data: bytes, flagset: FlagSet | None) -> dict:
    report = pcap.analyse(data)
    sections = [
        facts(
            "capture",
            [
                ("format", report.format),
                ("link type", report.link_type),
                ("packets", report.packets),
            ],
        ),
        table(
            "what it carried",
            ["name", "kind", "size", "from", "what it is"],
            [
                [obj.name, obj.kind, len(obj.data), obj.source, obj.description]
                for obj in report.objects
            ],
        ),
    ]
    flags: list[str] = []
    for obj in report.objects:
        flags += [hit.text for hit in find_flags(obj.data, flagset)]
    return {"sections": sections, "flags": flags, "notes": report.notes, "commands": []}


def _keylog(data: bytes, flagset: FlagSet | None) -> dict:
    opened = core_readers.open_with("keylog", data, flagset, "sslkeyfile")
    sections = [facts("TLS key log", [("what", opened.detail)])]
    return {"sections": sections, "flags": [], "notes": opened.notes, "commands": opened.commands}


def _compressed(data: bytes, flagset: FlagSet | None) -> dict:
    opened = core_readers.open_with("compressed", data, flagset, "stream")
    rows = [[child.name, len(child.data), _preview(child.data)] for child in opened.children]
    sections = [
        facts("compressed stream", [("what", opened.detail)]),
        table("decompressed content", ["name", "size", "preview"], rows),
    ]
    flags = [hit.text for child in opened.children for hit in find_flags(child.data, flagset)]
    return {"sections": sections, "flags": flags, "notes": opened.notes, "commands": []}


def _repair(data: bytes, flagset: FlagSet | None) -> dict:
    report = repair.repair(data)
    sections = [
        table(
            "what was wrong, and what was done",
            ["offset", "was", "is now", "why"],
            [[f"{fix.offset:#x}", fix.old.hex(), fix.new.hex(), fix.why] for fix in report.fixes],
        ),
        table(
            "files carved out of it",
            ["name", "kind", "size", "why"],
            [[item.name, item.ext, len(item.data), item.why] for item in report.carved],
        ),
    ]
    flags = [hit.text for hit in find_flags(report.repaired or data, flagset)]
    return {"sections": sections, "flags": flags, "notes": report.notes, "commands": []}


def _time(data: bytes, flagset: FlagSet | None) -> dict:
    groups = timestamps.from_bytes(data)
    sections = [
        table(
            f"readings of {label}",
            ["epoch", "date", "note"],
            [[reading.epoch, reading.text, reading.note] for reading in readings],
        )
        for label, readings in groups
    ]
    notes = (
        []
        if groups
        else ["4 or 8 bytes are a timestamp field; no reading landed between 1990 and 2100"]
    )
    return {"sections": sections, "flags": [], "notes": notes, "commands": []}


def timeline(report) -> dict:
    """`ctfc timeline` in the same display shape, so the Files renderer draws it.

    It is not a reader (it runs *every* reader, through `solve.walk`), which is
    why it is not in the registry below: the browser reaches it from its own
    Timeline tab, as a background job, because walking a file takes time.
    """
    sections = [
        facts(
            "timeline",
            [("span", report.span), ("dates", len(report.entries)), ("files", report.files)],
        ),
        table(
            "every date, oldest first",
            ["when (UTC)", "what happened", "to what", "from", "note"],
            [[e.when, e.kind, e.what, e.source, e.note] for e in report.entries],
        ),
    ]
    return {
        "sections": sections,
        "flags": [],
        "notes": report.notes,
        "commands": ["ctfc timeline <file or folder>   # a whole folder, with each file's mtime"],
        "reader": "timeline",
        "label": "every date the file carries",
        "command": "ctfc timeline",
        "sniffed": True,
        "budget": report.budget,
    }


def workspace(report) -> dict:
    """`ctfc workspace` in the same display shape, for the Workspace tab.

    Mirrors `render.print_workspace`: the pairs that worked first; the pools
    (secrets, named keys) only when nothing worked, because that is when you
    read them; and what is encrypted, with the command when ctfc cannot try it.
    """
    sections = [
        facts(
            "workspace",
            [
                ("files", report.files),
                ("pieces read", report.pieces),
                ("pairs tried", report.tried),
                ("secrets", len(report.secrets)),
                ("encrypted things", len(report.ciphertexts)),
            ],
        )
    ]
    if report.hits:
        sections.append(
            table(
                "pairs that worked",
                ["secret", "found in", "opens", "how", "what came out"],
                [[h.secret, h.secret_where, h.target, h.how, h.preview] for h in report.hits],
            )
        )
    else:
        sections.append(
            table(
                "candidate secrets",
                ["value", "found in", "why"],
                [[f.value, f.where, f.why] for f in report.secrets],
            )
        )
        sections.append(
            table(
                "named key candidates",
                ["key (hex)", "found in", "why"],
                [[f.value, f.where, f.why] for f in report.keys],
            )
        )
    sections.append(
        table(
            "things that are encrypted",
            ["what", "kind", "tried here?"],
            [
                [c.name, c.kind, "yes" if c.testable else (c.command or "no")]
                for c in report.ciphertexts
            ],
        )
    )
    if report.skipped:
        sections.append(table("pairs never reached", ["pair"], [[s] for s in report.skipped]))
    flags = list(report.flags)
    for hit in report.hits:
        flags += [flag for flag in hit.flags if flag not in flags]
    notes = list(report.notes)
    if not report.hits:
        notes.insert(0, f"no pair worked ({report.tried} tried): the secret may be in another file")
    return {
        "sections": [s for s in sections if s.get("rows")],
        "flags": flags,
        "notes": notes,
        "commands": [hit.command for hit in report.hits if hit.command],
        "reader": "workspace",
        "label": "the files together: secrets x ciphertexts",
        "command": "ctfc workspace <folder>",
        "sniffed": True,
        "budget": report.budget,
    }


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------
#
# Which reader claims which file is decided once, in `ctfc/core/readers.py`,
# because the terminal asks the same question (`ctfc solve` walks a file with
# exactly this table). What is left here is one display adapter per reader -
# and `time`, which is display-only: four bytes could be anything, so it is
# never sniffed, only chosen by hand in the dropdown.

ADAPTERS: dict[str, Callable[[bytes, FlagSet | None], dict]] = {
    "archive": _archive,
    "office": _office,
    "msg": _msg,
    "mail": _mail,
    "msi": _msi,
    "pdf": _pdf,
    "stego": _stego,
    "wav": _wav,
    "exif": _exif,
    "pe": _pe,
    "exe": _exe,
    "winartifact": _winartifact,
    "evtx": _evtx,
    "hive": _hive,
    "sqlite": _sqlite,
    "pcap": _pcap,
    "keylog": _keylog,
    "compressed": _compressed,
    "repair": _repair,
    "zip": _zip,
}


@dataclass(frozen=True)
class Reader:
    """One format reader, as the web tab sees it."""

    name: str  # the id the browser sends back
    label: str  # what the dropdown shows
    command: str  # the terminal command that does the same thing
    sniff: Callable[[bytes], bool]  # cheap "is this mine?"
    run: Callable[[bytes, FlagSet | None], dict]  # -> {sections, flags, notes, commands}


READERS: tuple[Reader, ...] = tuple(
    Reader(reader.name, reader.label, reader.command, reader.sniff, ADAPTERS[reader.name])
    for reader in core_readers.READERS
) + (Reader("time", "read 4 or 8 bytes as a timestamp", "ctfc time", lambda data: False, _time),)
READERS_BY_NAME = {reader.name: reader for reader in READERS}

# Kept under this name because the browser dropdown and the web tests have
# always known it so; the rule itself now lives in core.
office_sniff = core_readers.office_sniff


def catalogue() -> list[dict]:
    """The readers, for the browser's dropdown."""
    return [
        {"name": reader.name, "label": reader.label, "command": reader.command}
        for reader in READERS
    ]


def sniff(data: bytes) -> str:
    """Which reader claims these bytes, or "" when none does (decided in core)."""
    return core_readers.sniff(data)


def analyse(data: bytes, name: str = "", flagset: FlagSet | None = None) -> dict:
    """Run one reader (named, or sniffed) and return the display shape."""
    chosen = name or sniff(data)
    if not chosen:
        raise FormatError(
            "no reader recognises this file. The Detect tab says what it looks like, "
            "and the dropdown above runs any reader by hand"
        )
    reader = READERS_BY_NAME.get(chosen)
    if reader is None:
        known = ", ".join(sorted(READERS_BY_NAME))
        raise FormatError(f"unknown reader {chosen!r}; known: {known}")
    result = reader.run(data, flagset)
    result.update(
        {
            "reader": reader.name,
            "label": reader.label,
            "command": reader.command,
            "sniffed": not name,
        }
    )
    return result
