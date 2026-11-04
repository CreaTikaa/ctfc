"""One door for every archive that is not a ZIP: tar, 7z, RAR, CAB - and a
Docker image, which is a tar full of tars.

`ctfc zip` already does the ZIP family. This module is its counterpart for the
rest, and its job is mostly to answer the three questions that decide what to do
next:

1. **what is in it** - the names and sizes, read out of the headers rather than
   by trusting an extraction;
2. **is it encrypted, and in which way** - because the answer differs per
   format, and the difference is the whole attack. ZipCrypto has a
   known-plaintext break; 7z and RAR do not, so there the useful answer is the
   exact `*2john` + hashcat command, with the right mode number. Both 7z and RAR
   can also encrypt the *file list*, and saying which case you are in saves ten
   minutes of confusion;
3. **can it be opened right here** - stored, deflate, bzip2, LZMA, LZMA2 and
   MSZIP are all decoded offline by the standard library, so for most archives
   the contents come out with no external tool at all. Anything else (PPMd,
   LZX, RAR's own compression) is named and handed to the real tool.

The contents, where they are readable, are then searched for flags, so that the
common case - a one-file archive with the flag in it - ends in one command.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ctfc.core import cab as cab_module
from ctfc.core import dockerimg, rar, sevenzip, tarfmt, timestamps
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags

# Formats this module recognises, in the order sniff() tests them.
FORMATS = ("7z", "rar", "cab", "tar")
# Contents bigger than this are not searched for flags.
FLAG_SEARCH_LIMIT = 4 << 20
# Hashcat modes for the formats that have to be cracked rather than attacked.
HASHCAT_MODES = {
    "7z": ("11600", "7z2john.pl"),
    "rar5": ("13000", "rar2john"),
    "rar4": ("12500", "rar2john"),
}


class ArchiveError(FormatError):
    """The data is not an archive this module reads."""


@dataclass
class ArchiveEntry:
    """One member, in the same shape whatever the format was."""

    name: str
    size: int = 0
    packed: int = 0
    method: str = ""
    encrypted: bool = False
    directory: bool = False
    crc: int | None = None
    # The member's modification time, as text ("YYYY-MM-DD HH:MM:SS UTC"), when
    # the format records one. tar and cab do; 7z's is in an optional header
    # ctfc does not read, and RAR's listing here does not carry it.
    modified: str = ""
    notes: list[str] = field(default_factory=list)
    data: bytes | None = None  # filled when the format and codec allowed it
    # False for the members that have no content of their own (directories,
    # symlinks, 7z's empty entries), so that "ctfc could not read it" stays
    # about the ones where that is actually true.
    content_expected: bool = True


@dataclass
class ArchiveReport:
    """What the archive is, what it holds, and what to run next."""

    format: str = ""
    entries: list[ArchiveEntry] = field(default_factory=list)
    encrypted_names: bool = False  # the listing itself needs a password
    docker: dockerimg.DockerReport | None = None
    trailing: bytes = b""
    flags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    @property
    def any_encrypted(self) -> bool:
        return self.encrypted_names or any(entry.encrypted for entry in self.entries)

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "encrypted_names": self.encrypted_names,
            "entries": [
                {
                    "name": entry.name,
                    "size": entry.size,
                    "packed": entry.packed,
                    "method": entry.method,
                    "encrypted": entry.encrypted,
                    "directory": entry.directory,
                    "crc": None if entry.crc is None else f"{entry.crc:08x}",
                    "modified": entry.modified,
                    "extracted": entry.data is not None,
                    "notes": list(entry.notes),
                }
                for entry in self.entries
            ],
            "trailing": len(self.trailing),
            "flags": list(self.flags),
            "docker": None if self.docker is None else self.docker.to_dict(),
            "notes": list(self.notes),
            "commands": list(self.commands),
        }


def sniff(data: bytes) -> str:
    """Which format this is: "7z", "rar4", "rar5", "cab", "tar", or "" for none."""
    if sevenzip.is_sevenzip(data):
        return "7z"
    version = rar.version_of(data)
    if version:
        return f"rar{version}"
    if cab_module.is_cab(data):
        return "cab"
    if tarfmt.looks_like_tar(data):
        return "tar"
    return ""


def analyse(
    data: bytes,
    path: str = "archive",
    flagset: FlagSet | None = None,
    read_contents: bool = True,
) -> ArchiveReport:
    """Read whichever archive this is and say what to do with it."""
    kind = sniff(data)
    if not kind:
        raise ArchiveError(_wrong_format_reason(data))
    if kind == "7z":
        report = _from_sevenzip(data, read_contents)
    elif kind.startswith("rar"):
        report = _from_rar(data)
    elif kind == "cab":
        report = _from_cab(data, read_contents)
    else:
        report = _from_tar(data, read_contents)

    if read_contents:
        _search_flags(report, flagset)
    _add_commands(report, path)
    return report


def _wrong_format_reason(data: bytes) -> str:
    """Name the command that *does* read this, rather than only saying no.

    The containers get confused with each other constantly - an .msi and a .doc
    are the same file format, a .docx and a .jar are both ZIPs - so a refusal is
    only useful if it ends with the right command.
    """
    if data[:4] == b"PK\x03\x04":
        return (
            "this is a ZIP (which includes .docx/.xlsx, .jar, .apk): `ctfc zip <file>` "
            "reads the archive itself, `ctfc office <file>` its macros"
        )
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return (
            "this is an OLE2 compound file, not an archive: `ctfc msi <file>` for an "
            "installer, `ctfc msg <file>` for an Outlook message, `ctfc office <file>` "
            "for a .doc/.xls"
        )
    if data[:2] in (b"\x1f\x8b", b"BZ") or data[:5] == b"\xfd7zXZ":
        return (
            "this is a compressed file, not an archive: decompress it first "
            "(gunzip/bunzip2/unxz) - a .tar.gz is a tar once it is gunzipped"
        )
    return (
        "not a tar, 7z, RAR or cabinet. A ZIP (and the .docx/.jar/.apk family) "
        "goes to `ctfc zip`; for anything else start with `ctfc detect`"
    )


# ---------------------------------------------------------------------------
# One adapter per format
# ---------------------------------------------------------------------------


def _from_tar(data: bytes, read_contents: bool) -> ArchiveReport:
    """A tar, plus the two things only a hand-written reader notices."""
    report = ArchiveReport(format="tar")
    entries, end = tarfmt.read_entries(data)
    for entry in entries:
        member = ArchiveEntry(
            name=entry.name,
            size=entry.size,
            packed=entry.size,
            method="stored",
            directory=entry.kind == "directory",
            modified=timestamps.from_unix(entry.mtime),
            notes=list(entry.problems),
        )
        if entry.kind not in ("file", "directory"):
            member.notes.append(entry.kind + (f" -> {entry.link}" if entry.link else ""))
        member.content_expected = entry.is_file
        if read_contents and entry.is_file:
            member.data = tarfmt.member(data, entry)
        report.entries.append(member)

    report.trailing = tarfmt.trailing_after_end(data, end)
    if report.trailing:
        report.notes.append(
            f"{len(report.trailing)} byte(s) follow the end-of-archive marker at offset "
            f"{end}: tar stops reading there, so this is invisible to `tar tf`. "
            "Run `ctfc detect` on the tail"
        )
    if dockerimg.looks_like_image(data):
        report.notes.append(
            "this tar is a saved Docker image: the layer analysis is below "
            "(a file deleted by a later layer is still in an earlier one)"
        )
        try:
            report.docker = dockerimg.analyse(data, read_layers=read_contents)
        except dockerimg.DockerError as exc:
            report.notes.append(f"the Docker layout could not be read: {exc}")
    return report


def _from_sevenzip(data: bytes, read_contents: bool) -> ArchiveReport:
    """A .7z, decoding what the standard library can decode."""
    archive = sevenzip.read(data)
    if read_contents and not archive.header_encrypted:
        archive = sevenzip.extract(data, archive)
    report = ArchiveReport(format="7z", encrypted_names=archive.header_encrypted)
    report.notes += archive.notes
    for entry in archive.entries:
        report.entries.append(
            ArchiveEntry(
                name=entry.name,
                size=entry.size,
                method=entry.method or ("(empty)" if entry.empty else ""),
                encrypted=entry.encrypted,
                directory=entry.directory,
                crc=entry.crc,
                data=entry.data,
                content_expected=not entry.empty,
            )
        )
    if archive.kdf_iterations:
        report.notes.append(
            f"the key is the password hashed {archive.kdf_iterations} times with SHA-256"
            + (f", salt {archive.salt.hex()}" if archive.salt else " (no salt)")
            + (f", IV {archive.iv.hex()}" if archive.iv else "")
        )
    return report


def _from_rar(data: bytes) -> ArchiveReport:
    """A RAR. Nothing is decompressed: that part belongs to unrar."""
    archive = rar.read(data)
    report = ArchiveReport(
        format=f"rar{archive.version}", encrypted_names=archive.encrypted_headers
    )
    report.notes += archive.notes
    for entry in archive.entries:
        report.entries.append(
            ArchiveEntry(
                name=entry.name,
                size=entry.size,
                packed=entry.packed,
                method=entry.method,
                encrypted=entry.encrypted,
                directory=entry.directory,
                crc=entry.crc,
                notes=list(entry.notes),
                content_expected=not entry.directory,
            )
        )
    stored = [
        entry for entry in archive.entries if entry.method == "stored" and not entry.encrypted
    ]
    if stored:
        report.notes.append(
            f"{len(stored)} entry/entries are stored uncompressed, so their bytes are in "
            "the file as they are: `ctfc detect` on the archive finds them, and `strings` works"
        )
    if not report.entries and not report.encrypted_names:
        report.notes.append("no file headers: the archive may be a fragment")
    return report


def _from_cab(data: bytes, read_contents: bool) -> ArchiveReport:
    """A cabinet, decompressing stored and MSZIP folders."""
    cabinet = cab_module.read(data)
    if read_contents:
        cabinet = cab_module.extract(data, cabinet)
    report = ArchiveReport(format="cab")
    report.notes += cabinet.notes
    methods = {folder.method for folder in cabinet.folders}
    for file in cabinet.files:
        folder = cabinet.folders[file.folder] if file.folder < len(cabinet.folders) else None
        report.entries.append(
            ArchiveEntry(
                name=file.name,
                size=file.size,
                method=folder.method if folder else "?",
                data=file.data,
                # from_dos, not the cabinet's own text: every event in ctfc
                # carries the same "... UTC" shape so that sorting is a string
                # comparison (a DOS stamp has no zone - it is the writer's clock).
                modified=timestamps.from_dos(file.date, file.time),
                notes=[f"modified {file.dos_timestamp}"],
            )
        )
    if methods & {"LZX", "Quantum"}:
        report.notes.append(
            "LZX/Quantum folders are not decoded by ctfc: `cabextract <file>` does it"
        )
    return report


# ---------------------------------------------------------------------------
# What to do next
# ---------------------------------------------------------------------------


def _search_flags(report: ArchiveReport, flagset: FlagSet | None) -> None:
    """Look for flags in whatever contents came out, and in the Docker report."""
    found: list[str] = []
    for entry in report.entries:
        if entry.data and len(entry.data) <= FLAG_SEARCH_LIMIT:
            found += [hit.text for hit in find_flags(entry.data, flagset)]
    if report.docker is not None:
        found += report.docker.flags
    seen: list[str] = []
    for text in found:
        if text not in seen:
            seen.append(text)
    report.flags = seen


def _add_commands(report: ArchiveReport, path: str) -> None:
    """The commands worth printing: cracking, and the local tool for the rest."""
    if report.format == "7z" and report.any_encrypted:
        mode, extractor = HASHCAT_MODES["7z"]
        report.commands.append(f"{extractor} {path} > h && hashcat -m {mode} h wordlist")
        report.commands.append(f"7z x -p<password> {path}")
    if report.format.startswith("rar") and report.any_encrypted:
        mode, extractor = HASHCAT_MODES.get(report.format, HASHCAT_MODES["rar5"])
        report.commands.append(f"{extractor} {path} > h && hashcat -m {mode} h wordlist")
        report.commands.append(f"unrar x -p<password> {path}")
    if report.format == "tar" and report.docker is not None:
        report.commands.append(f"ctfc archive {path} --extract ./layers && ctfc scan ./layers")
    unopened = [entry for entry in report.entries if entry.data is None and entry.content_expected]
    if unopened and not report.any_encrypted and report.format != "rar4":
        tool = {"7z": "7z x", "cab": "cabextract", "tar": "tar xf", "rar5": "unrar x"}.get(
            report.format, "7z x"
        )
        report.commands.append(f"{tool} {path}   # for the entries ctfc could not decode")
    if report.format.startswith("rar"):
        report.commands.append(f"unrar x {path}   # RAR's compression is unrar's job")


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _safe_destination(root: Path, name: str) -> Path:
    """Where a member may be written: inside `root`, whatever its name claims.

    An archive can name a member `../../etc/cron.d/x`; this is the one place
    that has to refuse it, because everything else only reads.
    """
    cleaned = name.replace("\\", "/").lstrip("/")
    parts = [part for part in cleaned.split("/") if part not in ("", ".", "..")]
    if not parts:
        parts = ["unnamed"]
    return root.joinpath(*parts)


def extract(report: ArchiveReport, destination: str | Path) -> list[Path]:
    """Write every member whose bytes we have, plus each Docker layer's files."""
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    # For a Docker image the layer tars are expanded into one folder each below,
    # so writing them out again as single files only doubles the output.
    skip = (
        {layer.digest.lstrip("./") for layer in report.docker.layers}
        if report.docker is not None
        else set()
    )
    for entry in report.entries:
        if entry.data is None or entry.name.lstrip("./") in skip:
            continue
        target = _safe_destination(root, entry.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(entry.data)
        written.append(target)
    if report.docker is not None:
        written += _extract_docker(report.docker, root)
    if report.trailing:
        target = root / "trailing-data.bin"
        target.write_bytes(report.trailing)
        written.append(target)
    return written


def _extract_docker(docker: dockerimg.DockerReport, root: Path) -> list[Path]:
    """One folder per layer, so `ctfc scan` can walk them in build order."""
    written: list[Path] = []
    for layer in docker.layers:
        if not layer.data:
            continue
        folder = root / f"layer-{layer.index:02d}-{layer.short}"
        try:
            members, _end = tarfmt.read_entries(layer.data)
        except tarfmt.TarError:
            continue
        for member in members:
            if not member.is_file:
                continue
            target = _safe_destination(folder, member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tarfmt.member(layer.data, member))
            written.append(target)
    return written
