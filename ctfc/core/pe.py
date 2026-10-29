"""Triage a Windows executable: what it is, what it calls, and what is bolted on.

A PE file is a set of nested headers that each say where the next thing is, so
reading it is a matter of following offsets carefully:

    MZ ....... e_lfanew at 0x3C points at ->
    PE\\0\\0 ... COFF header (machine, section count, timestamp)
               optional header (entry point, subsystem, and 16 data directories)
               section headers (name, where it is on disk, where it is in memory)

Two things make a PE different from most formats here. Addresses inside it are
**RVAs** - offsets into the image once Windows has laid it out in memory, not
offsets in the file - so every lookup has to be translated back through the
section table. And the file on disk is usually *bigger* than the sections
describe: whatever sits past the last section is an **overlay**, which is where a
dropper keeps its payload and an installer its archive.

What this reports, and why each one matters in a challenge:

- **packing**: a section with high entropy, or a raw size of zero and a large
  virtual size, or a name like `UPX0`. A packed binary has almost no imports,
  because it resolves them itself at run time.
- **imports**: the API names say what the program does far more plainly than any
  disassembly - `VirtualAlloc` + `CreateRemoteThread` is injection, `CryptDecrypt`
  means a key is in there somewhere, `InternetOpenUrl` means it phones home.
- **W+X sections**: writable *and* executable is what self-modifying or unpacking
  code needs, and no compiler emits it.
- **overlay**: appended data, handed straight to `ctfc detect`.
- **.NET**: if directory 14 is present the real code is IL, and a decompiler
  (dnSpy, ILSpy) reads it like source - there is no point disassembling it.

Nothing is executed; this only reads bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ctfc.core.scoring import shannon_entropy

MZ = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"
PE32_MAGIC = 0x010B
PE32PLUS_MAGIC = 0x020B
COFF_SIZE = 20
SECTION_SIZE = 40
MAX_SECTIONS = 96
MAX_IMPORTS = 4000

MACHINES = {
    0x014C: "x86 (32-bit)",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x01C4: "ARMv7 (Thumb-2)",
    0x0200: "Itanium",
    0x0EBC: "EFI byte code",
}
SUBSYSTEMS = {
    1: "native (driver)",
    2: "Windows GUI",
    3: "Windows console",
    5: "OS/2",
    7: "POSIX",
    9: "Windows CE",
    10: "EFI application",
    13: "EFI ROM",
    16: "Windows boot application",
}
# Section characteristics worth naming.
SECTION_EXECUTE = 0x20000000
SECTION_READ = 0x40000000
SECTION_WRITE = 0x80000000
SECTION_UNINITIALISED = 0x00000080
# Data directory slots we look at.
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_SECURITY = 4
DIR_TLS = 9
DIR_CLR = 14
# Section names that give a packer away.
PACKER_SECTIONS = {
    "UPX0": "UPX",
    "UPX1": "UPX",
    "UPX2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    "ASPack": "ASPack",
    ".themida": "Themida",
    ".winlice": "WinLicense",
    "Themida": "Themida",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".enigma1": "Enigma",
    ".petite": "Petite",
    ".MPRESS1": "MPRESS",
    ".nsp0": "NsPack",
}
# (API name, what using it means). Matched case-insensitively, prefix-wise, so
# the A/W suffixes are covered by one entry.
NOTABLE_IMPORTS = (
    ("VirtualAlloc", "allocates executable memory: unpacking or shellcode"),
    ("VirtualProtect", "changes page permissions: self-modifying code"),
    ("WriteProcessMemory", "writes into another process"),
    ("CreateRemoteThread", "runs code in another process: injection"),
    ("NtUnmapViewOfSection", "process hollowing"),
    ("QueueUserAPC", "injection through an APC"),
    ("SetWindowsHookEx", "hooks input: keylogging"),
    ("GetAsyncKeyState", "reads the keyboard: keylogging"),
    ("LoadLibrary", "resolves a DLL at run time: hides what it imports"),
    ("GetProcAddress", "resolves an API by name at run time"),
    ("CryptDecrypt", "decrypts data: a key is in here"),
    ("CryptGenKey", "generates a key"),
    ("CryptImportKey", "imports a key"),
    ("BCryptDecrypt", "decrypts data (CNG)"),
    ("InternetOpen", "makes an HTTP request"),
    ("InternetReadFile", "downloads data"),
    ("URLDownloadToFile", "downloads a file"),
    ("WinHttpOpen", "makes an HTTP request"),
    ("socket", "raw network access"),
    ("WinExec", "runs a command"),
    ("ShellExecute", "runs a program"),
    ("CreateProcess", "starts a process"),
    ("RegSetValue", "writes to the registry: persistence"),
    ("RegCreateKey", "creates a registry key"),
    ("IsDebuggerPresent", "anti-debug check"),
    ("CheckRemoteDebuggerPresent", "anti-debug check"),
    ("NtQueryInformationProcess", "anti-debug check"),
    ("OutputDebugString", "anti-debug trick"),
    ("GetTickCount", "timing check: anti-debug or sandbox evasion"),
    ("Sleep", "delays execution: sandbox evasion"),
    ("FindFirstFile", "enumerates files"),
    ("CreateService", "installs a service: persistence"),
    ("AdjustTokenPrivileges", "escalates privileges"),
)
PACKED_ENTROPY = 7.2  # a section above this is compressed or encrypted
FEW_IMPORTS = 10  # a real program imports far more than this


class PeError(Exception):
    """The data is not a PE we can read."""


@dataclass
class Section:
    """One section header, plus what its bytes look like."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def flags(self) -> str:
        parts = []
        if self.characteristics & SECTION_READ:
            parts.append("R")
        if self.characteristics & SECTION_WRITE:
            parts.append("W")
        if self.characteristics & SECTION_EXECUTE:
            parts.append("X")
        return "".join(parts) or "-"

    @property
    def writable_and_executable(self) -> bool:
        return bool(self.characteristics & SECTION_WRITE) and bool(
            self.characteristics & SECTION_EXECUTE
        )


@dataclass
class PeReport:
    """What the executable is and what it does."""

    machine: str = ""
    bits: int = 32
    subsystem: str = ""
    timestamp: int = 0
    timestamp_text: str = ""
    entry_point: int = 0
    is_dll: bool = False
    is_dotnet: bool = False
    signed: bool = False
    sections: list[Section] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    overlay: bytes = b""
    overlay_offset: int = 0
    notable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def import_count(self) -> int:
        return sum(len(names) for names in self.imports.values())

    def to_dict(self) -> dict:
        return {
            "machine": self.machine,
            "bits": self.bits,
            "subsystem": self.subsystem,
            "timestamp": self.timestamp,
            "timestamp_text": self.timestamp_text,
            "entry_point": self.entry_point,
            "is_dll": self.is_dll,
            "is_dotnet": self.is_dotnet,
            "signed": self.signed,
            "sections": [
                {
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "virtual_size": section.virtual_size,
                    "raw_size": section.raw_size,
                    "flags": section.flags,
                    "entropy": round(section.entropy, 2),
                }
                for section in self.sections
            ],
            "imports": {dll: list(names) for dll, names in self.imports.items()},
            "import_count": self.import_count,
            "exports": list(self.exports),
            "overlay_size": len(self.overlay),
            "overlay_offset": self.overlay_offset,
            "notable": list(self.notable),
            "notes": list(self.notes),
        }


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


class Pe:
    """A parsed PE, with the RVA translation everything else needs."""

    def __init__(self, data: bytes) -> None:
        if data[:2] != MZ:
            raise PeError("not a PE: the file must start with 'MZ'")
        if len(data) < 0x40:
            raise PeError("truncated: there is not even a DOS header")
        self.data = data
        pe_offset = _u32(data, 0x3C)
        if pe_offset <= 0 or pe_offset + COFF_SIZE + 4 > len(data):
            raise PeError(f"e_lfanew points to {pe_offset}, which is outside the file")
        if data[pe_offset : pe_offset + 4] != PE_SIGNATURE:
            raise PeError(
                f"no 'PE\\0\\0' at {pe_offset}: this is a DOS or OS/2 executable, not a PE"
            )
        self.pe_offset = pe_offset
        coff = pe_offset + 4
        self.machine = _u16(data, coff)
        self.section_count = _u16(data, coff + 2)
        self.timestamp = _u32(data, coff + 4)
        self.optional_size = _u16(data, coff + 16)
        self.characteristics = _u16(data, coff + 18)
        if self.section_count > MAX_SECTIONS:
            raise PeError(f"{self.section_count} sections is not plausible")

        optional = coff + COFF_SIZE
        if optional + 2 > len(data):
            raise PeError("truncated before the optional header")
        magic = _u16(data, optional)
        if magic == PE32PLUS_MAGIC:
            self.bits = 64
            directories_at = optional + 112
        elif magic == PE32_MAGIC:
            self.bits = 32
            directories_at = optional + 96
        else:
            raise PeError(f"unknown optional header magic {magic:#06x}")
        self.entry_point = _u32(data, optional + 16)
        self.subsystem = _u16(data, optional + 68)
        # The number of directories is declared, but 16 is what the layout assumes.
        count = _u32(data, directories_at - 4) if directories_at - 4 + 4 <= len(data) else 16
        self.directories: list[tuple[int, int]] = []
        for index in range(min(count, 16)):
            at = directories_at + index * 8
            if at + 8 > len(data):
                break
            self.directories.append((_u32(data, at), _u32(data, at + 4)))

        self.sections: list[Section] = []
        table = optional + self.optional_size
        for index in range(self.section_count):
            at = table + index * SECTION_SIZE
            if at + SECTION_SIZE > len(data):
                break
            name = data[at : at + 8].rstrip(b"\x00").decode("latin-1", "replace")
            section = Section(
                name=name,
                virtual_size=_u32(data, at + 8),
                virtual_address=_u32(data, at + 12),
                raw_size=_u32(data, at + 16),
                raw_offset=_u32(data, at + 20),
                characteristics=_u32(data, at + 36),
            )
            body = data[section.raw_offset : section.raw_offset + section.raw_size]
            # Shannon of an all-identical block is zero, but the log can land on
            # -0.0, which prints as "-0.00". Note that max(-0.0, 0.0) returns
            # -0.0 in Python, since the two compare equal - so test explicitly.
            measured = shannon_entropy(body) if body else 0.0
            section.entropy = measured if measured > 0.0 else 0.0
            self.sections.append(section)

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def offset_of(self, rva: int) -> int | None:
        """Translate an RVA into a file offset, through the section table.

        This is the step that makes a PE awkward: addresses in the headers refer
        to the image as Windows maps it, not to the file.
        """
        for section in self.sections:
            start = section.virtual_address
            # Use the larger of the two sizes: a section may be padded either way.
            size = max(section.virtual_size, section.raw_size)
            if start <= rva < start + size:
                offset = section.raw_offset + (rva - start)
                return offset if 0 <= offset < len(self.data) else None
        # Before the first section: the headers are mapped one-to-one.
        if self.sections and rva < self.sections[0].virtual_address:
            return rva if rva < len(self.data) else None
        return None

    def string_at(self, rva: int, limit: int = 256) -> str:
        offset = self.offset_of(rva)
        if offset is None:
            return ""
        end = self.data.find(b"\x00", offset, offset + limit)
        raw = self.data[offset : end if end != -1 else offset + limit]
        return raw.decode("latin-1", "replace")

    def imports(self) -> dict[str, list[str]]:
        """The import table: DLL name -> the functions taken from it."""
        rva, _size = self.directory(DIR_IMPORT)
        if not rva:
            return {}
        start = self.offset_of(rva)
        if start is None:
            return {}
        result: dict[str, list[str]] = {}
        total = 0
        for index in range(1000):
            at = start + index * 20
            if at + 20 > len(self.data):
                break
            lookup_rva = _u32(self.data, at)
            name_rva = _u32(self.data, at + 12)
            address_rva = _u32(self.data, at + 16)
            if not (lookup_rva or name_rva or address_rva):
                break  # the all-zero descriptor ends the table
            dll = self.string_at(name_rva) or f"(unnamed {index})"
            names: list[str] = []
            # The lookup table holds the names; a bound import only has the
            # address table, so fall back to it.
            thunk_rva = lookup_rva or address_rva
            thunk = self.offset_of(thunk_rva)
            if thunk is not None:
                step = 8 if self.bits == 64 else 4
                high_bit = 1 << (63 if self.bits == 64 else 31)
                for slot in range(2000):
                    at_thunk = thunk + slot * step
                    if at_thunk + step > len(self.data) or total >= MAX_IMPORTS:
                        break
                    value = int.from_bytes(self.data[at_thunk : at_thunk + step], "little")
                    if value == 0:
                        break
                    if value & high_bit:
                        names.append(f"#{value & 0xFFFF}")  # imported by ordinal
                    else:
                        # IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name.
                        name = self.string_at((value & 0x7FFFFFFF) + 2)
                        if name:
                            names.append(name)
                    total += 1
            result[dll] = names
        return result

    def exports(self) -> list[str]:
        """Exported function names, for a DLL."""
        rva, _size = self.directory(DIR_EXPORT)
        start = self.offset_of(rva) if rva else None
        if start is None or start + 40 > len(self.data):
            return []
        count = _u32(self.data, start + 24)
        names_rva = _u32(self.data, start + 32)
        table = self.offset_of(names_rva) if names_rva else None
        if table is None:
            return []
        names = []
        for index in range(min(count, 4000)):
            at = table + index * 4
            if at + 4 > len(self.data):
                break
            name = self.string_at(_u32(self.data, at))
            if name:
                names.append(name)
        return names

    def overlay(self) -> tuple[int, bytes]:
        """Whatever sits past the last section on disk."""
        end = max(
            (
                section.raw_offset + section.raw_size
                for section in self.sections
                if section.raw_size
            ),
            default=0,
        )
        # A signature lives past the sections legitimately; do not call it overlay.
        security_rva, security_size = self.directory(DIR_SECURITY)
        if security_rva and security_size:
            end = max(end, security_rva + security_size)
        if 0 < end < len(self.data):
            return end, self.data[end:]
        return len(self.data), b""


def analyse(data: bytes) -> PeReport:
    """Read the executable and report what it is and what it does."""
    from ctfc.core import timestamps

    pe = Pe(data)
    report = PeReport(
        machine=MACHINES.get(pe.machine, f"machine {pe.machine:#06x}"),
        bits=pe.bits,
        subsystem=SUBSYSTEMS.get(pe.subsystem, f"subsystem {pe.subsystem}"),
        timestamp=pe.timestamp,
        entry_point=pe.entry_point,
        is_dll=bool(pe.characteristics & 0x2000),
        sections=pe.sections,
    )
    readings = timestamps.readings(pe.timestamp)
    unix = next((r for r in readings if r.epoch == "Unix seconds"), None)
    now = datetime.now(UTC)
    if unix is not None and unix.when <= now:
        report.timestamp_text = unix.text
    elif unix is not None:
        # A build date in the future is not a date. Roslyn and other
        # reproducible-build toolchains put a hash of the content in this field
        # instead, which always has the high bit set - hence a "date" past 2038.
        report.notes.append(
            f"the build timestamp ({pe.timestamp:#x}) reads as {unix.text}, which is in the "
            "future: it is a content hash from a reproducible build, not a build date. "
            "Every .NET SDK assembly looks like this"
        )
    elif pe.timestamp:
        report.notes.append(
            f"the build timestamp ({pe.timestamp:#x}) is not a plausible date: it was "
            "zeroed for a reproducible build, or faked"
        )

    report.is_dotnet = bool(pe.directory(DIR_CLR)[0])
    report.signed = bool(pe.directory(DIR_SECURITY)[0])
    report.imports = pe.imports()
    report.exports = pe.exports()
    report.overlay_offset, report.overlay = pe.overlay()

    if report.is_dotnet:
        report.notes.append(
            ".NET assembly (a CLR directory is present): the real code is IL, so a "
            "decompiler reads it almost as source - dnSpy, ILSpy or `ilspycmd`. "
            "Disassembling the native stub is a waste of time"
        )
        if pe.machine not in MACHINES:
            # Every .NET SDK assembly on this machine reports 0xfd1d here. The
            # code is IL, so the field does not have to name a real CPU.
            report.notes.append(
                f"its machine field ({pe.machine:#06x}) is not a real CPU, which is normal "
                "for an IL-only assembly: there is no native code for it to describe"
            )

    # Packing: the name, then the shape of the sections.
    for section in pe.sections:
        packer = PACKER_SECTIONS.get(section.name)
        if packer:
            report.notes.append(f"section {section.name!r} names a packer: {packer}")
        if section.entropy >= PACKED_ENTROPY and section.raw_size > 1024:
            report.notes.append(
                f"section {section.name!r} has entropy {section.entropy:.2f}: it is "
                "compressed or encrypted, which is what a packed or protected binary looks like"
            )
        if section.writable_and_executable:
            report.notes.append(
                f"section {section.name!r} is writable AND executable: no compiler emits "
                "that, so the code modifies or unpacks itself"
            )
        if section.raw_size == 0 and section.virtual_size > 4096:
            report.notes.append(
                f"section {section.name!r} takes no space on disk but {section.virtual_size} "
                "bytes in memory: it is filled in at run time (classic unpacking stub)"
            )

    if report.imports and report.import_count < FEW_IMPORTS:
        report.notes.append(
            f"only {report.import_count} import(s) in total: a packed binary resolves its "
            "own imports at run time, which is why the table looks nearly empty"
        )
    if not report.imports:
        report.notes.append(
            "no import table at all: either packed, or the imports are resolved by hand "
            "from the export tables (shellcode-style)"
        )

    # What the APIs say the program does.
    lowered = {name.lower(): dll for dll, names in report.imports.items() for name in names}
    for api, meaning in NOTABLE_IMPORTS:
        for imported, dll in lowered.items():
            if imported.startswith(api.lower()):
                report.notable.append(f"{imported} ({dll}): {meaning}")
                break

    if pe.directory(DIR_TLS)[0]:
        report.notes.append(
            "a TLS directory is present: its callbacks run before the entry point, which "
            "is a standard anti-debug trick - set a breakpoint on them, not on main"
        )
    if report.overlay:
        report.notes.append(
            f"{len(report.overlay)} byte(s) of overlay after the last section (offset "
            f"{report.overlay_offset}): a dropper keeps its payload here. "
            "`ctfc detect` it, or `ctfc pe <file> --extract <dir>`"
        )
    if report.signed:
        report.notes.append("an Authenticode signature is present (directory 4)")
    return report
