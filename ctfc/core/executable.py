"""Triage the executables that are not Windows PEs: ELF, Java, Android.

`ctfc pe` covers Windows. This covers the other three things a challenge hands
you, and each is read for one specific reason:

- **ELF** (Linux): the segment flags, the libraries it needs, the symbols it
  imports and whether its section headers were thrown away. `readelf` is usually
  installed and does more than this - what this adds is the triage reading:
  a writable *and* executable segment, a missing section table, a UPX header, an
  overlay after the last section, a `RUNPATH` pointing somewhere odd.
- **Java `.class` / `.jar`**: the **constant pool**. Every string a Java program
  uses is in it, in one block, in clear - the key, the URL, the password, the
  flag. There is no need to decompile anything to read them, and a JAR is just
  a ZIP of class files, so the whole archive can be swept at once.
- **Android `.dex`**: the same idea. A DEX file begins with a table of *every*
  string in the program, as an array of offsets; following it needs twenty lines
  and gives what `strings` cannot, because the lengths are ULEB128 and the text
  is MUTF-8.

Nothing is executed and nothing is disassembled: this reads tables and reports
what they say. For real reverse engineering the report names the tool
(`objdump`, `jadx`, `cfr`, `procyon`).
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field

from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet, find_flags
from ctfc.core.scoring import shannon_entropy

ELF_MAGIC = b"\x7fELF"
CLASS_MAGIC = b"\xca\xfe\xba\xbe"
DEX_MAGIC = b"dex\n"
MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe",  # 64-bit little endian
    b"\xce\xfa\xed\xfe",  # 32-bit little endian
    b"\xca\xfe\xba\xbe",  # a fat binary - same magic as a Java class!
)

# --- ELF -------------------------------------------------------------------
ELF_TYPES = {1: "relocatable object", 2: "executable", 3: "shared object / PIE", 4: "core dump"}
ELF_MACHINES = {
    0x02: "SPARC",
    0x03: "x86",
    0x08: "MIPS",
    0x14: "PowerPC",
    0x15: "PowerPC 64",
    0x16: "S390",
    0x28: "ARM",
    0x2A: "SuperH",
    0x32: "IA-64",
    0x3E: "x86-64",
    0xB7: "AArch64",
    0xF3: "RISC-V",
}
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
DT_NEEDED = 1
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHT_NOBITS = 8
# Imported symbols worth pointing at: the crypto and the "this is a dropper" set.
NOTABLE_SYMBOLS = {
    "AES_encrypt": "AES, from OpenSSL's low-level API",
    "AES_set_encrypt_key": "AES key schedule (OpenSSL)",
    "EVP_EncryptInit_ex": "OpenSSL EVP: the cipher name is a string nearby",
    "EVP_DecryptInit_ex": "OpenSSL EVP decryption",
    "EVP_BytesToKey": "OpenSSL's password-to-key function (`openssl enc`)",
    "PKCS5_PBKDF2_HMAC": "PBKDF2: the iteration count is an argument",
    "RAND_bytes": "OpenSSL randomness",
    "MD5_Init": "MD5",
    "SHA256_Init": "SHA-256",
    "crypt": "the libc password hash",
    "system": "runs a shell command",
    "popen": "runs a shell command and reads its output",
    "execve": "replaces itself with another program",
    "fork": "forks",
    "ptrace": "anti-debugging, or debugging something else",
    "dlopen": "loads a library by name at runtime",
    "socket": "opens a socket",
    "connect": "connects out",
    "inflate": "zlib decompression",
    "deflate": "zlib compression",
    "getenv": "reads the environment",
    "mprotect": "makes memory executable: unpacking, or shellcode",
}
PACKED_ENTROPY = 7.2

# --- Java ------------------------------------------------------------------
CONSTANT_UTF8 = 1
CONSTANT_INTEGER = 3
CONSTANT_FLOAT = 4
CONSTANT_LONG = 5
CONSTANT_DOUBLE = 6
CONSTANT_CLASS = 7
CONSTANT_STRING = 8
CONSTANT_FIELDREF = 9
CONSTANT_METHODREF = 10
CONSTANT_INTERFACE_METHODREF = 11
CONSTANT_NAME_AND_TYPE = 12
CONSTANT_METHOD_HANDLE = 15
CONSTANT_METHOD_TYPE = 16
CONSTANT_DYNAMIC = 17
CONSTANT_INVOKE_DYNAMIC = 18
CONSTANT_MODULE = 19
CONSTANT_PACKAGE = 20
# How many bytes each constant takes after its tag, and whether it eats two slots.
CONSTANT_SIZES = {
    CONSTANT_INTEGER: 4,
    CONSTANT_FLOAT: 4,
    CONSTANT_LONG: 8,
    CONSTANT_DOUBLE: 8,
    CONSTANT_CLASS: 2,
    CONSTANT_STRING: 2,
    CONSTANT_FIELDREF: 4,
    CONSTANT_METHODREF: 4,
    CONSTANT_INTERFACE_METHODREF: 4,
    CONSTANT_NAME_AND_TYPE: 4,
    CONSTANT_METHOD_HANDLE: 3,
    CONSTANT_METHOD_TYPE: 2,
    CONSTANT_DYNAMIC: 4,
    CONSTANT_INVOKE_DYNAMIC: 4,
    CONSTANT_MODULE: 2,
    CONSTANT_PACKAGE: 2,
}
JAVA_VERSIONS = {
    45: "Java 1.1",
    46: "Java 1.2",
    47: "Java 1.3",
    48: "Java 1.4",
    49: "Java 5",
    50: "Java 6",
    51: "Java 7",
    52: "Java 8",
    53: "Java 9",
    54: "Java 10",
    55: "Java 11",
    56: "Java 12",
    57: "Java 13",
    58: "Java 14",
    59: "Java 15",
    60: "Java 16",
    61: "Java 17",
    62: "Java 18",
    63: "Java 19",
    64: "Java 20",
    65: "Java 21",
}
MAX_STRINGS = 4000
MIN_STRING = 3
MAX_CLASSES = 200
# Java and Android APIs worth naming when they appear in the pool.
NOTABLE_JAVA = {
    "javax/crypto/Cipher": "javax.crypto: the transformation string says the mode",
    "javax/crypto/spec/SecretKeySpec": "a key is built from bytes - they are nearby",
    "javax/crypto/spec/IvParameterSpec": "an IV is built from bytes",
    "javax/crypto/spec/PBEKeySpec": "PBKDF2: the iteration count is an argument",
    "java/security/MessageDigest": "a hash",
    "java/util/Base64": "base64",
    "android/util/Base64": "base64 (Android)",
    "java/lang/Runtime": "runs a command",
    "java/net/HttpURLConnection": "makes an HTTP request",
    "java/net/URL": "a URL is built",
    "dalvik/system/DexClassLoader": "loads more code at runtime (Android)",
    "java/lang/reflect/Method": "calls methods by name, to hide them",
}


class ExecutableError(FormatError):
    """The data is not an executable this module reads."""


@dataclass
class ElfSection:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    entropy: float = 0.0

    @property
    def permissions(self) -> str:
        """The section flags that matter: write, execute, allocate."""
        return "".join(
            letter for bit, letter in ((0x2, "A"), (0x1, "W"), (0x4, "X")) if self.flags & bit
        )


@dataclass
class ElfSegment:
    kind: int
    flags: int
    offset: int
    address: int
    file_size: int
    memory_size: int

    @property
    def permissions(self) -> str:
        return "".join(
            letter for bit, letter in ((0x4, "R"), (0x2, "W"), (0x1, "X")) if self.flags & bit
        )


@dataclass
class ElfReport:
    """What an ELF is and what it needs."""

    bits: int = 64
    endian: str = "little"
    kind: str = ""
    machine: str = ""
    entry: int = 0
    interpreter: str = ""
    soname: str = ""
    runpath: str = ""
    needed: list[str] = field(default_factory=list)
    sections: list[ElfSection] = field(default_factory=list)
    segments: list[ElfSegment] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    notable: list[str] = field(default_factory=list)
    stripped: bool = False
    static: bool = False
    overlay: int = 0
    overlay_bytes: bytes = b""
    end_of_file: int = 0  # where the structures end, header tables included
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bits": self.bits,
            "endian": self.endian,
            "kind": self.kind,
            "machine": self.machine,
            "entry": self.entry,
            "interpreter": self.interpreter,
            "soname": self.soname,
            "runpath": self.runpath,
            "needed": list(self.needed),
            "sections": [
                {
                    "name": section.name,
                    "permissions": section.permissions,
                    "address": section.address,
                    "size": section.size,
                    "entropy": round(section.entropy, 2),
                }
                for section in self.sections
            ],
            "segments": [
                {
                    "permissions": segment.permissions,
                    "offset": segment.offset,
                    "file_size": segment.file_size,
                    "memory_size": segment.memory_size,
                }
                for segment in self.segments
            ],
            "symbols": list(self.symbols),
            "notable": list(self.notable),
            "stripped": self.stripped,
            "static": self.static,
            "overlay": self.overlay,
            "notes": list(self.notes),
        }


@dataclass
class ClassReport:
    """One Java class file, read for its constant pool."""

    name: str = ""
    superclass: str = ""
    version: str = ""
    strings: list[str] = field(default_factory=list)  # the literals the code uses
    classes: list[str] = field(default_factory=list)  # the types it refers to
    members: list[str] = field(default_factory=list)  # method and field names
    notable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "superclass": self.superclass,
            "version": self.version,
            "strings": list(self.strings),
            "classes": list(self.classes),
            "members": list(self.members),
            "notable": list(self.notable),
            "notes": list(self.notes),
        }


@dataclass
class DexReport:
    """An Android DEX file, read for its string table."""

    version: str = ""
    strings: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    checksum_ok: bool | None = None
    notable: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "strings": list(self.strings),
            "classes": list(self.classes),
            "checksum_ok": self.checksum_ok,
            "notable": list(self.notable),
            "notes": list(self.notes),
        }


@dataclass
class ExecutableReport:
    """Whichever executable it was."""

    kind: str = ""  # "elf" | "class" | "jar" | "dex" | "pe" | "macho"
    elf: ElfReport | None = None
    classes: list[ClassReport] = field(default_factory=list)
    dex: DexReport | None = None
    flags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "elf": None if self.elf is None else self.elf.to_dict(),
            "classes": [item.to_dict() for item in self.classes],
            "dex": None if self.dex is None else self.dex.to_dict(),
            "flags": list(self.flags),
            "notes": list(self.notes),
            "commands": list(self.commands),
        }


def sniff(data: bytes) -> str:
    """Which executable this is: "elf", "class", "jar", "dex", "pe", "macho", or ""."""
    if data[:4] == ELF_MAGIC:
        return "elf"
    if data[:4] == DEX_MAGIC:
        return "dex"
    if data[:4] == CLASS_MAGIC:
        # Same four bytes as a Mach-O fat binary. A class file's next field is a
        # version number below 100; a fat binary's is an architecture count.
        minor = int.from_bytes(data[4:6], "big")
        major = int.from_bytes(data[6:8], "big")
        if 45 <= major <= 100 and minor < 100:
            return "class"
        return "macho"
    if data[:4] in MACHO_MAGICS:
        return "macho"
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
        except (zipfile.BadZipFile, OSError, ValueError):
            return ""
        if any(name.endswith(".class") for name in names) or "META-INF/MANIFEST.MF" in names:
            return "jar"
        if "classes.dex" in names:
            return "dex"
        return ""
    return ""


def analyse(data: bytes, flagset: FlagSet | None = None) -> ExecutableReport:
    """Triage whichever executable this is."""
    kind = sniff(data)
    report = ExecutableReport(kind=kind)
    if kind == "elf":
        report.elf = read_elf(data)
        report.commands.append("readelf -a <file> | less      # the full headers")
        report.commands.append("objdump -d <file> | less      # the disassembly")
    elif kind == "class":
        report.classes = [read_class(data)]
        report.commands.append("javap -c -p <file>            # the bytecode, from the JDK")
        report.commands.append("cfr <file> / procyon <file>   # back to Java source")
    elif kind == "jar":
        report.classes = read_jar(data, report)
        report.commands.append("ctfc zip <file>               # the archive itself")
        report.commands.append("cfr <file> / jadx <file>      # back to Java source")
    elif kind == "dex":
        if data[:4] == b"PK\x03\x04":
            report.notes.append(
                "this is an APK: `ctfc zip <file>` lists it, and `classes.dex` inside it "
                "is what this reads - extract it first"
            )
            raise ExecutableError(
                "this is an APK (a ZIP): extract classes.dex from it and run ctfc on that, "
                "or use `jadx <file>` for the whole app"
            )
        report.dex = read_dex(data)
        report.commands.append("jadx <file>                   # back to Java source")
    elif kind == "pe":
        raise ExecutableError("this is a Windows executable: `ctfc pe <file>` reads it")
    elif kind == "macho":
        raise ExecutableError(
            "this is a Mach-O (macOS) binary, which ctfc does not read: "
            "`otool -l <file>` and `nm <file>` do"
        )
    else:
        raise ExecutableError(
            "not an executable this reads: expected ELF, a Java class or JAR, or an "
            "Android DEX. `ctfc pe` reads Windows binaries, `ctfc detect` says what "
            "this is instead"
        )
    _find_flags(report, flagset)
    return report


def _find_flags(report: ExecutableReport, flagset: FlagSet | None) -> None:
    """Flags in the strings each reader recovered - which is why they are read."""
    texts: list[str] = []
    if report.elf is not None:
        texts += report.elf.symbols + report.elf.needed + [report.elf.runpath]
    for item in report.classes:
        texts += item.strings + item.members
    if report.dex is not None:
        texts += report.dex.strings
    for text in texts:
        if not text:
            continue
        for hit in find_flags(text.encode("utf-8", "replace"), flagset):
            if hit.text not in report.flags:
                report.flags.append(hit.text)


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


def read_elf(data: bytes) -> ElfReport:
    """Read an ELF's headers, sections, segments and dynamic information."""
    if data[:4] != ELF_MAGIC:
        raise ExecutableError("not an ELF (the four bytes 7f 45 4c 46 are missing)")
    if len(data) < 52:
        raise ExecutableError(f"truncated: {len(data)} bytes, the header alone is 52")
    report = ElfReport()
    report.bits = 64 if data[4] == 2 else 32
    report.endian = "big" if data[5] == 2 else "little"
    order = report.endian
    wide = report.bits == 64

    def number(offset: int, size: int) -> int:
        if offset + size > len(data):
            raise ExecutableError(f"a field at {offset} is past the end of the file")
        return int.from_bytes(data[offset : offset + size], order)

    report.kind = ELF_TYPES.get(number(16, 2), f"type {number(16, 2)}")
    machine = number(18, 2)
    report.machine = ELF_MACHINES.get(machine, f"machine {machine:#x}")
    report.entry = number(24, 8) if wide else number(24, 4)
    ph_offset = number(32, 8) if wide else number(28, 4)
    sh_offset = number(40, 8) if wide else number(32, 4)
    ph_entry_size = number(54, 2) if wide else number(42, 2)
    ph_count = number(56, 2) if wide else number(44, 2)
    sh_entry_size = number(58, 2) if wide else number(46, 2)
    sh_count = number(60, 2) if wide else number(48, 2)
    sh_strndx = number(62, 2) if wide else number(50, 2)

    if sh_count > 10_000 or ph_count > 1000:
        raise ExecutableError(
            f"the header claims {sh_count} sections and {ph_count} segments, which is "
            "not a real ELF"
        )

    # --- segments. The flags word moves between 32- and 64-bit, which is the
    # one real difference between the two layouts.
    for index in range(ph_count):
        at = ph_offset + index * ph_entry_size
        if at + ph_entry_size > len(data):
            break
        kind = number(at, 4)
        if wide:
            segment = ElfSegment(
                kind=kind,
                flags=number(at + 4, 4),
                offset=number(at + 8, 8),
                address=number(at + 16, 8),
                file_size=number(at + 32, 8),
                memory_size=number(at + 40, 8),
            )
        else:
            segment = ElfSegment(
                kind=kind,
                flags=number(at + 24, 4),
                offset=number(at + 4, 4),
                address=number(at + 8, 4),
                file_size=number(at + 16, 4),
                memory_size=number(at + 20, 4),
            )
        report.segments.append(segment)
        if kind == PT_INTERP and segment.file_size:
            raw = data[segment.offset : segment.offset + segment.file_size]
            report.interpreter = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")

    # --- sections, named through the section-name string table.
    names = b""
    if sh_count and sh_strndx < sh_count:
        at = sh_offset + sh_strndx * sh_entry_size
        if at + sh_entry_size <= len(data):
            start = number(at + 24, 8) if wide else number(at + 16, 4)
            size = number(at + 32, 8) if wide else number(at + 20, 4)
            names = data[start : start + size]
    for index in range(sh_count):
        at = sh_offset + index * sh_entry_size
        if at + sh_entry_size > len(data):
            break
        name_offset = number(at, 4)
        end = names.find(b"\x00", name_offset)
        name = names[name_offset : end if end >= 0 else None].decode("utf-8", "replace")
        section = ElfSection(
            name=name,
            kind=number(at + 4, 4),
            flags=number(at + 8, 8) if wide else number(at + 8, 4),
            address=number(at + 16, 8) if wide else number(at + 12, 4),
            offset=number(at + 24, 8) if wide else number(at + 16, 4),
            size=number(at + 32, 8) if wide else number(at + 20, 4),
        )
        if section.kind != SHT_NOBITS and section.offset + section.size <= len(data):
            section.entropy = shannon_entropy(data[section.offset : section.offset + section.size])
        report.sections.append(section)

    _elf_dynamic(data, report, number, wide)
    _elf_symbols(data, report, number, wide, sh_entry_size)
    # The section header table itself normally sits at the very end of the file,
    # after all the section data, so it has to count as part of the file or every
    # ELF looks like it has an appended payload.
    report.end_of_file = max(
        sh_offset + sh_count * sh_entry_size, ph_offset + ph_count * ph_entry_size
    )
    _elf_notes(data, report)
    return report


def _elf_dynamic(data: bytes, report: ElfReport, number, wide: bool) -> None:
    """The dynamic table: which libraries it needs, and from where."""
    dynamic = next((s for s in report.sections if s.name == ".dynamic"), None)
    strings = next((s for s in report.sections if s.name == ".dynstr"), None)
    if dynamic is None:
        segment = next((s for s in report.segments if s.kind == PT_DYNAMIC), None)
        if segment is None:
            report.static = True
            return
        start, size = segment.offset, segment.file_size
    else:
        start, size = dynamic.offset, dynamic.size
    table = data[strings.offset : strings.offset + strings.size] if strings is not None else b""
    step = 16 if wide else 8
    for at in range(start, min(start + size, len(data)) - step + 1, step):
        tag = number(at, 8) if wide else number(at, 4)
        value = number(at + 8, 8) if wide else number(at + 4, 4)
        if tag == 0:
            break
        if tag in (DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH) and table:
            end = table.find(b"\x00", value)
            text = table[value : end if end >= 0 else None].decode("utf-8", "replace")
            if tag == DT_NEEDED:
                report.needed.append(text)
            elif tag == DT_SONAME:
                report.soname = text
            else:
                report.runpath = text


def _elf_symbols(data: bytes, report: ElfReport, number, wide: bool, sh_entry_size: int) -> None:
    """The dynamic symbol names: what it calls, and what it exports."""
    report.stripped = not any(section.kind == SHT_SYMTAB for section in report.sections)
    dynsym = next((s for s in report.sections if s.kind == SHT_DYNSYM), None)
    strings = next((s for s in report.sections if s.name == ".dynstr"), None)
    if dynsym is None or strings is None:
        return
    table = data[strings.offset : strings.offset + strings.size]
    entry = 24 if wide else 16
    for at in range(dynsym.offset, min(dynsym.offset + dynsym.size, len(data)) - entry + 1, entry):
        name_offset = number(at, 4)
        end = table.find(b"\x00", name_offset)
        name = table[name_offset : end if end >= 0 else None].decode("utf-8", "replace")
        if name and name not in report.symbols:
            report.symbols.append(name)
        if len(report.symbols) >= MAX_STRINGS:
            break
    for name in report.symbols:
        meaning = NOTABLE_SYMBOLS.get(name)
        if meaning:
            report.notable.append(f"{name}: {meaning}")


def _elf_notes(data: bytes, report: ElfReport) -> None:
    """The triage reading: the things that make this binary unusual."""
    if not report.sections:
        report.notes.append(
            "no section headers at all: they were stripped off, which is what a packer "
            "does (the program only needs the segments). `readelf -l` still works"
        )
    for segment in report.segments:
        if segment.kind == PT_LOAD and {"W", "X"} <= set(segment.permissions):
            report.notes.append(
                f"a loadable segment is writable *and* executable ({segment.permissions}) "
                "at offset "
                f"{segment.offset:#x}: that is either a packer or self-modifying code"
            )
        if segment.kind == PT_GNU_STACK and "X" in segment.permissions:
            report.notes.append("the stack is executable: an old binary, or a deliberate one")
    if b"UPX!" in data[:4096] or any("upx" in s.name.lower() for s in report.sections):
        report.notes.append(
            "UPX: the header says so. `upx -d <file>` unpacks it, and the original "
            "sections come back"
        )
    for section in report.sections:
        if section.entropy >= PACKED_ENTROPY and section.size > 2048:
            report.notes.append(
                f"section {section.name!r} has entropy {section.entropy:.2f}: it is "
                "compressed, encrypted or packed data rather than code"
            )
    if report.static:
        report.notes.append(
            "statically linked (no dynamic table): every library is inside it, so the "
            "symbol names are the only guide - and `strings` is more useful than usual"
        )
    if report.stripped:
        report.notes.append(
            "stripped (no symbol table): function names are gone. The dynamic symbols "
            "below are the imported ones, which survive stripping"
        )
    if report.runpath:
        report.notes.append(
            f"RUNPATH/RPATH {report.runpath!r}: the loader searches there first, which "
            "is a hijacking path if it is writable"
        )
    ends = [
        section.offset + section.size for section in report.sections if section.kind != SHT_NOBITS
    ]
    ends += [segment.offset + segment.file_size for segment in report.segments]
    ends.append(report.end_of_file)
    end = max(ends, default=0)
    if end and len(data) > end:
        report.overlay = len(data) - end
        report.overlay_bytes = data[end:]
        report.notes.append(
            f"{report.overlay} byte(s) after the last section or segment: an appended "
            "payload is invisible to every normal tool. `ctfc detect` the tail"
        )


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


def read_class(data: bytes) -> ClassReport:
    """Read a Java class file's constant pool, which is where its strings are.

    The pool is a list of tagged entries, and the only awkward parts are that it
    is **1-indexed** and that a long or a double takes *two* slots - a design
    mistake from 1995 that every parser has to carry. UTF-8 entries hold every
    name and literal in the class; a `String` entry is a pointer to one of them,
    which is how the literals can be told apart from the identifiers.
    """
    if data[:4] != CLASS_MAGIC:
        raise ExecutableError("not a Java class file (the magic cafebabe is missing)")
    if len(data) < 10:
        raise ExecutableError(f"truncated: {len(data)} bytes")
    report = ClassReport()
    minor = int.from_bytes(data[4:6], "big")
    major = int.from_bytes(data[6:8], "big")
    report.version = f"class file {major}.{minor} ({JAVA_VERSIONS.get(major, 'unknown Java')})"
    count = int.from_bytes(data[8:10], "big")
    if count > 100_000:
        raise ExecutableError(f"a constant pool of {count} entries is not a real class")

    utf8: dict[int, str] = {}
    string_refs: list[int] = []
    class_refs: list[int] = []
    name_refs: list[int] = []
    # A `Class` constant does not hold a name, it holds the index of the UTF-8
    # entry that does. `this_class` then points at the `Class` constant, so
    # resolving a class name is two hops and this map is the first one.
    class_names: dict[int, int] = {}
    position = 10
    index = 1
    while index < count:
        if position >= len(data):
            raise ExecutableError(f"the constant pool ends early, at entry {index} of {count}")
        tag = data[position]
        position += 1
        if tag == CONSTANT_UTF8:
            if position + 2 > len(data):
                raise ExecutableError("a UTF-8 constant has no length")
            length = int.from_bytes(data[position : position + 2], "big")
            raw = data[position + 2 : position + 2 + length]
            if len(raw) < length:
                raise ExecutableError("a UTF-8 constant runs past the end of the file")
            utf8[index] = _modified_utf8(raw)
            position += 2 + length
        elif tag in CONSTANT_SIZES:
            size = CONSTANT_SIZES[tag]
            if tag == CONSTANT_STRING:
                string_refs.append(int.from_bytes(data[position : position + 2], "big"))
            elif tag == CONSTANT_CLASS:
                name_index = int.from_bytes(data[position : position + 2], "big")
                class_refs.append(name_index)
                class_names[index] = name_index
            elif tag == CONSTANT_NAME_AND_TYPE:
                name_refs.append(int.from_bytes(data[position : position + 2], "big"))
            position += size
        else:
            raise ExecutableError(f"constant pool tag {tag} at {position - 1} is not valid")
        # A long or a double takes two slots. Nobody knows why either.
        index += 2 if tag in (CONSTANT_LONG, CONSTANT_DOUBLE) else 1

    if position + 6 <= len(data):
        this_class = int.from_bytes(data[position + 2 : position + 4], "big")
        super_class = int.from_bytes(data[position + 4 : position + 6], "big")
        report.name = _resolve_class(utf8, class_names, this_class)
        report.superclass = _resolve_class(utf8, class_names, super_class)

    report.strings = [utf8[ref] for ref in string_refs if ref in utf8][:MAX_STRINGS]
    report.classes = sorted({utf8[ref] for ref in class_refs if ref in utf8})[:MAX_STRINGS]
    report.members = sorted({utf8[ref] for ref in name_refs if ref in utf8})[:MAX_STRINGS]
    for needle, why in NOTABLE_JAVA.items():
        if any(needle in name for name in report.classes):
            report.notable.append(f"{needle}: {why}")
    if report.strings:
        report.notes.append(
            f"{len(report.strings)} string literal(s) in the constant pool: a key, a URL "
            "or a password in a Java program is one of them, in clear"
        )
    return report


def _resolve_class(utf8: dict[int, str], class_names: dict[int, int], index: int) -> str:
    """A class name, through the two hops the format requires.

    `this_class` is the index of a `Class` constant; that constant holds the
    index of the UTF-8 entry with the actual name. A malformed file may point
    straight at the UTF-8 entry, so that reading is accepted as a fallback.
    """
    if index in class_names:
        return utf8.get(class_names[index], "")
    return utf8.get(index, "")


def _modified_utf8(raw: bytes) -> str:
    """Java's "modified UTF-8": a NUL is two bytes, and astral characters are six.

    Python's decoder rejects both forms, so the two substitutions are undone
    first. It matters because a class file with a NUL in a string - which an
    obfuscator will happily emit - otherwise refuses to decode at all.
    """
    if b"\xc0\x80" in raw:
        raw = raw.replace(b"\xc0\x80", b"\x00")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


def read_jar(data: bytes, report: ExecutableReport) -> list[ClassReport]:
    """Every class in a JAR, read for its constant pool.

    A JAR is a ZIP, so this is a sweep rather than a parse: the point is to get
    every string of every class in one place, because that is where the key is.
    """
    classes: list[ClassReport] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        names = [name for name in archive.namelist() if name.endswith(".class")]
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ExecutableError(f"not a readable JAR: {exc}") from exc
    if len(names) > MAX_CLASSES:
        report.notes.append(
            f"{len(names)} class files: the first {MAX_CLASSES} are read. "
            "`ctfc zip <file>` lists them all"
        )
        names = names[:MAX_CLASSES]
    for name in names:
        try:
            payload = archive.read(name)
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError) as exc:
            report.notes.append(f"{name}: {exc}")
            continue
        try:
            item = read_class(payload)
        except ExecutableError as exc:
            report.notes.append(f"{name}: {exc}")
            continue
        item.notes.insert(0, f"from {name}")
        classes.append(item)
    try:
        manifest = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
    except (KeyError, zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        manifest = ""
    for line in manifest.splitlines():
        if line.lower().startswith(("main-class:", "class-path:", "premain-class:")):
            report.notes.append(f"manifest: {line.strip()}")
    if not classes:
        raise ExecutableError("no readable class file in this JAR")
    return classes


# ---------------------------------------------------------------------------
# Android DEX
# ---------------------------------------------------------------------------


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """An unsigned LEB128: 7 bits per byte, little end first."""
    value = 0
    shift = 0
    for step in range(5):
        if offset + step >= len(data):
            raise ExecutableError("a LEB128 runs past the end of the file")
        byte = data[offset + step]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset + step + 1
        shift += 7
    raise ExecutableError("a LEB128 longer than five bytes is not valid")


def read_dex(data: bytes) -> DexReport:
    """Read a DEX file's string table, which holds every string in the program.

    The header points at an array of `string_ids`, each a file offset to a
    `string_data_item`: a ULEB128 *character* count followed by MUTF-8 bytes.
    Following that array is the whole trick - the strings themselves are not
    contiguous and `strings` finds only some of them.
    """
    if data[:4] != DEX_MAGIC:
        raise ExecutableError("not a DEX file (the magic dex\\n is missing)")
    if len(data) < 112:
        raise ExecutableError(f"truncated: {len(data)} bytes, the header alone is 112")
    report = DexReport(version=data[4:7].decode("ascii", "replace"))
    if int.from_bytes(data[40:44], "little") != 0x12345678:
        raise ExecutableError(
            "the endian tag is not 0x12345678: this is a big-endian DEX, which no real "
            "Android build produces"
        )
    # The header's own checksum is an adler32 of everything after it, which is a
    # free integrity check: a patched DEX usually has a stale one.
    import zlib

    report.checksum_ok = (
        int.from_bytes(data[8:12], "little") == zlib.adler32(data[12:]) & 0xFFFFFFFF
    )

    string_count = int.from_bytes(data[56:60], "little")
    string_offset = int.from_bytes(data[60:64], "little")
    type_count = int.from_bytes(data[64:68], "little")
    type_offset = int.from_bytes(data[68:72], "little")
    if string_count > 1_000_000:
        raise ExecutableError(f"{string_count} strings is not a real DEX file")

    ids: list[int] = []
    for index in range(min(string_count, MAX_STRINGS * 2)):
        at = string_offset + index * 4
        if at + 4 > len(data):
            break
        ids.append(int.from_bytes(data[at : at + 4], "little"))
    for offset in ids:
        if not 0 < offset < len(data):
            continue
        try:
            length, start = _uleb128(data, offset)
        except ExecutableError:
            continue
        end = data.find(b"\x00", start)
        raw = data[start : end if end >= 0 else start + length * 3]
        text = _modified_utf8(raw)
        if len(text) >= MIN_STRING:
            report.strings.append(text)
        if len(report.strings) >= MAX_STRINGS:
            report.notes.append(f"only the first {MAX_STRINGS} strings are listed")
            break

    # The type table is a list of indexes into the string table, so the class
    # names come out of the strings we already have.
    for index in range(min(type_count, MAX_STRINGS)):
        at = type_offset + index * 4
        if at + 4 > len(data):
            break
        string_index = int.from_bytes(data[at : at + 4], "little")
        if string_index < len(report.strings):
            name = report.strings[string_index]
            if name.startswith("L") and name.endswith(";"):
                report.classes.append(name[1:-1].replace("/", "."))

    for needle, why in NOTABLE_JAVA.items():
        if any(needle in text for text in report.strings):
            report.notable.append(f"{needle}: {why}")
    if report.checksum_ok is False:
        report.notes.append(
            "the header checksum does not match the file: it was edited after being "
            "built, which is worth knowing"
        )
    report.notes.append(
        f"{len(report.strings)} string(s) from the string table: every string the "
        "program uses is there, including the ones `strings` misses"
    )
    return report
