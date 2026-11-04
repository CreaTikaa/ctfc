"""Strings out of a Go or Rust binary, where `strings` is useless.

Why `strings` fails on these two. In C, a literal is NUL-terminated, so a
scanner can find its end. In Go and Rust a string is a **(pointer, length)
pair**: the bytes in the read-only section carry no terminator at all, and the
compiler packs the literals end to end. `strings` therefore prints one
thousand-character run with the interesting part buried in it:

    ...exit hook invoked exitCYBN{go_string_literal}<invalid reflect.Value>...

Two things are done here instead.

**The slice scan.** Every 8-byte-aligned position in the data sections is read
as a (pointer, length) pair; when the pointer lands inside `.rodata`, the
length is small, and the bytes there are printable, that is a string header and
the string is cut at exactly the right place. On the Go binary above this
returns `CYBN{go_string_literal}` on its own, as its own entry. It is not a
heuristic about *characters* - it reads the structure the compiler emitted.

**The Go function table.** A Go binary carries `.gopclntab`, whose
`funcnametab` is a block of NUL-terminated names: every function in the binary,
including the program's own (`main.decrypt`, `main.(*Vault).Open`), which is
the map a reverse engineer wants first. The header is read for `go1.16` and
later (magics `0xfffffffa`, `0xfffffff0`, `0xfffffff1`); the pre-1.16 layout is
named and not parsed, because guessing it would be worse than saying so.

**Rust gets less, and the report says so.** Rust puts the length of a literal
in the *code* as an immediate, not in a data-section header, so the slice scan
finds nothing to read (verified on a real `rustc -O` binary). What is
extractable without disassembling is the compiler version, the `/rustc/<hash>`
marker and the **source file paths** the panic machinery embeds - which still
gives the crate layout and often the author's own module names.

Checked against the real toolchains: the function names against
`go tool nm`, the version against `go version`, and both fixtures are built by
the tests when `go` / `rustc` are installed (and skipped, with the reason, when
they are not).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# pclntab magics, newest first. The value is the Go release that introduced it.
PCLNTAB_MAGICS = {
    0xFFFFFFF1: "go1.20+",
    0xFFFFFFF0: "go1.18",
    0xFFFFFFFA: "go1.16",
    0xFFFFFFFB: "go1.2",  # named, not parsed: a different header entirely
}
GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"
GO_VERSION_RE = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?")
RUSTC_VERSION_RE = re.compile(rb"rustc[ -](\d+\.\d+\.\d+)")
RUSTC_PATH_RE = re.compile(rb"/rustc/([0-9a-f]{8,40})")
# A source path a Rust binary embeds for its panic messages.
RUST_SOURCE_RE = re.compile(rb"[\w./-]{0,60}\.rs")

# Limits. A binary is big and a challenge payload is not: these keep the scan
# bounded and the report readable.
MIN_SLICE = 2
MAX_SLICE = 512
MAX_SLICES = 4000
MAX_FUNCTIONS = 20_000
# The sections a string header can live in.
DATA_SECTIONS = (".rodata", ".data", ".data.rel.ro", ".noptrdata", ".rdata")


@dataclass
class Section:
    """Just enough of a section for this module (any reader can fill it)."""

    name: str
    address: int
    offset: int
    size: int


@dataclass
class BinStrings:
    """What a Go or Rust binary gave up."""

    toolchain: str = ""  # "go" | "rust" | ""
    version: str = ""
    module: str = ""  # Go: the module path from .go.buildinfo ("github.com/x/y")
    slices: list[str] = field(default_factory=list)  # exact string literals
    functions: list[str] = field(default_factory=list)  # Go: from .gopclntab
    files: list[str] = field(default_factory=list)  # Go: compilation units
    sources: list[str] = field(default_factory=list)  # Rust: embedded .rs paths
    notes: list[str] = field(default_factory=list)

    @property
    def own_functions(self) -> list[str]:
        """The program's own functions, not the runtime's or a dependency's.

        The module path from `.go.buildinfo` is the exact answer when it is
        there: a function of this program is `main.*` or `<module>/...`. The
        skip list below is the fallback for a binary built without it.
        """
        if self.module:
            keep = ("main.", f"{self.module}.", f"{self.module}/")
            return [name for name in self.functions if name.startswith(keep)]
        skip = (
            "runtime.",
            "internal/",
            "type:",
            "go:",
            "sync.",
            "syscall.",
            "reflect.",
            "os.",
            "fmt.",
            "strconv.",
            "sort.",
            "time.",
            "errors.",
            "io.",
            "bytes.",
            "strings.",
            "unicode",
            "math",
            "encoding/",
            "crypto/",
            "bufio.",
            "context.",
            "path",
            "regexp",
            "net.",
            "net/",
            "vendor/",
        )
        return [name for name in self.functions if not name.startswith(skip)]

    def to_dict(self) -> dict:
        return {
            "toolchain": self.toolchain,
            "version": self.version,
            "module": self.module,
            "slices": list(self.slices),
            "functions": list(self.functions),
            "own_functions": self.own_functions,
            "files": list(self.files),
            "sources": list(self.sources),
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Which toolchain built this?
# ---------------------------------------------------------------------------


def detect(data: bytes, sections: list[Section]) -> tuple[str, str]:
    """("go"|"rust"|"", version). Cheap: section names first, then markers."""
    names = {section.name for section in sections}
    if ".gopclntab" in names or ".note.go.buildid" in names or GO_BUILDINFO_MAGIC in data[:]:
        return "go", go_version(data, sections)
    if b"go:buildid" in data[:4096] or GO_VERSION_RE.search(data[:1_000_000]):
        return "go", go_version(data, sections)
    rust = RUSTC_VERSION_RE.search(data)
    if rust:
        return "rust", f"rustc {rust.group(1).decode()}"
    marker = RUSTC_PATH_RE.search(data)
    if marker:
        return "rust", f"rustc commit {marker.group(1).decode()}"
    return "", ""


def go_module(data: bytes) -> str:
    """The module path `.go.buildinfo` records, which `go version -m` prints too."""
    at = data.find(GO_BUILDINFO_MAGIC)
    if at < 0:
        return ""
    window = data[at : at + 4096]
    match = re.search(rb"path\t([!-~]{1,200})", window)
    return match.group(1).decode("utf-8", "replace") if match else ""


def go_version(data: bytes, sections: list[Section]) -> str:
    """The Go release, from `.go.buildinfo` - the same place `go version` reads."""
    at = data.find(GO_BUILDINFO_MAGIC)
    if at >= 0:
        match = GO_VERSION_RE.search(data[at : at + 512])
        if match:
            return match.group(0).decode()
    match = GO_VERSION_RE.search(data)
    return match.group(0).decode() if match else ""


# ---------------------------------------------------------------------------
# The slice scan: a (pointer, length) pair is a string header
# ---------------------------------------------------------------------------


def _reader(data: bytes, sections: list[Section]):
    """A function that reads `n` bytes at a virtual address, or b""."""
    mapped = [
        section
        for section in sections
        if section.address and section.size and section.name not in (".bss", ".noptrbss", ".tbss")
    ]

    def read(address: int, count: int) -> bytes:
        for section in mapped:
            if section.address <= address < section.address + section.size:
                start = section.offset + (address - section.address)
                return data[start : start + count]
        return b""

    return read


def _printable(text: bytes) -> bool:
    """A literal worth reporting: printable, and not only whitespace."""
    if not text.strip():
        return False
    return all(32 <= byte < 127 or byte in (9, 10, 13) for byte in text)


def slice_strings(
    data: bytes, sections: list[Section], pointer_size: int = 8, limit: int = MAX_SLICES
) -> list[str]:
    """Every string a (pointer, length) header in the data sections points at.

    This is the part `strings` cannot do: the length comes from the binary's own
    structure, so each literal is cut exactly where the compiler ended it.
    """
    read = _reader(data, sections)
    rodata = next((item for item in sections if item.name == ".rodata"), None)
    if rodata is None or not rodata.address:
        return []
    low, high = rodata.address, rodata.address + rodata.size

    found: dict[bytes, None] = {}
    for section in sections:
        if section.name not in DATA_SECTIONS or not section.address:
            continue
        blob = data[section.offset : section.offset + section.size]
        for position in range(0, max(0, len(blob) - 2 * pointer_size), pointer_size):
            pointer = int.from_bytes(blob[position : position + pointer_size], "little")
            if not (low <= pointer < high):
                continue
            length = int.from_bytes(
                blob[position + pointer_size : position + 2 * pointer_size], "little"
            )
            if not (MIN_SLICE <= length <= MAX_SLICE):
                continue
            text = read(pointer, length)
            if len(text) == length and _printable(text):
                found.setdefault(text, None)
                if len(found) >= limit:
                    return [item.decode("utf-8", "replace") for item in found]
    return [item.decode("utf-8", "replace") for item in found]


# ---------------------------------------------------------------------------
# The Go function table
# ---------------------------------------------------------------------------


def find_pclntab(data: bytes) -> int:
    """Where the pclntab starts, when no section is named `.gopclntab`.

    A Windows Go binary keeps the table inside `.rdata`, and a stripped ELF
    keeps it without the section name, so the magic is searched for instead.
    A hit only counts when the two bytes after it are zero and the minLC and
    pointer-size fields are plausible - which is what the runtime itself checks.
    """
    for magic in (0xFFFFFFF1, 0xFFFFFFF0, 0xFFFFFFFA, 0xFFFFFFFB):
        needle = magic.to_bytes(4, "little")
        at = -1
        while True:
            at = data.find(needle, at + 1)
            if at < 0:
                break
            header = data[at : at + 8]
            if len(header) < 8:
                break
            if header[4:6] == b"\x00\x00" and header[6] in (1, 2, 4) and header[7] in (4, 8):
                return at
    return -1


def go_functions(data: bytes, sections: list[Section]) -> tuple[list[str], list[str], list[str]]:
    """(functions, files, notes) read from `.gopclntab`.

    The header, for go1.16 and later, is: magic (4), two pad bytes, minLC,
    pointer size, then a series of pointer-sized words. go1.18 inserted
    `textStart` after `nfiles`, which is the only difference that matters here.
    `funcnametab` is then a block of NUL-terminated names.
    """
    table = next((item for item in sections if item.name == ".gopclntab"), None)
    if table is not None:
        blob = data[table.offset : table.offset + table.size]
    else:
        at = find_pclntab(data)
        if at < 0:
            return [], [], ["no pclntab found: the function table could not be located"]
        blob = data[at:]
    if len(blob) < 64:
        return [], [], [".gopclntab is too short to hold a header"]

    magic = int.from_bytes(blob[:4], "little")
    if magic not in PCLNTAB_MAGICS:
        return [], [], [f"the pclntab magic {magic:#x} is not one ctfc knows"]
    release = PCLNTAB_MAGICS[magic]
    if magic == 0xFFFFFFFB:
        return (
            [],
            [],
            [
                "this is the go1.2-1.15 pclntab, whose header is laid out differently; "
                "ctfc does not parse it (the slice scan below still works). "
                "`go tool nm <file>` reads it"
            ],
        )

    pointer_size = blob[7] or 8
    if pointer_size not in (4, 8):
        return [], [], [f"pclntab pointer size {pointer_size} is not 4 or 8"]

    def word(index: int) -> int:
        start = 8 + index * pointer_size
        return int.from_bytes(blob[start : start + pointer_size], "little")

    # go1.18+ : nfunc, nfiles, textStart, funcnameOffset, cuOffset, ...
    # go1.16  : nfunc, nfiles,            funcnameOffset, cuOffset, ...
    shift = 1 if magic in (0xFFFFFFF0, 0xFFFFFFF1) else 0
    count = word(0)
    files_count = word(1)
    funcname_at = word(2 + shift)
    cu_at = word(3 + shift)
    filetab_at = word(4 + shift)

    notes = [f"pclntab {release}: {count} function(s), {files_count} file(s)"]
    if magic == 0xFFFFFFFA:
        notes.append(
            "the go1.16 header layout is used here; it is the documented one but is "
            "not the layout verified on this machine (which had go1.25)"
        )
    if not 0 < funcname_at < cu_at <= len(blob):
        return [], [], [*notes, "the funcname table offsets are out of range"]

    names = [
        name.decode("utf-8", "replace") for name in blob[funcname_at:cu_at].split(b"\x00") if name
    ][:MAX_FUNCTIONS]
    files: list[str] = []
    if 0 < filetab_at < len(blob):
        end = min(len(blob), filetab_at + 1_000_000)
        files = [
            item.decode("utf-8", "replace")
            for item in blob[filetab_at:end].split(b"\x00")
            if item and item.endswith((b".go", b".s"))
        ][:MAX_FUNCTIONS]
    return names, files, notes


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def rust_sources(data: bytes, limit: int = 400) -> list[str]:
    """The `.rs` paths a Rust binary embeds for its panic messages."""
    found: dict[str, None] = {}
    for match in RUST_SOURCE_RE.finditer(data):
        text = match.group(0).decode("utf-8", "replace")
        if len(text) < 5 or ".." in text:
            continue
        found.setdefault(text, None)
        if len(found) >= limit:
            break
    return list(found)


# ---------------------------------------------------------------------------
# The whole thing
# ---------------------------------------------------------------------------


def analyse(data: bytes, sections: list[Section], pointer_size: int = 8) -> BinStrings:
    """Read whichever of the two this is, and say what was not possible."""
    toolchain, version = detect(data, sections)
    report = BinStrings(toolchain=toolchain, version=version)
    if not toolchain:
        return report

    if toolchain == "go":
        report.module = go_module(data)
        if report.module:
            report.notes.append(f"module path (from .go.buildinfo): {report.module}")
        report.functions, report.files, notes = go_functions(data, sections)
        report.notes += notes
        report.slices = slice_strings(data, sections, pointer_size)
        own = report.own_functions
        if own:
            report.notes.append(
                f"{len(own)} function(s) outside the runtime and the standard library: "
                + ", ".join(own[:8])
                + (" ..." if len(own) > 8 else "")
            )
        report.notes.append(
            f"{len(report.slices)} string literal(s) read through their (pointer, length) "
            "headers - `strings` runs these together, because a Go string has no "
            "terminator"
        )
        return report

    report.sources = rust_sources(data)
    report.slices = slice_strings(data, sections, pointer_size)
    report.notes.append(
        "Rust puts the length of a literal in the code as an immediate, not in a "
        "data-section header, so the (pointer, length) scan finds little or nothing. "
        "What is here instead: the compiler version, and the source paths the panic "
        "machinery embeds. For the literals themselves, a disassembler is the tool "
        "(`objdump -d`, Ghidra, or `rustfilt` over `nm --demangle`)"
    )
    if report.sources:
        own = [path for path in report.sources if "/rustc/" not in path and "cargo" not in path]
        if own:
            report.notes.append(
                "source paths that are not the standard library's: " + ", ".join(own[:8])
            )
    return report
