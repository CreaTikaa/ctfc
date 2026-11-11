"""Go and Rust binaries, checked against the real toolchains.

`strings` is useless on both: a Go or Rust string literal has no terminator,
so a scanner prints one thousand-character run with the interesting part buried
inside it. These tests build a real binary with the toolchain installed on the
machine - no committed 2 MB fixture - and then insist on three things:

1. the literal comes out **on its own**, cut where the compiler ended it;
2. the Go function table agrees with `go tool nm`, and the version with
   `go version`;
3. where the technique does not work (Rust's literals, a PE's absolute string
   headers), the report *says so* rather than returning something plausible.

Everything skips, with the reason printed, when the toolchain is missing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ctfc.core import binstrings, executable, pe

GO = shutil.which("go") or (
    "/usr/local/go/bin/go" if Path("/usr/local/go/bin/go").is_file() else None
)
RUSTC = shutil.which("rustc") or (
    str(Path.home() / ".cargo/bin/rustc") if (Path.home() / ".cargo/bin/rustc").is_file() else None
)
GO_FLAG = "CYBN{go_string_literal}"
RUST_FLAG = "CYBN{rust_string_literal}"
GO_SOURCE = f"""package main

import "fmt"

func main() {{
\tfmt.Println("{GO_FLAG}")
\tfmt.Println("the neighbour literal, which strings glues to the first")
}}
"""
RUST_SOURCE = f"""fn main() {{
    println!("{{}}", "{RUST_FLAG}");
    println!("{{}}", "the neighbour literal, glued by strings");
}}
"""


@pytest.fixture(scope="module")
def go_binary(tmp_path_factory) -> Path:
    if GO is None:
        pytest.skip("the Go toolchain is not installed on this machine")
    folder = tmp_path_factory.mktemp("go")
    (folder / "main.go").write_text(GO_SOURCE)
    (folder / "go.mod").write_text("module ctfcdemo\n\ngo 1.21\n")
    target = folder / "demo"
    result = subprocess.run(
        [GO, "build", "-o", str(target), "."],
        cwd=folder,
        capture_output=True,
        timeout=600,
        env={
            "HOME": str(folder),
            "PATH": "/usr/bin:/bin:/usr/local/go/bin",
            "GOCACHE": str(folder / "cache"),
        },
    )
    if result.returncode != 0:
        pytest.skip(f"go build failed: {result.stderr.decode()[:200]}")
    return target


@pytest.fixture(scope="module")
def rust_binary(tmp_path_factory) -> Path:
    if RUSTC is None:
        pytest.skip("the Rust toolchain is not installed on this machine")
    folder = tmp_path_factory.mktemp("rust")
    source = folder / "main.rs"
    source.write_text(RUST_SOURCE)
    target = folder / "demo"
    result = subprocess.run(
        [RUSTC, "-O", "-o", str(target), str(source)],
        cwd=folder,
        capture_output=True,
        timeout=600,
    )
    if result.returncode != 0:
        pytest.skip(f"rustc failed: {result.stderr.decode()[:200]}")
    return target


def read(path: Path) -> tuple[bytes, list[binstrings.Section]]:
    data = path.read_bytes()
    report = executable.analyse(data)
    sections = [
        binstrings.Section(item.name, item.address, item.offset, item.size)
        for item in (report.elf.sections if report.elf else [])
    ]
    return data, sections


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def test_the_go_literal_comes_out_on_its_own(go_binary):
    data, sections = read(go_binary)
    found = binstrings.analyse(data, sections)

    assert found.toolchain == "go"
    assert GO_FLAG in found.slices, "the literal must be its own entry, not part of a run"
    assert any("neighbour literal" in text for text in found.slices)


def test_strings_glues_what_the_slice_scan_separates(go_binary):
    """The reason this module exists, asserted rather than claimed."""
    data = go_binary.read_bytes()
    at = data.find(GO_FLAG.encode())
    assert at > 0
    # No NUL anywhere near it: a plain scanner cannot find either end.
    window = data[at - 40 : at + len(GO_FLAG) + 40]
    assert b"\x00" not in window


@pytest.mark.skipif(GO is None, reason="the Go toolchain is not installed")
def test_the_function_table_agrees_with_go_tool_nm(go_binary):
    data, sections = read(go_binary)
    functions, _files, _notes = binstrings.go_functions(data, sections)

    result = subprocess.run([GO, "tool", "nm", str(go_binary)], capture_output=True, timeout=300)
    if result.returncode != 0:
        pytest.skip(f"go tool nm failed: {result.stderr.decode()[:200]}")
    theirs = {
        line.split()[-1]
        for line in result.stdout.decode().splitlines()
        if line.strip() and len(line.split()) >= 2
    }

    assert "main.main" in functions
    assert "main.main" in theirs
    # Every name go tool nm calls a text symbol of the program must be in ours.
    theirs_own = {name for name in theirs if name.startswith("main.")}
    assert theirs_own <= set(functions), sorted(theirs_own - set(functions))


@pytest.mark.skipif(GO is None, reason="the Go toolchain is not installed")
def test_the_version_agrees_with_go_version(go_binary):
    data, sections = read(go_binary)
    ours = binstrings.go_version(data, sections)
    result = subprocess.run([GO, "version", str(go_binary)], capture_output=True, timeout=120)
    if result.returncode != 0:
        pytest.skip("go version failed on the built binary")
    assert ours and ours in result.stdout.decode()


def test_the_module_path_names_the_program_s_own_functions(go_binary):
    data, sections = read(go_binary)
    found = binstrings.analyse(data, sections)
    assert found.module == "ctfcdemo"
    assert found.own_functions == ["main.main"]  # the rest is runtime and stdlib


def test_ctfc_exe_reports_the_toolchain(go_binary):
    report = executable.analyse(go_binary.read_bytes())
    assert report.toolchain is not None
    assert report.toolchain.toolchain == "go"
    assert any("pclntab" in note for note in report.notes)
    assert any("go tool nm" in command for command in report.commands)
    assert GO_FLAG in report.flags  # found in the literals, not only by `solve`


def test_solve_reads_a_go_binary(go_binary):
    from ctfc.core.solve import solve

    report = solve(go_binary.read_bytes(), str(go_binary))
    assert GO_FLAG in [flag.text for flag in report.flags]


@pytest.mark.skipif(GO is None, reason="the Go toolchain is not installed")
def test_the_pclntab_locator_agrees_with_the_section(go_binary):
    """The magic scan must land exactly where the section header says."""
    data, sections = read(go_binary)
    section = next(item for item in sections if item.name == ".gopclntab")
    assert binstrings.find_pclntab(data) == section.offset


@pytest.mark.skipif(GO is None, reason="the Go toolchain is not installed")
def test_a_windows_go_binary_is_read_without_any_section_name(tmp_path, go_binary):
    """A Go PE keeps the table inside .rdata: the locator is what finds it."""
    folder = tmp_path / "win"
    folder.mkdir()
    (folder / "main.go").write_text(GO_SOURCE)
    (folder / "go.mod").write_text("module ctfcdemo\n\ngo 1.21\n")
    target = folder / "demo.exe"
    result = subprocess.run(
        [GO, "build", "-o", str(target), "."],
        cwd=folder,
        capture_output=True,
        timeout=600,
        env={
            "HOME": str(folder),
            "PATH": "/usr/bin:/bin:/usr/local/go/bin",
            "GOOS": "windows",
            "GOARCH": "amd64",
            "GOCACHE": str(folder / "cache"),
        },
    )
    if result.returncode != 0:
        pytest.skip(f"cross build failed: {result.stderr.decode()[:200]}")

    data = target.read_bytes()
    report = pe.analyse(data)
    assert report.toolchain is not None
    assert report.toolchain.module == "ctfcdemo"
    assert "main.main" in report.toolchain.functions
    # And it must admit what it cannot do here.
    assert any("image base" in note for note in report.notes)

    # The web Files tab shows the same table, and repeats the limit.
    result = _files_tab(data)
    facts = next(s for s in result["sections"] if s["title"] == "built by go")
    assert ["module", "ctfcdemo"] in facts["rows"]
    assert any("image base" in note for note in result["notes"])


def _files_tab(data: bytes) -> dict:
    """What the web Files tab sends back for a dropped binary."""
    import base64

    from ctfc.config import Config
    from ctfc.web.app import create_app

    app = create_app(Config(max_upload_mb=16))
    app.testing = True
    payload = {"input": "b64:" + base64.b64encode(data).decode(), "format": "auto", "options": {}}
    return app.test_client().post("/api/file", json=payload).get_json()


def test_the_web_files_tab_shows_the_go_report(go_binary):
    """The literals are the point of the reader: the page must show them, not only ELF."""
    result = _files_tab(go_binary.read_bytes())
    titles = [section["title"] for section in result["sections"]]
    assert "built by go" in titles
    literals = next(s for s in result["sections"] if s["title"].startswith("string literals"))
    assert GO_FLAG in literals["text"].splitlines()  # on its own line, not glued
    own = next(s for s in result["sections"] if "function(s) of this program" in s["title"])
    assert own["rows"] == [["main.main"]]
    assert GO_FLAG in result["flags"]


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def test_a_rust_binary_is_recognised_and_its_limit_stated(rust_binary):
    data, sections = read(rust_binary)
    found = binstrings.analyse(data, sections)

    assert found.toolchain == "rust"
    assert found.version  # a version or the rustc commit hash
    assert found.sources, "the embedded .rs paths are what is extractable here"
    assert any("immediate" in note for note in found.notes)
    assert any("disassembler" in note or "objdump" in note for note in found.notes)

    result = _files_tab(data)
    assert "built by rust" in [section["title"] for section in result["sections"]]
    assert any("source paths" in section["title"] for section in result["sections"])


def test_rust_does_not_invent_literals(rust_binary):
    """The slice scan finds little or nothing in a Rust binary - and must not pretend."""
    data, sections = read(rust_binary)
    found = binstrings.analyse(data, sections)
    for text in found.slices:
        at = data.find(text.encode())
        assert at >= 0, "a reported literal must really be in the file"


# ---------------------------------------------------------------------------
# The edges, with no toolchain needed
# ---------------------------------------------------------------------------


def test_a_plain_c_binary_is_neither():
    data = Path("/bin/ls").read_bytes()
    _data, sections = read(Path("/bin/ls"))
    found = binstrings.analyse(data, sections)
    assert found.toolchain == ""
    assert found.slices == []


def test_rubbish_does_not_raise():
    found = binstrings.analyse(b"\x7fELF not really", [])
    assert found.toolchain == ""


def test_a_truncated_pclntab_is_reported():
    sections = [binstrings.Section(".gopclntab", 0x1000, 0, 8)]
    _functions, _files, notes = binstrings.go_functions(
        b"\xf1\xff\xff\xff\x00\x00\x01\x08", sections
    )
    assert any("too short" in note for note in notes)


def test_an_unknown_pclntab_magic_is_named():
    sections = [binstrings.Section(".gopclntab", 0x1000, 0, 100)]
    _functions, _files, notes = binstrings.go_functions(b"\xaa" * 100, sections)
    assert any("magic" in note for note in notes)


def test_the_pre_1_16_layout_is_declined_rather_than_guessed():
    header = (0xFFFFFFFB).to_bytes(4, "little") + b"\x00\x00\x01\x08" + bytes(60)
    sections = [binstrings.Section(".gopclntab", 0x1000, 0, len(header))]
    _functions, _files, notes = binstrings.go_functions(header, sections)
    assert any("does not parse it" in note for note in notes)
