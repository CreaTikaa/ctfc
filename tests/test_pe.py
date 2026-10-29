"""Tests for Windows executable triage (core/pe.py).

The hand-built PEs check the parser against the format; the tests at the bottom
check it against real binaries that happen to ship on a Debian box.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from ctfc.core import pe

# Real PEs that come with the mingw cross-compilers and the .NET SDK.
REAL_PE32 = Path("/usr/i686-w64-mingw32/lib/zlib1.dll")
REAL_PE32PLUS = Path("/usr/x86_64-w64-mingw32/lib/zlib1.dll")
REAL_DOTNET = Path("/usr/share/dotnet/sdk/8.0.427/System.Resources.Extensions.dll")


def build_pe(
    sections: list[tuple[str, int, int, int, bytes]],
    bits: int = 32,
    machine: int = 0x014C,
    timestamp: int = 1665826054,
    characteristics: int = 0x2000,
    directories: dict[int, tuple[int, int]] | None = None,
    overlay: bytes = b"",
) -> bytes:
    """A minimal but real PE. Each section is (name, vaddr, vsize, flags, body)."""
    optional_size = 240 if bits == 64 else 224
    headers_size = 0x80 + 4 + pe.COFF_SIZE + optional_size + len(sections) * pe.SECTION_SIZE
    raw_at = (headers_size + 511) // 512 * 512  # section data starts aligned

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x80).to_bytes(4, "little")

    coff = struct.pack(
        "<HHIIIHH", machine, len(sections), timestamp, 0, 0, optional_size, characteristics
    )

    optional = bytearray(optional_size)
    optional[0:2] = (pe.PE32PLUS_MAGIC if bits == 64 else pe.PE32_MAGIC).to_bytes(2, "little")
    optional[16:20] = (0x1000).to_bytes(4, "little")  # entry point
    optional[68:70] = (3).to_bytes(2, "little")  # console subsystem
    directory_at = 112 if bits == 64 else 96
    optional[directory_at - 4 : directory_at] = (16).to_bytes(4, "little")
    for index, (rva, size) in (directories or {}).items():
        at = directory_at + index * 8
        optional[at : at + 4] = rva.to_bytes(4, "little")
        optional[at + 4 : at + 8] = size.to_bytes(4, "little")

    table = bytearray()
    bodies = bytearray()
    cursor = raw_at
    for name, vaddr, vsize, flags, body in sections:
        padded = body + bytes(-len(body) % 512)
        entry = bytearray(pe.SECTION_SIZE)
        entry[0:8] = name.encode("latin-1")[:8].ljust(8, b"\x00")
        entry[8:12] = vsize.to_bytes(4, "little")
        entry[12:16] = vaddr.to_bytes(4, "little")
        entry[16:20] = len(padded).to_bytes(4, "little")
        entry[20:24] = (cursor if padded else 0).to_bytes(4, "little")
        entry[36:40] = flags.to_bytes(4, "little")
        table += entry
        bodies += padded
        cursor += len(padded)

    head = bytes(dos) + pe.PE_SIGNATURE + coff + bytes(optional) + bytes(table)
    return head + bytes(raw_at - len(head)) + bytes(bodies) + overlay


TEXT = pe.SECTION_READ | pe.SECTION_EXECUTE
DATA = pe.SECTION_READ | pe.SECTION_WRITE


def simple() -> bytes:
    return build_pe([(".text", 0x1000, 0x200, TEXT, b"\x90" * 0x200)])


# ---------------------------------------------------------------------------
# The headers
# ---------------------------------------------------------------------------


def test_a_file_that_is_not_mz_is_refused():
    with pytest.raises(pe.PeError, match="must start with 'MZ'"):
        pe.analyse(b"\x7fELF" + bytes(500))


def test_a_dos_executable_without_a_pe_header_is_named():
    """An NE/MZ-only binary is a real thing to be handed; say what it is."""
    data = bytearray(simple())
    data[0x80:0x84] = b"NE\x00\x00"
    with pytest.raises(pe.PeError, match="DOS or OS/2"):
        pe.analyse(bytes(data))


def test_an_e_lfanew_pointing_outside_the_file_is_refused():
    data = bytearray(simple())
    data[0x3C:0x40] = (0x7FFFFFFF).to_bytes(4, "little")
    with pytest.raises(pe.PeError, match="outside the file"):
        pe.analyse(bytes(data))


def test_an_unknown_optional_magic_is_refused():
    data = bytearray(simple())
    data[0x80 + 4 + pe.COFF_SIZE : 0x80 + 4 + pe.COFF_SIZE + 2] = (0x9999).to_bytes(2, "little")
    with pytest.raises(pe.PeError, match="optional header magic"):
        pe.analyse(bytes(data))


def test_an_absurd_section_count_is_refused():
    data = bytearray(simple())
    data[0x80 + 6 : 0x80 + 8] = (5000).to_bytes(2, "little")
    with pytest.raises(pe.PeError, match="not plausible"):
        pe.analyse(bytes(data))


def test_the_basics_are_read():
    report = pe.analyse(simple())
    assert report.machine == "x86 (32-bit)"
    assert report.bits == 32
    assert report.subsystem == "Windows console"
    assert report.entry_point == 0x1000
    assert report.is_dll is True  # characteristics 0x2000
    assert report.timestamp_text == "2022-10-15 09:27:34 UTC"


def test_a_pe32plus_is_recognised():
    report = pe.analyse(
        build_pe([(".text", 0x1000, 0x200, TEXT, b"\x90" * 0x200)], bits=64, machine=0x8664)
    )
    assert report.bits == 64
    assert report.machine == "x86-64"


def test_sections_are_listed_with_flags_and_entropy():
    report = pe.analyse(
        build_pe(
            [
                (".text", 0x1000, 0x200, TEXT, b"\x90" * 0x200),
                (".data", 0x2000, 0x100, DATA, bytes(0x100)),
            ]
        )
    )
    assert [section.name for section in report.sections] == [".text", ".data"]
    assert report.sections[0].flags == "RX"
    assert report.sections[1].flags == "RW"


def test_entropy_is_never_negative_zero():
    """Shannon of a constant block is 0, and max(-0.0, 0.0) is -0.0 in Python."""
    report = pe.analyse(build_pe([(".data", 0x1000, 0x100, DATA, bytes(0x200))]))
    assert report.sections[0].entropy == 0.0
    assert f"{report.sections[0].entropy:.2f}" == "0.00"


# ---------------------------------------------------------------------------
# What it says about the program
# ---------------------------------------------------------------------------


def test_a_writable_executable_section_is_called_out():
    report = pe.analyse(
        build_pe([(".text", 0x1000, 0x200, TEXT | pe.SECTION_WRITE, b"\x90" * 512)])
    )
    assert report.sections[0].writable_and_executable
    assert any("writable AND executable" in note for note in report.notes)


def test_a_packer_section_name_is_recognised():
    report = pe.analyse(build_pe([("UPX1", 0x1000, 0x200, TEXT, b"\x90" * 512)]))
    assert any("UPX" in note for note in report.notes)


def test_a_high_entropy_section_is_reported_as_packed():
    import random

    rng = random.Random(3)
    body = bytes(rng.randrange(256) for _ in range(4096))
    report = pe.analyse(build_pe([(".text", 0x1000, 0x1000, TEXT, body)]))
    assert any("compressed or encrypted" in note for note in report.notes)


def test_a_section_with_no_disk_space_is_reported():
    report = pe.analyse(build_pe([(".bss", 0x1000, 0x8000, DATA, b"")]))
    assert any("takes no space on disk" in note for note in report.notes)


def test_no_import_table_is_explained():
    report = pe.analyse(simple())
    assert any("no import table at all" in note for note in report.notes)


def test_a_future_timestamp_is_called_a_reproducible_build_hash():
    """Roslyn puts a content hash here, which always reads as a date past 2038."""
    report = pe.analyse(
        build_pe([(".text", 0x1000, 0x200, TEXT, bytes(512))], timestamp=0xD09D1425)
    )
    assert report.timestamp_text == ""
    assert any("reproducible build" in note for note in report.notes)


def test_a_dotnet_directory_sends_you_to_a_decompiler():
    report = pe.analyse(
        build_pe(
            [(".text", 0x1000, 0x200, TEXT, bytes(512))], directories={pe.DIR_CLR: (0x2000, 72)}
        )
    )
    assert report.is_dotnet
    assert any("dnSpy" in note for note in report.notes)


def test_a_tls_directory_is_flagged_as_anti_debug():
    report = pe.analyse(
        build_pe(
            [(".text", 0x1000, 0x200, TEXT, bytes(512))], directories={pe.DIR_TLS: (0x2000, 24)}
        )
    )
    assert any("before the entry point" in note for note in report.notes)


def test_an_overlay_is_found_and_offered():
    payload = b"\x89PNG\r\n\x1a\n" + b"appended payload"
    report = pe.analyse(build_pe([(".text", 0x1000, 0x200, TEXT, b"\x90" * 512)], overlay=payload))
    assert report.overlay == payload
    assert any("overlay after the last section" in note for note in report.notes)


def test_rva_translation_uses_the_section_table():
    """An RVA is an offset into the mapped image, not into the file."""
    data = build_pe([(".text", 0x1000, 0x200, TEXT, b"ABCD" + bytes(508))])
    parsed = pe.Pe(data)
    offset = parsed.offset_of(0x1000)
    assert offset is not None
    assert data[offset : offset + 4] == b"ABCD"
    assert parsed.offset_of(0x900000) is None


# ---------------------------------------------------------------------------
# Against real binaries
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not REAL_PE32.is_file(), reason="the mingw32 zlib1.dll is not installed")
def test_a_real_pe32_dll_parses_completely():
    report = pe.analyse(REAL_PE32.read_bytes())
    assert report.machine == "x86 (32-bit)" and report.bits == 32
    assert report.is_dll
    assert report.timestamp_text.startswith("2022-")
    # zlib exports these, which is a check on the export table walk.
    assert {"adler32", "crc32", "deflate", "inflate"} <= set(report.exports)
    assert "KERNEL32.dll" in report.imports
    assert "VirtualProtect" in report.imports["KERNEL32.dll"]
    assert {section.name for section in report.sections} >= {".text", ".data", ".rdata"}


@pytest.mark.skipif(not REAL_PE32PLUS.is_file(), reason="the mingw64 zlib1.dll is not installed")
def test_a_real_pe32plus_dll_parses_completely():
    """The 64-bit thunks are 8 bytes wide, so the import walk differs."""
    report = pe.analyse(REAL_PE32PLUS.read_bytes())
    assert report.bits == 64 and report.machine == "x86-64"
    assert {"adler32", "crc32", "deflate", "inflate"} <= set(report.exports)
    assert report.import_count > 20


@pytest.mark.skipif(not REAL_DOTNET.is_file(), reason="the .NET SDK is not installed")
def test_a_real_dotnet_assembly_is_explained_rather_than_misread():
    """Its machine field is not a CPU and its timestamp is a content hash."""
    report = pe.analyse(REAL_DOTNET.read_bytes())
    assert report.is_dotnet
    assert report.timestamp_text == ""
    assert any("reproducible build" in note for note in report.notes)
    assert any("not a real CPU" in note for note in report.notes)
    assert any("dnSpy" in note for note in report.notes)
