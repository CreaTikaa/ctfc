"""Tests for the executables that are not Windows PEs (core/executable.py).

Ground truth comes from outside wherever it exists: the ELF reader is checked
against the system's own binaries and `readelf`, and the Java reader against a
class the **JDK itself compiles**, compared with `javap -v`. The DEX fixture is
built from the format's own integrity rules (its adler32 checksum and SHA-1
signature are computed properly), which is the strongest check available here -
no Android tooling is installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ctfc.core import executable as ex

REAL_ELFS = [Path(path) for path in ("/bin/ls", "/bin/bash", "/usr/bin/python3")]
JAVA_SOURCE = """
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Probe {
    private static final String KEY = "0123456789abcdef";
    private static final String FLAG = "CYBN{javac_ground_truth}";

    public static void main(String[] args) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY.getBytes(), "AES"));
        System.out.println(cipher.doFinal(FLAG.getBytes()).length);
    }
}
"""

# ---------------------------------------------------------------------------
# sniff
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("executable_dropper.elf", "elf"),
        ("executable_secret.class", "class"),
        ("executable_secret.jar", "jar"),
        ("executable_app.dex", "dex"),
    ],
)
def test_sniff(fixture_bytes, name, expected):
    assert ex.sniff(fixture_bytes(name)) == expected


def test_a_windows_binary_is_sent_to_ctfc_pe():
    with pytest.raises(ex.ExecutableError, match="ctfc pe"):
        ex.analyse(b"MZ" + bytes(200))


def test_a_mach_o_is_named_rather_than_half_read():
    with pytest.raises(ex.ExecutableError, match="Mach-O"):
        ex.analyse(b"\xcf\xfa\xed\xfe" + bytes(200))


def test_a_java_class_and_a_fat_mach_o_share_a_magic_number():
    """cafebabe is both. The version field after it tells them apart."""
    assert ex.sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + bytes(100)) == "class"
    assert ex.sniff(b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + bytes(100)) == "macho"


def test_something_else_is_refused_with_a_direction():
    with pytest.raises(ex.ExecutableError, match="ctfc detect"):
        ex.analyse(b"\x89PNG\r\n\x1a\n" + bytes(100))


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


def test_elf_header_and_dynamic_table(fixture_bytes):
    report = ex.read_elf(fixture_bytes("executable_dropper.elf"))
    assert report.bits == 64
    assert report.endian == "little"
    assert report.kind == "executable"
    assert report.machine == "x86-64"
    assert report.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert report.needed == ["libc.so.6", "libcrypto.so.3"]
    assert report.runpath == "/tmp/lib"


def test_elf_symbols_and_what_they_mean(fixture_bytes):
    report = ex.read_elf(fixture_bytes("executable_dropper.elf"))
    assert "EVP_DecryptInit_ex" in report.symbols
    assert any("PBKDF2" in line for line in report.notable)
    assert any("mprotect" in line for line in report.notable)


def test_elf_notices_a_writable_executable_segment(fixture_bytes):
    report = ex.read_elf(fixture_bytes("executable_dropper.elf"))
    assert any("writable *and* executable" in note for note in report.notes)
    assert any("RUNPATH" in note for note in report.notes)


def test_elf_finds_what_is_appended_after_the_last_section(fixture_bytes):
    report = ex.read_elf(fixture_bytes("executable_dropper.elf"))
    assert report.overlay > 0
    assert report.overlay_bytes[:4] == b"PK\x03\x04"
    assert any("after the last section" in note for note in report.notes)


@pytest.mark.parametrize("path", REAL_ELFS, ids=[path.name for path in REAL_ELFS])
def test_elf_reads_the_systems_own_binaries(path):
    """A real ELF must read without a single note about being broken."""
    if not path.is_file():
        pytest.skip(f"{path} is not on this machine")
    report = ex.read_elf(path.read_bytes())
    assert report.bits in (32, 64)
    assert report.sections
    assert report.segments
    # The header tables live at the end of a normal ELF: that must not read as
    # an appended payload, which is the bug this test exists for.
    assert report.overlay == 0
    assert not any("after the last section" in note for note in report.notes)


@pytest.mark.parametrize("path", REAL_ELFS, ids=[path.name for path in REAL_ELFS])
def test_elf_needed_libraries_match_readelf(path):
    if not path.is_file():
        pytest.skip(f"{path} is not on this machine")
    if shutil.which("readelf") is None:
        pytest.skip("readelf is not installed")
    out = subprocess.run(
        ["readelf", "-d", str(path)], capture_output=True, timeout=60, check=True
    ).stdout.decode()
    theirs = [line.split("[")[1].split("]")[0] for line in out.splitlines() if "(NEEDED)" in line]
    assert ex.read_elf(path.read_bytes()).needed == theirs


def test_an_appended_payload_on_a_real_binary_is_seen():
    path = Path("/bin/ls")
    if not path.is_file():
        pytest.skip("/bin/ls is not on this machine")
    report = ex.read_elf(path.read_bytes() + b"CYBN{appended}" * 4)
    assert report.overlay == len(b"CYBN{appended}" * 4)


def test_elf_refuses_what_is_not_an_elf():
    with pytest.raises(ex.ExecutableError, match="not an ELF"):
        ex.read_elf(b"MZ" + bytes(100))


def test_an_elf_claiming_thousands_of_sections_is_refused(fixture_bytes):
    data = bytearray(fixture_bytes("executable_dropper.elf"))
    data[60:62] = (50_000).to_bytes(2, "little")
    with pytest.raises(ex.ExecutableError, match="not a real ELF"):
        ex.read_elf(bytes(data))


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------


def test_class_constant_pool(fixture_bytes):
    report = ex.read_class(fixture_bytes("executable_secret.class"))
    assert report.name == "Secret"
    assert report.superclass == "java/lang/Object"
    assert "AES/CBC/PKCS5Padding" in report.strings
    assert "0123456789abcdef" in report.strings
    assert "CYBN{java_literal}" in report.strings


def test_class_notable_apis(fixture_bytes):
    report = ex.read_class(fixture_bytes("executable_secret.class"))
    assert any("javax.crypto" in line for line in report.notable)
    assert any("SecretKeySpec" in line for line in report.notable)


def test_class_version_is_named(fixture_bytes):
    report = ex.read_class(fixture_bytes("executable_secret.class"))
    assert "Java 17" in report.version


def test_modified_utf8_handles_javas_two_byte_nul():
    """Java encodes a NUL as c0 80, which Python's UTF-8 decoder rejects."""
    assert ex._modified_utf8(b"a\xc0\x80b") == "a\x00b"


def test_a_long_constant_takes_two_pool_slots():
    """A 1995 design mistake every parser has to carry: skip it and the pool shifts."""
    pool = bytes([5]) + (1).to_bytes(8, "big")  # CONSTANT_Long
    pool += bytes([1]) + (4).to_bytes(2, "big") + b"name"
    pool += bytes([7]) + (3).to_bytes(2, "big")  # Class -> entry 3 ("name")
    header = (0xCAFEBABE).to_bytes(4, "big") + (0).to_bytes(2, "big") + (61).to_bytes(2, "big")
    data = header + (5).to_bytes(2, "big") + pool + bytes(8)
    report = ex.read_class(data)
    assert "name" in report.classes


def test_class_refuses_rubbish():
    with pytest.raises(ex.ExecutableError, match="not a Java class"):
        ex.read_class(b"PK\x03\x04" + bytes(100))
    with pytest.raises(ex.ExecutableError):
        ex.read_class(
            (0xCAFEBABE).to_bytes(4, "big") + bytes(2) + (61).to_bytes(2, "big") + b"\xff\xff"
        )


def test_jar_sweeps_every_class(fixture_bytes):
    report = ex.analyse(fixture_bytes("executable_secret.jar"))
    assert report.kind == "jar"
    assert len(report.classes) == 2
    assert {item.name for item in report.classes} == {"Secret", "Helper"}
    assert any("http://10.0.0.5/stage2" in item.strings for item in report.classes)
    assert "CYBN{java_literal}" in report.flags


def test_jar_manifest_main_class(fixture_bytes):
    report = ex.analyse(fixture_bytes("executable_secret.jar"))
    assert any("Main-Class: Secret" in note for note in report.notes)


@pytest.mark.skipif(shutil.which("javac") is None, reason="the JDK is not installed")
def test_our_constant_pool_matches_javap_on_a_jdk_compiled_class(tmp_path):
    """Compile with the JDK, read with ctfc, compare with javap. No fixtures involved."""
    source = tmp_path / "Probe.java"
    source.write_text(JAVA_SOURCE)
    subprocess.run(
        ["javac", str(source)], cwd=tmp_path, capture_output=True, timeout=300, check=True
    )
    compiled = (tmp_path / "Probe.class").read_bytes()
    ours = ex.read_class(compiled)
    assert ours.name == "Probe"
    assert ours.superclass == "java/lang/Object"
    assert "CYBN{javac_ground_truth}" in ours.strings
    assert "AES/ECB/PKCS5Padding" in ours.strings

    if shutil.which("javap") is None:
        return
    out = subprocess.run(
        ["javap", "-v", "-p", str(tmp_path / "Probe.class")],
        capture_output=True,
        timeout=300,
        check=True,
    ).stdout.decode()
    # Every literal javap reports as a String constant must be in our list.
    theirs = [
        line.split("// ", 1)[1].strip()
        for line in out.splitlines()
        if "= String" in line and "// " in line
    ]
    assert theirs
    for literal in theirs:
        assert literal in ours.strings, f"javap found {literal!r} and we did not"


# ---------------------------------------------------------------------------
# DEX
# ---------------------------------------------------------------------------


def test_dex_string_table(fixture_bytes):
    report = ex.read_dex(fixture_bytes("executable_app.dex"))
    assert report.version == "035"
    assert "CYBN{dex_string_table}" in report.strings
    assert "AES/CBC/NoPadding" in report.strings


def test_dex_class_names_come_from_the_type_table(fixture_bytes):
    report = ex.read_dex(fixture_bytes("executable_app.dex"))
    assert "com.example.Main" in report.classes


def test_dex_header_checksum_is_checked(fixture_bytes):
    """A patched DEX usually has a stale adler32, and that is worth saying."""
    data = fixture_bytes("executable_app.dex")
    assert ex.read_dex(data).checksum_ok is True
    patched = bytearray(data)
    patched[-1] ^= 0xFF
    report = ex.read_dex(bytes(patched))
    assert report.checksum_ok is False
    assert any("edited after being built" in note for note in report.notes)


def test_dex_refuses_a_big_endian_file(fixture_bytes):
    data = bytearray(fixture_bytes("executable_app.dex"))
    data[40:44] = (0x78563412).to_bytes(4, "little")
    with pytest.raises(ex.ExecutableError, match="endian tag"):
        ex.read_dex(bytes(data))


def test_dex_refuses_rubbish():
    with pytest.raises(ex.ExecutableError, match="not a DEX"):
        ex.read_dex(b"PK\x03\x04" + bytes(200))


def test_an_apk_is_named_as_an_apk():
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00" + bytes(200))
    with pytest.raises(ex.ExecutableError, match="APK"):
        ex.analyse(buffer.getvalue())


def test_uleb128():
    assert ex._uleb128(bytes([0x7F]), 0) == (0x7F, 1)
    assert ex._uleb128(bytes([0x80, 0x01]), 0) == (128, 2)
    with pytest.raises(ex.ExecutableError):
        ex._uleb128(b"\xff" * 6, 0)


# ---------------------------------------------------------------------------
# .NET strings, through ctfc pe
# ---------------------------------------------------------------------------

DOTNET = Path("/usr/share/dotnet/sdk/8.0.427/System.Resources.Extensions.dll")


@pytest.mark.skipif(not DOTNET.is_file(), reason="no .NET assembly on this machine")
def test_dotnet_metadata_heaps_are_read():
    from ctfc.core import pe

    data = DOTNET.read_bytes()
    heaps = pe.dotnet_heaps(pe.Pe(data))
    assert {"#~", "#Strings", "#US", "#Blob"} <= set(heaps)
    report = pe.analyse(data)
    assert report.is_dotnet
    assert report.dotnet_identifiers
    assert report.dotnet_literals
    assert any("#US" in note for note in report.notes)


def test_dotnet_compressed_integer():
    from ctfc.core import pe

    assert pe._compressed_uint(bytes([0x03]), 0) == (3, 1)
    assert pe._compressed_uint(bytes([0x80 | 0x01, 0x00]), 0) == (256, 2)
    assert pe._compressed_uint(bytes([0xC0, 0x00, 0x40, 0x00]), 0) == (0x4000, 4)


def test_a_non_dotnet_pe_has_no_heaps(fixture_bytes):
    from ctfc.core import pe

    data = Path("/usr/i686-w64-mingw32/lib/zlib1.dll")
    if not data.is_file():
        pytest.skip("the mingw32 zlib1.dll is not installed")
    report = pe.analyse(data.read_bytes())
    assert not report.is_dotnet
    assert report.dotnet_literals == []


# ---------------------------------------------------------------------------
# JSON and the CLI
# ---------------------------------------------------------------------------


def test_to_dict_round_trips(fixture_bytes):
    payload = json.loads(json.dumps(ex.analyse(fixture_bytes("executable_dropper.elf")).to_dict()))
    assert payload["kind"] == "elf"
    assert payload["elf"]["needed"] == ["libc.so.6", "libcrypto.so.3"]


def test_cli_exe_on_a_jar():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("exe", "tests/fixtures/executable_secret.jar", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["kind"] == "jar"
    assert "CYBN{java_literal}" in payload["flags"]


def test_cli_exe_extracts_the_appended_payload(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc(
        "exe", "tests/fixtures/executable_dropper.elf", "--extract", str(tmp_path), "--json"
    )
    assert result.returncode == 0
    assert (tmp_path / "overlay.bin").read_bytes()[:4] == b"PK\x03\x04"
