"""Tests for core/repair.py and `ctfc repair` (the "Pixel Rehab" shape).

The fixture is built by tests/make_fixtures.py: a PNG whose first byte is 0x88, a
real 7z appended after IEND (written by hand, checked with `7z t`), and the first
6 bytes of a PNG signature pasted over the 7z magic.
"""

import os
import shutil
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from ctfc.core.detect import detect
from ctfc.core.magic import load_signatures
from ctfc.core.repair import (
    carve,
    near_miss,
    pasted_header,
    repair,
    validate,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
SEVEN_ZIP = b"7z\xbc\xaf'\x1c"


def signature(ext: str):
    return next(sig for sig in load_signatures() if sig.ext == ext and sig.offset == 0)


# ---------------------------------------------------------------------------
# One corrupted magic byte
# ---------------------------------------------------------------------------


def test_one_wrong_byte_is_found_and_fixed():
    png = (FIXTURES / "png_with_zip.png").read_bytes()
    broken = b"\x88" + png[1:]
    sig, offset, actual = near_miss(broken)
    assert (sig.ext, offset, actual) == ("png", 0, 0x88)
    report = repair(broken)
    assert report.repaired[:8] == b"\x89PNG\r\n\x1a\n"
    assert report.fixes[0].command("f") == "printf '\\x89' | dd of=f bs=1 seek=0 conv=notrunc"


def test_intact_and_twice_damaged_files_are_left_alone():
    png = (FIXTURES / "png_with_zip.png").read_bytes()
    assert near_miss(png) is None  # nothing to fix
    assert near_miss(b"\x88\x51" + png[2:]) is None  # two bytes off: a guess, refused
    assert near_miss(os.urandom(64)) is None


def test_no_intact_fixture_is_reported_as_corrupted():
    """The rule must not fire on ordinary files: a 4-of-5 match by chance is ~1 in 4e9."""
    for path in sorted(FIXTURES.iterdir()):
        if path.name == "audit_pixel_rehab.fun" or not path.is_file():
            continue
        assert near_miss(path.read_bytes()) is None, path.name


# ---------------------------------------------------------------------------
# Structure checks: only strong ones confirm a format
# ---------------------------------------------------------------------------


def seven_zip_start(body: bytes = b"\x00" * 20) -> bytes:
    return SEVEN_ZIP + b"\x00\x04" + zlib.crc32(body).to_bytes(4, "little") + body


def test_7z_is_confirmed_by_its_start_header_crc():
    assert validate(seven_zip_start(), signature("7z")) is True
    damaged = bytearray(seven_zip_start())
    damaged[20] ^= 1
    assert validate(bytes(damaged), signature("7z")) is False


def test_png_xz_zip_elf_checks():
    png = (FIXTURES / "png_with_zip.png").read_bytes()
    assert validate(png, signature("png")) is True
    assert validate(png[:29] + b"\x00\x00\x00\x00" + png[33:], signature("png")) is False
    flags = b"\x00\x04"
    xz = b"\xfd7zXZ\x00" + flags + zlib.crc32(flags).to_bytes(4, "little")
    assert validate(xz, signature("xz")) is True
    zip_header = (
        b"PK\x03\x04"
        + b"\x14\x00"
        + b"\x00\x00"
        + b"\x08\x00"
        + bytes(16)
        + b"\x08\x00\x00\x00flag.txt"
    )
    assert validate(zip_header, signature("zip")) is True
    elf = b"\x7fELF\x02\x01\x01" + bytes(13) + (1).to_bytes(4, "little")
    assert validate(elf, signature("elf")) is True


def test_random_bytes_confirm_nothing():
    """Under a pasted header, random bytes must never "confirm" any format."""
    for _ in range(200):
        body = os.urandom(64)
        for sig in load_signatures():
            if sig.offset == 0 and validate(sig.magic + body, sig) is True:
                pytest.fail(f"{sig.ext} confirmed on random bytes")


def test_formats_without_a_strong_check_are_never_confirmed():
    assert validate(b"GIF89a" + os.urandom(20), signature("gif")) is None


# ---------------------------------------------------------------------------
# The Pixel Rehab fixture, end to end
# ---------------------------------------------------------------------------


def test_pixel_rehab_is_solved_in_one_pass():
    report = repair((FIXTURES / "audit_pixel_rehab.fun").read_bytes())
    assert [fix.offset for fix in report.fixes] == [0, 0x43]
    assert report.fixes[1].new == SEVEN_ZIP
    assert [item.ext for item in report.carved] == ["7z"]  # ONE answer, not a list
    piece = report.carved[0].data
    assert piece.startswith(SEVEN_ZIP)
    assert validate(piece, signature("7z")) is True
    assert any("pasted over the real header" in note for note in report.notes)


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z is not installed")
def test_the_carved_7z_opens_with_the_real_tool(tmp_path):
    report = repair((FIXTURES / "audit_pixel_rehab.fun").read_bytes())
    archive = tmp_path / "carved.7z"
    archive.write_bytes(report.carved[0].data)
    done = subprocess.run(["7z", "x", "-y", f"-o{tmp_path}", str(archive)], capture_output=True)
    assert done.returncode == 0, done.stdout.decode()
    assert (tmp_path / "real_flag.txt").read_text() == "CYBN{fixture_pixel_rehab}\n"


@pytest.mark.skipif(shutil.which("dd") is None, reason="no dd")
def test_the_by_hand_commands_give_the_same_file(tmp_path):
    """The printf | dd lines ctfc prints must reproduce exactly what it carved."""
    source = FIXTURES / "audit_pixel_rehab.fun"
    report = repair(source.read_bytes())
    fixed = tmp_path / "fixed"
    fixed.write_bytes(source.read_bytes())
    for fix in report.fixes:
        subprocess.run(["bash", "-c", fix.command(str(fixed))], check=True, capture_output=True)
    item = report.carved[0]
    assert fixed.read_bytes()[item.offset :] == item.data


def test_carve_finds_files_inside():
    zip_part = (FIXTURES / "png_with_zip.png").read_bytes()
    found = carve(b"junk" * 4 + zip_part)
    assert found[0].ext == "png" and found[0].offset == 16


def test_pasted_header_prefers_the_longest_prefix():
    data = b"\x89PNG\r\n" + os.urandom(40)
    worn, fits = pasted_header(data)
    assert worn.ext == "png"
    assert all(len(sig.magic) == 6 for sig in fits)


def test_detect_points_to_repair():
    rules = {g.rule: g for g in detect((FIXTURES / "audit_pixel_rehab.fun").read_bytes()).guesses}
    assert "magic.corrupted" in rules
    assert "ctfc repair" in rules["magic.corrupted"].next_step


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_repair_writes_the_pieces(tmp_path):
    out = tmp_path / "out"
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "ctfc",
            "repair",
            "tests/fixtures/audit_pixel_rehab.fun",
            "--out",
            str(out),
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr.decode()
    assert (out / "audit_pixel_rehab.fun.repaired").read_bytes()[:4] == b"\x89PNG"
    assert (out / "carved_01_0x43.7z").read_bytes().startswith(SEVEN_ZIP)
    assert "7z x" in done.stdout.decode()


def test_cli_repair_on_a_healthy_file_says_so():
    done = subprocess.run(
        [sys.executable, "-m", "ctfc", "repair", "tests/fixtures/xor_single_byte.bin"],
        cwd=ROOT,
        capture_output=True,
        timeout=60,
    )
    assert done.returncode == 1
    assert "nothing to repair" in done.stdout.decode()
