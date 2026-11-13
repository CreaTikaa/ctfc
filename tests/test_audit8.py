"""Fixes from the eighth public audit (2026-11-13).

- zip2john `$pkzip2$` lines: identified, cracked, and the file decrypted from
  the line (BuckeyeCTF 2025 zip2john2zip). Checked against Python's zipfile,
  7z and hashcat, which are not ours.
- a reader's flag is rated again by solve ("0x{2:X8}" in a PowerShell log).
- repair.byte_order no longer swaps a whole big file for nothing.
- the generic flag regex no longer goes quadratic on binary data.
- `ctfc zip --wordlist` no longer claims "none is the password" on WinZip AES.
"""

from __future__ import annotations

import io
import os
import shutil
import struct
import subprocess
import time
import zipfile
import zlib

import pytest

from ctfc.core import pkzip2, zipcrypto
from ctfc.core.flags import default_flagset, plain_hits, rate
from ctfc.core.hashes import identify
from ctfc.core.repair import byte_order, swap_words
from tests.make_fixtures import zipcrypto_zip

PASSWORD = b"sunshine42"
BODY = b"CYBN{z1p2j0hn_h0lds_th3_d4t4}\n"


def zip2john_line(archive: bytes, name: str = "flag.txt") -> str:
    """The `$pkzip2$` line zip2john prints for a one-entry ZipCrypto archive.

    Written from john's documented layout (pkzip_fmt_plug.c), from the bytes of
    the archive: a check that ctfc reads the same fields hashcat reads.
    """
    method, _time, _date, crc, comp, size, name_len, extra_len = struct.unpack(
        "<HHHIIIHH", archive[8:30]
    )
    start = 30 + name_len + extra_len
    data = archive[start : start + comp]
    fields = [
        "1", "1", "2", "0",
        f"{comp:x}", f"{size:x}", f"{crc:08x}", "0", f"{start:x}",
        f"{method:x}", f"{len(data):x}", f"{crc >> 16:04x}", "0000", data.hex(),
    ]  # fmt: skip
    return f"x.zip/{name}:$pkzip2${'*'.join(fields)}*$/pkzip2$:{name}:x.zip::x.zip"


@pytest.fixture
def archive() -> bytes:
    return zipcrypto_zip("flag.txt", BODY, PASSWORD)


# ---------------------------------------------------------------- ZipCrypto


def test_zipcrypto_decrypts_like_the_standard_library(archive):
    # zipfile has its own ZipCrypto: ours must agree with it byte for byte.
    assert zipfile.ZipFile(io.BytesIO(archive)).read("flag.txt", pwd=PASSWORD) == BODY
    parsed = pkzip2.parse(zip2john_line(archive))
    plain = zipcrypto.decrypt(parsed.entries[0].data, zipcrypto.keys_for(PASSWORD))[12:]
    assert zlib.decompress(plain, -zlib.MAX_WBITS) == BODY


def test_the_header_check_rejects_most_wrong_passwords(archive):
    entry = pkzip2.parse(zip2john_line(archive)).entries[0]
    checks = entry.checks(1)
    assert zipcrypto.header_matches(entry.data, PASSWORD, checks)
    wrong = sum(zipcrypto.header_matches(entry.data, b"w%d" % i, checks) for i in range(2000))
    assert wrong < 40  # about 1 in 256


# ---------------------------------------------------------------- $pkzip2$


def test_the_line_is_parsed(archive):
    parsed = pkzip2.parse(zip2john_line(archive))
    entry = parsed.entries[0]
    assert parsed.name == "flag.txt"
    assert entry.full and entry.compression == 8
    assert entry.crc == zlib.crc32(BODY) and entry.size == len(BODY)
    assert pkzip2.hashcat_mode(parsed) == 17200


def test_garbage_is_not_a_line():
    assert pkzip2.parse("$pkzip2$1*1*2*zz*$/pkzip2$") is None
    assert pkzip2.parse("hello") is None


def test_the_password_decrypts_the_file_out_of_the_line(archive):
    found = pkzip2.crack(pkzip2.parse(zip2john_line(archive)), [b"a", b"b", PASSWORD])
    assert found.password == PASSWORD and found.plaintext == BODY and found.tried == 3


def test_ctfc_hash_cracks_and_finds_the_flag(archive):
    report = identify(zip2john_line(archive), passwords=(b"nope", PASSWORD))
    assert report.matches[0].format.id == "pkzip2"
    assert report.matches[0].cracked == PASSWORD.decode()
    assert report.recovered == BODY
    assert report.flags == ["CYBN{z1p2j0hn_h0lds_th3_d4t4}"]


def test_the_rebuilt_zip_opens_with_the_standard_library(archive):
    rebuilt = pkzip2.rebuild_zip(pkzip2.parse(zip2john_line(archive)))
    assert zipfile.ZipFile(io.BytesIO(rebuilt)).read("flag.txt", pwd=PASSWORD) == BODY


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not installed")
def test_the_rebuilt_zip_opens_with_7z(archive, tmp_path):
    target = tmp_path / "rebuilt.zip"
    target.write_bytes(pkzip2.rebuild_zip(pkzip2.parse(zip2john_line(archive))))
    good = subprocess.run(
        ["7z", "t", f"-p{PASSWORD.decode()}", str(target)], capture_output=True, text=True
    )
    bad = subprocess.run(["7z", "t", "-pwrong", str(target)], capture_output=True, text=True)
    assert "Everything is Ok" in good.stdout
    assert "Everything is Ok" not in bad.stdout


@pytest.mark.skipif(
    shutil.which("hashcat") is None or not os.environ.get("CTFC_HASHCAT"),
    reason="hashcat check is slow: set CTFC_HASHCAT=1 to run it",
)
def test_hashcat_reads_the_same_line(archive, tmp_path):
    # Ground truth for the line format: hashcat cracks it to the same password.
    line = zip2john_line(archive).split(":")[1]
    (tmp_path / "h").write_text(line + "\n")
    (tmp_path / "w").write_text("nope\n" + PASSWORD.decode() + "\n")
    result = subprocess.run(
        ["hashcat", "-m", "17200", "-a", "0", str(tmp_path / "h"), str(tmp_path / "w"),
         "--potfile-disable", "--quiet"],
        capture_output=True, text=True, timeout=300,
    )  # fmt: skip
    assert result.stdout.strip().endswith(":" + PASSWORD.decode())


def test_solve_reads_a_zip2john_file(archive, tmp_path):
    from ctfc.core.solve import solve

    hash_file = tmp_path / "hash.txt"
    hash_file.write_text(zip2john_line(archive))
    report = solve(hash_file.read_bytes(), str(hash_file))
    # sunshine42 is not in the embedded list: no flag, but the right next step.
    assert not report.flags
    assert any(step.rule == "zip2john" for step in report.next_steps)
    hashcat = [s for step in report.next_steps for s in step.tools if s.tool.id == "hashcat"]
    assert hashcat and "{hashcat_mode}" not in " ".join(hashcat[0].command)


# ---------------------------------------------------------------- the other fixes


def test_a_weak_generic_text_from_a_reader_is_not_a_flag():
    assert rate("0x{2:X8}") is not None and rate("0x{2:X8}") <= 0.45
    assert rate("CYBN{real_one}") >= 0.9
    assert rate("no braces here") is None


def test_byte_order_swap_is_unchanged_and_fast():
    for width in (2, 4, 8):
        for size in (0, 1, 7, 64, 1001):
            data = os.urandom(size)
            slow = b"".join(data[i : i + width][::-1] for i in range(0, size, width))
            assert swap_words(data, width) == slow
    big = os.urandom(50_000_000)
    started = time.monotonic()
    assert byte_order(big) is None
    assert time.monotonic() - started < 3


def test_the_generic_regex_is_not_quadratic():
    # Binary output of a XOR guess: many "{", no "}" and no newline.
    noise = bytes(random_byte for random_byte in os.urandom(400_000) if random_byte not in b"}\n")
    text = noise.replace(b"\x00", b"a{").decode("latin-1")
    started = time.monotonic()
    plain_hits(text, default_flagset())
    assert time.monotonic() - started < 1.5


def test_zip_wordlist_says_so_when_it_cannot_try_aes():
    from ctfc.core.zipinfo import Entry, ZipReport, crack_with_wordlist

    aes = Entry("flag.txt", 99, 0x0001, 0, 100, 80, 0, aes_strength="AES-256", real_method=8)
    report = ZipReport(entries=[aes], comment="")
    crack_with_wordlist(b"", report, (b"a", b"b"))
    assert any("NOT tried" in note for note in report.notes)
    assert not any("none of the" in note for note in report.notes)
