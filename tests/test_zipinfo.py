"""Tests for close ZIP inspection (core/zipinfo.py)."""

from __future__ import annotations

import io
import shutil
import subprocess
import zipfile
import zlib

import pytest

from ctfc.core import zipinfo
from ctfc.core.budget import Budget


def build(entries: list[tuple[str, bytes]], comment: bytes = b"") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, payload)
        archive.comment = comment
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_entries_are_read_from_the_central_directory():
    data = build([("a.txt", b"hello"), ("dir/b.bin", b"\x00\x01\x02")])
    report = zipinfo.analyse(data)
    assert [entry.name for entry in report.entries] == ["a.txt", "dir/b.bin"]
    assert report.entries[0].uncompressed_size == 5
    assert report.entries[0].crc == zlib.crc32(b"hello")


def test_something_that_is_not_a_zip_is_refused():
    with pytest.raises(zipinfo.ZipError, match="not a ZIP"):
        zipinfo.analyse(b"\x89PNG\r\n\x1a\n" + bytes(200))


def test_a_truncated_archive_says_so():
    data = build([("a.txt", b"hello")])
    with pytest.raises(zipinfo.ZipError, match="truncated"):
        zipinfo.analyse(data[:40] + b"PK\x03\x04")


def test_the_archive_comment_is_surfaced():
    data = build([("a.txt", b"x")], comment=b"the flag is CYBN{zip_comment}")
    report = zipinfo.analyse(data)
    assert "CYBN{zip_comment}" in report.comment
    assert any("CYBN{zip_comment}" in note for note in report.notes)


def test_an_unencrypted_archive_says_to_just_extract_it():
    report = zipinfo.analyse(build([("a.txt", b"hello there")]))
    assert any("nothing is encrypted" in note for note in report.notes)
    assert report.commands == []


def test_data_appended_after_the_archive_is_reported():
    data = build([("a.txt", b"hello")]) + b"\x89PNG\r\n\x1a\nhidden"
    report = zipinfo.analyse(data)
    assert report.trailing == 14
    assert any("after the end of the archive" in note for note in report.notes)


def test_a_concatenated_archive_still_parses():
    """A self-extracting stub in front moves every offset; the directory is found anyway."""
    data = b"MZ" + bytes(2048) + build([("a.txt", b"hello")])
    report = zipinfo.analyse(data)
    assert [entry.name for entry in report.entries] == ["a.txt"]


# ---------------------------------------------------------------------------
# Things a well-behaved reader hides
# ---------------------------------------------------------------------------


def test_a_local_header_that_disagrees_is_reported():
    """unzip trusts the directory, other tools trust the local header."""
    data = bytearray(build([("real.txt", b"hello")]))
    position = data.find(b"PK\x03\x04")
    name_at = position + 30
    data[name_at : name_at + 8] = b"fake.txt"
    report = zipinfo.analyse(bytes(data))
    problems = " ".join(report.entries[0].problems)
    assert "fake.txt" in problems and "real.txt" in problems


def test_a_local_crc_that_disagrees_is_reported():
    data = bytearray(build([("a.txt", b"hello")]))
    position = data.find(b"PK\x03\x04")
    data[position + 14 : position + 18] = (0xDEADBEEF).to_bytes(4, "little")
    report = zipinfo.analyse(bytes(data))
    assert any("CRC differs" in problem for problem in report.entries[0].problems)


def test_a_path_that_escapes_the_folder_is_reported():
    report = zipinfo.analyse(build([("../../etc/passwd", b"root")]))
    assert any("escapes the extraction folder" in note for note in report.notes)


def test_an_ordinary_subdirectory_is_not_reported_as_traversal():
    report = zipinfo.analyse(build([("docs/notes/a.txt", b"fine")]))
    assert not any("escapes" in note for note in report.notes)


def test_a_bomb_ratio_is_warned_about():
    report = zipinfo.analyse(build([("big.txt", b"A" * 200_000)]))
    assert any("expands" in note for note in report.notes)


# ---------------------------------------------------------------------------
# Recovering a short file from its CRC32
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", [b"A", b"hi", b"CYB", b"\x00\xff"])
def test_a_short_payload_is_recovered_from_its_crc(payload):
    assert zipinfo.recover_from_crc(zlib.crc32(payload), len(payload)) == payload


def test_a_three_byte_payload_outside_the_alphabet_is_not_claimed():
    """Three bytes only searches flag-ish characters; it must not lie otherwise."""
    payload = b"\x01\x02\x03"
    assert zipinfo.recover_from_crc(zlib.crc32(payload), 3) is None


def test_a_longer_file_is_not_attempted():
    payload = b"too long for this"
    assert zipinfo.recover_from_crc(zlib.crc32(payload), len(payload)) is None


def test_the_budget_stops_the_search():
    budget = Budget(max_attempts=5, max_seconds=10)
    assert zipinfo.recover_from_crc(zlib.crc32(b"zz"), 2, budget) is None


def test_the_recovered_content_shows_up_in_the_report():
    report = zipinfo.analyse(build([("tiny.txt", b"CYB")]))
    entry = report.entries[0]
    assert entry.recovered == b"CYB"
    assert any("gives the content away" in note for note in report.notes)


# ---------------------------------------------------------------------------
# Against real archives, when the tools are installed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("zip") is None, reason="the zip command is not installed")
def test_a_real_zipcrypto_archive_is_named_correctly(tmp_path):
    (tmp_path / "tiny.txt").write_bytes(b"CYB")
    (tmp_path / "normal.txt").write_bytes(b"an ordinary file with some text in it")
    subprocess.run(  # noqa: S603 - our own fixed arguments
        ["zip", "-q", "-P", "hunter2", "secret.zip", "tiny.txt", "normal.txt"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    report = zipinfo.analyse((tmp_path / "secret.zip").read_bytes(), "secret.zip")
    assert all(entry.encrypted and entry.zipcrypto for entry in report.entries)
    assert any("known-plaintext" in note for note in report.notes)
    assert any("bkcrack" in command for command in report.commands)
    # The CRC is the plaintext's, in clear, even though the entry is encrypted.
    tiny = next(entry for entry in report.entries if entry.name == "tiny.txt")
    assert tiny.recovered == b"CYB"


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z is not installed")
def test_a_real_winzip_aes_archive_is_told_apart(tmp_path):
    """AES is the case where there is NO known-plaintext shortcut."""
    (tmp_path / "normal.txt").write_bytes(b"an ordinary file with some text in it")
    subprocess.run(  # noqa: S603 - our own fixed arguments
        ["7z", "a", "-tzip", "-phunter2", "-mem=AES256", "aes.zip", "normal.txt"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    report = zipinfo.analyse((tmp_path / "aes.zip").read_bytes(), "aes.zip")
    entry = report.entries[0]
    assert entry.encrypted and not entry.zipcrypto
    assert "AES-256" in entry.method_name
    assert any("password has to be cracked" in note for note in report.notes)
    # The actionable difference: bkcrack must NOT be offered for an AES archive.
    assert not any("bkcrack" in command for command in report.commands)
    assert any("13600" in command for command in report.commands)
    # AE-2 zeroes the CRC, which is exactly why the short-file trick cannot work.
    assert entry.crc == 0
    assert any("AE-2" in note for note in report.notes)
