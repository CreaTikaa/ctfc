"""Tests for reading a Windows event log (core/evtx.py)."""

from __future__ import annotations

import base64
import struct
from pathlib import Path

import pytest

from ctfc.core import evtx

FIXTURES = Path(__file__).parent / "fixtures"


def record(number: int, timestamp: int, strings: list[str], bad_trailer: bool = False) -> bytes:
    body = b"".join(text.encode("utf-16-le") + b"\x00\x00" for text in strings)
    size = evtx.RECORD_HEADER_SIZE + len(body) + 4
    trailer = size + 1 if bad_trailer else size
    return (
        evtx.RECORD_MAGIC
        + struct.pack("<I", size)
        + struct.pack("<Q", number)
        + struct.pack("<Q", timestamp)
        + body
        + struct.pack("<I", trailer)
    )


def log(records: list[bytes], chunks: int = 1, next_record: int | None = None) -> bytes:
    chunk = bytearray(evtx.CHUNK_SIZE)
    chunk[0:8] = evtx.CHUNK_MAGIC
    body = b"".join(records)
    chunk[evtx.CHUNK_HEADER_SIZE : evtx.CHUNK_HEADER_SIZE + len(body)] = body
    header = bytearray(evtx.FILE_HEADER_SIZE)
    header[0:8] = evtx.FILE_MAGIC
    if next_record is not None:
        header[24:32] = struct.pack("<Q", next_record)
    header[42:44] = struct.pack("<H", chunks)
    return bytes(header) + bytes(chunk)


FILETIME = 133476575820000000  # December 2023


# ---------------------------------------------------------------------------
# The framing
# ---------------------------------------------------------------------------


def test_a_file_that_is_not_an_event_log_is_refused():
    with pytest.raises(evtx.EvtxError, match="not an event log"):
        evtx.analyse(b"MZ" + bytes(5000))


def test_a_truncated_header_is_refused():
    with pytest.raises(evtx.EvtxError, match="truncated"):
        evtx.analyse(evtx.FILE_MAGIC + bytes(100))


def test_records_are_walked_with_their_numbers_and_timestamps():
    data = log([record(1, FILETIME, ["first"]), record(2, FILETIME + 10_000_000, ["second"])])
    found = evtx.records(data)
    assert [item.number for item in found] == [1, 2]
    assert found[0].when == "2023-12-21 18:39:42 UTC"
    assert found[1].when == "2023-12-21 18:39:43 UTC"


def test_a_record_whose_trailing_size_disagrees_is_not_a_record():
    """The size written twice is what tells a record from four stray bytes."""
    data = log([record(1, FILETIME, ["only one"], bad_trailer=True)])
    assert evtx.records(data) == []


def test_four_stray_magic_bytes_are_not_mistaken_for_a_record():
    data = bytearray(log([record(1, FILETIME, ["real record here"])]))
    data += evtx.RECORD_MAGIC + b"\x00\x00\x00\x00"
    found = evtx.records(bytes(data))
    assert [item.number for item in found] == [1]


def test_records_are_found_even_when_the_chunk_count_is_wrong():
    """A log carved out of a disk image or a memory dump has a stale count."""
    data = bytearray(log([record(7, FILETIME, ["carved out"])]))
    data[42:44] = struct.pack("<H", 99)  # a count that cannot be right
    found = evtx.records(bytes(data))
    assert [item.number for item in found] == [7]


def test_a_wrong_chunk_count_is_explained():
    data = bytearray(log([record(1, FILETIME, ["a record"])]))
    data[42:44] = struct.pack("<H", 99)
    report = evtx.analyse(bytes(data))
    assert any("found by their own magic" in note for note in report.notes)


def test_a_truncated_log_is_noticed_from_the_next_record_number():
    data = log([record(1, FILETIME, ["only one survived"])], next_record=500)
    report = evtx.analyse(data)
    assert any("record(s) are missing" in note for note in report.notes)


def test_an_empty_log_says_so():
    report = evtx.analyse(log([]))
    assert report.records == []
    assert any("no record found" in note for note in report.notes)


# ---------------------------------------------------------------------------
# The strings inside a record
# ---------------------------------------------------------------------------


def test_utf16_strings_are_extracted():
    blob = "alice".encode("utf-16-le") + b"\x00\x00" + "C:\\Temp".encode("utf-16-le")
    assert evtx.utf16_strings(blob) == ["alice", "C:\\Temp"]


def test_short_runs_are_not_reported_as_strings():
    assert evtx.utf16_strings("ab".encode("utf-16-le")) == []


def test_duplicate_strings_are_reported_once():
    blob = ("same" * 1).encode("utf-16-le") + b"\x00\x00" + "same".encode("utf-16-le")
    assert evtx.utf16_strings(blob) == ["same"]


def test_binary_noise_yields_no_strings():
    assert evtx.utf16_strings(bytes(range(256))) == []


# ---------------------------------------------------------------------------
# What it points at
# ---------------------------------------------------------------------------


def test_a_credential_in_a_record_is_surfaced():
    data = log([record(1, FILETIME, ["Service Control Manager", "db_password = sup3rs3cret"])])
    report = evtx.analyse(data)
    assert report.interesting[0].secrets == ["db_password = sup3rs3cret"]


def test_an_encoded_powershell_command_is_decoded():
    script = "Write-Host 'hello there'"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    data = log([record(1, FILETIME, ["PowerShell", f"powershell.exe -enc {encoded}"])])
    report = evtx.analyse(data)
    assert report.interesting[0].command == script


def test_a_flag_inside_the_decoded_command_is_found():
    """The flag is in the decoded script, not in the base64 that carried it."""
    script = "Write-Host 'CYBN{inside_the_command}'"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    data = log([record(1, FILETIME, ["PowerShell", f"powershell.exe -enc {encoded}"])])
    report = evtx.analyse(data)
    assert report.interesting[0].flags == ["CYBN{inside_the_command}"]


def test_a_flag_written_plainly_is_found_too():
    data = log([record(1, FILETIME, ["Some Provider", "the answer is CYBN{plain_in_the_log}"])])
    report = evtx.analyse(data)
    assert report.interesting[0].flags == ["CYBN{plain_in_the_log}"]


def test_ordinary_records_are_not_called_interesting():
    data = log([record(1, FILETIME, ["Microsoft-Windows-Security-Auditing", "alice", "logon"])])
    report = evtx.analyse(data)
    assert report.records and report.interesting == []


def test_the_limits_are_stated_rather_than_left_implicit():
    """It reads records and strings, not binary XML - the report must say so."""
    report = evtx.analyse(log([record(1, FILETIME, ["something"])]))
    joined = " ".join(report.notes)
    assert "not the binary XML" in joined
    assert "evtx_dump" in joined


def test_the_fixture_log_gives_the_flag_and_the_credential():
    data = (FIXTURES / "audit_security.evtx").read_bytes()
    report = evtx.analyse(data)
    assert len(report.records) == 3
    assert any("CYBN{fixture_evtx_record}" in record.flags for record in report.interesting)
    assert any(record.secrets for record in report.interesting)
