"""Tests for the compound files that are not documents: .msg, .msi, embedded objects.

The three fixtures are real OLE2 files - `7z l` lists all of them, and for the
installer 7-Zip *decodes the table names*, which is the independent check that
our MSI name encoding agrees with 7-Zip's.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from ctfc.core import archive, cfb, embedded, msg, msi, office

# ---------------------------------------------------------------------------
# Outlook .msg
# ---------------------------------------------------------------------------


def test_msg_is_recognised(fixture_bytes):
    assert msg.looks_like_msg(fixture_bytes("compound_message.msg"))
    assert not msg.looks_like_msg(fixture_bytes("compound_installer.msi"))
    assert not msg.looks_like_msg(b"not a compound file")


def test_msg_headers_and_body(fixture_bytes):
    report = msg.analyse(fixture_bytes("compound_message.msg"))
    assert report.headers["subject"] == "the archive you asked for"
    assert report.headers["sender address"] == "alice@example.org"
    assert "CYBN{msg_body}" in report.body
    assert report.recipients == ["Bob <bob@corp.local>"]


def test_msg_property_names_carry_the_tag_and_the_type():
    """`__substg1.0_0037001F`: 0037 is the subject, 001F says it is UTF-16."""
    assert msg._property_of("__substg1.0_0037001F") == (0x0037, 0x001F)
    assert msg._property_of("__attach_version1.0_#00000000/__substg1.0_37010102") == (
        0x3701,
        0x0102,
    )
    assert msg._property_of("__properties_version1.0") is None


def test_msg_attachment_comes_out_whole(fixture_bytes):
    report = msg.analyse(fixture_bytes("compound_message.msg"))
    assert len(report.attachments) == 1
    attachment = report.attachments[0]
    assert attachment.name == "secret.zip"
    assert attachment.mime == "application/zip"
    assert attachment.data[:4] == b"PK\x03\x04"


def test_msg_flags_come_from_the_body(fixture_bytes):
    report = msg.analyse(fixture_bytes("compound_message.msg"))
    assert "CYBN{msg_body}" in report.flags


def test_msg_says_when_an_attachment_hides_its_content(fixture_bytes):
    """The flag inside a zipped attachment is compressed: say so, do not stay silent."""
    report = msg.analyse(fixture_bytes("compound_message.msg"))
    assert "CYBN{msg_attachment}" not in report.flags
    assert any("secret.zip is a ZIP archive" in note for note in report.notes)
    assert any("ctfc zip" in note for note in report.notes)


def test_msg_transport_headers_are_kept(fixture_bytes):
    report = msg.analyse(fixture_bytes("compound_message.msg"))
    assert "Received: from mail.example.org" in report.transport_headers
    assert any("Received chain" in note for note in report.notes)


def test_msg_refuses_a_document_and_says_where_to_go(fixture_bytes):
    with pytest.raises(msg.MsgError, match="ctfc office"):
        msg.analyse(fixture_bytes("audit_macro.doc"))
    with pytest.raises(msg.MsgError, match="OLE2 compound file"):
        msg.analyse(b"From: alice\r\n\r\nplain text mail")


def test_msg_to_dict(fixture_bytes):
    payload = json.loads(json.dumps(msg.analyse(fixture_bytes("compound_message.msg")).to_dict()))
    assert payload["attachments"][0]["name"] == "secret.zip"
    assert "CYBN{msg_body}" in payload["flags"]


# ---------------------------------------------------------------------------
# MSI
# ---------------------------------------------------------------------------


def test_msi_name_encoding_round_trips():
    for name in ("_StringData", "_StringPool", "CustomAction", "Binary.payload", "a", "ab.c_d"):
        assert msi.decode_name(msi.encode_name(name)) == name


def test_msi_name_encoding_matches_the_published_ranges():
    """Two 6-bit indexes per code point in the U+3800 range, one in U+4800."""
    assert msi.decode_name(chr(0x4800)) == "0"
    assert msi.decode_name(chr(0x3800)) == "00"
    assert msi.decode_name(chr(0x3800 + 1 + (2 << 6))) == "12"
    assert msi.decode_name("plain") == "plain"


def test_msi_is_recognised(fixture_bytes):
    assert msi.looks_like_msi(fixture_bytes("compound_installer.msi"))
    assert not msi.looks_like_msi(fixture_bytes("compound_message.msg"))


def test_msi_tables_and_string_pool(fixture_bytes):
    report = msi.analyse(fixture_bytes("compound_installer.msi"))
    assert "_StringData" in report.streams
    assert "CustomAction" in report.streams
    assert "ctfc demo installer" in report.strings
    assert "CYBN{msi_string_pool}" in report.strings


def test_msi_string_pool_order_is_length_then_refcount():
    """Get the pair order wrong and every string after the first is garbage."""
    import struct

    data = b"alphabeta"
    pool = struct.pack("<HH", 1252, 0) + struct.pack("<HH", 5, 1) + struct.pack("<HH", 4, 1)
    assert msi.read_string_pool(data, pool) == ["alpha", "beta"]


def test_msi_embedded_cabinet_is_opened(fixture_bytes):
    report = msi.analyse(fixture_bytes("compound_installer.msi"))
    assert report.cabinet_files == ["payload.exe"]
    assert "CYBN{msi_cabinet}" in report.flags


def test_msi_decodes_the_powershell_command_it_would_run(fixture_bytes):
    report = msi.analyse(fixture_bytes("compound_installer.msi"))
    assert report.commands == ["Write-Host 'CYBN{msi_encoded_command}'"]
    assert "CYBN{msi_encoded_command}" in report.flags
    assert any("PowerShell is launched" in line for line in report.indicators)
    assert any("http URL" in line for line in report.indicators)


def test_msi_names_its_own_limit(fixture_bytes):
    report = msi.analyse(fixture_bytes("compound_installer.msi"))
    assert any("row-level table decoding is not implemented" in note for note in report.notes)


def test_msi_refuses_a_message(fixture_bytes):
    with pytest.raises(msi.MsiError, match="ctfc msg"):
        msi.analyse(fixture_bytes("compound_message.msg"))


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z is not installed")
def test_msi_stream_names_match_7zips_decoding(fixture_bytes, tmp_path):
    """7-Zip decodes MSI stream names too: ours must say the same thing."""
    path = tmp_path / "setup.msi"
    path.write_bytes(fixture_bytes("compound_installer.msi"))
    out = subprocess.run(
        ["7z", "l", "-tCompound", str(path)], capture_output=True, timeout=60, check=True
    ).stdout.decode()
    for name in ("_StringData", "_StringPool", "_Tables", "CustomAction", "Binary.payload"):
        assert name in out
        assert name in msi.analyse(fixture_bytes("compound_installer.msi")).streams


# ---------------------------------------------------------------------------
# Embedded objects in a document
# ---------------------------------------------------------------------------


def test_embedded_object_is_found_and_unwrapped(fixture_bytes):
    report = office.analyse(fixture_bytes("compound_embedded.doc"))
    assert len(report.objects) == 1
    item = report.objects[0]
    assert item.name == "update.bat"
    assert item.source_path == r"C:\Users\author\Desktop\update.bat"
    assert b"CYBN{embedded_object}" in item.data
    assert b"powershell" in item.data


def test_embedded_object_path_is_reported(fixture_bytes):
    """The path on the author's machine leaks out of the Ole10Native stream."""
    report = office.analyse(fixture_bytes("compound_embedded.doc"))
    assert any("came from C:\\Users\\author\\Desktop" in note for note in report.notes)


def test_embedded_object_in_a_document_with_no_macro(fixture_bytes):
    report = office.analyse(fixture_bytes("compound_embedded.doc"))
    assert report.macros == []
    assert any("embedded object(s)" in note for note in report.notes)


def test_embedded_nested_compound_file_is_returned_raw():
    container = cfb.CfbFile(streams={"ObjectPool/_1/CONTENTS": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"})
    objects = embedded.find_objects(container)
    assert len(objects) == 1
    assert "nested compound file" in objects[0].notes[0]


def test_embedded_rubbish_is_reported_not_raised():
    container = cfb.CfbFile(streams={"ObjectPool/_1/\x01Ole10Native": b"\x00" * 8})
    objects = embedded.find_objects(container)
    assert len(objects) == 1
    assert objects[0].notes and "not readable" in objects[0].notes[0]


def test_office_to_dict_carries_the_objects(fixture_bytes):
    payload = json.loads(
        json.dumps(office.analyse(fixture_bytes("compound_embedded.doc")).to_dict())
    )
    assert payload["objects"][0]["name"] == "update.bat"


# ---------------------------------------------------------------------------
# No dead ends between the three readers
# ---------------------------------------------------------------------------


def test_archive_sends_a_compound_file_to_the_right_command(fixture_bytes):
    with pytest.raises(archive.ArchiveError, match="ctfc msi"):
        archive.analyse(fixture_bytes("compound_installer.msi"))


def test_archive_sends_a_zip_to_ctfc_zip(fixture_bytes):
    with pytest.raises(archive.ArchiveError, match="ctfc zip"):
        archive.analyse(fixture_bytes("audit_zipcrypto.zip"))


def test_archive_names_a_gzip_for_what_it_is():
    with pytest.raises(archive.ArchiveError, match="gunzip"):
        archive.analyse(b"\x1f\x8b\x08\x00" + bytes(100))


def test_office_points_at_msg_and_msi(fixture_bytes):
    message = office.analyse(fixture_bytes("compound_message.msg"))
    assert any("ctfc msg" in note for note in message.notes)
    installer = office.analyse(fixture_bytes("compound_installer.msi"))
    assert any("ctfc msi" in note for note in installer.notes)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_msg_extracts_the_attachment(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc(
        "msg", "tests/fixtures/compound_message.msg", "--extract", str(tmp_path), "--json"
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["headers"]["subject"] == "the archive you asked for"
    assert (tmp_path / "secret.zip").read_bytes()[:4] == b"PK\x03\x04"


def test_cli_msi(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc(
        "msi", "tests/fixtures/compound_installer.msi", "--extract", str(tmp_path), "--json"
    )
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert "CYBN{msi_cabinet}" in payload["flags"]
    assert (tmp_path / "payload.exe").exists()


def test_cli_office_extracts_the_embedded_object(tmp_path):
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("office", "tests/fixtures/compound_embedded.doc", "--extract", str(tmp_path))
    assert result.returncode == 1  # no macro: that is the documented exit code
    assert (tmp_path / "update.bat").read_bytes().count(b"CYBN{embedded_object}") == 1
