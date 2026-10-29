"""Tests for the OLE2 reader (core/cfb.py) and VBA extraction (core/office.py)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from ctfc.core import cfb, office
from ctfc.core.lens import analyse as lens_analyse

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def doc() -> bytes:
    return (FIXTURES / "audit_macro.doc").read_bytes()


# ---------------------------------------------------------------------------
# The container
# ---------------------------------------------------------------------------


def test_signature_check():
    assert cfb.is_cfb(bytes.fromhex("d0cf11e0a1b11ae1") + bytes(600))
    assert not cfb.is_cfb(b"PK\x03\x04" + bytes(600))


def test_streams_are_found_with_their_full_path(doc):
    container = cfb.read(doc)
    assert "VBA/Module1" in container.streams
    assert container.find("module1") == ["VBA/Module1"]


def test_a_stream_keeps_its_exact_declared_size(doc):
    container = cfb.read(doc)
    # The fixture pads the stream to a sector boundary; the reader must cut it
    # back to the size the directory entry declares.
    assert len(container.streams["VBA/dir"]) == 4096


def test_rejects_what_is_not_a_compound_file():
    with pytest.raises(cfb.CfbError, match="not an OLE2"):
        cfb.read(b"PK\x03\x04" + bytes(600))


def test_rejects_a_truncated_file():
    with pytest.raises(cfb.CfbError, match="truncated"):
        cfb.read(bytes.fromhex("d0cf11e0a1b11ae1") + bytes(10))


def test_a_corrupt_sector_size_is_refused():
    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    header[30:32] = (7).to_bytes(2, "little")  # 2^7 is not a legal sector size
    with pytest.raises(cfb.CfbError, match="sector size"):
        cfb.read(bytes(header) + bytes(512))


# ---------------------------------------------------------------------------
# The MS-OVBA compressed container
# ---------------------------------------------------------------------------


def test_decompress_round_trips_against_an_independent_compressor():
    """tests/make_fixtures.py implements the compressor from the spec separately."""
    from make_fixtures import ovba_compress

    for text in (
        b"Sub AutoOpen()\r\nEnd Sub\r\n",
        b"Dim a\r\n" * 200,  # very repetitive: exercises the copy tokens
        bytes(range(256)) * 3,  # binary, exercises long offsets
        b"x",
    ):
        assert office.decompress_container(ovba_compress(text)) == text


def test_decompress_needs_the_container_signature():
    with pytest.raises(office.OfficeError, match="0x01"):
        office.decompress_container(b"\x02\x00\x00")


def test_a_corrupt_copy_token_is_refused_not_looped():
    """A token pointing before the chunk must raise, not read wild memory."""
    # compressed chunk, flag byte says "one copy token", token offset is huge
    body = bytes([0x01]) + (0x8000 | (0b011 << 12) | (5 - 3)).to_bytes(2, "little")
    body += bytes([0x01]) + b"\xff\xff"
    with pytest.raises(office.OfficeError, match="before the chunk"):
        office.decompress_container(body)


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


def test_ole2_macro_is_recovered(doc):
    report = office.analyse(doc)
    assert report.container == "ole2"
    assert [macro.module for macro in report.macros] == ["VBA/Module1"]
    assert "Sub AutoOpen()" in report.macros[0].code
    assert 'key = "K"' in report.macros[0].code


def test_project_metadata_streams_are_not_reported_as_macros(doc):
    """`dir`, `PROJECT` and `_VBA_PROJECT` hold metadata, not source."""
    report = office.analyse(doc)
    assert all("dir" != macro.module.rsplit("/", 1)[-1] for macro in report.macros)


def test_autorun_and_behaviour_are_pointed_out(doc):
    report = office.analyse(doc)
    joined = " ".join(report.indicators)
    assert "AutoOpen" in joined
    assert "runs by itself" in joined
    assert "Xor" in joined


def test_ooxml_reads_the_project_out_of_the_zip():
    data = (FIXTURES / "audit_macro.docm").read_bytes()
    report = office.analyse(data)
    assert report.container == "ooxml"
    assert report.macros and "vbaProject.bin" in report.macros[0].module
    assert "Sub AutoOpen()" in report.macros[0].code


def test_ooxml_reports_a_remote_template_target():
    data = (FIXTURES / "audit_macro.docm").read_bytes()
    report = office.analyse(data)
    assert report.externals == ["http://eldoria.invalid/template.dotm"]
    assert any("remote template" in note for note in report.notes)


def test_a_docx_without_a_macro_says_so_clearly():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", "<x/>")
    report = office.analyse(buffer.getvalue())
    assert report.macros == []
    assert any("no vbaProject.bin" in note for note in report.notes)


def test_something_that_is_not_a_document_is_refused():
    with pytest.raises(office.OfficeError, match="not an Office document"):
        office.analyse(b"\x89PNG\r\n\x1a\n" + bytes(100))


def test_the_macro_hands_over_to_code_lens_and_the_flag_comes_out(doc):
    """The whole point: the document alone yields the flag, no manual reading."""
    report = office.analyse(doc)
    lens = lens_analyse(report.source.encode(), filename="macro.vbs")
    assert lens.language == "vbs"
    # Code Lens resolves `Xor Asc(key)` back to key = "K" and peels the blob.
    assert any("CYBN{fixture_vba_macro}" in line for line in lens.summary)
