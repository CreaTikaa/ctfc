"""Tests for static PDF analysis (core/pdf.py)."""

from __future__ import annotations

import base64
import zlib
from pathlib import Path

import pytest

from ctfc.core import pdf
from ctfc.core.lens import analyse as lens_analyse

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def sample() -> bytes:
    return (FIXTURES / "audit_malicious.pdf").read_bytes()


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def stream_object(dictionary: bytes, payload: bytes) -> bytes:
    return b"%PDF-1.7\n1 0 obj\n" + dictionary + b"\nstream\n" + payload + b"\nendstream\nendobj\n"


def test_flate_stream_is_decoded():
    data = stream_object(b"<< /Filter /FlateDecode >>", zlib.compress(b"hello flate"))
    assert pdf.parse_objects(data)[0].stream == b"hello flate"


def test_ascii_hex_stream_is_decoded():
    data = stream_object(b"<< /Filter /ASCIIHexDecode >>", b"68656c6c6f>")
    assert pdf.parse_objects(data)[0].stream == b"hello"


def test_ascii85_stream_is_decoded():
    encoded = base64.a85encode(b"hello ascii85")
    data = stream_object(b"<< /Filter /ASCII85Decode >>", encoded + b"~>")
    assert pdf.parse_objects(data)[0].stream == b"hello ascii85"


def test_run_length_stream_is_decoded():
    # literal run of 3 bytes, then "AA" as a repeat of 2, then the end marker.
    payload = bytes([2]) + b"abc" + bytes([255]) + b"A" + bytes([128])
    data = stream_object(b"<< /Filter /RunLengthDecode >>", payload)
    assert pdf.parse_objects(data)[0].stream == b"abcAA"


def test_chained_filters_are_applied_in_order():
    inner = zlib.compress(b"two layers")
    data = stream_object(
        b"<< /Filter [/ASCII85Decode /FlateDecode] >>", base64.a85encode(inner) + b"~>"
    )
    assert pdf.parse_objects(data)[0].stream == b"two layers"


def test_an_image_filter_is_left_alone_with_a_note():
    data = stream_object(b"<< /Filter /DCTDecode >>", b"\xff\xd8\xff\xe0jpegbytes")
    obj = pdf.parse_objects(data)[0]
    assert obj.stream.startswith(b"\xff\xd8")
    assert "image data" in obj.note


def test_an_unsupported_filter_says_so_rather_than_failing():
    data = stream_object(b"<< /Filter /Crypt >>", b"whatever")
    assert "unsupported filter /Crypt" in pdf.parse_objects(data)[0].note


def test_a_broken_flate_stream_is_reported_not_raised():
    data = stream_object(b"<< /Filter /FlateDecode >>", b"not actually deflate data")
    assert "failed" in pdf.parse_objects(data)[0].note


def lzw_encode(data: bytes, early: int = 1) -> bytes:
    """LZW as PDF writes it, implemented here so the decoder is tested against
    something other than itself (and so the 9->12 bit widening is exercised)."""
    table = {bytes([value]): value for value in range(256)}
    next_code = 258
    width = 9
    out_bits: list[str] = []

    def emit(code: int) -> None:
        out_bits.append(format(code, f"0{width}b"))

    emit(256)  # clear
    current = b""
    for byte in data:
        candidate = current + bytes([byte])
        if candidate in table:
            current = candidate
            continue
        emit(table[current])
        table[candidate] = next_code
        next_code += 1
        if next_code + early >= (1 << width) and width < 12:
            width += 1
        current = bytes([byte])
    if current:
        emit(table[current])
    emit(257)  # end of data
    stream = "".join(out_bits)
    stream += "0" * (-len(stream) % 8)
    return bytes(int(stream[i : i + 8], 2) for i in range(0, len(stream), 8))


@pytest.mark.parametrize(
    "payload",
    [
        b"---AAABBB",
        b"a" * 300,  # long runs
        bytes(range(256)) * 6,  # forces the code width past 9 bits
        b"the quick brown fox jumps over the lazy dog " * 20,
    ],
)
def test_lzw_decodes_what_an_independent_encoder_produced(payload):
    assert pdf._lzw(lzw_encode(payload)) == payload


def test_lzw_stops_at_the_end_of_data_marker():
    """Bytes after the EOD code must be ignored, not decoded as more data."""
    encoded = lzw_encode(b"stop here") + b"\xff\xff\xff"
    assert pdf._lzw(encoded) == b"stop here"


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_something_that_is_not_a_pdf_is_refused():
    with pytest.raises(pdf.PdfError, match="not a PDF"):
        pdf.analyse(b"\x89PNG\r\n\x1a\n" + bytes(200))


def test_objects_are_found_without_trusting_the_xref(sample):
    """A hand-edited PDF has a wrong xref; scanning must still find the objects."""
    report = pdf.analyse(sample)
    numbers = sorted({obj.number for obj in report.objects})
    assert numbers == [1, 2, 3, 4, 5, 6, 7]


def test_a_wrong_length_does_not_truncate_the_stream():
    """/Length is not trusted: the stream runs to `endstream`."""
    payload = zlib.compress(b"the full content is here")
    data = stream_object(b"<< /Length 4 /Filter /FlateDecode >>", payload)
    assert pdf.parse_objects(data)[0].stream == b"the full content is here"


def test_incremental_revisions_are_counted_and_explained(sample):
    report = pdf.analyse(sample)
    assert report.revisions == 2
    assert any("earlier versions are still in the file" in note for note in report.notes)


def test_the_removed_revision_content_is_still_reported(sample):
    """The classic redaction failure: the old object 4 is still in the bytes."""
    report = pdf.analyse(sample)
    assert any(text == "CYBN{fixture_pdf_revision}" for _, text in report.flags)


def test_indicators_name_the_dangerous_keys(sample):
    report = pdf.analyse(sample)
    joined = " ".join(report.indicators)
    assert "/OpenAction" in joined
    assert "as soon as the document is opened" in joined
    assert "/EmbeddedFile" in joined


def test_encryption_is_reported_with_the_john_hand_off():
    data = b"%PDF-1.7\n1 0 obj\n<< /Encrypt 2 0 R >>\nendobj\ntrailer\n<< /Encrypt 2 0 R >>\n%%EOF"
    report = pdf.analyse(data)
    assert report.encrypted
    assert any("pdf2john" in note for note in report.notes)


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------


def test_embedded_file_keeps_the_name_from_its_filespec(sample):
    report = pdf.analyse(sample)
    assert [name for name, _ in report.embedded] == ["payload.txt"]
    assert report.embedded[0][1] == b"CYBN{fixture_pdf_embedded}\n"


def test_javascript_is_extracted_from_the_dictionary(sample):
    report = pdf.analyse(sample)
    assert report.javascript
    assert "String.fromCharCode" in report.javascript[0][1]


def test_javascript_written_as_hex_is_extracted():
    code = b"app.alert('hi there everyone')"
    data = b"%PDF-1.7\n1 0 obj\n<< /S /JavaScript /JS <" + code.hex().encode() + b"> >>\nendobj\n"
    report = pdf.analyse(data)
    assert report.javascript[0][1] == code.decode()


def test_a_literal_string_with_escapes_and_nesting_is_read():
    data = (
        b"%PDF-1.7\n1 0 obj\n<< /S /JavaScript /JS "
        rb"(app.alert\(\"a \(nested\) one\"\); var x = '\101';)" + b" >>\nendobj\n"
    )
    code = pdf.analyse(data).javascript[0][1]
    assert 'app.alert("a (nested) one")' in code
    assert "'A'" in code  # \101 is octal for 'A'


def test_the_javascript_hands_over_to_code_lens(sample):
    """The char-code array has to come out as the flag, not stay a list of numbers."""
    report = pdf.analyse(sample)
    source = "\n".join(code for _, code in report.javascript)
    lens = lens_analyse(source.encode(), filename="pdf.js")
    assert lens.language == "javascript"
    assert any("CYBN{fixture_pdf_js}" in str(item) for item in lens.artifacts)
