"""Page text of a PDF (core/pdftext.py): what `pdftotext` shows, for a flag search.

Checked on the corpus against pdftotext (98% of its words, every real flag);
here the three shapes that hid a flag from a plain search are rebuilt.
"""

from __future__ import annotations

import zlib

from ctfc.core import pdf, pdftext
from ctfc.core.solve import solve

FLAG = "CYBN{gl1ph_numb3rs_n0t_l3tters}"


def _pdf(objects: list[bytes]) -> bytes:
    body = b"%PDF-1.4\n"
    for number, obj in enumerate(objects, 1):
        body += b"%d 0 obj\n" % number + obj + b"\nendobj\n"
    return body + b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"


def _stream(content: bytes) -> bytes:
    packed = zlib.compress(content)
    return (
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(packed) + packed + b"\nendstream"
    )


def _cmap(text: str, first_code: int) -> bytes:
    """A ToUnicode CMap sending codes first_code, first_code+1... to `text`'s characters."""
    entries = b"".join(b"<%04X> <%04X>\n" % (first_code + i, ord(ch)) for i, ch in enumerate(text))
    return (
        b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
        b"1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
        b"%d beginbfchar\n" % len(text) + entries + b"endbfchar\nendcmap end end"
    )


def _page(contents: int, font: int) -> bytes:
    return (
        b"<< /Type /Page /Parent 2 0 R /Contents %d 0 R "
        b"/Resources << /Font << /F1 %d 0 R >> >> >>" % (contents, font)
    )


def _glyphs(text: str, alphabet: str, first_code: int) -> bytes:
    return b"".join(b"<%04X> Tj\n" % (first_code + alphabet.index(ch)) for ch in text)


def test_a_subset_font_is_read_through_its_tounicode_cmap():
    alphabet = "".join(dict.fromkeys(FLAG))
    content = b"BT /F1 12 Tf 72 700 Td\n" + _glyphs(FLAG, alphabet, 3) + b"ET"
    data = _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            _page(4, 5),
            _stream(content),
            b"<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 6 0 R >>",
            _stream(_cmap(alphabet, 3)),
        ]
    )
    assert FLAG.encode() not in zlib.decompress(zlib.compress(data))  # not in clear
    report = pdf.analyse(data)
    assert FLAG in {text for _number, text in report.flags}
    assert FLAG in [found.text for found in solve(data, "doc.pdf").flags]


def test_a_tj_array_is_joined_back():
    content = b"BT /F1 12 Tf [(CYBN{sp) -40 (lit_by_k) 12 (erning})] TJ ET"
    data = _pdf([b"<< /Type /Catalog >>", _stream(content)])
    report = pdf.analyse(data)
    assert "CYBN{split_by_kerning}" in {text for _number, text in report.flags}


def test_the_same_font_name_on_two_pages_means_two_fonts():
    first, second = "CYBN{page_one}", "CYBN{page_two}"
    one, two = "".join(dict.fromkeys(first)), "".join(dict.fromkeys(second))[::-1]
    data = _pdf(
        [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            _page(5, 7),
            _page(6, 8),
            _stream(b"BT /F1 12 Tf\n" + _glyphs(first, one, 1) + b"ET"),
            _stream(b"BT /F1 12 Tf\n" + _glyphs(second, two, 1) + b"ET"),
            b"<< /Type /Font /Subtype /Type0 /ToUnicode 9 0 R >>",
            b"<< /Type /Font /Subtype /Type0 /ToUnicode 10 0 R >>",
            _stream(_cmap(one, 1)),
            _stream(_cmap(two, 1)),
        ]
    )
    found = {text for _number, text in pdf.analyse(data).flags}
    assert {first, second} <= found


def test_bfrange_entries_are_expanded():
    cmap = (
        b"1 beginbfrange\n<0010> <0012> <0041>\nendbfrange\n"
        b"1 beginbfrange\n<0020> <0021> [<0061> <0062>]\nendbfrange"
    )
    mapping = pdftext.parse_cmap(cmap)
    assert mapping[b"\x00\x10"] == "A" and mapping[b"\x00\x12"] == "C"
    assert mapping[b"\x00\x20"] == "a" and mapping[b"\x00\x21"] == "b"
