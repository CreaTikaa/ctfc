"""PDF Standard encryption (core/pdfcrypt.py), on files qpdf itself encrypted.

The fixtures were made by `qpdf --encrypt` (see make_fixtures.ENCRYPTED_PDFS),
so they are the ground truth: a PDF with an EMPTY user password still has every
stream and string encrypted, and ctfc must read it in clear at every revision.
The real case: uoftctf 2024 "secret message" (RC4 40-bit, empty password).
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from ctfc.core import pdf, pdfcrypt
from ctfc.core.solve import solve
from tests.make_fixtures import ENCRYPTED_PDF_FLAG, ENCRYPTED_PDFS, FIXTURES

EMPTY = [name for name, user, _args in ENCRYPTED_PDFS if not user]


@pytest.mark.parametrize("name", EMPTY)
def test_empty_password_pdfs_are_read_in_clear(name):
    data = (FIXTURES / name).read_bytes()
    assert ENCRYPTED_PDF_FLAG.encode() not in data  # it really is encrypted
    report = pdf.analyse(data)
    assert report.encrypted and report.crypt is not None
    assert report.crypt.password == "" and report.crypt.which == "user"
    found = {text for _number, text in report.flags}
    assert ENCRYPTED_PDF_FLAG in found
    assert "CYBN{title_in_an_encrypted_pdf}" in found  # a string, not a stream
    assert any("CYBN{js_in_an_encrypted_pdf}" in code for _n, code in report.javascript)


@pytest.mark.parametrize("name", EMPTY)
def test_solve_flags_an_empty_password_pdf(name):
    report = solve((FIXTURES / name).read_bytes(), name)
    assert ENCRYPTED_PDF_FLAG in [flag.text for flag in report.flags]


def test_each_revision_is_named():
    methods = {name: pdfcrypt.open_pdf((FIXTURES / name).read_bytes()).describe() for name in EMPTY}
    assert methods["pdf_encrypted_r2_empty.pdf"].startswith("RC4 40-bit, revision 2")
    assert methods["pdf_encrypted_r3_rc4_empty.pdf"].startswith("RC4 128-bit, revision 3")
    assert methods["pdf_encrypted_r4_aes_empty.pdf"].startswith("AES-128, revision 4")
    assert methods["pdf_encrypted_r6_empty.pdf"].startswith("AES-256, revision 6")


def test_a_real_user_password_is_needed_and_works():
    data = (FIXTURES / "pdf_encrypted_r4_user_s3cret.pdf").read_bytes()
    assert pdfcrypt.open_pdf(data) is None
    closed = pdf.analyse(data)
    assert closed.crypt is None and any("pdf2john" in note for note in closed.notes)
    opened = pdf.analyse(data, passwords=(b"", b"wrong", b"s3cret"))
    assert opened.crypt.password == "s3cret"
    assert ENCRYPTED_PDF_FLAG in {text for _n, text in opened.flags}


def test_the_owner_password_opens_it_too():
    data = (FIXTURES / "pdf_encrypted_r4_user_s3cret.pdf").read_bytes()
    crypt = pdfcrypt.open_pdf(data, (b"own3r",))
    assert crypt is not None and crypt.which == "owner"


def test_an_unencrypted_pdf_is_untouched():
    data = (FIXTURES / "audit_malicious.pdf").read_bytes()
    assert pdfcrypt.open_pdf(data) is None
    assert pdf.analyse(data).crypt is None


def test_literal_strings_round_trip():
    value = bytes(range(256)) + b"()\\"
    literal = pdfcrypt._literal(value)
    assert pdf._unescape(pdf._balanced_literal(literal, 1)) == value


@pytest.mark.skipif(shutil.which("qpdf") is None, reason="qpdf not installed")
def test_streams_match_qpdf_decrypt(tmp_path):
    # Ground truth on the spot: what qpdf --decrypt writes equals what ctfc reads.
    for name in EMPTY:
        clear = tmp_path / f"clear-{name}"
        subprocess.run(
            ["qpdf", "--decrypt", str(FIXTURES / name), str(clear)],
            check=False,
            capture_output=True,
        )
        ours = pdf.analyse((FIXTURES / name).read_bytes())
        theirs = pdf.analyse(clear.read_bytes())

        def streams(report):
            return sorted(
                o.stream for o in report.objects if o.stream and b"/XRef" not in o.dictionary
            )

        assert streams(ours) == streams(theirs), name
