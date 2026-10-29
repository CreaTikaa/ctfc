"""Tests for e-mail / MIME extraction out of a capture (core/mail.py)."""

from __future__ import annotations

import base64
from pathlib import Path

from ctfc.core import mail
from ctfc.core.pcap import solve as solve_pcap

FIXTURES = Path(__file__).parent / "fixtures"

SIMPLE = (
    b"From: a@b.invalid\r\n"
    b"To: c@d.invalid\r\n"
    b"Subject: hello there\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"the body\r\n"
)


def multipart(body: str, filename: str, content: bytes) -> bytes:
    return (
        "From: a@b.invalid\r\n"
        "Subject: with a file\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="XX"\r\n'
        "\r\n"
        "--XX\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n" + body + "\r\n"
        "--XX\r\n"
        f'Content-Type: application/octet-stream; name="{filename}"\r\n'
        "Content-Transfer-Encoding: base64\r\n"
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        "\r\n" + base64.b64encode(content).decode() + "\r\n"
        "--XX--\r\n"
    ).encode()


def test_a_plain_message_is_parsed():
    found = mail.parse_message(SIMPLE)
    assert found is not None
    assert found.subject == "hello there"
    assert found.headers["From"] == "a@b.invalid"
    assert [part.data for part in found.parts] == [b"the body\r\n"]
    assert found.parts[0].is_body


def test_an_attachment_is_decoded_from_base64():
    raw = multipart("see attached", "payload.bin", b"\x89PNG\r\n\x1a\nreal bytes")
    found = mail.parse_message(raw)
    assert found is not None
    files = [part for part in found.parts if not part.is_body]
    assert len(files) == 1
    assert files[0].filename == "payload.bin"
    assert files[0].data == b"\x89PNG\r\n\x1a\nreal bytes"


def test_quoted_printable_body_is_decoded():
    raw = (
        b"From: a@b.invalid\r\nSubject: qp\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n"
        b"\r\npassword =3D hunter2\r\n"
    )
    found = mail.parse_message(raw)
    assert found is not None
    assert b"password = hunter2" in found.parts[0].data


def test_imap_literal_gives_the_exact_message():
    stream = b"3 FETCH (BODY[] {" + str(len(SIMPLE)).encode() + b"}\r\n" + SIMPLE + b")\r\n3 OK\r\n"
    messages = mail.find_messages(stream)
    assert messages == [SIMPLE]


def test_smtp_data_is_cut_at_the_lone_dot():
    stream = b"EHLO x\r\n250 ok\r\nDATA\r\n354 go\r\n" + SIMPLE + b"\r\n.\r\n250 queued\r\n"
    messages = mail.find_messages(stream)
    assert len(messages) == 1
    assert b"Subject: hello there" in messages[0]
    assert b"250 queued" not in messages[0]


def test_two_messages_in_one_stream():
    second = SIMPLE.replace(b"hello there", b"second one")
    stream = (
        b"1 FETCH (BODY[] {" + str(len(SIMPLE)).encode() + b"}\r\n" + SIMPLE + b")\r\n"
        b"2 FETCH (BODY[] {" + str(len(second)).encode() + b"}\r\n" + second + b")\r\n"
    )
    subjects = [item.subject for item in mail.extract(stream)]
    assert subjects == ["hello there", "second one"]


def test_a_stream_with_no_mail_yields_nothing():
    assert mail.extract(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == []
    assert mail.extract(b"\x00\xff" * 200) == []


def test_a_truncated_message_does_not_raise():
    """A capture cut mid-attachment must degrade, not explode."""
    raw = multipart("body", "f.bin", b"A" * 300)[:200]
    mail.parse_message(raw)  # must not raise


def test_attachment_filename_cannot_escape_the_extract_folder():
    """The name comes from the sample, so it must be reduced to a plain name."""
    from ctfc.core.pcap import _safe_name

    assert "/" not in _safe_name("../../etc/passwd", "x.bin")
    assert not _safe_name("../../etc/passwd", "x.bin").startswith(".")
    assert _safe_name("", "fallback.bin") == "fallback.bin"
    assert _safe_name("....", "fallback.bin") == "fallback.bin"


def test_fixture_capture_gives_the_body_and_the_zip():
    data = (FIXTURES / "audit_mail_imap.pcap").read_bytes()
    _, findings = solve_pcap(data, "audit_mail_imap.pcap")
    kinds = {finding.extracted.kind for finding in findings}
    assert "mail-body" in kinds and "mail-attachment" in kinds
    body = next(f for f in findings if f.extracted.kind == "mail-body")
    assert b"CYBN{fixture_mail_imap}" in body.extracted.data
    assert b"eldoriaismylife" in body.extracted.data  # the ZIP password
    zipped = next(f for f in findings if f.extracted.kind == "mail-attachment")
    assert zipped.extracted.data.startswith(b"PK\x03\x04")
