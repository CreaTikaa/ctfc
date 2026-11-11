"""The TLS key log reader: recognise an SSLKEYLOGFILE and print the tshark command.

A capture of HTTPS is unreadable without the session keys; a challenge that
ships `sslkeyfile` next to the `.pcap` is handing them over. The one forgotten
step is the tshark option that uses them.
"""

from __future__ import annotations

from pathlib import Path

from ctfc.core import readers

FIXTURES = Path(__file__).parent / "fixtures"


def test_keylog_is_recognised():
    data = (FIXTURES / "tls_keylog.txt").read_bytes()
    assert readers.sniff(data) == "keylog"


def test_keylog_reports_the_secrets_and_the_command():
    data = (FIXTURES / "tls_keylog.txt").read_bytes()
    opened = readers.open_with("keylog", data, None, "sslkeyfile")
    assert "secret" in opened.detail
    assert any("tls.keylog_file" in command for command in opened.commands)


def test_a_normal_text_file_is_not_a_keylog():
    assert not readers.keylog_sniff(b"# just a comment\nhello world\nnothing here\n")


def test_a_capture_is_not_a_keylog():
    assert not readers.keylog_sniff(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + bytes(40))
