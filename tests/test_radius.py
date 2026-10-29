"""Tests for RADIUS PAP recovery (core/radius.py) and its pcap integration."""

from __future__ import annotations

import hashlib
from pathlib import Path

from ctfc.core import radius
from ctfc.core.pcap import solve as solve_pcap

FIXTURES = Path(__file__).parent / "fixtures"


def hide(password: bytes, authenticator: bytes, secret: bytes) -> bytes:
    """The forward RFC 2865 construction, written here so the test is independent."""
    padded = password + b"\x00" * (-len(password) % 16)
    out = bytearray()
    previous = authenticator
    for start in range(0, len(padded), 16):
        stream = hashlib.md5(secret + previous).digest()
        cipher = bytes(p ^ s for p, s in zip(padded[start : start + 16], stream, strict=True))
        out += cipher
        previous = cipher
    return bytes(out)


def test_decrypt_is_the_inverse_of_hide():
    auth = bytes(range(16))
    hidden = hide(b"hunter2", auth, b"testing123")
    assert radius.decrypt_password(hidden, auth, b"testing123") == b"hunter2"


def test_decrypt_handles_several_blocks():
    auth = bytes(range(16, 32))
    password = b"a-long-password-over-16-bytes!!"
    hidden = hide(password, auth, b"s3cr3t")
    assert radius.decrypt_password(hidden, auth, b"s3cr3t") == password


def test_bad_lengths_are_rejected_not_crashed():
    assert radius.decrypt_password(b"short", bytes(16), b"x") == b""
    assert radius.decrypt_password(bytes(16), b"too-short", b"x") == b""


def test_recover_guesses_a_common_shared_secret():
    auth = bytes(range(16))
    hidden = hide(b"CYBN{radius}", auth, b"testing123")
    found = radius.recover(hidden, auth)
    assert found and found[0].secret == b"testing123"
    assert found[0].password == b"CYBN{radius}"
    assert found[0].is_flag


def test_recover_returns_nothing_when_no_secret_fits():
    auth = bytes(range(16))
    hidden = hide(b"flag", auth, b"a-secret-not-in-any-list-xyz")
    assert radius.recover(hidden, auth, secrets=[b"wrong", b"alsowrong"]) == []


def test_parse_access_request_reads_the_attributes():
    auth = bytes(range(16))
    hidden = hide(b"pw", auth, b"secret")
    payload = (
        bytes([1, 7])
        + (20 + 2 + 3 + 2 + len(hidden)).to_bytes(2, "big")
        + auth
        + bytes([1, 2 + 3])
        + b"bob"
        + bytes([2, 2 + len(hidden)])
        + hidden
    )
    request = radius.parse_access_request(payload)
    assert request is not None
    assert request.user_name == b"bob"
    assert request.user_password == hidden


def test_parse_rejects_a_non_access_request():
    assert radius.parse_access_request(b"\x02" + bytes(40)) is None  # code 2 = Access-Accept


def test_pcap_recovers_the_radius_password_end_to_end():
    data = (FIXTURES / "audit_radius.pcap").read_bytes()
    _, findings = solve_pcap(data, "audit_radius.pcap")
    radius_findings = [f for f in findings if f.extracted.kind == "radius-pap"]
    assert radius_findings, "the RADIUS Access-Request was not recognised"
    assert radius_findings[0].best is not None
    assert b"CYBN{fixture_radius_pap}" in radius_findings[0].best.data
