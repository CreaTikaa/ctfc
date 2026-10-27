"""Tests for ctfc.core.inputs: turning user input specs into bytes."""

import io

import pytest

from ctfc.core.inputs import InputError, looks_like_base64, looks_like_hex, parse_input


def test_hex_prefix():
    assert parse_input("hex:41 42:43 0x44").data == b"ABCD"


def test_b64_prefix_with_missing_padding_and_urlsafe():
    assert parse_input("b64:QUJDRA").data == b"ABCD"
    assert parse_input("b64:-_8").data == b"\xfb\xff"


def test_text_prefix_keeps_text():
    inp = parse_input("text:deadbeef")
    assert inp.data == b"deadbeef"
    assert inp.source == "text"


def test_file(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\x00\x01")
    inp = parse_input(str(f))
    assert inp.data == b"\x00\x01"
    assert inp.source.startswith("file:")


def test_stdin():
    assert parse_input("-", stdin=io.BytesIO(b"xyz")).data == b"xyz"


def test_bare_hex_is_detected_with_note():
    inp = parse_input("deadbeef")
    assert inp.data == bytes.fromhex("deadbeef")
    assert inp.source == "auto-hex"
    assert inp.notes


def test_bare_base64_is_detected_with_note():
    inp = parse_input("Q1lCTntoZWxsb30=")
    assert inp.data == b"CYBN{hello}"
    assert inp.source == "auto-b64"


def test_plain_word_stays_text():
    inp = parse_input("password")
    assert inp.data == b"password"
    assert inp.source == "text"


def test_invalid_hex_has_helpful_message():
    with pytest.raises(InputError, match="hex"):
        parse_input("hex:zz")


def test_helpers():
    assert looks_like_hex("de ad be ef")
    assert not looks_like_hex("abc")
    assert looks_like_base64("SGVsbG8gd29ybGQ=")
    assert not looks_like_base64("hello")
