"""Tests for decoding protobuf without a .proto (core/protobuf.py)."""

from __future__ import annotations

import random
import zlib
from pathlib import Path

import pytest

from ctfc.core import protobuf as pb
from ctfc.core.auto import auto_decode

FIXTURES = Path(__file__).parent / "fixtures"


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        seven = value & 0x7F
        value >>= 7
        out.append(seven | 0x80 if value else seven)
        if not value:
            return bytes(out)


def tag(number: int, wire_type: int) -> bytes:
    return varint((number << 3) | wire_type)


def message(*fields: bytes) -> bytes:
    return b"".join(fields)


def string_field(number: int, text: bytes) -> bytes:
    return tag(number, 2) + varint(len(text)) + text


# ---------------------------------------------------------------------------
# The wire format
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, 1, 127, 128, 300, 2**31, 2**63 - 1])
def test_varints_round_trip(value):
    decoded, position = pb.read_varint(varint(value), 0)
    assert decoded == value
    assert position == len(varint(value))


def test_a_varint_running_past_the_end_raises():
    with pytest.raises(pb.ProtobufError, match="past the end"):
        pb.read_varint(b"\x80", 0)


def test_a_varint_longer_than_ten_bytes_raises():
    with pytest.raises(pb.ProtobufError, match="ten bytes"):
        pb.read_varint(b"\x80" * 12, 0)


def test_each_wire_type_is_decoded():
    data = message(
        tag(1, 0) + varint(42),
        tag(2, 1) + (7).to_bytes(8, "little"),
        string_field(3, b"hello"),
        tag(4, 5) + (1234).to_bytes(4, "little"),
    )
    fields = pb.parse(data)
    assert [(f.number, f.kind, f.value) for f in fields] == [
        (1, "varint", 42),
        (2, "fixed64", 7),
        (3, "string", "hello"),
        (4, "fixed32", 1234),
    ]


def test_a_nested_message_is_followed():
    inner = message(tag(1, 0) + varint(2024), tag(2, 0) + varint(7))
    data = message(tag(1, 0) + varint(1), tag(3, 2) + varint(len(inner)) + inner)
    fields = pb.parse(data)
    nested = next(f for f in fields if f.number == 3)
    assert nested.kind == "message"
    assert [(f.number, f.value) for f in nested.nested] == [(1, 2024), (2, 7)]


def test_text_wins_over_reading_a_short_string_as_a_message():
    """`"hi"` parses as a message too; reading it that way helps nobody."""
    data = message(tag(1, 0) + varint(1), string_field(2, b"hi"))
    fields = pb.parse(data)
    assert fields[1].kind == "string"
    assert fields[1].value == "hi"


def test_binary_that_is_not_a_message_stays_bytes():
    data = message(tag(1, 0) + varint(1), string_field(2, b"\xff\xfe\xfd\xfc"))
    assert pb.parse(data)[1].kind == "bytes"


def test_an_implausible_field_number_is_refused():
    with pytest.raises(pb.ProtobufError, match="not plausible"):
        pb.parse(tag(99999, 0) + varint(1))


def test_field_number_zero_is_refused():
    with pytest.raises(pb.ProtobufError, match="not plausible"):
        pb.parse(tag(0, 0) + varint(1))


def test_a_group_wire_type_is_refused_rather_than_guessed():
    with pytest.raises(pb.ProtobufError, match="wire type 3"):
        pb.parse(tag(1, 3))


def test_a_truncated_fixed_field_is_refused():
    with pytest.raises(pb.ProtobufError, match="truncated"):
        pb.parse(tag(1, 5) + b"\x01\x02")


def test_a_length_running_past_the_end_is_refused():
    with pytest.raises(pb.ProtobufError, match="past the end"):
        pb.parse(tag(1, 2) + varint(100) + b"short")


# ---------------------------------------------------------------------------
# Not claiming things that are not protobuf
# ---------------------------------------------------------------------------


def test_a_real_message_is_accepted():
    data = message(tag(1, 0) + varint(42), string_field(2, b"CYBN{accepted}"))
    assert pb.looks_like_protobuf(data)


def test_something_too_short_proves_nothing():
    assert not pb.looks_like_protobuf(tag(1, 0) + varint(1))


@pytest.mark.parametrize("length", [32, 128, 512])
def test_random_noise_is_almost_never_claimed(length):
    """The format decodes by accident, so this is the number that matters."""
    rng = random.Random(11)
    hits = sum(
        1
        for _ in range(2000)
        if pb.looks_like_protobuf(bytes(rng.randrange(256) for _ in range(length)))
    )
    assert hits / 2000 < 0.01, f"{hits} false positives at {length} bytes"


def test_other_formats_are_not_claimed():
    blobs = {
        "png": (FIXTURES / "audit_lsb.png").read_bytes(),
        "zlib": zlib.compress(b"hello world " * 20),
        "text": b"the quick brown fox jumps over the lazy dog at some length",
        "json": b'{"user":"bob","admin":true,"id":42}',
    }
    for label, blob in blobs.items():
        assert not pb.looks_like_protobuf(blob), f"{label} was claimed as protobuf"


# ---------------------------------------------------------------------------
# Output and integration
# ---------------------------------------------------------------------------


def test_the_rendering_matches_decode_raw_style():
    inner = message(tag(1, 0) + varint(7))
    data = message(
        tag(1, 0) + varint(42),
        string_field(2, b"hello"),
        tag(3, 2) + varint(len(inner)) + inner,
    )
    rendered = pb.decode_to_text(data).decode()
    assert rendered == '1: 42\n2: "hello"\n3 {\n  1: 7\n}'


def test_the_fixture_decodes_through_auto_and_gives_the_flag():
    """It is a registry decoder, so `auto` picks it up with no special casing."""
    data = (FIXTURES / "audit_message.pb").read_bytes()
    best = auto_decode(data)[0]
    assert best.label == "protobuf"
    assert b"CYBN{fixture_protobuf}" in best.data
    assert best.score >= 0.8


def test_the_decoder_is_registered_under_its_own_name():
    from ctfc.core.encodings import DECODERS_BY_NAME

    assert "protobuf" in DECODERS_BY_NAME
