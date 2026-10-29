"""Tests for LSB steganography (core/stego.py): image decoding, then extraction."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pytest

from ctfc.core import stego

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers that build images independently of ctfc
# ---------------------------------------------------------------------------


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big")
        + kind
        + payload
        + zlib.crc32(kind + payload).to_bytes(4, "big")
    )


def make_png(width: int, height: int, pixels: bytes, colour: int = 2, filters=None) -> bytes:
    """An 8-bit PNG. `filters` gives the filter byte per row (default: 0 = none)."""
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[colour]
    stride = width * channels
    raw = bytearray()
    for row in range(height):
        raw += bytes([0 if filters is None else filters[row]])
        raw += pixels[row * stride : (row + 1) * stride]
    head = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, colour, 0, 0, 0])
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", head)
        + png_chunk(b"IDAT", zlib.compress(bytes(raw)))
        + png_chunk(b"IEND", b"")
    )


def make_bmp(width: int, height: int, rows_bottom_up: list[bytes], bits: int = 24) -> bytes:
    pixels = b"".join(rows_bottom_up)
    offset = 54
    header = b"BM" + struct.pack("<IHHI", offset + len(pixels), 0, 0, offset)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, bits, 0, len(pixels), 0, 0, 0, 0)
    return header + dib + pixels


def hide(message: bytes, width: int, height: int, channel: int = 0, channels: int = 3) -> bytes:
    """Write `message` one bit per sample of `channel`, MSB first, row-major."""
    bits = [(byte >> (7 - index)) & 1 for byte in message for index in range(8)]
    pixels = bytearray()
    position = 0
    for y in range(height):
        for x in range(width):
            pixel = [(x * 7) % 256, (y * 11) % 256, 64, 255][:channels]
            if position < len(bits):
                pixel[channel] = (pixel[channel] & 0xFE) | bits[position]
                position += 1
            pixels += bytes(pixel)
    return bytes(pixels)


# ---------------------------------------------------------------------------
# PNG decoding
# ---------------------------------------------------------------------------


def test_a_flat_png_decodes_to_its_pixels():
    pixels = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    image = stego.load(make_png(2, 2, pixels))
    assert (image.width, image.height, image.channels) == (2, 2, 3)
    assert image.data == pixels
    assert image.channel_names == "rgba"


@pytest.mark.parametrize("filter_type", [0, 1, 2, 3, 4])
def test_every_png_filter_is_undone(filter_type):
    """Sub, Up, Average and Paeth all have to be reversed exactly."""
    width, height = 6, 4
    pixels = bytes((x * 13 + y * 7) % 256 for y in range(height) for x in range(width * 3))
    # Re-filter the pixels the way an encoder would, then check we get them back.
    raw = bytearray()
    previous = bytearray(width * 3)
    for row in range(height):
        line = pixels[row * width * 3 : (row + 1) * width * 3]
        encoded = bytearray()
        for index, value in enumerate(line):
            left = line[index - 3] if index >= 3 else 0
            up = previous[index]
            upper_left = previous[index - 3] if index >= 3 else 0
            if filter_type == 0:
                encoded.append(value)
            elif filter_type == 1:
                encoded.append((value - left) & 0xFF)
            elif filter_type == 2:
                encoded.append((value - up) & 0xFF)
            elif filter_type == 3:
                encoded.append((value - ((left + up) >> 1)) & 0xFF)
            else:
                encoded.append((value - stego._paeth(left, up, upper_left)) & 0xFF)
        raw += bytes([filter_type]) + encoded
        previous = bytearray(line)
    head = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    data = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", head)
        + png_chunk(b"IDAT", zlib.compress(bytes(raw)))
        + png_chunk(b"IEND", b"")
    )
    assert stego.load(data).data == pixels


def test_text_chunks_are_read():
    pixels = bytes(12)
    data = make_png(2, 2, pixels)
    with_text = data[:33] + png_chunk(b"tEXt", b"Author\x00the flag is elsewhere") + data[33:]
    image = stego.load(with_text)
    assert image.texts == [("Author", "the flag is elsewhere")]


def test_compressed_text_chunk_is_inflated():
    pixels = bytes(12)
    data = make_png(2, 2, pixels)
    payload = b"Note\x00\x00" + zlib.compress(b"compressed comment")
    with_text = data[:33] + png_chunk(b"zTXt", payload) + data[33:]
    assert stego.load(with_text).texts == [("Note", "compressed comment")]


def test_an_interlaced_png_is_refused_with_a_reason():
    head = (2).to_bytes(4, "big") + (2).to_bytes(4, "big") + bytes([8, 2, 0, 0, 1])
    data = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", head) + png_chunk(b"IEND", b"")
    with pytest.raises(stego.StegoError, match="interlaced"):
        stego.load(data)


def test_a_bad_idat_stream_is_reported():
    head = (2).to_bytes(4, "big") + (2).to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    data = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", head)
        + png_chunk(b"IDAT", b"not deflate")
        + png_chunk(b"IEND", b"")
    )
    with pytest.raises(stego.StegoError, match="does not inflate"):
        stego.load(data)


def test_something_that_is_not_an_image_is_refused():
    with pytest.raises(stego.StegoError, match="not a PNG or BMP"):
        stego.load(b"%PDF-1.7\n" + bytes(100))


# ---------------------------------------------------------------------------
# BMP decoding
# ---------------------------------------------------------------------------


def test_bmp_rows_are_flipped_and_padding_dropped():
    """A positive height means the stored rows are bottom-up."""
    top = bytes([1, 2, 3, 4, 5, 6]) + b"\x00\x00"  # 2 px of 3 bytes, padded to 8
    bottom = bytes([7, 8, 9, 10, 11, 12]) + b"\x00\x00"
    image = stego.load(make_bmp(2, 2, [bottom, top]))
    assert image.data == bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    assert image.channel_names == "bgra"


def test_a_compressed_bmp_is_refused():
    data = bytearray(make_bmp(2, 2, [bytes(8), bytes(8)]))
    data[30:34] = (1).to_bytes(4, "little")  # BI_RLE8
    with pytest.raises(stego.StegoError, match="compressed BMP"):
        stego.load(bytes(data))


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_the_fixture_message_comes_out_with_its_combination():
    data = (FIXTURES / "audit_lsb.png").read_bytes()
    report = stego.analyse(data)
    assert report.candidates, "nothing extracted"
    best = report.candidates[0]
    assert b"CYBN{fixture_lsb_red}" in best.data
    assert best.params == {
        "plane": 0,
        "channels": "r",
        "order": "row-major",
        "bit_order": "msb",
    }


def test_the_decoy_text_chunk_is_surfaced_too():
    report = stego.analyse((FIXTURES / "audit_lsb.png").read_bytes())
    assert any("nothing to see here" in note for note in report.notes)


@pytest.mark.parametrize("channel,name", [(0, "r"), (1, "g"), (2, "b")])
def test_a_message_in_any_single_channel_is_found(channel, name):
    message = b"CYBN{channel_" + name.encode() + b"}\x00"
    pixels = hide(message, 48, 16, channel=channel)
    report = stego.analyse(make_png(48, 16, pixels))
    assert report.candidates
    assert message.rstrip(b"\x00") in report.candidates[0].data
    assert report.candidates[0].params["channels"] == name


def test_a_bmp_label_names_blue_not_red():
    """Index 0 is blue in a BMP: the label has to say so, or it misleads."""
    message = b"CYBN{bmp_blue}\x00"
    bits = [(byte >> (7 - i)) & 1 for byte in message for i in range(8)]
    width, height = 40, 8
    rows = []
    position = 0
    for _ in range(height):
        row = bytearray()
        for x in range(width):
            blue, green, red = 100, 150, (x * 3) % 256
            if position < len(bits):
                blue = (blue & 0xFE) | bits[position]
                position += 1
            row += bytes([blue, green, red])
        row += b"\x00" * (-len(row) % 4)
        rows.append(bytes(row))
    report = stego.analyse(make_bmp(width, height, list(reversed(rows))))
    assert report.candidates
    assert report.candidates[0].params["channels"] == "b"
    assert b"CYBN{bmp_blue}" in report.candidates[0].data


def test_a_plain_gradient_yields_nothing_rather_than_noise():
    """A smooth image read bit by bit gives a short repeating cycle, not a message."""
    pixels = bytes(
        value
        for y in range(20)
        for x in range(40)
        for value in ((x * 6) % 256, (y * 12) % 256, 200)
    )
    report = stego.analyse(make_png(40, 20, pixels))
    assert report.candidates == []
    assert any("no LSB combination" in note for note in report.notes)


def test_the_generated_snippet_reproduces_the_message():
    """The teaching layer must actually run and print the same bytes."""
    message = b"CYBN{snippet_check}\x00"
    pixels = hide(message, 48, 16)
    data = make_png(48, 16, pixels)
    report = stego.analyse(data)
    snippet = report.candidates[0].python
    namespace = {"pixels": stego.load(data).data}
    printed: list[str] = []
    namespace["print"] = lambda value: printed.append(repr(value))
    exec(snippet, namespace)  # noqa: S102 - our own generated code, not a sample
    assert "CYBN{snippet_check}" in printed[0]
