"""PNG surgery tests: the shrunk height, the wrong CRC, and the file that is fine.

The last one matters as much as the others: a tool that "repairs" a healthy
file is worse than one that repairs nothing, so every test below that tampers
with a PNG is paired with the check that the corrected bytes are byte-for-byte
the original again.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from ctfc.core import pngfix, repair

MAGIC = b"\x89PNG\r\n\x1a\n"


def chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def make_png(width: int = 16, height: int = 24, colour: int = 2, depth: int = 8) -> bytes:
    """A small, valid, non-interlaced PNG with predictable pixels."""
    channels = pngfix.CHANNELS[colour]
    row = width * channels * depth // 8
    rows = b"".join(
        b"\x00" + bytes([(x * 7 + y * 13) % 256 for x in range(row)]) for y in range(height)
    )
    header = struct.pack(">IIBBBBB", width, height, depth, colour, 0, 0, 0)
    return (
        MAGIC + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")
    )


def shrink(png: bytes, height: int, fix_crc: bool = False) -> bytes:
    """Edit the declared height, the way a challenge author does."""
    out = bytearray(png)
    out[20:24] = height.to_bytes(4, "big")
    if fix_crc:
        out[29:33] = (zlib.crc32(b"IHDR" + bytes(out[16:29])) & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(out)


# ---------------------------------------------------------------------------
# The classic: the bottom of the image was never drawn
# ---------------------------------------------------------------------------


def test_recovers_a_height_edited_without_touching_the_crc():
    original = make_png(16, 24)
    report = pngfix.analyse(shrink(original, 8))

    assert report.height == 8
    assert report.real_height == 24
    assert report.repaired == original
    # One fix: the height. The CRC was already the right one, which is itself
    # the evidence, and the report says so rather than "fixing" it.
    assert len(report.fixes) == 1
    assert any("without recomputing the checksum" in note for note in report.notes)


def test_recovers_a_height_whose_crc_was_recomputed():
    original = make_png(16, 24)
    report = pngfix.analyse(shrink(original, 8, fix_crc=True))

    assert report.real_height == 24
    assert report.repaired == original
    assert len(report.fixes) == 2  # the height, then the CRC it invalidated


@pytest.mark.parametrize(("colour", "depth"), [(0, 8), (2, 8), (4, 8), (6, 8), (2, 16)])
def test_the_row_arithmetic_holds_for_every_colour_type(colour, depth):
    original = make_png(11, 17, colour=colour, depth=depth)
    report = pngfix.analyse(shrink(original, 3))
    assert report.real_height == 17
    assert report.repaired == original


def test_a_healthy_png_is_returned_untouched():
    original = make_png(20, 20)
    report = pngfix.analyse(original)

    assert report.fixes == []
    assert report.repaired == original
    assert report.real_height == report.height == 20
    assert any("every chunk CRC matches" in note for note in report.notes)


def test_a_truncated_idat_is_reported_not_corrected():
    """Fewer rows than the header claims means a damaged file, not a cropped one."""
    original = make_png(16, 24)
    cut = original[: len(original) - 60]  # chop into the IDAT
    report = pngfix.analyse(cut)

    assert not any("cropped" in why for _o, _a, _b, why in report.fixes)
    assert report.notes


# ---------------------------------------------------------------------------
# The other ways a PNG is tampered with
# ---------------------------------------------------------------------------


def test_a_wrong_chunk_crc_is_found_and_corrected():
    original = make_png(8, 8)
    broken = bytearray(original)
    # ... IDAT payload | IDAT CRC (4) | IEND length (4) | "IEND" ...
    crc_offset = original.index(b"IEND") - 8
    broken[crc_offset] ^= 0xFF
    report = pngfix.analyse(bytes(broken))

    assert len(report.fixes) == 1
    offset, old, new, why = report.fixes[0]
    assert offset == crc_offset
    assert "CRC32 does not match" in why
    assert report.repaired == original


def test_an_impossible_depth_and_colour_pair_is_named():
    png = bytearray(make_png(8, 8))
    png[24] = 3  # bit depth 3 exists for nothing
    report = pngfix.analyse(bytes(png))
    assert any("bit depth 3 is not allowed" in note for note in report.notes)


def test_text_chunks_are_read():
    original = make_png(8, 8)
    with_text = original[: -len(chunk(b"IEND", b""))]
    with_text += chunk(b"tEXt", b"Comment\x00the flag is in the bottom rows")
    with_text += chunk(b"zTXt", b"Hint\x00\x00" + zlib.compress(b"CYBN{in_a_ztxt_chunk}"))
    with_text += chunk(b"IEND", b"")
    report = pngfix.analyse(with_text)

    texts = dict(report.texts)
    assert "bottom rows" in texts["Comment"]
    assert texts["Hint"] == "CYBN{in_a_ztxt_chunk}"


def test_not_a_png_says_so():
    report = pngfix.analyse(b"GIF89a and the rest")
    assert report.fixes == []
    assert any("not a PNG" in note for note in report.notes)


def test_an_interlaced_png_is_reported_not_corrected():
    png = bytearray(make_png(8, 8))
    png[28] = 1  # interlace method 1 = Adam7
    png[29:33] = (zlib.crc32(b"IHDR" + bytes(png[16:29])) & 0xFFFFFFFF).to_bytes(4, "big")
    report = pngfix.analyse(bytes(png))
    assert any("interlaced" in note for note in report.notes)
    assert report.fixes == []


# ---------------------------------------------------------------------------
# Through `ctfc repair`, which is where a user meets it
# ---------------------------------------------------------------------------


def test_repair_puts_the_height_back():
    original = make_png(16, 24)
    report = repair.repair(shrink(original, 6))

    assert report.repaired == original
    assert report.changed
    assert any("cropped" in fix.why for fix in report.fixes)


def test_repair_leaves_a_healthy_png_alone():
    original = make_png(12, 12)
    report = repair.repair(original)
    assert report.repaired == original
    assert not any("IHDR" in fix.why for fix in report.fixes)


def test_the_flag_in_the_hidden_rows_comes_out_of_solve():
    """End to end: a cropped PNG whose hidden rows hold a tEXt flag."""
    from ctfc.core.solve import solve

    original = make_png(16, 24)
    body = original[: -len(chunk(b"IEND", b""))]
    body += chunk(b"tEXt", b"Secret\x00CYBN{below_the_crop}")
    body += chunk(b"IEND", b"")
    report = solve(shrink(body, 4), "cropped.png")
    assert "CYBN{below_the_crop}" in [flag.text for flag in report.flags]
