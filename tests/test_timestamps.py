"""Tests for reading a number as a date (core/timestamps.py)."""

from __future__ import annotations

import struct
from datetime import UTC, datetime

from ctfc.core import timestamps


def epochs(value: int) -> list[str]:
    return [reading.epoch for reading in timestamps.readings(value)]


def dated(value: int, epoch: str) -> str:
    return next(r.text for r in timestamps.readings(value) if r.epoch == epoch)


# ---------------------------------------------------------------------------
# Each clock
# ---------------------------------------------------------------------------


def test_unix_seconds():
    assert dated(1700000000, "Unix seconds") == "2023-11-14 22:13:20 UTC"


def test_unix_milliseconds():
    assert dated(1700000000123, "Unix milliseconds") == "2023-11-14 22:13:20 UTC"


def test_unix_microseconds():
    assert dated(1700000000123456, "Unix microseconds") == "2023-11-14 22:13:20 UTC"


def test_windows_filetime():
    """100-nanosecond ticks since 1601 - the one everything Windows writes."""
    assert dated(133476575820000000, "Windows FILETIME") == "2023-12-21 18:39:42 UTC"


def test_webkit_chrome():
    assert dated(13350574800000000, "WebKit / Chrome") == "2024-01-24 13:00:00 UTC"


def test_mac_absolute():
    assert dated(720000000, "Mac absolute time") == "2023-10-26 08:00:00 UTC"


def test_a_filetime_is_not_also_read_as_unix_seconds():
    """The sizes are far enough apart that there is no ambiguity."""
    assert epochs(133476575820000000) == ["Windows FILETIME"]


def test_the_dos_packed_field_is_unpacked():
    """High 16 bits are the date (year since 1980), low 16 the time."""
    packed = ((2024 - 1980) << 9 | 12 << 5 | 21) << 16 | (18 << 11 | 39 << 5 | 21)
    reading = next(r for r in timestamps.readings(packed) if "DOS" in r.epoch)
    assert reading.text == "2024-12-21 18:39:42 UTC"


def test_an_invalid_dos_field_is_dropped_not_guessed():
    bad = (0 << 9 | 13 << 5 | 40) << 16  # month 13, day 40
    assert not any("DOS" in epoch for epoch in epochs(bad))


# ---------------------------------------------------------------------------
# What must NOT be reported
# ---------------------------------------------------------------------------


def test_a_tiny_number_is_not_a_date():
    """42 seconds past an epoch is not a timestamp, it is a number."""
    assert timestamps.readings(42) == []


def test_zero_is_not_a_date():
    assert timestamps.readings(0) == []


def test_a_reading_that_lands_on_its_own_epoch_is_rejected():
    """Dividing a small number by a billion always lands on the epoch itself."""
    for reading in timestamps.readings(1700000000):
        assert reading.epoch != "Mac absolute nanoseconds"


def test_dates_outside_1990_to_2100_are_dropped():
    # Seconds that would land in 1971: plausible arithmetic, useless answer.
    assert "Unix seconds" not in epochs(40_000_000)
    # And one far in the future.
    assert "Unix seconds" not in epochs(90_000_000_000)


def test_a_huge_number_does_not_raise():
    timestamps.readings(2**70)  # must not overflow


# ---------------------------------------------------------------------------
# Raw fields out of a binary
# ---------------------------------------------------------------------------


def test_an_eight_byte_field_is_tried_both_ways_round():
    """Windows writes FILETIME little-endian, so both orders have to be offered."""
    raw = struct.pack("<Q", 133476575820000000)
    groups = timestamps.from_bytes(raw)
    labels = " ".join(label for label, _ in groups)
    assert "little-endian" in labels
    little = next(found for label, found in groups if "little" in label)
    assert any(r.epoch == "Windows FILETIME" for r in little)


def test_a_four_byte_unix_field_is_read():
    raw = struct.pack("<I", 1700000000)
    groups = timestamps.from_bytes(raw)
    found = next(found for label, found in groups if "little" in label)
    assert any(r.epoch == "Unix seconds" and "2023-11-14" in r.text for r in found)


def test_a_field_of_the_wrong_length_gives_nothing():
    assert timestamps.from_bytes(b"\x01\x02\x03") == []


def test_a_zero_field_gives_nothing():
    assert timestamps.from_bytes(bytes(8)) == []


def test_readings_are_sorted_with_the_finest_tick_first():
    """A number is reported under every clock it fits, most likely first."""
    found = timestamps.readings(1700000000)
    assert found[0].epoch == "Unix seconds"


def test_every_reading_is_timezone_aware_utc():
    for reading in timestamps.readings(1700000000):
        assert reading.when.tzinfo is UTC
        assert reading.when >= datetime(1990, 1, 1, tzinfo=UTC)
