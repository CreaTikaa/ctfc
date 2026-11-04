"""EXIF tests, checked against exiftool where it is installed.

The rule in this repository is that a new format reader is only finished when
something that is *not* ours agrees with it. `exiftool` is installed here, so
the first test reads the fixture with both and compares - and when exiftool is
missing, that test skips with the reason named rather than quietly passing.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from ctfc.core import exif, readers, stego
from ctfc.core.solve import solve

FIXTURE = Path(__file__).parent / "fixtures" / "exif_photo.jpg"
FLAG = "CYBN{exif_user_comment}"
EXIFTOOL = shutil.which("exiftool")


@pytest.fixture
def photo() -> bytes:
    return FIXTURE.read_bytes()


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------


@pytest.mark.skipif(EXIFTOOL is None, reason="exiftool is not installed on this machine")
def test_every_field_agrees_with_exiftool(photo):
    result = subprocess.run(
        [EXIFTOOL, "-json", "-n", str(FIXTURE)],  # -n: numbers, not prettified text
        capture_output=True,
        check=True,
    )
    theirs = json.loads(result.stdout.decode())[0]
    ours = exif.read(photo)

    assert ours.get("Make") == theirs["Make"]
    assert ours.get("Model") == theirs["Model"]
    assert ours.get("Software") == theirs["Software"]
    assert ours.get("DateTimeOriginal") == theirs["DateTimeOriginal"]
    assert ours.get("UserComment") == theirs["UserComment"]
    # -n gives the GPS point as signed decimal degrees, which is what we compute.
    assert ours.latitude == pytest.approx(theirs["GPSLatitude"], abs=1e-6)
    assert ours.longitude == pytest.approx(theirs["GPSLongitude"], abs=1e-6)


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------


def test_the_fields_and_the_gps_point(photo):
    report = exif.read(photo)
    assert report.container == "jpeg"
    assert report.byte_order == "little"
    assert report.get("UserComment") == FLAG
    assert report.coordinates == "48.858367, 2.294481"
    assert "above sea level" in report.altitude
    assert "openstreetmap.org" in report.map_url


def test_the_southern_and_western_hemispheres_are_negative():
    assert exif._gps_decimal("48 51 30.12", "N") == pytest.approx(48.858367, abs=1e-6)
    assert exif._gps_decimal("48 51 30.12", "S") == pytest.approx(-48.858367, abs=1e-6)
    assert exif._gps_decimal("2 17 40.13", "W") == pytest.approx(-2.294481, abs=1e-6)
    assert exif._gps_decimal("nonsense", "N") is None


def test_a_jpeg_without_exif_says_so():
    bare = b"\xff\xd8\xff\xfe" + struct.pack(">H", 6) + b"hiya" + b"\xff\xd9"
    with pytest.raises(exif.ExifError, match="no APP1/Exif"):
        exif.read(bare)


def test_a_png_without_an_exif_chunk_says_so():
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 0) + b"IEND" + bytes(4)
    with pytest.raises(exif.ExifError, match="no eXIf"):
        exif.read(png)


def test_something_that_is_not_an_image_at_all():
    with pytest.raises(exif.ExifError, match="not a JPEG"):
        exif.read(b"just some text, no image here at all")


def test_an_entry_pointing_outside_the_file_is_reported_not_crashed(photo):
    """A hostile offset must come back as a note, not an exception."""
    broken = bytearray(photo)
    # The Make entry's value offset: push it far past the end of the file.
    position = broken.index(b"II\x2a\x00") + 8 + 2 + 8
    broken[position : position + 4] = (0xFFFF00).to_bytes(4, "little")
    report = exif.read(bytes(broken))
    assert any("outside the file" in tag.value for tag in report.tags)


def test_a_truncated_exif_block_does_not_loop():
    head = FIXTURE.read_bytes()[:40]
    with pytest.raises(exif.ExifError):
        exif.read(head)


# ---------------------------------------------------------------------------
# Where a user meets it
# ---------------------------------------------------------------------------


def test_ctfc_stego_reads_a_jpeg_s_metadata_instead_of_its_low_bits(photo):
    report = stego.analyse(photo)
    assert report.kind == "jpeg"
    fields = dict(report.texts)
    assert fields["UserComment"] == FLAG
    assert "COM segment" in fields
    assert any("no raw pixels" in note for note in report.notes)
    assert report.candidates == []  # no LSB claim on a JPEG, ever


def test_the_registry_claims_a_jpeg_and_hands_back_the_date(photo):
    assert readers.sniff(photo) == "exif"
    opened = readers.open_with("exif", photo, None, "photo.jpg")
    assert FLAG in opened.flags
    assert [event.when for event in opened.events] == ["2024-05-17 09:30:00 UTC"]
    assert "GPS" in opened.detail


def test_solve_finds_the_flag_in_a_photograph(photo):
    assert FLAG in [flag.text for flag in solve(photo, "photo.jpg").flags]


def test_the_web_tab_renders_the_fields(photo):
    from ctfc.web import formats

    answer = formats.analyse(photo)
    assert answer["reader"] == "exif"
    assert FLAG in answer["flags"]
    assert any(section["kind"] == "table" for section in answer["sections"])


def test_the_timeline_takes_the_date(photo, tmp_path):
    from ctfc.core.timeline import build

    (tmp_path / "photo.jpg").write_bytes(photo)
    report = build(tmp_path, filesystem=False)
    assert [entry.kind for entry in report.entries] == ["photograph taken"]
    assert report.entries[0].when == "2024-05-17 09:30:00 UTC"


def test_the_exif_date_shape_is_converted_and_rubbish_is_dropped():
    assert readers._exif_date("2024:05:17 09:30:00") == "2024-05-17 09:30:00 UTC"
    assert readers._exif_date("") == ""
    assert readers._exif_date("not a date at all") == ""
