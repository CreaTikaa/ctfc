"""`ctfc timeline` tests: six formats, one table, in order.

What is checked: that each reader's dates actually arrive, that they are all in
the same shape so sorting works, that a date which cannot be trusted is kept
and flagged rather than dropped, and that --since/--until narrow the window.
"""

from __future__ import annotations

import io
import struct
import tarfile
import time
import zipfile
from datetime import UTC, datetime, timedelta

from ctfc.core import readers, timeline
from ctfc.core.budget import Budget

SHAPE = "%Y-%m-%d %H:%M:%S UTC"


def build(root, **kwargs) -> timeline.TimelineReport:
    return timeline.build(root, budget=Budget(max_attempts=200_000, max_seconds=30), **kwargs)


def tar_with_mtime(when: int) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("notes.txt")
        info.size = 5
        info.mtime = when
        tar.addfile(info, io.BytesIO(b"hello"))
    return buf.getvalue()


# ---------------------------------------------------------------------------
# The dates arrive, in one shape
# ---------------------------------------------------------------------------


def test_a_zip_entry_date_reaches_the_table(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        info = zipfile.ZipInfo("flag.txt", date_time=(2024, 5, 17, 9, 30, 0))
        archive.writestr(info, "x")
    (tmp_path / "chal.zip").write_bytes(buf.getvalue())

    report = build(tmp_path, filesystem=False)
    rows = [entry for entry in report.entries if entry.kind.startswith("ZIP entry")]
    assert rows and rows[0].when.startswith("2024-05-17 09:30")
    assert rows[0].what == "flag.txt"
    # A DOS stamp has no time zone, and the row has to say so.
    assert "local clock" in rows[0].note


def test_a_tar_member_date_reaches_the_table(tmp_path):
    when = int(datetime(2022, 3, 1, 12, 0, tzinfo=UTC).timestamp())
    (tmp_path / "chal.tar").write_bytes(tar_with_mtime(when))

    report = build(tmp_path, filesystem=False)
    rows = [entry for entry in report.entries if "member modified" in entry.kind]
    assert rows and rows[0].when == "2022-03-01 12:00:00 UTC"


def test_the_windows_artefacts_bring_their_dates(fixture_bytes, tmp_path):
    (tmp_path / "dropper.lnk").write_bytes(fixture_bytes("winartifact_dropper.lnk"))
    (tmp_path / "log.evtx").write_bytes(fixture_bytes("audit_security.evtx"))

    report = build(tmp_path, filesystem=False)
    kinds = {entry.kind for entry in report.entries}
    assert "shortcut target created" in kinds
    assert "shortcut target written" in kinds
    assert "event log record" in kinds


def test_every_date_has_the_same_shape_and_the_table_is_sorted(fixture_bytes, tmp_path):
    (tmp_path / "dropper.lnk").write_bytes(fixture_bytes("winartifact_dropper.lnk"))
    (tmp_path / "pack.cab").write_bytes(fixture_bytes("archive_mszip.cab"))
    (tmp_path / "chal.tar").write_bytes(tar_with_mtime(int(time.time()) - 86_400))

    report = build(tmp_path)
    assert report.entries
    for entry in report.entries:
        datetime.strptime(entry.when, SHAPE)  # raises if the shape differs
    assert report.entries == sorted(report.entries, key=lambda entry: entry.when)
    assert report.span.startswith(report.entries[0].when)


def test_the_file_s_own_mtime_is_included_and_can_be_left_out(tmp_path):
    (tmp_path / "plain.bin").write_bytes(b"\x00" * 64)
    assert any(entry.kind == "filesystem mtime" for entry in build(tmp_path).entries)
    assert not build(tmp_path, filesystem=False).entries


# ---------------------------------------------------------------------------
# A stamp that cannot be trusted is kept, and said so
# ---------------------------------------------------------------------------


def test_a_date_in_the_future_is_kept_and_flagged(tmp_path):
    ahead = int((datetime.now(UTC) + timedelta(days=800)).timestamp())
    (tmp_path / "forged.tar").write_bytes(tar_with_mtime(ahead))

    report = build(tmp_path, filesystem=False)
    rows = [entry for entry in report.entries if "member modified" in entry.kind]
    assert rows, "a forged date must be reported, not dropped"
    assert "in the future" in rows[0].note


def test_a_pe_build_stamp_arrives(tmp_path):
    from tests.test_pe import build_pe

    (tmp_path / "dropper.exe").write_bytes(
        build_pe([(".text", 0x1000, 0x200, 0x60000020, b"\x90" * 32)], timestamp=1665826054)
    )
    report = build(tmp_path, filesystem=False)
    rows = [entry for entry in report.entries if entry.kind == "PE build stamp"]
    assert rows and rows[0].when.startswith("2022-10-15")


# ---------------------------------------------------------------------------
# The window, and the edges
# ---------------------------------------------------------------------------


def test_since_and_until_narrow_the_window(fixture_bytes, tmp_path):
    (tmp_path / "dropper.lnk").write_bytes(fixture_bytes("winartifact_dropper.lnk"))
    (tmp_path / "log.evtx").write_bytes(fixture_bytes("audit_security.evtx"))

    whole = build(tmp_path, filesystem=False)
    narrow = build(tmp_path, filesystem=False, since="2023-11-14", until="2023-11-14")
    assert narrow.entries
    assert len(narrow.entries) < len(whole.entries)
    assert all(entry.when.startswith("2023-11-14") for entry in narrow.entries)


def test_until_includes_the_whole_day(fixture_bytes, tmp_path):
    (tmp_path / "log.evtx").write_bytes(fixture_bytes("audit_security.evtx"))
    report = build(tmp_path, filesystem=False, until="2023-12-21")
    assert report.entries  # the records are at 18:39 on that day


def test_an_empty_folder_says_so(tmp_path):
    report = build(tmp_path)
    assert report.entries == []
    assert report.notes


def test_a_missing_path_is_a_note(tmp_path):
    report = build(tmp_path / "nope")
    assert any("does not exist" in note for note in report.notes)


def test_a_single_file_works_as_well_as_a_folder(fixture_bytes, tmp_path):
    target = tmp_path / "dropper.lnk"
    target.write_bytes(fixture_bytes("winartifact_dropper.lnk"))
    report = build(target, filesystem=False)
    assert report.files == 1
    assert report.entries


def test_report_round_trips_through_json(fixture_bytes, tmp_path):
    import json

    (tmp_path / "dropper.lnk").write_bytes(fixture_bytes("winartifact_dropper.lnk"))
    payload = json.loads(json.dumps(build(tmp_path).to_dict()))
    assert payload["entries"][0]["when"]
    assert payload["span"]


# ---------------------------------------------------------------------------
# The registry side: readers hand back events
# ---------------------------------------------------------------------------


def test_events_are_part_of_what_a_reader_returns(fixture_bytes):
    data = fixture_bytes("winartifact_dropper.lnk")
    opened = readers.open_with("winartifact", data, None, "dropper.lnk")
    assert opened.events
    assert all(event.when and event.kind for event in opened.events)


def test_a_reader_with_no_dates_returns_none(fixture_bytes):
    opened = readers.open_with("sqlite", fixture_bytes("audit_notes.sqlite"), None, "notes.sqlite")
    assert opened.events == []


def test_the_iso_helper_reads_the_two_shapes_formats_use():
    assert readers._iso("2024-05-17T09:30:00Z") == "2024-05-17 09:30:00 UTC"
    assert readers._iso("Fri, 17 May 2024 09:30:00 +0000") == "2024-05-17 09:30:00 UTC"
    assert readers._iso("not a date") == ""
    assert readers._iso("") == ""


def test_a_png_is_not_mistaken_for_a_timestamp_source():
    """A format with no dates must not invent any out of its bytes."""
    png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + bytes(17)
    opened = readers.open_with("stego", png, None, "x.png")
    assert opened.events == []
