"""`ctfc solve` tests: one file in, the answer out.

The shapes below are the ones a forensics challenge actually has - a flag two
containers down, a flag behind a decoding chain, a flag inside a file that only
exists after the archive was opened - because the whole claim of this command
is that it gets to the bottom without the user choosing the next command.

Two things are checked every time: that the flag came out, and that the
**trail** printed next to it is made of commands that exist, in the right
order. A trail nobody can replay is worse than no trail.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile

import pytest

from ctfc.core import readers
from ctfc.core.budget import Budget
from ctfc.core.solve import MAX_PIECES, solve

FLAG = b"CYBN{solve_walks_the_tree}"


def tar_of(members: dict[str, bytes]) -> bytes:
    """A tar holding the given members, built in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, body in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            tar.addfile(info, io.BytesIO(body))
    return buf.getvalue()


def zip_of(members: dict[str, bytes], compress: bool = True) -> bytes:
    """A ZIP holding the given members, deflated so the flag is not in the bytes."""
    buf = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", mode) as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# The flag at the bottom
# ---------------------------------------------------------------------------


def test_flag_in_the_bytes_as_they_are():
    report = solve(b"nothing here. " + FLAG + b" and nothing after", "note.txt")
    assert [flag.text for flag in report.flags] == [FLAG.decode()]
    assert report.flags[0].how == "the file itself"
    # Nothing was opened, so there is nothing to replay.
    assert report.flags[0].trail == []


def test_flag_in_a_deflated_zip_member():
    data = zip_of({"readme.txt": b"nothing " * 50, "flag.txt": FLAG + b" " * 40})
    assert FLAG not in data  # it really is compressed away
    report = solve(data, "chal.zip")

    assert [flag.text for flag in report.flags] == [FLAG.decode()]
    assert report.flags[0].where.endswith("flag.txt")
    assert report.flags[0].trail == ["unzip -j -d out1 chal.zip"]


def test_flag_two_containers_down():
    inner = zip_of({"deep.txt": FLAG + b" padding" * 20})
    data = zip_of({"inner.zip": inner})
    report = solve(data, "outer.zip")

    assert [flag.text for flag in report.flags] == [FLAG.decode()]
    # Each level has its own extraction folder, and the second command reads
    # the file the first one wrote.
    assert report.flags[0].trail == [
        "unzip -j -d out1 outer.zip",
        "unzip -j -d out2 out1/inner.zip",
    ]


def test_flag_behind_a_decoding_chain_then_a_container():
    """base64 -> gzip -> tar -> the member: the case `auto` alone cannot finish."""
    import base64

    data = base64.b64encode(gzip.compress(tar_of({"secret.txt": FLAG + b"\n"})))
    report = solve(data, "chal.txt")

    assert [flag.text for flag in report.flags] == [FLAG.decode()]
    assert report.flags[0].trail == ["ctfc auto chal.txt"]
    assert any("base64" in step for step in report.steps)


def test_carves_what_is_appended_after_an_image(fixture_bytes):
    """A PNG with a ZIP behind it: the carver runs even though stego claimed the file."""
    report = solve(fixture_bytes("png_with_zip.png"), "poly.png")
    assert report.flags or report.leads
    assert any("carved" in step or "read as" in step for step in report.steps)


# ---------------------------------------------------------------------------
# What it says when there is no flag
# ---------------------------------------------------------------------------


def test_leads_when_no_flag_and_each_one_has_a_command():
    data = zip_of({"notes.txt": b"the password is hunter2, keep it safe\n" * 3})
    report = solve(data, "chal.zip")

    assert report.flags == []
    assert report.leads
    for lead in report.leads:
        assert lead.command.strip()
        assert 0.0 <= lead.score <= 1.0


def test_an_encrypted_archive_hands_over_rather_than_guessing(fixture_bytes):
    """`solve` never brute-forces a password: it prints the command that would."""
    report = solve(fixture_bytes("audit_zipcrypto.zip"), "secret.zip")
    assert report.flags == []
    commands = " ".join(lead.command for lead in report.leads)
    assert "bkcrack" in commands or "zip2john" in commands
    assert "secret.zip" in commands  # the real file name, not a placeholder


def test_says_so_when_nothing_came_out():
    report = solve(bytes(range(256)) * 4, "noise.bin")
    assert report.flags == []
    assert report.notes


# ---------------------------------------------------------------------------
# The limits: a budget, a depth, a piece count
# ---------------------------------------------------------------------------


def test_budget_is_shared_by_the_whole_walk():
    # Distinct contents, or the walk would dedupe them and finish instantly.
    members = {
        f"file{index}.bin": zip_of({"x.txt": f"noise {index} ".encode() * 200})
        for index in range(40)
    }
    budget = Budget(max_attempts=10_000_000, max_seconds=0.05)
    report = solve(zip_of(members), "big.zip", budget=budget)

    assert report.flags == []
    assert any("budget" in note for note in report.notes)
    assert report.pieces < MAX_PIECES


def test_depth_stops_the_walk():
    data = zip_of({"inner.zip": zip_of({"deep.txt": FLAG + b" padding" * 20})})
    report = solve(data, "outer.zip", max_depth=1)
    assert report.flags == []  # the flag is one level past the limit


def test_the_same_bytes_are_looked_at_once():
    twice = tar_of({"a.bin": b"identical payload " * 20, "b.bin": b"identical payload " * 20})
    report = solve(twice, "chal.tar")
    # Two members, one distinct content: the second is not walked again.
    assert report.pieces <= 2


# ---------------------------------------------------------------------------
# The reader table itself
# ---------------------------------------------------------------------------


def test_every_reader_opens_without_raising():
    """An opener must turn a bad file into a note, never into an exception."""
    for reader in readers.READERS:
        opened = readers.open_with(reader.name, b"\x00\x01\x02 not this format at all")
        assert opened.reader == reader.name
        assert isinstance(opened.children, list)


def test_unknown_reader_is_reported_not_raised():
    opened = readers.open_with("nope", b"data")
    assert "unknown reader" in opened.error


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("zip", zip_of({"a.txt": b"hello world, this is a member"})),
        ("archive", tar_of({"a.txt": b"hello world, this is a member"})),
    ],
)
def test_children_carry_their_bytes(name, data):
    opened = readers.open_with(name, data)
    assert opened.reader == name
    assert [child.data for child in opened.children] == [b"hello world, this is a member"]


def test_sniff_order_keeps_a_docx_away_from_the_zip_reader(fixture_bytes):
    assert readers.sniff(fixture_bytes("audit_macro.docm")) == "office"


def test_report_round_trips_through_json():
    import json

    report = solve(FLAG + b" in plain sight", "note.txt")
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["flags"][0]["text"] == FLAG.decode()
    assert payload["path"] == "note.txt"


def test_an_apk_is_walked_as_a_zip_not_dead_ended():
    """An APK is a ZIP full of resources: solve must walk it, not stop at the DEX.

    Found auditing picoCTF "Mob psycho", where the flag is a hex string in
    res/color/flag.txt inside the APK. The exe reader used to claim the APK and
    refuse it ("extract classes.dex"); it now leaves an APK to the zip reader.
    """
    import binascii

    dex = b"dex\n035\x00" + bytes(200)  # enough to make the sniffer say "dex"
    members = {"classes.dex": dex, "res/color/flag.txt": binascii.hexlify(FLAG)}
    report = solve(zip_of(members), "app.apk")

    assert [flag.text for flag in report.flags] == [FLAG.decode()]
    assert "flag.txt" in report.flags[0].where


def test_a_raw_dex_still_goes_to_the_exe_reader():
    """The APK carve-out must not change a bare .dex: the exe reader keeps it."""
    from ctfc.core.readers import sniff

    assert sniff(b"dex\n035\x00" + bytes(200)) == "exe"
