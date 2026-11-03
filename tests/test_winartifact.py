"""Tests for the Windows artefacts: .lnk, prefetch, jump lists (core/winartifact.py).

Ground truth comes from outside where it exists. The prefetch fixture is opened
with **libscca** (`pyscca`, installed system-wide) and every field we claim to
read is compared with what it says; the shortcut is checked against `file`,
whose libmagic parses .lnk flags and strings. The prefetch run-count offsets in
`LAYOUTS` were measured against libscca rather than copied from a document, and
the test below is what keeps them honest.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from ctfc.core import lnk, winartifact


def _pyscca_available() -> bool:
    """libscca lives in the system Python, not the virtualenv: ask it directly."""
    if shutil.which("python3") is None:
        return False
    return (
        subprocess.run(
            ["python3", "-c", "import pyscca"], capture_output=True, timeout=30
        ).returncode
        == 0
    )


HAS_PYSCCA = _pyscca_available()

# ---------------------------------------------------------------------------
# sniff
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("winartifact_dropper.lnk", "lnk"),
        ("winartifact_powershell.pf", "prefetch"),
        ("winartifact_jumplist.automaticDestinations-ms", "jumplist"),
    ],
)
def test_sniff(fixture_bytes, name, expected):
    assert winartifact.sniff(fixture_bytes(name)) == expected


def test_a_hive_is_recognised_and_handed_to_ctfc_hive():
    report = winartifact.analyse(b"regf" + bytes(500))
    assert report.kind == "hive"
    assert any("ctfc hive" in command for command in report.commands)
    assert any("InventoryApplicationFile" in note for note in report.notes)


def test_something_else_is_refused_with_a_direction():
    with pytest.raises(winartifact.ArtifactError, match="ctfc detect"):
        winartifact.analyse(b"\x89PNG\r\n\x1a\n" + bytes(100))


# ---------------------------------------------------------------------------
# Shortcuts
# ---------------------------------------------------------------------------


def test_lnk_target_and_command_line(fixture_bytes):
    report = lnk.analyse(fixture_bytes("winartifact_dropper.lnk"))
    assert report.target == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert report.arguments.startswith("-nop -w hidden -enc ")
    assert report.description == "Invoice March 2026"
    assert report.working_directory == r"C:\Users\victim\Downloads"
    assert report.icon_location == r"%SystemRoot%\System32\shell32.dll"


def test_lnk_strings_are_utf16_when_the_flag_says_so(fixture_bytes):
    """The count is in characters, not bytes: get it wrong and every string halves."""
    report = lnk.analyse(fixture_bytes("winartifact_dropper.lnk"))
    assert report.flags & lnk.IS_UNICODE
    assert "\x00" not in report.description
    assert len(report.description) == len("Invoice March 2026")


def test_lnk_is_a_witness_as_well_as_a_payload(fixture_bytes):
    report = lnk.analyse(fixture_bytes("winartifact_dropper.lnk"))
    assert report.machine_id == "DESKTOP-CTF01"
    assert report.volume_serial == "1a2b3c4d"
    assert report.volume_label == "USB_STICK"
    assert "removable" in report.drive_type
    assert report.target_size == 452608
    assert report.created.startswith("2023-11-14")


def test_lnk_decodes_the_payload_it_would_run(fixture_bytes):
    report = lnk.analyse(fixture_bytes("winartifact_dropper.lnk"))
    assert report.decoded_commands == ["Write-Host 'CYBN{lnk_encoded_command}'"]
    assert any("PowerShell" in line for line in report.indicators)
    assert any("hides its window" in line for line in report.indicators)


def test_winartifact_reports_the_flag_from_the_decoded_command(fixture_bytes):
    report = winartifact.analyse(fixture_bytes("winartifact_dropper.lnk"))
    assert report.flags == ["CYBN{lnk_encoded_command}"]


def test_lnk_refuses_what_is_not_a_shortcut():
    with pytest.raises(lnk.LnkError, match="not a Windows shortcut"):
        lnk.analyse(b"\x4c\x00\x00\x00" + bytes(100))


def test_lnk_counted_string_refuses_an_absurd_length():
    with pytest.raises(lnk.LnkError, match="not a real shortcut field"):
        lnk._counted_string(b"\xff\xff" + bytes(10), 0, True)


@pytest.mark.skipif(shutil.which("file") is None, reason="file(1) is not installed")
def test_lnk_fields_match_what_libmagic_says(fixture_bytes, tmp_path):
    path = tmp_path / "x.lnk"
    path.write_bytes(fixture_bytes("winartifact_dropper.lnk"))
    out = subprocess.run(
        ["file", str(path)], capture_output=True, timeout=30, check=True
    ).stdout.decode()
    assert "MS Windows shortcut" in out
    assert "Has command line arguments" in out
    assert "Has Description string" in out
    assert "Has Working directory" in out
    assert "length=452608" in out


# ---------------------------------------------------------------------------
# Prefetch
# ---------------------------------------------------------------------------


def test_prefetch_header(fixture_bytes):
    report = winartifact.read_prefetch(fixture_bytes("winartifact_powershell.pf"))
    assert report.version == 26
    assert report.version_name == "Windows 8.1"
    assert report.name == "POWERSHELL.EXE"
    assert report.run_count == 7
    assert report.runs[0].startswith("2023-11-14")
    assert len(report.runs) == 2


def test_prefetch_lists_every_file_the_program_loaded(fixture_bytes):
    report = winartifact.read_prefetch(fixture_bytes("winartifact_powershell.pf"))
    assert len(report.files) == 4
    assert any(path.endswith("STAGE2.PS1") for path in report.files)


def test_prefetch_points_at_the_files_that_are_not_system_dlls(fixture_bytes):
    """The whole value of a prefetch file: what the program actually worked on."""
    report = winartifact.read_prefetch(fixture_bytes("winartifact_powershell.pf"))
    assert any("STAGE2.PS1" in path for path in report.interesting)
    assert any("CYBN_PREFETCH.TXT" in path for path in report.interesting)
    assert not any("NTDLL.DLL" in path for path in report.interesting)


def test_prefetch_volume(fixture_bytes):
    report = winartifact.read_prefetch(fixture_bytes("winartifact_powershell.pf"))
    assert report.volumes and "deadbeef" in report.volumes[0]


def test_a_compressed_prefetch_file_says_so_instead_of_guessing():
    """Windows 10 writes MAM-compressed prefetch; ctfc names the tool and stops."""
    data = b"MAM\x04" + (4096).to_bytes(4, "little") + bytes(200)
    report = winartifact.read_prefetch(data)
    assert report.version_name.endswith("(compressed)")
    assert any("MAM-compressed" in note and "pyscca" in note for note in report.notes)
    assert report.files == []


def test_an_unknown_prefetch_version_is_refused_by_name():
    data = (99).to_bytes(4, "little") + b"SCCA" + bytes(500)
    with pytest.raises(winartifact.ArtifactError, match="version 99"):
        winartifact.read_prefetch(data)


@pytest.mark.skipif(not HAS_PYSCCA, reason="libscca (pyscca) is not installed")
def test_prefetch_matches_libscca(fixture_bytes, tmp_path):
    """Compare every field against a real Windows Prefetch reader."""
    path = tmp_path / "POWERSHELL.EXE-1A2B3C4D.pf"
    path.write_bytes(fixture_bytes("winartifact_powershell.pf"))
    script = (
        "import json, pyscca, sys\n"
        "f = pyscca.file()\n"
        "f.open(sys.argv[1])\n"
        "print(json.dumps({\n"
        "    'executable': f.executable_filename,\n"
        "    'version': f.format_version,\n"
        "    'run_count': f.run_count,\n"
        "    'last_run': str(f.get_last_run_time(0)),\n"
        "    'filenames': [f.get_filename(i) for i in range(f.number_of_filenames)],\n"
        "}))\n"
    )
    out = subprocess.run(
        ["python3", "-c", script, str(path)], capture_output=True, timeout=60, check=True
    ).stdout.decode()
    theirs = json.loads(out)
    ours = winartifact.read_prefetch(fixture_bytes("winartifact_powershell.pf"))
    assert ours.name == theirs["executable"]
    assert ours.version == theirs["version"]
    assert ours.run_count == theirs["run_count"]
    assert ours.files == theirs["filenames"]
    # libscca prints the time without a zone; ours says UTC, as it is.
    assert ours.runs[0].startswith(theirs["last_run"][:19])


# ---------------------------------------------------------------------------
# Jump lists
# ---------------------------------------------------------------------------


def test_jumplist_entries_are_shortcuts(fixture_bytes):
    report = winartifact.read_jumplist(
        fixture_bytes("winartifact_jumplist.automaticDestinations-ms")
    )
    assert [entry.stream for entry in report.entries] == ["1", "2"]
    assert report.entries[0].path == r"C:\Users\victim\Documents\notes.txt"
    assert report.entries[1].path == r"D:\secret\CYBN_jumplist.docx"
    assert report.entries[0].machine_id == "DESKTOP-CTF01"


def test_jumplist_destlist_gives_the_order(fixture_bytes):
    report = winartifact.read_jumplist(
        fixture_bytes("winartifact_jumplist.automaticDestinations-ms")
    )
    assert report.order[0] == r"C:\Users\victim\Documents\notes.txt"
    assert any("DestList" in note for note in report.notes)


def test_custom_destinations_is_shortcuts_end_to_end():
    from tests.make_fixtures import make_lnk  # noqa: PLC0415

    data = b"\x02\x00\x00\x00" + make_lnk(r"C:\a\one.txt") + make_lnk(r"C:\b\two.txt")
    report = winartifact.read_jumplist(data)
    assert [entry.path for entry in report.entries] == [r"C:\a\one.txt", r"C:\b\two.txt"]
    assert any("concatenated" in note for note in report.notes)


def test_a_jump_list_with_nothing_in_it_is_refused():
    with pytest.raises(winartifact.ArtifactError, match="not a jump list"):
        winartifact.read_jumplist(b"\x02\x00\x00\x00" + bytes(100))


# ---------------------------------------------------------------------------
# JSON and the CLI
# ---------------------------------------------------------------------------


def test_to_dict_round_trips(fixture_bytes):
    payload = json.loads(
        json.dumps(winartifact.analyse(fixture_bytes("winartifact_dropper.lnk")).to_dict())
    )
    assert payload["kind"] == "lnk"
    assert payload["lnk"]["machine_id"] == "DESKTOP-CTF01"
    assert payload["flags"] == ["CYBN{lnk_encoded_command}"]


def test_cli_winartifact_lnk():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("winartifact", "tests/fixtures/winartifact_dropper.lnk", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["lnk"]["decoded_commands"] == ["Write-Host 'CYBN{lnk_encoded_command}'"]


def test_cli_winartifact_prefetch():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("winartifact", "tests/fixtures/winartifact_powershell.pf", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["prefetch"]["run_count"] == 7


def test_detect_points_at_the_right_command(fixture_bytes):
    from ctfc.core.detect import detect

    report = detect(fixture_bytes("winartifact_dropper.lnk"))
    assert any("ctfc winartifact" in guess.next_step for guess in report.guesses)
    report = detect(fixture_bytes("winartifact_powershell.pf"))
    assert any("ctfc winartifact" in guess.next_step for guess in report.guesses)


def test_a_volume_guid_is_not_reported_as_a_flag(fixture_bytes):
    """`\\VOLUME{01d9c0b2-...}` matches the generic flag shape. Windows is full of them."""
    report = winartifact.analyse(fixture_bytes("winartifact_powershell.pf"))
    assert all("VOLUME{" not in flag for flag in report.flags)
