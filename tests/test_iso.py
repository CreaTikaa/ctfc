"""The ISO 9660 reader (core/iso.py): the files inside a .iso disk image.

A .iso is how a disc or USB image is handed over, and the flag is a file in it.
Ground truth: 7z, which lists the same files, where it is installed. WaniCTF
2024 "tiny_usb" is a one-file ISO.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from ctfc.core import iso, readers

FIXTURES = Path(__file__).parent / "fixtures"
HAS_7Z = shutil.which("7z") is not None


def test_iso_is_recognised():
    data = (FIXTURES / "iso_flag.iso").read_bytes()
    assert iso.looks_like_iso(data)
    assert readers.sniff(data) == "iso"


def test_files_and_their_bytes_are_read():
    report = iso.read((FIXTURES / "iso_flag.iso").read_bytes())
    assert report.volume_id == "CTFC_ISO"
    by_name = {f.path.upper(): f.data for f in report.files}
    assert by_name["FLAG.TXT"] == b"CYBN{iso_9660_reader}\n"
    assert any(path.endswith("NOTE.TXT") for path in by_name)  # a file in a subdirectory


def test_solve_pulls_the_flag_file_out_of_the_image():
    from ctfc.core.solve import solve

    report = solve((FIXTURES / "iso_flag.iso").read_bytes(), path="iso_flag.iso")
    assert "CYBN{iso_9660_reader}" in {flag.text for flag in report.flags}


def test_a_non_iso_is_rejected():
    assert not iso.looks_like_iso(b"\x00" * 40000)
    with pytest.raises(iso.IsoError):
        iso.read(b"not an iso" * 5000)


@pytest.mark.skipif(not HAS_7Z, reason="7z not installed")
def test_file_list_matches_7z():
    out = subprocess.run(
        ["7z", "l", str(FIXTURES / "iso_flag.iso")],
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    sizes_7z = {int(line.split()[3]) for line in out.splitlines() if "flag.txt" in line.lower()}
    ours = {
        len(f.data)
        for f in iso.read((FIXTURES / "iso_flag.iso").read_bytes()).files
        if f.path.upper().endswith("FLAG.TXT")
    }
    assert ours and ours <= sizes_7z
