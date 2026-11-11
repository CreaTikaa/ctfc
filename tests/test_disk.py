"""The disk-image reader (core/disk.py): filesystems and files via The Sleuth Kit.

A disk/partition image holds the flag as a file, sometimes a deleted one. TSK is
the ground truth - it is the tool this reader drives - so the tests that extract
files are skipped where it is not installed, and the detection/boundary tests run
everywhere. Fixture: a hand-built FAT12 image with a live file, a note, and a
deleted file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ctfc.core import disk, readers

FIXTURES = Path(__file__).parent / "fixtures"
HAS_TSK = disk.available()


def test_detects_a_filesystem_image():
    data = (FIXTURES / "disk_fat12.img").read_bytes()
    assert disk.looks_like_disk_image(data)
    assert readers.sniff(data) == "disk"


def test_detects_ext_and_ntfs_and_partition_tables():
    ext = bytearray(2048)
    ext[0x438:0x43A] = b"\x53\xef"  # ext superblock magic
    assert disk.looks_like_disk_image(bytes(ext))
    ntfs = bytearray(2048)
    ntfs[3:11] = b"NTFS    "
    assert disk.looks_like_disk_image(bytes(ntfs))
    mbr = bytearray(2048)
    mbr[510:512] = b"\x55\xaa"
    mbr[0x1BE] = 0x80  # bootable
    mbr[0x1BE + 4] = 0x83  # Linux partition type
    assert disk.looks_like_disk_image(bytes(mbr))


def test_does_not_claim_random_bytes():
    import random

    rng = random.Random(4)
    for _ in range(200):
        assert not disk.looks_like_disk_image(bytes(rng.randrange(256) for _ in range(2048)))


def test_iso_is_left_to_the_iso_reader():
    iso_data = (FIXTURES / "iso_flag.iso").read_bytes()
    assert readers.sniff(iso_data) == "iso"  # not "disk"


@pytest.mark.skipif(not HAS_TSK, reason="The Sleuth Kit not installed")
def test_extracts_files_and_recovers_a_deleted_one():
    report = disk.analyse((FIXTURES / "disk_fat12.img").read_bytes())
    assert any("FAT12" in p.fs_type for p in report.partitions)
    by_name = {f.path.upper(): f for f in report.files}
    assert by_name["FLAG.TXT"].data == b"CYBN{fat12_disk_reader}\n"
    deleted = [f for f in report.files if f.deleted]
    assert deleted and b"CYBN{deleted_but_recovered}" in deleted[0].data


@pytest.mark.skipif(not HAS_TSK, reason="The Sleuth Kit not installed")
def test_solve_flags_a_file_inside_a_disk_image():
    from ctfc.core.solve import solve

    report = solve((FIXTURES / "disk_fat12.img").read_bytes(), path="disk_fat12.img")
    assert "CYBN{fat12_disk_reader}" in {flag.text for flag in report.flags}


@pytest.mark.skipif(not HAS_TSK, reason="The Sleuth Kit not installed")
def test_file_list_matches_tsk():
    import shutil
    import subprocess

    out = subprocess.run(
        [shutil.which("fls"), "-r", "-p", str(FIXTURES / "disk_fat12.img")],
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    tsk_files = {line.split("\t")[-1] for line in out.splitlines() if line.startswith("r/r")}
    ours = {f.path for f in disk.analyse((FIXTURES / "disk_fat12.img").read_bytes()).files}
    assert ours <= tsk_files
