"""Tests for core/luks.py and the LUKS case of `ctfc keys`.

real_luks1_header.bin / real_luks2_header.bin are the metadata of volumes made by
the real `cryptsetup luksFormat` (see tests/make_fixtures.py), so the parser and
the digest check are tested against the reference implementation, not ourselves.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from ctfc.core import luks
from ctfc.core.budget import Budget
from ctfc.core.keyhunt import hunt

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def master(fixture_bytes) -> bytes:
    return bytes.fromhex(fixture_bytes("real_luks_master_key.hex").decode().strip())


@pytest.mark.parametrize(
    "name,version", [("real_luks1_header.bin", 1), ("real_luks2_header.bin", 2)]
)
def test_real_headers_are_read(fixture_bytes, name, version):
    header = luks.parse_header(fixture_bytes(name))
    assert header.version == version
    assert header.cipher == "aes-xts-plain64"
    assert header.key_bytes == 64
    assert header.digest_hash == "sha256"


@pytest.mark.parametrize("name", ["real_luks1_header.bin", "real_luks2_header.bin"])
def test_the_header_confirms_the_master_key_and_only_it(fixture_bytes, master, name):
    header = luks.parse_header(fixture_bytes(name))
    assert luks.is_master_key(header, master)
    assert not luks.is_master_key(header, master[32:] + master[:32])  # wrong order
    assert not luks.is_master_key(header, master[:32])  # wrong size


def test_both_orders_of_two_halves_are_built(master):
    keys = [(master[32:], "B"), (master[:32], "A")]
    built = {key: how for key, how in luks.candidates(keys, 64)}
    assert built[master] == "A || B"
    assert master[32:] + master[:32] in built


def test_header_inside_a_disk_image(fixture_bytes):
    image = bytes(1024 * 1024) + fixture_bytes("real_luks1_header.bin")
    assert luks.find_header(image).offset == 1024 * 1024
    assert luks.find_header(b"LUKS\xba\xbe" + bytes(600)) is None  # not a valid header


def test_keys_against_a_luks_volume_confirms_the_master_key(fixture_bytes, master):
    """The two halves are in memory in the opposite order: the header decides."""
    report = hunt(fixture_bytes("audit_luks_mem.raw"), fixture_bytes("real_luks2_header.bin"))
    assert report.luks is not None
    assert bytes.fromhex(report.luks["master_key_hex"]) == master
    assert "@0x7c00 ||" in report.luks["built_from"]
    assert any("cryptsetup open --volume-key-file" in line for line in report.luks["commands"])
    assert report.tested <= 4  # only the AES key schedules, not every random window


def test_luks_with_the_wrong_dump_says_so(fixture_bytes):
    report = hunt(
        fixture_bytes("memdump_aes.bin"),
        fixture_bytes("real_luks1_header.bin"),
        budget=Budget(max_seconds=20),
    )
    assert report.luks is None
    assert any("no candidate matches" in note for note in report.notes)


def test_cli_keys_luks_json():
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "ctfc",
            "keys",
            "tests/fixtures/audit_luks_mem.raw",
            "--against",
            "tests/fixtures/real_luks1_header.bin",
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr.decode()
    result = json.loads(done.stdout)
    assert result["luks"]["key_bits"] == 512
