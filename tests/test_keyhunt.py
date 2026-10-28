"""Tests for key hunting (core/keyhunt.py).

The fixtures are built by tests/make_fixtures.py with its own AES key expansion
(S-box by brute-force inverse), so ctfc's expansion is not checked against itself.
The expansion is also pinned to the FIPS-197 appendix A vectors below.
"""

import json
import os
import subprocess
import sys

import pytest

from ctfc.core.budget import Budget
from ctfc.core.detect import detect
from ctfc.core.keyhunt import (
    SBOX,
    expand_key,
    extract_candidates,
    find_aes_schedules,
    find_ascii_keys,
    find_encoded,
    find_labelled,
    hunt,
)

HUNTS = [
    ("memdump_aes.bin", "memdump_aes_ct.bin", "aes_schedule", 0x5A30, "CYBN{fixture_key_schedule}"),
    ("strings_dump.txt", "strings_dump_ct.bin", "labelled", None, "CYBN{fixture_strings_key}"),
    (
        "binary_with_key.bin",
        "binary_with_key_ct.bin",
        "ascii_near_constant",
        0x700,
        "CYBN{fixture_ascii_key}",
    ),
]


# ---------------------------------------------------------------------------
# AES key expansion (FIPS-197) and the schedule scan
# ---------------------------------------------------------------------------


def test_sbox_known_values():
    assert SBOX[0x00] == 0x63
    assert SBOX[0x53] == 0xED  # the worked example of FIPS-197 section 5.1.1
    assert SBOX[0xFF] == 0x16
    assert len(set(SBOX)) == 256  # a permutation


@pytest.mark.parametrize(
    "key,last_round_key",
    [
        ("2b7e151628aed2a6abf7158809cf4f3c", "d014f9a8c9ee2589e13f0cc8b6630ca6"),
        ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "e98ba06f448c773c8ecc720401002202"),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "fe4890d1e6188d0b046df344706c631e",
        ),
    ],
)
def test_key_expansion_fips197(key, last_round_key):
    expanded = expand_key(bytes.fromhex(key))
    assert len(expanded) == {16: 176, 24: 208, 32: 240}[len(key) // 2]
    assert expanded[-16:].hex() == last_round_key


def test_schedule_found_at_any_offset_and_across_chunks():
    data = bytearray(os.urandom(300_000))
    plants = {16: 3, 24: 65_536 - 50, 32: 200_001}  # the 24-byte one straddles a chunk border
    for size, offset in plants.items():
        key = os.urandom(size)
        schedule = expand_key(key)
        data[offset : offset + len(schedule)] = schedule
    found = find_aes_schedules(bytes(data), chunk=65_536)
    assert sorted((c.offset, len(c.key)) for c in found) == sorted(
        (o, s) for s, o in plants.items()
    )


def test_damaged_schedule_still_matches():
    key = os.urandom(32)
    schedule = bytearray(expand_key(key))
    for position in (100, 150, 200):  # three flipped bytes out of 240
        schedule[position] ^= 0xFF
    found = find_aes_schedules(bytes(1000) + bytes(schedule) + bytes(1000))
    assert [c.key for c in found] == [key]


def test_no_schedule_in_random_or_zero_data():
    assert find_aes_schedules(os.urandom(200_000)) == []
    assert find_aes_schedules(bytes(100_000)) == []


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_labelled_values():
    data = (
        b"cfg: aes_key = 00112233445566778899aabbccddeeff\niv="
        + b"ab" * 16
        + b"\npassword: hunter2\n"
    )
    found = {(c.role, c.key) for c in find_labelled(data)}
    assert ("key", bytes.fromhex("00112233445566778899aabbccddeeff")) in found
    assert ("iv", b"\xab" * 16) in found
    assert ("passphrase", b"hunter2") in found


def test_encoded_keys_and_no_hex_read_as_base64():
    data = b"x " + b"41" * 32 + b" y " + b"QUFBQUFBQUFBQUFBQUFBQQ==" + b"\n"
    found = find_encoded(data)
    assert [(c.kind, len(c.key)) for c in found] == [("hex", 32), ("base64", 16)]


def test_ascii_key_at_the_end_of_a_c_string():
    data = b"\x01\x02junk!!" + b"Sup3rS3cr3tK3y!!" + b"\x00\x00rest"
    keys = [c.key for c in find_ascii_keys(data)]
    assert b"Sup3rS3cr3tK3y!!" in keys


def test_candidates_are_ranked_and_unique(fixture_bytes):
    candidates = extract_candidates(fixture_bytes("memdump_aes.bin"))
    assert candidates[0].kind == "aes_schedule"
    keys = [(c.key, c.role) for c in candidates]
    assert len(keys) == len(set(keys))
    strengths = [c.strength for c in candidates]
    assert strengths == sorted(strengths, reverse=True)


# ---------------------------------------------------------------------------
# The hunt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dump,ciphertext,kind,offset,flag", HUNTS)
def test_hunt_finds_the_key(fixture_bytes, dump, ciphertext, kind, offset, flag):
    report = hunt(fixture_bytes(dump), fixture_bytes(ciphertext))
    assert report.winner is not None, report.notes
    assert report.winner.kind == kind
    if offset is not None:
        assert report.winner.offset == offset
    best = report.results[0]
    assert flag in best.data.decode()
    assert best.reasons[0].startswith(f"key found at offset 0x{report.winner.offset:x}")


@pytest.mark.parametrize("dump,ciphertext,kind,offset,flag", HUNTS)
def test_generated_script_reproduces_it(
    fixture_bytes, tmp_path, dump, ciphertext, kind, offset, flag
):
    best = hunt(fixture_bytes(dump), fixture_bytes(ciphertext)).results[0]
    script = tmp_path / "reproduce.py"
    script.write_text(best.python)
    (tmp_path / "input.bin").write_bytes(fixture_bytes(ciphertext))
    done = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=60
    )
    assert done.returncode == 0, best.python + done.stderr.decode()
    assert flag in done.stdout.decode()
    assert best.python.startswith("# key found at offset")


def test_without_ciphertext_candidates_are_only_listed(fixture_bytes):
    report = hunt(fixture_bytes("strings_dump.txt"))
    assert report.tested == 0
    assert report.candidates
    assert any("nothing tested" in note for note in report.notes)


def test_wrong_ciphertext_says_so(fixture_bytes):
    report = hunt(fixture_bytes("strings_dump.txt"), os.urandom(64))
    assert report.winner is None
    assert any("no candidate decrypted" in note for note in report.notes)


def test_budget_stops_the_hunt(fixture_bytes):
    budget = Budget(max_attempts=2, max_seconds=30)
    report = hunt(fixture_bytes("binary_with_key.bin"), os.urandom(64), budget=budget)
    assert report.tested <= 2
    assert any("stopped after" in note for note in report.notes)


def test_report_serialises(fixture_bytes):
    report = hunt(fixture_bytes("memdump_aes.bin"), fixture_bytes("memdump_aes_ct.bin"))
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["winner"]["offset_hex"] == "0x5a30"
    assert payload["candidate_count"] >= 1


def test_detect_reports_the_key_schedule(fixture_bytes):
    guesses = [
        g for g in detect(fixture_bytes("memdump_aes.bin")).guesses if g.rule == "keys.aes_schedule"
    ]
    assert guesses and "0x5a30" in guesses[0].label
    assert guesses[0].apply == {"tab": "keys", "options": {}}
