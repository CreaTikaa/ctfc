"""`ctfc scan` tests: a folder of carved files must come out ranked sensibly.

The folders are built in the test, shaped like what `binwalk -e` or Wireshark's
"export objects" leaves behind: a few payloads, a couple of ordinary files, and
some random noise that must *not* be reported.
"""

import random

import pytest

from ctfc.core.budget import Budget
from ctfc.core.scan import PLAIN_TEXT_CAP, list_files, scan, scan_file


@pytest.fixture
def carved(tmp_path, fixture_bytes):
    """A folder that looks like the output of a carving tool."""
    (tmp_path / "sub").mkdir()
    files = {
        "0x1000.txt": fixture_bytes("layers_b64_zlib_hex.txt"),
        "0x2000.png": fixture_bytes("png_with_zip.png"),
        "0x3000.enc": fixture_bytes("openssl_salted_md5.bin"),
        "sub/creds.txt": fixture_bytes("mysqlna_hash.txt"),
        "sub/0x4000.bin": fixture_bytes("xor_repeating.bin"),
        "readme.txt": b"just an ordinary readme with nothing of interest in it at all.\n",
        # Real randomness: bytes(range(256)) would be the RC4 S-box initial
        # state, which detect rightly flags as a crypto constant.
        "noise.bin": random.Random(3).randbytes(4096),
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    return tmp_path


def by_name(report) -> dict:
    return {result.path.name: result for result in report.files}


def test_lists_files_recursively(carved):
    names = {path.name for path in list_files(carved)}
    assert "creds.txt" in names and "0x1000.txt" in names
    assert {path.name for path in list_files(carved, recursive=False)} < names


def test_skips_noise_files(tmp_path):
    (tmp_path / ".DS_Store").write_bytes(b"x" * 100)
    (tmp_path / "module.pyc").write_bytes(b"x" * 100)
    (tmp_path / "real.bin").write_bytes(b"x" * 100)
    assert [path.name for path in list_files(tmp_path)] == ["real.bin"]


def test_ranks_the_payloads_above_the_noise(carved):
    report = scan(carved)
    ranked = [result.path.name for result in report.files]
    assert ranked[0] in ("0x4000.bin", "0x1000.txt"), ranked
    results = by_name(report)
    assert results["0x1000.txt"].interest > 0.9, "a full decoding chain is a strong finding"
    assert results["noise.bin"].interest == 0.0, "random bytes must not be reported"
    assert results["readme.txt"].interest <= PLAIN_TEXT_CAP


def test_a_decoded_chain_is_reported_with_its_result(carved):
    report = scan(carved)
    result = by_name(report)["0x1000.txt"]
    assert result.best is not None
    assert b"CYBN{fixture_layers_b64_zlib_hex}" in result.best.data
    assert any("auto:" in reason for reason in result.reasons)


def test_a_container_is_worth_opening_even_without_a_chain(carved):
    """An openssl enc file decodes to nothing here, but it is still a finding."""
    result = by_name(scan(carved))["0x3000.enc"]
    assert result.interest >= 0.6
    assert "openssl" in result.kind.lower()


def test_a_polyglot_is_spotted(carved):
    """The PNG has a ZIP appended: that is more interesting than a plain PNG."""
    result = by_name(scan(carved))["0x2000.png"]
    assert result.interest >= 0.7
    assert any("appended" in reason or "polyglot" in reason for reason in result.reasons)


def test_a_flag_in_a_file_wins(tmp_path):
    (tmp_path / "plain.txt").write_bytes(b"nothing here")
    (tmp_path / "found.txt").write_bytes(b"the flag is CYBN{scan_found_it} enjoy")
    report = scan(tmp_path)
    assert report.files[0].path.name == "found.txt"
    assert report.files[0].interest > 0.9
    assert any("a flag pattern was found" in note for note in report.notes)


def test_interesting_threshold(carved):
    report = scan(carved)
    assert len(report.interesting(0.9)) < len(report.interesting(0.4))


def test_budget_stops_the_scan_cleanly(carved):
    report = scan(carved, budget=Budget(max_attempts=10, max_seconds=0.001))
    assert any("time budget spent" in note for note in report.notes)


def test_unreadable_file_is_reported_not_raised(tmp_path):
    target = tmp_path / "locked.bin"
    target.write_bytes(b"secret")
    target.chmod(0o000)
    try:
        result = scan_file(target)
    finally:
        target.chmod(0o644)
    assert result.kind == "unreadable" and result.error


def test_missing_folder_says_so(tmp_path):
    report = scan(tmp_path / "nope")
    assert not report.files and any("does not exist" in note for note in report.notes)


def test_scanning_a_single_file_works(carved):
    report = scan(carved / "0x1000.txt")
    assert len(report.files) == 1 and report.files[0].best is not None


def test_empty_folder(tmp_path):
    report = scan(tmp_path)
    assert any("no file to scan" in note for note in report.notes)
