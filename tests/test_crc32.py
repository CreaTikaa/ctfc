"""Tests for working backwards from a CRC32 (core/crc32.py).

The point of the module is not only to find *a* preimage - that is a linear
solve and always possible - but to say how much a given answer is worth. These
tests check both: that the real content comes back when it is findable, and that
a coincidence is labelled as one.
"""

from __future__ import annotations

import json
import zlib

import pytest

from ctfc.core import crc32
from ctfc.core.budget import Budget

# ---------------------------------------------------------------------------
# The pieces
# ---------------------------------------------------------------------------


def test_brute_force_finds_a_short_string():
    assert crc32.brute_force(zlib.crc32(b"ab"), 2) == b"ab"
    assert crc32.brute_force(zlib.crc32(b"\xff\x00"), 2) == b"\xff\x00"
    assert crc32.brute_force(zlib.crc32(b"abcd"), 4) is None  # beyond its range


def test_word_list_finds_a_word_and_its_variants():
    found = dict((payload, how) for payload, how in crc32.from_word_list(zlib.crc32(b"dragon")))
    assert b"dragon" in found
    newline = dict(crc32.from_word_list(zlib.crc32(b"secret\n")))
    assert b"secret\n" in newline
    assert "newline" in newline[b"secret\n"]


def test_pattern_fills_the_unknown_characters():
    assert crc32.from_pattern(zlib.crc32(b"CYBN{abc}"), b"CYBN{???}") == b"CYBN{abc}"
    assert crc32.from_pattern(zlib.crc32(b"CYBN{abc}"), b"CYBN{zzz}") is None


def test_the_crc_register_can_be_run_backwards():
    """Each CRC step is invertible, which is what makes the two-halves search work."""
    start = 0xFFFFFFFF
    forward = crc32._update(start, b"second half")
    assert crc32._undo(forward, b"second half") == start


def test_meet_in_the_middle_finds_a_word_that_is_in_no_list():
    text = b"zxqvbn"
    found = crc32.meet_in_the_middle(zlib.crc32(text), len(text))
    assert found == text


def test_meet_in_the_middle_over_digits():
    assert crc32.meet_in_the_middle(zlib.crc32(b"4242"), 4, b"0123456789") == b"4242"


def test_meet_in_the_middle_refuses_a_space_it_cannot_afford():
    assert crc32.meet_in_the_middle(0, 8, crc32.PRINTABLE) is None


# ---------------------------------------------------------------------------
# The linear solve
# ---------------------------------------------------------------------------


def test_solve_linear_over_gf2():
    columns = [0b0011, 0b0101, 0b1000]
    chosen = crc32.solve_linear(columns, 0b0110)
    assert chosen is not None
    result = 0
    for index in chosen:
        result ^= columns[index]
    assert result == 0b0110
    assert crc32.solve_linear([0b0001], 0b0010) is None


def test_solve_preimage_needs_at_least_thirty_two_free_bits():
    """Thirty-two is necessary but not sufficient: those bits may not span GF(2)^32."""
    # Four bytes with four free bits each is only 16 equations' worth: hopeless.
    assert crc32.solve_preimage(0xDEADBEEF, 4, 0x61, 0x0F) is None
    # Nine of them is 36 bits, which does span it; four free *bytes* always do.
    assert crc32.solve_preimage(0xDEADBEEF, 9, 0x61, 0x0F) is not None
    assert crc32.solve_preimage(0xDEADBEEF, 4, 0x00, 0xFF) is not None


def test_a_solved_preimage_really_has_that_crc():
    for length in (4, 5, 9, 20, 64):
        found = crc32.solve_preimage(0x12345678, length, 0x00, 0xFF)
        assert found is not None and len(found) == length
        assert zlib.crc32(found) & 0xFFFFFFFF == 0x12345678


def test_a_solved_preimage_stays_inside_its_character_class():
    found = crc32.solve_preimage(0x12345678, 12, 0x30, 0x07)
    assert found is not None
    assert all(ord("0") <= byte <= ord("7") for byte in found)
    assert zlib.crc32(found) & 0xFFFFFFFF == 0x12345678


# ---------------------------------------------------------------------------
# The entry points, and how much an answer is worth
# ---------------------------------------------------------------------------


def test_recover_prefers_the_word_list():
    report = crc32.recover(zlib.crc32(b"dragon"), 6)
    assert report.results[0].data == b"dragon"
    assert report.results[0].method == "word list"
    assert report.results[0].exact


def test_recover_falls_back_to_the_two_halves_search():
    report = crc32.recover(zlib.crc32(b"zxqvb"), 5)
    assert report.results[0].data == b"zxqvb"
    assert report.results[0].method == "meet in the middle"
    assert report.results[0].exact


def test_recover_marks_a_long_match_as_not_the_original():
    """At eight characters the space is bigger than the checksum: say so."""
    text = b"qzjwvxkb"  # eight letters, and in no word list
    report = crc32.recover(zlib.crc32(text), len(text))
    assert report.results
    assert not report.results[0].exact
    assert "not necessarily the original" in report.results[0].note


def test_recover_solves_a_preimage_when_asked_and_labels_it():
    report = crc32.recover(0xDEADBEEF, 12, solve=True)
    assert report.results
    result = report.results[0]
    assert result.method == "solved"
    assert not result.exact
    assert zlib.crc32(result.data) & 0xFFFFFFFF == 0xDEADBEEF
    assert any("not 'what" in note for note in report.notes)


def test_recover_without_solve_stays_silent_rather_than_inventing():
    report = crc32.recover(0xDEADBEEF, 12, solve=False)
    assert report.results == []


def test_any_length_deduces_the_length():
    report = crc32.recover_any_length(zlib.crc32(b"1337"))
    assert report.results[0].data == b"1337"
    assert report.length == 4
    assert report.results[0].exact


def test_any_length_labels_a_coincidence_for_a_random_checksum():
    """A random checksum has *some* preimage; it must not be sold as the content."""
    report = crc32.recover_any_length(0x11223344, budget=Budget(max_seconds=30))
    for result in report.results:
        assert not result.exact
        assert "%" in result.note


def test_the_spaces_are_searched_smallest_first():
    spaces = crc32.searchable_spaces()
    assert spaces == sorted(spaces)
    assert spaces[0][3] == 1  # one byte, over digits: ten possibilities


def test_collision_estimate():
    assert crc32.collision_estimate(2**32) == pytest.approx(1.0)
    assert crc32.collision_estimate(10**4) < 0.001


def test_report_to_dict():
    payload = json.loads(json.dumps(crc32.recover(zlib.crc32(b"dragon"), 6).to_dict()))
    assert payload["results"][0]["text"] == "dragon"
    assert payload["target"] == f"{zlib.crc32(b'dragon'):08x}"


# ---------------------------------------------------------------------------
# Through the ZIP reader and the CLI
# ---------------------------------------------------------------------------


def test_zip_recovers_a_six_byte_file_from_its_crc():
    """This is the whole point: six bytes used to be out of reach, three was the limit."""
    import io
    import zipfile

    from ctfc.core import zipinfo

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("password.txt", b"dragon")
    report = zipinfo.analyse(buffer.getvalue())
    assert report.entries[0].recovered == b"dragon"


def test_zip_does_not_report_a_fabricated_preimage():
    import io
    import zipfile

    from ctfc.core import zipinfo

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("blob.bin", bytes(range(8)))
    report = zipinfo.analyse(buffer.getvalue())
    assert report.entries[0].recovered is None


def test_cli_crc():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("crc", f"{zlib.crc32(b'dragon'):08x}", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["results"][0]["text"] == "dragon"


def test_cli_crc_pattern():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("crc", f"0x{zlib.crc32(b'CYBN{ab}'):08x}", "--pattern", "CYBN{??}", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout.decode())
    assert payload["results"][0]["text"] == "CYBN{ab}"


def test_cli_crc_refuses_rubbish():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc("crc", "not-a-number")
    assert result.returncode == 2
    assert b"is not a CRC32" in result.stderr
