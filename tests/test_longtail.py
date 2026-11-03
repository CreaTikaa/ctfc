"""Tests for the encoding long tail (ideas.md 3.3).

What earns a place in `encodings.py` rather than a link to dcode.fr is that the
decoding is *deterministic*, so `auto` can simply try it. These tests check
three things for each one: the round trip, that `applicable` is tight enough not
to fire on the wrong input, and - for base45 - the published RFC test vectors,
which is real ground truth rather than our encoder agreeing with our decoder.
"""

from __future__ import annotations

import pytest

from ctfc.core import classical
from ctfc.core import encodings as e
from ctfc.core.auto import auto_decode
from ctfc.core.flags import default_flagset

MESSAGE = b"CYBN{the_long_tail_of_encodings} and a sentence so the scoring has text."

# ---------------------------------------------------------------------------
# Base45, against RFC 9285's own test vectors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("plain", "encoded"),
    [
        (b"AB", "BB8"),
        (b"Hello!!", "%69 VD92EX0"),
        (b"base-45", "UJCLQE7W581"),
        (b"ietf!", "QED8WEX0"),
    ],
)
def test_base45_matches_the_rfc_test_vectors(plain, encoded):
    assert e.base45_encode(plain) == encoded
    assert e.base45_decode(encoded.encode()) == plain


def test_base45_keeps_the_spaces_it_encodes():
    """A space is base45 character 36: squeezing whitespace out corrupts the value."""
    assert " " in e.base45_encode(b"Hello!!")
    assert e.base45_decode(b"%69 VD92EX0\n") == b"Hello!!"


def test_base45_rejects_an_impossible_length():
    # Three characters carry two bytes, so a length of 3n+1 cannot happen.
    assert not e.base45_ok(b"BB8X")


# ---------------------------------------------------------------------------
# basE91, Z85, uuencode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["base91", "z85", "base45"])
def test_round_trip(name, fixture_bytes):
    data = fixture_bytes(f"longtail_{name}.txt")
    decoder = e.DECODERS_BY_NAME[name]
    assert decoder.applicable(data)
    decoded = decoder.decode(data)
    assert MESSAGE in decoded  # z85 pads to a multiple of four bytes


def test_base91_round_trips_every_length():
    for length in range(1, 40):
        payload = bytes(range(length))
        assert e.base91_decode(e.base91_encode(payload).encode()) == payload


def test_z85_needs_whole_groups():
    assert not e.z85_ok(b"abcd")  # not a multiple of five characters
    with pytest.raises(e.DecodeError, match="multiple of five"):
        e.z85_decode(b"abcdef")


def test_uuencode(fixture_bytes):
    data = fixture_bytes("longtail_uu.txt")
    assert e.uu_ok(data)
    assert e.uu_decode(data) == MESSAGE
    assert not e.uu_ok(b"no begin line here\nM0123456789\n")


# ---------------------------------------------------------------------------
# Morse, Bacon, Polybius, tap code, A1Z26
# ---------------------------------------------------------------------------


def test_morse(fixture_bytes):
    data = fixture_bytes("longtail_morse.txt")
    assert e.morse_ok(data)
    assert e.morse_decode(data) == b"CYBNFLAG IN MORSE CODE"


def test_morse_accepts_the_separators_seen_in_the_wild():
    assert e.morse_decode(b"-.-. -.-- -... -. | .-- .- .-.") == b"CYBN WAR"
    assert e.morse_decode(b"-.-. -.-- -... -.   .-- .- .-.") == b"CYBN WAR"
    assert e.morse_decode(b"_._. _.__ _... _.") == b"CYBN"


def test_bacon_both_tables(fixture_bytes):
    data = fixture_bytes("longtail_bacon.txt")
    assert e.bacon26_ok(data)
    assert e.bacon26_decode(data) == b"CYBNFLAGINBACON"
    # The 24-letter table is a different cipher, not a different reading: a code
    # above 23 simply does not exist in it.
    with pytest.raises(e.DecodeError, match="24-letter"):
        e.bacon24_decode(data)
    old_style = e.bacon_encode("FLAG", e.BACON24)
    assert e.bacon24_decode(old_style.encode()) == b"FLAG"


def test_bacon_works_with_any_two_letters():
    assert e.bacon26_decode(e.bacon_encode("FLAG").encode()) == b"FLAG"
    swapped = e.bacon_encode("FLAG").replace("A", "0").replace("B", "1")
    assert e.bacon26_decode(swapped.encode()) == b"FLAG"


def test_polybius(fixture_bytes):
    data = fixture_bytes("longtail_polybius.txt")
    assert e.polybius_ok(data)
    assert e.polybius_decode(data) == b"CYBNFLAGINPOLYBIUS"


def test_tap_code(fixture_bytes):
    data = fixture_bytes("longtail_tap.txt")
    assert e.tap_ok(data)
    # The square differs from Polybius by one letter: C is tapped as K.
    assert e.tap_decode(data).startswith(b"CYBNFLAGIN")


def test_a1z26(fixture_bytes):
    data = fixture_bytes("longtail_a1z26.txt")
    assert e.a1z26_ok(data)
    assert e.a1z26_decode(data) == b"CYBNFLAG IN A ONE Z TWENTYSIX"


def test_the_small_alphabets_do_not_fire_on_noise():
    """With an alphabet this small, a short run happens by accident constantly."""
    assert not e.a1z26_ok(b"12 3")  # four numbers is not evidence of anything
    assert not e.morse_ok(b".. .")
    assert not e.polybius_ok(b"1122")
    assert not e.bacon26_ok(b"ABABA")


# ---------------------------------------------------------------------------
# Through auto
# ---------------------------------------------------------------------------


def test_auto_peels_base45(fixture_bytes):
    found = auto_decode(fixture_bytes("longtail_base45.txt"), flagset=default_flagset())
    assert found
    assert b"CYBN{the_long_tail_of_encodings}" in found[0].data


def test_auto_finds_morse_under_a_base64_layer():
    import base64

    blob = base64.b64encode(e.morse_encode("CYBNFLAG IN MORSE").encode())
    labels = [candidate.label for candidate in auto_decode(blob)]
    assert "base64 -> morse" in labels


def test_auto_peels_bacon(fixture_bytes):
    found = auto_decode(fixture_bytes("longtail_bacon.txt"))
    assert any(b"CYBNFLAGINBACON" == candidate.data for candidate in found)


# ---------------------------------------------------------------------------
# Beaufort
# ---------------------------------------------------------------------------


def test_beaufort_is_its_own_inverse():
    plain = b"Attack at dawn, and not before."
    cipher = classical.beaufort_decrypt(plain, "lemon")
    assert cipher != plain
    assert classical.beaufort_decrypt(cipher, "lemon") == plain


def test_beaufort_leaves_everything_but_letters_alone():
    assert classical.beaufort_decrypt(b"a-b 1!", "a") == b"a-z 1!"


def test_beaufort_needs_a_key():
    with pytest.raises(classical.ClassicalError, match="needs at least one letter"):
        classical.beaufort_decrypt(b"abc", "123")


def test_beaufort_is_solved_blind(fixture_bytes):
    """The key is found from the column frequencies, with no key given."""
    found = classical.solve_classical(
        fixture_bytes("classical_beaufort.txt"), flagset=default_flagset()
    )
    assert found
    best = found[0]
    assert best.label == "beaufort(key='lemon')"
    assert b"CYBN{beaufort_subtracts}" in best.data
    assert best.score > 0.9


def test_beaufort_with_the_key_given(fixture_bytes):
    found = classical.solve_classical(
        fixture_bytes("classical_beaufort.txt"), cipher="beaufort", params={"key": "lemon"}
    )
    assert b"universally acknowledged" in found[0].data
    assert "beaufort_decrypt" in found[0].python


def test_beaufort_key_is_accepted_from_the_command_line():
    assert classical.parse_key("beaufort", "lemon") == {"key": "lemon"}


def test_cli_classical_beaufort():
    from tests.test_cli import run_ctfc  # noqa: PLC0415

    result = run_ctfc(
        "classical", "tests/fixtures/classical_beaufort.txt", "--cipher", "beaufort", "--json"
    )
    assert result.returncode == 0
    assert b"beaufort_subtracts" in result.stdout
