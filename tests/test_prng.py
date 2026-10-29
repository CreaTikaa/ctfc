"""Tests for cloning a weak random generator (core/prng.py).

The ground truth is not our own code: the MT19937 tests compare against Python's
own `random`, and the java.util.Random values were produced by a real JVM
(`new Random(1234567890123L).nextInt()`).
"""

from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from ctfc.core import prng

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Tempering
# ---------------------------------------------------------------------------


def test_untemper_is_the_inverse_of_temper():
    rng = random.Random(1)
    for _ in range(200):
        word = rng.getrandbits(32)
        assert prng.untemper(prng.temper(word)) == word


def test_untempered_outputs_are_pythons_own_state():
    """Untempering 624 outputs gives back exactly what `getstate()` reports."""
    rng = random.Random(99)
    outputs = [rng.getrandbits(32) for _ in range(624)]
    state = rng.getstate()[1]
    assert state[624] == 624  # "stir before the next number", as the snippet assumes
    assert [prng.untemper(value) for value in outputs] == list(state[:624])


# ---------------------------------------------------------------------------
# MT19937: forward
# ---------------------------------------------------------------------------


def test_predicts_the_next_values():
    rng = random.Random(2024)
    captured = [rng.getrandbits(32) for _ in range(624)]
    report = prng.recover_mt19937(captured, forward=5, backward=0)
    assert report.generator == "MT19937"
    assert report.next_values == [rng.getrandbits(32) for _ in range(5)]


def test_prediction_starts_after_the_last_value_given():
    """Extra values confirm the clone; the prediction must not repeat them."""
    rng = random.Random(7)
    captured = [rng.getrandbits(32) for _ in range(700)]
    report = prng.recover_mt19937(captured, forward=3, backward=0)
    assert report.confirmed == 76
    assert report.next_values == [rng.getrandbits(32) for _ in range(3)]
    assert any("confirmed" in note for note in report.notes)


def test_capture_may_start_anywhere_in_the_stream():
    """624 *consecutive* words are enough: the twist boundary does not matter."""
    rng = random.Random(555)
    stream = [rng.getrandbits(32) for _ in range(1500)]
    report = prng.recover_mt19937(stream[300:924], forward=4, backward=0)
    assert report.next_values == stream[924:928]


def test_predicts_random_floats():
    """random.random() spends two words and shows 27 + 26 of their bits."""
    rng = random.Random(31337)
    captured = [rng.getrandbits(32) for _ in range(624)]
    report = prng.recover_mt19937(captured, forward=3, backward=0)
    assert report.next_floats == [rng.random() for _ in range(3)]


# ---------------------------------------------------------------------------
# MT19937: backward
# ---------------------------------------------------------------------------


def test_recovers_the_values_handed_out_earlier():
    """The tokens issued before the capture started, which is the useful half."""
    rng = random.Random(4242)
    stream = [rng.getrandbits(32) for _ in range(1400)]
    report = prng.recover_mt19937(stream[700:1324], forward=0, backward=5)
    # previous_values is most recent first.
    assert list(reversed(report.previous_values)) == stream[695:700]


# ---------------------------------------------------------------------------
# Refusals: say what is missing, never guess
# ---------------------------------------------------------------------------


def test_too_few_values_says_how_many_more():
    with pytest.raises(prng.PrngError, match="124 more"):
        prng.recover_mt19937([1] * 500)


def test_values_wider_than_32_bits_are_refused():
    with pytest.raises(prng.PrngError, match="32 bits"):
        prng.recover_mt19937([1 << 40] * 624)


def test_real_random_bytes_are_not_mistaken_for_mt19937():
    values = [int.from_bytes(os.urandom(4), "big") for _ in range(700)]
    with pytest.raises(prng.PrngError, match="not one uninterrupted run"):
        prng.recover_mt19937(values)


def test_a_gap_in_the_capture_is_detected():
    """One missing value breaks the recurrence, and that is reported, not hidden."""
    rng = random.Random(11)
    captured = [rng.getrandbits(32) for _ in range(700)]
    del captured[650]
    with pytest.raises(prng.PrngError, match="not one uninterrupted run"):
        prng.recover_mt19937(captured)


# ---------------------------------------------------------------------------
# java.util.Random (ground truth: a real JVM)
# ---------------------------------------------------------------------------

JAVA_SEED = 1234567890123
JAVA_OUTPUTS = [
    -8722476,
    -1977939436,
    -999828940,
    -741339138,
    -916778800,
    -1183211565,
    -1030857102,
    -187463566,
]


def test_java_seed_from_two_outputs():
    report = prng.recover_java_random(JAVA_OUTPUTS[:2], forward=6)
    assert report.generator == "java.util.Random"
    assert report.seed == JAVA_SEED
    assert report.next_values == JAVA_OUTPUTS[2:]


def test_java_extra_outputs_confirm_the_state():
    report = prng.recover_java_random(JAVA_OUTPUTS[:4], forward=4)
    assert report.seed == JAVA_SEED
    assert report.confirmed == 2
    assert report.next_values == JAVA_OUTPUTS[4:]


def test_java_needs_two_values():
    with pytest.raises(prng.PrngError, match="at least two"):
        prng.recover_java_random(JAVA_OUTPUTS[:1])


def test_java_refuses_numbers_it_cannot_produce():
    with pytest.raises(prng.PrngError, match="no 48-bit state"):
        prng.recover_java_random([1, 2, 3])


def test_java_snippet_replays_the_sequence():
    """The generated snippet is what the user runs by hand: it must be correct."""
    report = prng.recover_java_random(JAVA_OUTPUTS[:2], forward=2)
    namespace: dict = {}
    exec(compile(report.python, "<snippet>", "exec"), namespace)  # noqa: S102
    replay = namespace["JavaRandom"](JAVA_SEED)
    assert [replay.next_int() for _ in range(8)] == JAVA_OUTPUTS


# ---------------------------------------------------------------------------
# Dispatch, parsing, and the honest notes
# ---------------------------------------------------------------------------


def test_solve_picks_mt19937_when_there_are_enough_values():
    rng = random.Random(8)
    captured = [rng.getrandbits(32) for _ in range(624)]
    assert prng.solve(captured, forward=1, backward=0).generator == "MT19937"


def test_solve_picks_java_for_a_short_run():
    assert prng.solve(JAVA_OUTPUTS[:3], forward=1).generator == "java.util.Random"


def test_solve_explains_both_failures_at_once():
    with pytest.raises(prng.PrngError, match="too few to clone MT19937"):
        prng.solve([5, 7, 9, 11])


def test_parse_numbers_reads_the_shapes_a_challenge_prints():
    integers, floats = prng.parse_numbers("[1234, 0xff, -5]\n987\n0.25 1e3")
    assert integers == [1234, 255, -5, 987]
    assert floats == [0.25, 1000.0]


def test_parse_numbers_does_not_read_hex_as_a_float():
    """0xef contains an 'e': it is a number in hex, not scientific notation."""
    integers, floats = prng.parse_numbers("0xef 0xE5")
    assert integers == [0xEF, 0xE5]
    assert floats == []


def test_float_notes_say_what_is_missing():
    notes = prng.float_notes(3)
    assert any("11 bits per float" in note for note in notes)


def test_truncation_notes_spot_31_bit_output():
    """PHP's mt_rand() drops the low bit, so untempering cannot be applied."""
    rng = random.Random(3)
    values = [rng.getrandbits(32) >> 1 for _ in range(100)]
    notes = prng.truncation_notes(values)
    assert any("mt_rand" in note for note in notes)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def test_fixture_mt19937_is_cloned():
    text = (FIXTURES / "prng_mt19937.txt").read_text()
    integers, _ = prng.parse_numbers(text)
    report = prng.solve(integers, forward=3, backward=3)
    expected = random.Random(20251029)
    [expected.getrandbits(32) for _ in range(624)]
    assert report.next_values == [expected.getrandbits(32) for _ in range(3)]
    assert report.python.startswith('"""Clone Python')


def test_fixture_java_gives_the_seed_back():
    text = (FIXTURES / "prng_java_nextint.txt").read_text()
    integers, _ = prng.parse_numbers(text)
    report = prng.solve(integers, generator="java", forward=1)
    assert report.seed == JAVA_SEED
