"""Tests for the classical ciphers (core/classical.py) and their integration.

The fixtures are encrypted by tests/make_fixtures.py with its own code, so these
tests do not check ctfc against itself. The CyberChef strings pinned below were
checked by opening them in the real CyberChef v11.5.0 (all six fixtures decrypt).
"""

import base64
import subprocess
import sys
import zlib

import pytest

from ctfc.core import classical, pipeline
from ctfc.core.auto import auto_decode
from ctfc.core.classical import (
    ClassicalError,
    affine_decrypt,
    analyse,
    atbash,
    caesar_decrypt,
    find_cribs,
    index_of_coincidence,
    is_text_like,
    letters_of,
    parse_key,
    railfence_decrypt,
    railfence_encrypt,
    reduce_key,
    solve_classical,
    vigenere_decrypt,
    vigenere_encrypt,
    vigenere_key_lengths,
)
from ctfc.core.codegen import Step, step_code
from ctfc.core.detect import detect

FIXTURES = [
    ("classical_caesar.txt", "caesar(shift=19)", "CYBN{fixture_caesar_large_shift}"),
    ("classical_affine.txt", "affine(a=7, b=10)", "CYBN{fixture_affine_cipher}"),
    ("classical_atbash.txt", "atbash", "CYBN{fixture_atbash}"),
    ("classical_vigenere.txt", "vigenere(key='forensique')", "CYBN{fixture_vigenere_fr}"),
    ("classical_railfence.txt", "railfence(rails=4)", "CYBN{fixture_rail_fence}"),
    ("classical_vigenere_flag.txt", "vigenere(key='elf')", "CYBN{fixture_short_key}"),
]
ENGLISH = (
    b"Good job agent. The meeting is moved to Friday night, bring the usual equipment "
    b"and do not talk about it on the phone. The flag is CYBN{caesar_is_not_crypto}."
)


# ---------------------------------------------------------------------------
# The ciphers themselves
# ---------------------------------------------------------------------------


def test_caesar_keeps_case_and_punctuation():
    assert caesar_decrypt(b"Khoor, Zruog! 123", 3) == b"Hello, World! 123"
    assert caesar_decrypt(b"PLOA{fvzcyr}", 13) == b"CYBN{simple}"


def test_affine_and_its_inverse():
    # E(x) = 5x + 8: "AFFINE" -> "IHHWVC" (the classic textbook example)
    assert affine_decrypt(b"IHHWVC", 5, 8) == b"AFFINE"
    with pytest.raises(ClassicalError, match="coprime"):
        affine_decrypt(b"x", 13, 1)


def test_atbash_is_its_own_inverse():
    assert atbash(b"Hello") == b"Svool"
    assert atbash(atbash(ENGLISH)) == ENGLISH


def test_vigenere_textbook_and_key_advances_on_letters_only():
    assert vigenere_decrypt(b"LXFOPVEFRNHR", "lemon") == b"ATTACKATDAWN"
    # The space does not use a key letter (CyberChef and dcode behave the same)
    assert vigenere_decrypt(b"LXFOP VEFRNHR", "LEMON") == b"ATTAC KATDAWN"
    assert vigenere_decrypt(vigenere_encrypt(ENGLISH, "secret"), "secret") == ENGLISH
    with pytest.raises(ClassicalError, match="letters only"):
        vigenere_decrypt(b"abc", "k3y")


@pytest.mark.parametrize("rails", range(2, 9))
def test_railfence_round_trip_with_every_offset(rails):
    for offset in range(2 * (rails - 1)):
        assert (
            railfence_decrypt(railfence_encrypt(ENGLISH, rails, offset), rails, offset) == ENGLISH
        )


def test_railfence_textbook():
    assert railfence_decrypt(b"WECRLTEERDSOEEFEAOCAIVDEN", 3) == b"WEAREDISCOVEREDFLEEATONCE"


def test_railfence_bad_keys():
    with pytest.raises(ClassicalError):
        railfence_decrypt(b"abc", 1)
    with pytest.raises(ClassicalError):
        railfence_decrypt(b"abc", 5)


@pytest.mark.parametrize(
    "cipher,text,expected",
    [
        ("caesar", "3", {"shift": 3}),
        ("caesar", "29", {"shift": 3}),
        ("affine", "5, 8", {"a": 5, "b": 8}),
        ("vigenere", "lemon", {"key": "lemon"}),
        ("railfence", "3", {"rails": 3, "offset": 0}),
        ("railfence", "3,1", {"rails": 3, "offset": 1}),
        ("atbash", "", {}),
    ],
)
def test_parse_key(cipher, text, expected):
    assert parse_key(cipher, text) == expected


def test_parse_key_error_says_the_format():
    with pytest.raises(ClassicalError, match="affine 5,8"):
        parse_key("affine", "five")


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------


def test_index_of_coincidence():
    assert index_of_coincidence(letters_of(ENGLISH * 3)) > 0.06
    assert index_of_coincidence("abcdefghijklmnopqrstuvwxyz" * 4) < 0.04


def test_vigenere_key_length_is_found():
    ciphertext = vigenere_encrypt(ENGLISH * 2, "lemon")
    assert vigenere_key_lengths(letters_of(ciphertext))[0].length == 5


def test_families(fixture_bytes):
    assert analyse(fixture_bytes("classical_caesar.txt")).family == "monoalphabetic"
    assert analyse(fixture_bytes("classical_railfence.txt")).family == "natural"
    assert analyse(fixture_bytes("classical_vigenere.txt")).family == "polyalphabetic"


def test_text_like_refuses_base64_and_hex():
    assert is_text_like(b"Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj")
    assert is_text_like(b"PLOA{fvzcyr_fuvsg}")
    assert is_text_like(b"LXFOPVEFRNHR")
    assert not is_text_like(base64.b64encode(ENGLISH))
    assert not is_text_like(ENGLISH.hex().encode())
    assert not is_text_like(bytes(range(256)))


def test_cribs_from_the_flag_prefix():
    cribs = find_cribs(b"PLOA{fvzcyr}")
    assert cribs[0].prefix == "CYBN"
    assert cribs[0].shifts == [13, 13, 13, 13]
    # A real prefix in clear is not a shifted "flag{"
    assert find_cribs(b"CYBN{in_clear}") == []


def test_reduce_key():
    """A key that almost repeats a shorter period is offered as that period."""
    assert reduce_key("harbourharbour") == "harbour"
    shorter = reduce_key("harbourhadjuur")  # 3/4 of the letters repeat "harbour"
    assert shorter is not None and len(shorter) == 7
    assert reduce_key("lemon") is None


# ---------------------------------------------------------------------------
# Solving
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,label,flag", FIXTURES)
def test_fixture_is_solved(fixture_bytes, name, label, flag):
    best = solve_classical(fixture_bytes(name))[0]
    assert best.label == label
    assert flag in best.data.decode()
    assert best.score >= 0.9
    assert best.reasons


@pytest.mark.parametrize("name,label,flag", FIXTURES)
def test_generated_python_reproduces_it(fixture_bytes, tmp_path, name, label, flag):
    best = solve_classical(fixture_bytes(name))[0]
    script = tmp_path / "reproduce.py"
    script.write_text(best.python)
    (tmp_path / "input.bin").write_bytes(fixture_bytes(name))
    done = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=30
    )
    assert done.returncode == 0, best.python + done.stderr.decode()
    assert flag in done.stdout.decode()


def test_given_key_is_used_as_is(fixture_bytes):
    data = fixture_bytes("classical_affine.txt")
    best = solve_classical(data, cipher="affine", params={"a": 7, "b": 10})[0]
    assert "CYBN{fixture_affine_cipher}" in best.data.decode()
    assert "key given" in best.reasons[0]


def test_one_cipher_only(fixture_bytes):
    found = solve_classical(fixture_bytes("classical_caesar.txt"), cipher="atbash")
    assert all(candidate.params["cipher"] == "atbash" for candidate in found)


def test_nothing_on_plain_text_or_encoded_blobs():
    assert solve_classical(b"just some plain english text about the meeting tonight") == []
    assert solve_classical(base64.b64encode(ENGLISH)) == []
    assert solve_classical(b"\x00\x01\x02 binary") == []


def test_short_text_vigenere_is_refined(fixture_bytes):
    """80 letters, key of 7: frequency analysis alone gets a key letter wrong."""
    plain = (
        b"The secret meeting is tonight near the old harbour, bring the documents. "
        b"CYBN{vigenere_in_layers}"
    )
    best = solve_classical(vigenere_encrypt(plain, "harbour"))[0]
    assert best.params["key"] == "harbour"


def test_french_vigenere():
    plain = (
        b"Rendez-vous ce soir au vieux port, apportez les documents et ne parlez a "
        b"personne. Le drapeau est CYBN{chiffre_de_vigenere}"
    )
    assert solve_classical(vigenere_encrypt(plain, "bretagne"))[0].params["key"] == "bretagne"


def test_long_text_is_searched_on_a_sample_and_applied_whole():
    ciphertext = vigenere_encrypt(ENGLISH * 60, "secretkey")
    best = solve_classical(ciphertext, top_n=1)[0]
    assert best.params["key"] == "secretkey"
    assert len(best.data) == len(ciphertext)


# ---------------------------------------------------------------------------
# CyberChef strings (verified in CyberChef v11.5.0) and recipes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "step,recipe",
    [
        (Step("caesar", {"shift": 19}), "ROT13(true,true,false,7)"),
        (Step("affine", {"a": 7, "b": 10}), "Affine_Cipher_Decode(7,10)"),
        (Step("atbash"), "Atbash_Cipher()"),
        (Step("vigenere", {"key": "forensique"}), "Vigenère_Decode('forensique')"),
        (Step("railfence", {"rails": 4, "offset": 0}), "Rail_Fence_Cipher_Decode(4,0)"),
        (
            Step("railfence", {"rails": 4, "offset": 0, "trim": True}),
            "Remove_whitespace(false,true,true,false,false,false)Rail_Fence_Cipher_Decode(4,0)",
        ),
    ],
)
def test_cyberchef_recipes(step, recipe):
    assert step_code(step).cyberchef == recipe


def test_classical_steps_in_a_recipe():
    data = base64.b64encode(vigenere_encrypt(b"CYBN{in_a_recipe} see you there", "lemon"))
    steps = pipeline.parse_steps(["base64", {"op": "vigenere", "args": {"key": "lemon"}}])
    result = pipeline.run(data, steps)
    assert result.ok
    assert result.output.startswith(b"CYBN{in_a_recipe}")
    assert result.cyberchef.endswith("Vigenère_Decode('lemon')")


def test_recipe_classical_errors():
    with pytest.raises(pipeline.RecipeError, match="caesar needs"):
        pipeline.parse_steps([{"op": "caesar"}])
    steps = pipeline.parse_steps([{"op": "affine", "args": {"a": 2, "b": 1}}])
    assert "coprime" in pipeline.run(b"abc", steps).steps[0].error


# ---------------------------------------------------------------------------
# Integration: auto, detect
# ---------------------------------------------------------------------------


def test_auto_peels_base64_then_caesar():
    data = base64.b64encode(caesar_decrypt(b"Well done, the flag is CYBN{rot_after_b64} go on", -7))
    best = auto_decode(data)[0]
    assert best.label == "base64 -> caesar(shift=7)"
    assert b"CYBN{rot_after_b64}" in best.data


def test_auto_peels_base64_zlib_vigenere():
    plain = b"The secret meeting is tonight near the old harbour. CYBN{vigenere_in_layers} bye"
    data = base64.b64encode(zlib.compress(vigenere_encrypt(plain, "harbour")))
    best = auto_decode(data)[0]
    assert best.label.startswith("base64 -> zlib -> vigenere")
    assert b"CYBN{vigenere_in_layers}" in best.data


def test_auto_leaves_plain_text_alone():
    assert auto_decode(ENGLISH)[0].label == "(input as given)"


@pytest.mark.parametrize(
    "name,rule",
    [
        ("classical_caesar.txt", "classical.flag_shift"),
        ("classical_caesar.txt", "classical.monoalphabetic"),
        ("classical_vigenere.txt", "classical.vigenere"),
        ("classical_railfence.txt", "classical.transposition"),
    ],
)
def test_detect_names_the_family(fixture_bytes, name, rule):
    guesses = {guess.rule: guess for guess in detect(fixture_bytes(name)).guesses}
    assert rule in guesses
    assert guesses[rule].apply == {"tab": "auto", "options": {}}


def test_detect_vigenere_key_length(fixture_bytes):
    guess = next(
        g
        for g in detect(fixture_bytes("classical_vigenere.txt")).guesses
        if g.rule == "classical.vigenere"
    )
    assert "key length 10" in guess.label


def test_detect_says_nothing_classical_on_plain_text_and_base64():
    for data in (ENGLISH, base64.b64encode(ENGLISH), b"CYBN{plain_flag}"):
        assert not [g for g in detect(data).guesses if g.rule.startswith("classical")]


def test_flag_shift_makes_dcode_fire(fixture_bytes):
    """tools.toml suggests dcode on classical.* rules (FUTURE_RULES is gone)."""
    from ctfc.core.tools import gather, suggest

    signals, values = gather(fixture_bytes("classical_caesar.txt"), None)
    ids = [item.tool.id for item in suggest(signals, values, limit=10)]
    assert "dcode" in ids


def test_operations_list_matches_codegen():
    from ctfc.core.codegen import CLASSICAL_OPERATIONS

    assert tuple(classical.OPERATIONS) == CLASSICAL_OPERATIONS
