"""XOR solver tests, on fixtures built with known keys (see make_fixtures.py)."""

import base64
import subprocess
import sys

import pytest

from ctfc.core.auto import auto_decode
from ctfc.core.xor import (
    guess_key_lengths,
    hamming_distance,
    shrink_key,
    solve_single_byte,
    solve_xor,
    split_layers,
    xor_inputs,
    xor_two,
    xor_with_key,
)

FLAG = b"CYBN{fixture_xor_repeating}"


def test_basic_operations():
    assert xor_with_key(b"\x00\x01\x02", b"\x01") == b"\x01\x00\x03"
    assert xor_with_key(xor_with_key(b"secret data", b"key"), b"key") == b"secret data"
    assert xor_two(b"\xff\x0f", b"\x0f\x0f\x0f") == b"\xf0\x00"
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37  # classic example
    assert shrink_key(b"abcabcabc") == b"abc"
    assert shrink_key(b"abcd") == b"abcd"


def test_single_byte(fixture_bytes):
    best = solve_single_byte(fixture_bytes("xor_single_byte.bin"))[0]
    assert best.params["key_hex"] == "5a"
    assert FLAG in best.data


def test_key_length_guess(fixture_bytes):
    lengths = [guess.length for guess in guess_key_lengths(fixture_bytes("xor_repeating.bin"))]
    assert lengths[0] == 6


def test_repeating_key(fixture_bytes):
    best = solve_xor(fixture_bytes("xor_repeating.bin"))[0]
    assert best.params["key_hex"] == b"x0rK3y".hex()
    assert FLAG in best.data
    assert any("key length 6" in reason for reason in best.reasons)


def test_two_layers_are_split_back(fixture_bytes):
    best = solve_xor(fixture_bytes("xor_two_layers.bin"))[0]
    assert FLAG in best.data
    assert best.params["layers"] == [b"secret".hex(), "42"]
    assert "secret" in best.label and "0x42" in best.label


def test_split_layers_leaves_readable_keys_alone():
    assert split_layers(b"k3y!") is None
    assert split_layers(xor_with_key(b"password", b"\x13")) == (b"password", 0x13)


def test_known_file_header(fixture_bytes):
    best = solve_xor(fixture_bytes("xor_png.bin"))[0]
    assert best.params["key_hex"] == b"k3y!".hex()
    assert best.data.startswith(b"\x89PNG")


def test_guessed_header_is_not_self_confirming():
    """Assuming a PNG header must not make random data 'look like a PNG'."""
    text = b"Meet me at the old bridge at midnight, bring the documents."
    best = solve_xor(xor_with_key(text, b"key"))[0]
    assert best.data == text


def test_crib_dragging(fixture_bytes):
    best = solve_xor(fixture_bytes("xor_short_crib.bin"), cribs=[b"CYBN{"])[0]
    assert best.params["key_hex"] == b"Qx7#9".hex()
    assert b"CYBN{crib_dragging_works}" in best.data


def test_given_key():
    best = solve_xor(xor_with_key(b"hello world", b"k"), key=b"k")[0]
    assert best.data == b"hello world"


def test_two_time_pad(fixture_bytes):
    results = xor_inputs(
        fixture_bytes("two_time_pad_1.bin"), fixture_bytes("two_time_pad_2.bin"), crib=b" the "
    )
    fragments = {candidate.data for candidate in results}
    assert b" at t" in fragments  # "the" in message 2 reveals " at t" in message 1
    assert b"e arc" in fragments  # and the other way round


def test_auto_layers_with_xor(fixture_bytes):
    best = auto_decode(fixture_bytes("layers_b64_zlib_xor.txt"))[0]
    assert best.label == "base64 -> zlib -> xor(key='K3y!')"
    assert b"CYBN{fixture_multi_layer}" in best.data


def test_auto_powershell_dropper(fixture_bytes):
    best = auto_decode(fixture_bytes("powershell_xor.b64"))[0]
    assert best.label == "base64 -> xor(key='Upd4t3r!')"
    assert b"New-Object System.Net.WebClient" in best.data


@pytest.mark.parametrize("key", [b"\x5a", b"key", b"S3cr3tK3y!"])
def test_generated_python_reproduces(tmp_path, key):
    text = b"The password for the server is written on the back of the old notebook. " * 4
    best = solve_xor(xor_with_key(text, key))[0]
    script = tmp_path / "reproduce.py"
    script.write_text(best.python)
    (tmp_path / "input.bin").write_bytes(xor_with_key(text, key))
    result = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=30
    )
    assert result.returncode == 0, result.stderr.decode()
    assert b"password for the server" in result.stdout


def test_no_noise_on_random_data():
    import random

    rng = random.Random(4)
    for size in (40, 300, 2000):
        data = rng.randbytes(size)
        assert auto_decode(data) == []
        assert auto_decode(base64.b64encode(data)) == []
