"""Round-trip tests: encode with a reference implementation, decode with ctfc."""

import base64
import bz2
import codecs
import gzip
import lzma
import quopri
import zlib

import pytest

from ctfc.core import encodings
from ctfc.core.encodings import (
    DECODERS_BY_NAME,
    DecodeError,
    base58_encode,
    base62_encode,
)

SECRET = b"CYBN{s0me_s3cret_p4yload!} with spaces"


def encoded_samples() -> list[tuple[str, bytes]]:
    """(decoder name, encoded form of SECRET)"""
    return [
        ("hex", SECRET.hex().encode()),
        ("base64", base64.b64encode(SECRET)),
        ("base64url", base64.urlsafe_b64encode(b"\xfb\xff" + SECRET)),
        ("base32", base64.b32encode(SECRET)),
        ("base58", base58_encode(SECRET).encode()),
        ("base62", base62_encode(SECRET).encode()),
        ("base85", base64.b85encode(SECRET)),
        ("ascii85", base64.a85encode(SECRET, adobe=True)),
        ("url", b"".join(b"%%%02X" % byte for byte in SECRET)),
        ("html", "".join(f"&#{byte};" for byte in SECRET).encode()),
        ("quoted_printable", quopri.encodestring(SECRET.replace(b" ", b"\xe9"))),
        ("binary", " ".join(f"{byte:08b}" for byte in SECRET).encode()),
        ("decimal", " ".join(str(byte) for byte in SECRET).encode()),
        ("reverse", base64.b64encode(SECRET)[::-1]),
        ("rot13", codecs.encode(SECRET.decode(), "rot13").encode()),
        ("utf16le", SECRET.decode().encode("utf-16-le")),
        ("zlib", zlib.compress(SECRET)),
        ("gzip", gzip.compress(SECRET, mtime=0)),
        ("bz2", bz2.compress(SECRET)),
        ("lzma", lzma.compress(SECRET)),
        ("deflate", zlib.compress(SECRET * 3)[2:-4]),
        ("extract_base64", b"$x = '" + base64.b64encode(SECRET) + b"'; iex $x"),
        ("extract_hex", b"key = '" + SECRET.hex().encode() + b"'"),
    ]


EXPECTED = {
    "base64url": b"\xfb\xff" + SECRET,
    "quoted_printable": SECRET.replace(b" ", b"\xe9"),
    "reverse": base64.b64encode(SECRET),
    "deflate": SECRET * 3,
}


@pytest.mark.parametrize("name,encoded", encoded_samples())
def test_roundtrip(name, encoded):
    decoder = DECODERS_BY_NAME[name]
    assert decoder.applicable(encoded), f"{name} should apply"
    assert decoder.decode(encoded) == EXPECTED.get(name, SECRET)


def test_rot47_roundtrip():
    decoder = DECODERS_BY_NAME["rot47"]
    once = decoder.decode(SECRET)
    assert decoder.applicable(once)
    assert decoder.decode(once) == SECRET


def test_zero_width_decoding():
    bits = "".join(f"{byte:08b}" for byte in b"hi")
    hidden = "".join("​" if bit == "0" else "‌" for bit in bits)
    data = f"cover{hidden} text".encode()
    assert DECODERS_BY_NAME["zero_width_a"].decode(data) == b"hi"


def test_jwt():
    token = b"eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    assert DECODERS_BY_NAME["jwt"].decode(token) == b'{"alg":"none"}\n{"user":"admin"}'


def test_plain_word_is_not_base62_or_base64_run():
    assert not DECODERS_BY_NAME["base62"].applicable(b"password")
    assert not DECODERS_BY_NAME["extract_base64"].applicable(b"hello world")


def test_zip_bomb_is_capped(monkeypatch):
    import ctfc.core.encodings as enc

    monkeypatch.setattr(enc, "MAX_OUTPUT", 1000)
    out = enc.zlib_decode(zlib.compress(b"\x00" * 100_000))
    assert len(out) == 1000


def test_invalid_input_raises_decode_error():
    with pytest.raises(DecodeError):
        DECODERS_BY_NAME["zlib"].decode(b"\x78\x9cnot zlib at all")


# ---------------------------------------------------------------------------
# Custom base64 alphabets (improvement idea 2)
# ---------------------------------------------------------------------------


def shuffled_alphabet(seed: int) -> str:
    import random

    from ctfc.core.encodings import STANDARD_B64_ALPHABET

    letters = list(STANDARD_B64_ALPHABET)
    random.Random(seed).shuffle(letters)
    return "".join(letters)


def encode_with(alphabet: str, payload: bytes) -> str:
    import base64

    from ctfc.core.encodings import STANDARD_B64_ALPHABET

    standard = base64.b64encode(payload).decode()
    return standard.translate(str.maketrans(STANDARD_B64_ALPHABET, alphabet))


def test_find_custom_alphabet():
    from ctfc.core.encodings import STANDARD_B64_ALPHABET, find_custom_alphabet

    alphabet = shuffled_alphabet(7)
    found = find_custom_alphabet(f'TABLE = "{alphabet}"\n'.encode())
    assert found is not None and found[0] == alphabet
    # The standard alphabet is not "custom": it must not be reported.
    assert find_custom_alphabet(f'x = "{STANDARD_B64_ALPHABET}"'.encode()) is None
    assert find_custom_alphabet(b"nothing like an alphabet in here") is None


def test_decode_custom_base64_round_trip():
    from ctfc.core.encodings import decode_custom_base64

    alphabet = shuffled_alphabet(7)
    payload = b"CYBN{custom_alphabet} with enough text to be worth decoding"
    assert decode_custom_base64(encode_with(alphabet, payload).encode(), alphabet) == payload


def test_decode_custom_base64_ignores_the_alphabet_declaration():
    """The alphabet sits next to the payload; it must not be decoded as the payload."""
    from ctfc.core.encodings import decode_custom_base64

    alphabet = shuffled_alphabet(11)
    payload = b"CYBN{alphabet_not_swallowed} and some more text here to be sure"
    script = f'ALPHA = "{alphabet}"\nDATA = "{encode_with(alphabet, payload)}"\n'
    assert decode_custom_base64(script.encode(), alphabet) == payload


def test_decode_custom_base64_rejects_a_bad_alphabet():
    from ctfc.core.encodings import DecodeError, decode_custom_base64

    with pytest.raises(DecodeError, match="64 distinct characters"):
        decode_custom_base64(b"AAAA", "too short")


def test_auto_uses_an_alphabet_found_in_the_input():
    """The whole point: auto must spot the table and use it, with no option."""
    from ctfc.core.auto import auto_decode

    alphabet = shuffled_alphabet(5)
    payload = b"CYBN{custom_alphabet_auto} plus enough plain English words here to score."
    script = f'# payload\nALPHA = "{alphabet}"\nDATA = "{encode_with(alphabet, payload)}"\n'
    best = auto_decode(script.encode())[0]
    assert best.data == payload
    assert best.label == "base64(custom alphabet)"
    assert alphabet in best.cyberchef


@pytest.mark.parametrize("seed", [5, 11, 42])
def test_generated_snippet_decodes_a_custom_alphabet(tmp_path, seed):
    import subprocess
    import sys

    from ctfc.core.auto import auto_decode

    alphabet = shuffled_alphabet(seed)
    payload = b"CYBN{custom_alphabet_auto} plus enough plain English words here to score."
    script = f'ALPHA = "{alphabet}"\nDATA = "{encode_with(alphabet, payload)}"\n'.encode()
    best = auto_decode(script)[0]
    target = tmp_path / "r.py"
    target.write_text(best.python)
    (tmp_path / "input.bin").write_bytes(script)
    result = subprocess.run(
        [sys.executable, "-I", str(target)], cwd=tmp_path, capture_output=True, timeout=30
    )
    assert result.returncode == 0, best.python + result.stderr.decode()
    assert b"CYBN{custom_alphabet_auto}" in result.stdout


# ---------------------------------------------------------------------------
# PowerShell -EncodedCommand hidden in a binary (core/encodings.py)
# ---------------------------------------------------------------------------


def _ps_command(script: str, flag: str = "-enc") -> str:
    blob = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell.exe -NoProfile -W Hidden {flag} {blob}"


def test_encoded_command_in_plain_text():
    line = _ps_command("Write-Host 'hi'")
    assert encodings.find_encoded_command(line.encode()) == b"Write-Host 'hi'"


def test_every_abbreviation_of_the_flag_is_accepted():
    """PowerShell takes any unambiguous prefix of -EncodedCommand."""
    for flag in ("-e", "-en", "-enc", "-EncodedCommand", "-encodedcommand"):
        line = _ps_command("Write-Host 1", flag)
        assert encodings.find_encoded_command(line.encode()) == b"Write-Host 1", flag


def test_encoded_command_hidden_in_binary_noise_as_utf16le():
    """The .evtx / registry case: the command line is UTF-16LE inside a binary."""
    line = _ps_command("Get-Content secret.txt")
    for pad in (0, 1):  # both byte alignments
        blob = b"\x00" * pad + b"\xde\xad\xbe\xef" + line.encode("utf-16-le") + b"\x99" * 40
        assert encodings.find_encoded_command(blob) == b"Get-Content secret.txt"


def test_encoded_command_hidden_in_binary_noise_as_ascii():
    script = "whoami; Get-Process | Out-File log.txt"
    line = _ps_command(script)
    blob = b"\x00\x01\x02" + line.encode() + b"\xff\xfe"
    assert encodings.find_encoded_command(blob) == script.encode()


def test_no_command_means_none():
    assert encodings.find_encoded_command(b"nothing to see here") is None
    assert encodings.find_encoded_command(b"\x00\xff" * 500) is None


def test_a_long_option_value_is_not_mistaken_for_a_command():
    """-ExecutionPolicy and friends must not produce a bogus decode."""
    assert encodings.find_encoded_command(b"powershell -ExecutionPolicy Bypass -File x.ps1") is None


def test_base64_that_is_not_utf16_text_is_rejected():
    """Random bytes behind the flag are a false match, not a script."""
    blob = base64.b64encode(bytes(range(200))).decode()
    assert encodings.find_encoded_command(f"-enc {blob}".encode()) is None


def test_the_decoder_raises_cleanly_when_there_is_nothing():
    with pytest.raises(encodings.DecodeError):
        encodings.powershell_enc_decode(b"no command in here at all")
