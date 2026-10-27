"""Round-trip tests: encode with a reference implementation, decode with ctfc."""

import base64
import bz2
import codecs
import gzip
import lzma
import quopri
import zlib

import pytest

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
