"""Tests for hash length extension (core/hashext.py).

Two kinds of check. The compression functions are compared against `hashlib`, so
"our MD5 is MD5" is not taken on trust; and every forgery is verified by hashing
`secret || message` with `hashlib` - the same thing the target server would do.
"""

from __future__ import annotations

import hashlib

import pytest

from ctfc.core import hashext

# The published initial values, so a whole hash can be rebuilt from the
# compression function alone (that is what the test below does).
IVS = {
    "md5": (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    "sha1": (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0),
    "sha256": (
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ),
    "sha512": (
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ),
}

MESSAGES = [b"", b"abc", b"a" * 55, b"a" * 56, b"a" * 64, b"ctfc" * 40, bytes(range(256))]


def hash_by_hand(name: str, message: bytes) -> str:
    """Hash a message using only our compression function and padding."""
    algo = hashext.ALGORITHMS[name]
    state = IVS[name]
    data = message + algo.padding(len(message))
    assert len(data) % algo.block_size == 0
    for start in range(0, len(data), algo.block_size):
        state = algo.compress(state, data[start : start + algo.block_size])
    return algo.digest_from_state(state).hex()


@pytest.mark.parametrize("name", sorted(hashext.ALGORITHMS))
@pytest.mark.parametrize("message", MESSAGES, ids=lambda m: f"{len(m)}B")
def test_compression_function_reproduces_hashlib(name, message):
    assert hash_by_hand(name, message) == hashlib.new(name, message).hexdigest()


# ---------------------------------------------------------------------------
# The attack itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(hashext.ALGORITHMS))
@pytest.mark.parametrize("secret_length", [0, 1, 15, 16, 55, 56, 64, 120])
def test_forgery_is_accepted_by_hashlib(name, secret_length):
    """The forged digest must be what the server computes with the real secret."""
    secret = bytes((index * 7 + 3) % 251 for index in range(secret_length))
    data = b"user=guest&role=user"
    append = b"&role=admin"
    digest = hashlib.new(name, secret + data).digest()
    forgery = hashext.forge(digest, data, append, secret_length, algorithm=name, secret=secret)
    assert forgery.verified
    assert hashlib.new(name, secret + forgery.message).hexdigest() == forgery.digest
    assert forgery.message.startswith(data)
    assert forgery.message.endswith(append)


def test_algorithm_is_deduced_from_the_digest_length():
    digest = hashlib.sha1(b"secret" + b"data").digest()
    forgery = hashext.forge(digest, b"data", b"more", 6)
    assert forgery.algorithm == "sha1"


def test_unknown_secret_length_gives_one_candidate_each():
    secret = b"a_secret_of_13"
    digest = hashlib.md5(secret + b"amount=1").digest()
    found = hashext.forge_range(digest, b"amount=1", b"&admin=1", range(1, 25), secret=secret)
    assert len(found) == 24
    # The verified one comes first, and it is the real length.
    assert found[0].verified and found[0].secret_length == len(secret)
    assert sum(1 for forgery in found if forgery.verified) == 1


def test_candidates_in_the_same_block_share_a_digest_and_say_so():
    """The glue pads to a block, so short lengths differ only in the message."""
    digest = hashlib.sha256(b"key" + b"data").digest()
    found = hashext.forge_range(digest, b"data", b"!", range(1, 9))
    assert len({forgery.digest for forgery in found}) == 1
    assert len({forgery.message for forgery in found}) == 8
    assert any("only 1 distinct digest" in note for note in hashext.notes(found))


def test_url_encoding_keeps_every_byte():
    from urllib.parse import unquote_to_bytes

    digest = hashlib.md5(b"ssss" + b"a=1").digest()
    forgery = hashext.forge(digest, b"a=1", b"&b=2", 4)
    assert unquote_to_bytes(forgery.url_encoded) == forgery.message


# ---------------------------------------------------------------------------
# What the attack cannot do, said out loud
# ---------------------------------------------------------------------------


def test_sha224_is_refused_with_the_reason():
    digest = hashlib.sha224(b"x").digest()
    with pytest.raises(hashext.HashExtError, match="sha224"):
        hashext.forge(digest, b"data", b"more", 4)


def test_sha384_is_refused():
    digest = hashlib.sha384(b"x").digest()
    with pytest.raises(hashext.HashExtError, match="only 6 of its 8 state words"):
        hashext.forge(digest, b"data", b"more", 4)


def test_sha3_length_is_not_a_known_digest():
    with pytest.raises(hashext.HashExtError, match="sponges"):
        hashext.forge(bytes(17), b"data", b"more", 4)


def test_a_digest_of_the_wrong_length_for_a_forced_algorithm():
    with pytest.raises(hashext.HashExtError, match="sha256 digests are 32 bytes"):
        hashext.forge(bytes(16), b"data", b"more", 4, algorithm="sha256")


def test_negative_secret_length_is_refused():
    with pytest.raises(hashext.HashExtError, match="negative"):
        hashext.forge(bytes(16), b"data", b"more", -1)


# ---------------------------------------------------------------------------
# Length parsing
# ---------------------------------------------------------------------------


def test_parse_lengths_reads_a_number_a_range_and_a_list():
    assert hashext.parse_lengths("16") == [16]
    assert hashext.parse_lengths("8-12") == [8, 9, 10, 11, 12]
    assert hashext.parse_lengths("8,16,24") == [8, 16, 24]
    assert hashext.parse_lengths("1-3,16") == [1, 2, 3, 16]


def test_parse_lengths_refuses_nonsense():
    for spec in ("", "abc", "12-3", "-4"):
        with pytest.raises(hashext.HashExtError):
            hashext.parse_lengths(spec)


def test_parse_lengths_caps_the_number_of_candidates():
    with pytest.raises(hashext.HashExtError, match="more than the"):
        hashext.parse_lengths("1-500")


# ---------------------------------------------------------------------------
# The generated snippet
# ---------------------------------------------------------------------------


def test_snippet_reproduces_the_forgery():
    secret = b"hunter2hunter2"
    digest = hashlib.sha256(secret + b"a=1").digest()
    forgery = hashext.forge(digest, b"a=1", b"&b=2", len(secret))
    namespace: dict = {}
    exec(compile(forgery.python, "<snippet>", "exec"), namespace)  # noqa: S102
    assert namespace["forgery"].digest == forgery.digest
