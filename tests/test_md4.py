"""MD4, checked against RFC 1320 and used for NTLM.

NTLM is MD4 of the password in UTF-16LE, and it is the hash in every Windows
SAM dump. OpenSSL dropped MD4, so without our own implementation ctfc could
name an NTLM hash but never crack one.
"""

from __future__ import annotations

import pytest

from ctfc.core.md4 import md4, ntlm


@pytest.mark.parametrize(
    ("message", "digest"),
    [
        (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
        (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
        (b"message digest", "d9130a8164549fe818874806e1c7014b"),
        (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4",
        ),
    ],
)
def test_rfc1320_vectors(message, digest):
    assert md4(message).hex() == digest


def test_md4_handles_a_message_that_spans_two_blocks():
    # 120 bytes forces a second 64-byte block and the length padding there.
    assert md4(b"x" * 120).hex() == "d8f9adfc41ec43552619606c70cfd287"


def test_ntlm_of_a_known_password():
    # The empty-password NT hash, the one everyone recognises.
    assert ntlm("") == "31d6cfe0d16ae931b73c59d7e0c089c0"
    # A real SAM-dump answer (DUCTF 2024 "samiam", Administrator).
    assert ntlm("!checkerboard1") == "476b4dddbbffde29e739b618580adb1e"


def test_ntlm_matches_the_hashes_module():
    from ctfc.core.hashes import INSTANT_FORMATS

    assert INSTANT_FORMATS["ntlm"](b"!checkerboard1") == "476b4dddbbffde29e739b618580adb1e"
    assert INSTANT_FORMATS["md4"](b"abc") == "a448017aaf21d8525fc10ae87aa6729d"


def test_matches_pycryptodome_over_random_messages():
    """Ground truth: our MD4 must equal a reference MD4, not just the RFC vectors."""
    import os

    pycrypto = pytest.importorskip("Crypto.Hash.MD4")
    for _ in range(200):
        message = os.urandom(os.urandom(1)[0])
        assert md4(message).hex() == pycrypto.new(message).hexdigest()
