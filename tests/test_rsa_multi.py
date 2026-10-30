"""Tests for the RSA attacks that need more than one message (core/rsa_multi.py).

Each one is exact arithmetic, so the test is the strongest kind available: the
recovered plaintext has to be the plaintext, byte for byte.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, getPrime, long_to_bytes

from ctfc.core.rsa_multi import (
    Message,
    MultiError,
    common_modulus,
    franklin_reiter,
    hastad,
    solve_multi,
)

FIXTURES = Path(__file__).parent / "fixtures"


def modulus_of(name: str) -> tuple[int, int]:
    key = RSA.import_key((FIXTURES / name).read_bytes())
    return int(key.n), int(key.e)


def message_from(key_name: str, ct_name: str) -> Message:
    n, e = modulus_of(key_name)
    return Message(n, e, (FIXTURES / ct_name).read_bytes(), label=ct_name)


def keypair(bits: int = 256) -> tuple[int, int]:
    return getPrime(bits), getPrime(bits)


# ---------------------------------------------------------------------------
# Common modulus
# ---------------------------------------------------------------------------


def test_common_modulus_on_the_fixture():
    first = message_from("rsa_common_a.pub.pem", "rsa_common_a.bin")
    second = message_from("rsa_common_b.pub.pem", "rsa_common_b.bin")
    candidate = common_modulus(first, second)
    assert candidate.data == b"CYBN{fixture_common_modulus}"
    assert candidate.score >= 0.9


def test_common_modulus_works_whichever_order_the_pair_is_in():
    p, q = keypair()
    n = p * q
    message = bytes_to_long(b"order does not matter")
    first = Message(n, 17, long_to_bytes(pow(message, 17, n)))
    second = Message(n, 65539, long_to_bytes(pow(message, 65539, n)))
    assert common_modulus(second, first).data == b"order does not matter"


def test_common_modulus_needs_the_same_modulus():
    p, q = keypair()
    with pytest.raises(MultiError, match="same n"):
        common_modulus(Message(p * q, 3, b"\x01"), Message(p * q + 2, 5, b"\x01"))


def test_common_modulus_refuses_exponents_that_share_a_factor():
    """gcd(e1, e2) != 1 leaves only m^gcd, and saying so beats a wrong answer."""
    p, q = keypair()
    n = p * q
    with pytest.raises(MultiError, match="share a factor"):
        common_modulus(Message(n, 4, b"\x01"), Message(n, 6, b"\x01"))


# ---------------------------------------------------------------------------
# Hastad broadcast
# ---------------------------------------------------------------------------


def test_hastad_on_the_fixture():
    messages = [
        message_from(f"rsa_broadcast_{index}.pub.pem", f"rsa_broadcast_{index}.bin")
        for index in (1, 2, 3)
    ]
    candidate = hastad(messages)
    assert candidate.data == b"CYBN{fixture_hastad}"
    assert candidate.params["exact_root"] is True


def test_hastad_needs_as_many_ciphertexts_as_the_exponent():
    messages = [
        message_from(f"rsa_broadcast_{index}.pub.pem", f"rsa_broadcast_{index}.bin")
        for index in (1, 2)
    ]
    with pytest.raises(MultiError, match="needs 3 ciphertexts"):
        hastad(messages)


def test_hastad_points_at_the_better_attack_when_moduli_share_a_factor():
    """A shared prime factors both keys, which is a stronger result than the CRT."""
    shared, a, b = getPrime(256), getPrime(256), getPrime(256)
    message = bytes_to_long(b"hi")
    messages = [
        Message(shared * a, 3, long_to_bytes(pow(message, 3, shared * a))),
        Message(shared * b, 3, long_to_bytes(pow(message, 3, shared * b))),
        Message(a * b, 3, long_to_bytes(pow(message, 3, a * b))),
    ]
    with pytest.raises(MultiError, match="factors both keys"):
        hastad(messages)


def test_hastad_says_when_the_root_is_not_exact():
    """Padding breaks the attack; the report must not pretend otherwise."""
    message = bytes_to_long(b"padded message, not a bare integer")
    messages = []
    for _ in range(3):
        n = getPrime(256) * getPrime(256)
        # Encrypt *different* messages: the CRT value is then not a cube.
        messages.append(Message(n, 3, long_to_bytes(pow(message + n % 7, 3, n))))
    candidate = hastad(messages)
    assert candidate.params["exact_root"] is False
    assert any("not exact" in reason for reason in candidate.reasons)


# ---------------------------------------------------------------------------
# Franklin-Reiter
# ---------------------------------------------------------------------------


def test_franklin_reiter_on_the_fixture():
    n, e = modulus_of("rsa_related.pub.pem")
    first = Message(n, e, (FIXTURES / "rsa_related_1.bin").read_bytes())
    second = Message(n, e, (FIXTURES / "rsa_related_2.bin").read_bytes())
    candidate = franklin_reiter(first, second, 2, 1234567)
    assert candidate.data == b"CYBN{fixture_franklin_reiter}"


def test_franklin_reiter_rejects_a_wrong_relation():
    n, e = modulus_of("rsa_related.pub.pem")
    first = Message(n, e, (FIXTURES / "rsa_related_1.bin").read_bytes())
    second = Message(n, e, (FIXTURES / "rsa_related_2.bin").read_bytes())
    with pytest.raises(MultiError, match="does not hold"):
        franklin_reiter(first, second, 2, 7)


def test_franklin_reiter_refuses_a_large_exponent():
    p, q = keypair()
    n = p * q
    with pytest.raises(MultiError, match="too large for the polynomial GCD"):
        franklin_reiter(Message(n, 65537, b"\x01"), Message(n, 65537, b"\x02"), 2, 3)


# ---------------------------------------------------------------------------
# The dispatcher: the shape of the material picks the attack
# ---------------------------------------------------------------------------


def test_solve_multi_picks_common_modulus():
    report = solve_multi(
        [
            message_from("rsa_common_a.pub.pem", "rsa_common_a.bin"),
            message_from("rsa_common_b.pub.pem", "rsa_common_b.bin"),
        ]
    )
    assert report.tried == ["common modulus (same n, coprime exponents)"]
    assert report.candidates[0].data == b"CYBN{fixture_common_modulus}"


def test_solve_multi_picks_hastad():
    report = solve_multi(
        [
            message_from(f"rsa_broadcast_{index}.pub.pem", f"rsa_broadcast_{index}.bin")
            for index in (1, 2, 3)
        ]
    )
    assert "Hastad" in report.tried[0]
    assert report.candidates[0].data == b"CYBN{fixture_hastad}"


def test_solve_multi_uses_the_relation_when_one_is_given():
    n, e = modulus_of("rsa_related.pub.pem")
    report = solve_multi(
        [
            Message(n, e, (FIXTURES / "rsa_related_1.bin").read_bytes()),
            Message(n, e, (FIXTURES / "rsa_related_2.bin").read_bytes()),
        ],
        relation=(2, 1234567),
    )
    assert "Franklin-Reiter" in report.tried[0]
    assert report.candidates[0].data == b"CYBN{fixture_franklin_reiter}"


def test_solve_multi_needs_two_messages():
    with pytest.raises(MultiError, match="at least two"):
        solve_multi([message_from("rsa_common_a.pub.pem", "rsa_common_a.bin")])


def test_identical_keys_explain_what_would_be_needed():
    p, q = keypair()
    n = p * q
    with pytest.raises(MultiError, match="--relation"):
        solve_multi([Message(n, 3, b"\x01"), Message(n, 3, b"\x01")])


def test_a_shape_that_matches_nothing_says_so():
    """Two moduli with two exponents is neither attack."""
    first, second = getPrime(256) * getPrime(256), getPrime(256) * getPrime(256)
    with pytest.raises(MultiError, match="do not match any multi-message attack"):
        solve_multi([Message(first, 3, b"\x01"), Message(second, 65537, b"\x01")])


# ---------------------------------------------------------------------------
# The generated snippets
# ---------------------------------------------------------------------------


def test_common_modulus_snippet_runs_and_agrees():
    first = message_from("rsa_common_a.pub.pem", "rsa_common_a.bin")
    second = message_from("rsa_common_b.pub.pem", "rsa_common_b.bin")
    candidate = common_modulus(first, second)
    namespace: dict = {}
    exec(compile(candidate.python, "<snippet>", "exec"), namespace)  # noqa: S102
    assert namespace["m"] == bytes_to_long(candidate.data)
