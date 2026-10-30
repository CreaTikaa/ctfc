"""Tests for nonce reuse in ECDSA and DSA (core/signatures.py).

Three layers of checking, because this module carries its own elliptic curve
arithmetic:

1. the curve constants are verified from the definitions - G is on the curve and
   n*G is the point at infinity, for every curve in `data/curves.toml`;
2. the scalar multiplication is compared against pycryptodome on P-256;
3. the recovery is run on signatures made here with a known key, so the answer
   is known before the attack starts.
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path

import pytest

from ctfc.core import signatures as sigs

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# The curve table
# ---------------------------------------------------------------------------


def all_curves() -> list[sigs.Curve]:
    unique = {curve.id: curve for curve in sigs.load_curves().values()}
    return sorted(unique.values(), key=lambda curve: curve.id)


@pytest.mark.parametrize("curve", all_curves(), ids=lambda curve: curve.id)
def test_base_point_is_on_the_curve(curve):
    assert curve.is_on_curve(curve.g)


@pytest.mark.parametrize("curve", all_curves(), ids=lambda curve: curve.id)
def test_the_order_annihilates_the_base_point(curve):
    """n*G must be the point at infinity: that is what makes n the order."""
    assert curve.multiply(curve.n) is None


@pytest.mark.parametrize("curve", all_curves(), ids=lambda curve: curve.id)
def test_doubling_and_adding_agree(curve):
    """2*G computed both ways, which catches a wrong `a` in the table."""
    assert curve.add(curve.g, curve.g) == curve.multiply(2)


def test_scalar_multiplication_matches_pycryptodome():
    """An outside opinion on the arithmetic, on the one curve both support."""
    from Crypto.PublicKey import ECC

    key = ECC.generate(curve="p256")
    curve = sigs.find_curve("p-256")
    assert curve.multiply(int(key.d)) == (int(key.pointQ.x), int(key.pointQ.y))


def test_curve_aliases_resolve():
    for name in ("secp256k1", "SECP256K1", "bitcoin", "p256", "prime256v1", "secp384r1"):
        assert sigs.find_curve(name).id in {"secp256k1", "p-256", "p-384"}


def test_an_unknown_curve_lists_the_known_ones():
    with pytest.raises(sigs.SignatureError, match="known:"):
        sigs.find_curve("curve25519")


# ---------------------------------------------------------------------------
# Signing here, so the answer is known before the attack
# ---------------------------------------------------------------------------

CURVE = sigs.find_curve("secp256k1")


def make_signature(curve, private: int, nonce: int, message: bytes) -> sigs.Signature:
    """Sign like ECDSA does, with the nonce chosen by the caller."""
    digest = sigs.hash_to_int(hashlib.sha256(message).digest(), curve.n)
    r = curve.multiply(nonce)[0] % curve.n
    s = (pow(nonce, -1, curve.n) * (digest + r * private)) % curve.n
    return sigs.Signature(r, s, digest)


def reused_pair(curve=CURVE, seed: int = 1):
    rng = random.Random(seed)
    private = rng.randrange(1, curve.n)
    nonce = rng.randrange(1, curve.n)
    first = make_signature(curve, private, nonce, b"message one")
    second = make_signature(curve, private, nonce, b"message two")
    return private, nonce, first, second


def test_a_reused_nonce_gives_the_private_key():
    private, nonce, first, second = reused_pair()
    found = sigs.recover(first, second, CURVE.n)
    assert any(item.private_key == private and item.nonce == nonce for item in found)


def test_the_public_key_picks_the_right_variant():
    private, _, first, second = reused_pair(seed=2)
    public = CURVE.multiply(private)
    found = sigs.recover(first, second, CURVE.n, check=sigs.ec_checker(CURVE, public))
    assert found[0].verified
    assert found[0].private_key == private


def test_low_s_normalisation_is_handled():
    """Bitcoin's low-s rule flips a sign; the attack must try that."""
    private, _, first, second = reused_pair(seed=3)
    low = [
        sigs.Signature(item.r, min(item.s, CURVE.n - item.s), item.h) for item in (first, second)
    ]
    public = CURVE.multiply(private)
    found = sigs.recover(low[0], low[1], CURVE.n, check=sigs.ec_checker(CURVE, public))
    assert found[0].verified and found[0].private_key == private


def test_variants_that_give_the_same_key_are_merged():
    _, _, first, second = reused_pair(seed=4)
    found = sigs.recover(first, second, CURVE.n)
    assert len(found) == 2  # four sign combinations, two distinct keys
    assert any("k negated" in reason for item in found for reason in item.reasons)


def test_different_r_is_refused():
    _, _, first, second = reused_pair(seed=5)
    other = sigs.Signature(first.r + 1, second.s, second.h)
    with pytest.raises(sigs.SignatureError, match="different r"):
        sigs.recover(first, other, CURVE.n)


def test_the_same_hash_twice_is_refused():
    _, _, first, _ = reused_pair(seed=6)
    with pytest.raises(sigs.SignatureError, match="same hash"):
        sigs.recover(first, first, CURVE.n)


def test_dsa_nonce_reuse_with_the_public_check():
    """Same algebra modulo q; the check is y = g^d mod p.

    The group comes from pycryptodome's own DSA generator rather than from
    parameters invented here: a hand-rolled p and q is how a test ends up
    proving something about the wrong group.
    """
    from Crypto.PublicKey import DSA

    key = DSA.generate(1024)
    p_value, q, g = int(key.p), int(key.q), int(key.g)
    private, y = int(key.x), int(key.y)
    rng = random.Random(7)
    nonce = rng.randrange(1, q)
    r = pow(g, nonce, p_value) % q
    signatures = []
    for message in (b"one", b"two"):
        digest = sigs.hash_to_int(hashlib.sha256(message).digest(), q)
        s_value = (pow(nonce, -1, q) * (digest + r * private)) % q
        signatures.append(sigs.Signature(r, s_value, digest))
    report = sigs.solve(signatures, order=q, dsa_public=(p_value, g, y))
    assert report.algorithm == "DSA"
    assert report.recoveries[0].verified
    assert report.recoveries[0].private_key == private


# ---------------------------------------------------------------------------
# Detection and reporting
# ---------------------------------------------------------------------------


def test_signatures_without_reuse_say_there_is_nothing_to_do():
    rng = random.Random(8)
    private = rng.randrange(1, CURVE.n)
    signatures = [
        make_signature(CURVE, private, rng.randrange(1, CURVE.n), f"m{index}".encode())
        for index in range(4)
    ]
    report = sigs.solve(signatures, curve=CURVE)
    assert not report.recoveries
    assert any("no nonce was reused" in note for note in report.notes)


def test_solve_needs_a_curve_or_an_order():
    _, _, first, second = reused_pair(seed=9)
    with pytest.raises(sigs.SignatureError, match="group order"):
        sigs.solve([first, second])


def test_a_wrong_public_key_is_reported_not_hidden():
    _, _, first, second = reused_pair(seed=10)
    other = CURVE.multiply(12345)
    report = sigs.solve([first, second], curve=CURVE, public_point=other)
    assert not any(item.verified for item in report.recoveries)
    assert any("none of the variants matches" in note for note in report.notes)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def test_parse_key_value_lines():
    text = "r=0x10 s=0x20 h=0x30\nr = 17, s = 33, h = 49\n"
    found = sigs.parse_signatures(text)
    assert [(item.r, item.s, item.h) for item in found] == [(16, 32, 48), (17, 33, 49)]


def test_parse_csv_lines():
    found = sigs.parse_signatures("# a comment\n1,2,3\n4 5 6\n")
    assert [(item.r, item.s, item.h) for item in found] == [(1, 2, 3), (4, 5, 6)]


def test_parse_json_with_hashes():
    found = sigs.parse_signatures('[{"r": "0xff", "s": 2, "h": "0x10", "label": "sig A"}]')
    assert (found[0].r, found[0].s, found[0].h) == (255, 2, 16)
    assert found[0].label == "sig A"


def test_parse_json_hashes_the_message_itself():
    order = CURVE.n
    found = sigs.parse_signatures(
        '[{"r": 1, "s": 2, "message": "hello"}]', order=order, algorithm="sha256"
    )
    assert found[0].h == sigs.hash_to_int(hashlib.sha256(b"hello").digest(), order)


def test_parse_refuses_a_line_with_no_hash():
    with pytest.raises(sigs.SignatureError, match="no message hash"):
        sigs.parse_signatures("r=0x10 s=0x20\n")


def test_hash_is_truncated_to_the_order_like_the_standard_says():
    """SHA-256 under P-192 keeps the leftmost 192 bits, not the whole digest."""
    digest = hashlib.sha256(b"x").digest()
    order = sigs.find_curve("p-192").n
    assert sigs.hash_to_int(digest, order) == int.from_bytes(digest, "big") >> 64


def test_der_signature_is_read():
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import ECC
    from Crypto.Signature import DSS

    key = ECC.generate(curve="p256")
    signer = DSS.new(key, "fips-186-3", encoding="der")
    # pycryptodome signs a Crypto.Hash object, not a hashlib one.
    der = signer.sign(SHA256.new(b"message"))
    r, s = sigs.parse_der_signature(der)
    curve = sigs.find_curve("p-256")
    # Verify the pair ourselves: that is the real proof the two numbers are right.
    digest = sigs.hash_to_int(hashlib.sha256(b"message").digest(), curve.n)
    inverse = pow(s, -1, curve.n)
    point = curve.add(
        curve.multiply(digest * inverse % curve.n),
        curve.multiply(r * inverse % curve.n, (int(key.pointQ.x), int(key.pointQ.y))),
    )
    assert point[0] % curve.n == r


def test_a_non_der_signature_is_refused():
    with pytest.raises(sigs.SignatureError, match="0x30"):
        sigs.parse_der_signature(b"not der at all")


# ---------------------------------------------------------------------------
# Public keys and the fixture
# ---------------------------------------------------------------------------


def test_public_point_from_every_accepted_form():
    from Crypto.PublicKey import ECC

    key = ECC.generate(curve="p256")
    curve = sigs.find_curve("p-256")
    expected = (int(key.pointQ.x), int(key.pointQ.y))
    sec1 = b"\x04" + expected[0].to_bytes(32, "big") + expected[1].to_bytes(32, "big")
    compressed = bytes([2 + (expected[1] & 1)]) + expected[0].to_bytes(32, "big")
    for form in (
        key.public_key().export_key(format="PEM"),
        sec1.hex(),
        compressed.hex(),
        f"{expected[0]},{expected[1]}",
        f"0x{expected[0]:x}, 0x{expected[1]:x}",
    ):
        assert sigs.parse_public_point(form, curve) == expected


def test_a_point_not_on_the_curve_is_refused():
    curve = sigs.find_curve("p-256")
    with pytest.raises(sigs.SignatureError, match="not on p-256"):
        sigs.ec_checker(curve, (1, 2))


def test_the_fixture_gives_its_private_key_back():
    text = (FIXTURES / "ecdsa_nonce_reuse.txt").read_text()
    public = sigs.parse_public_point((FIXTURES / "ecdsa_nonce_reuse.pub").read_text(), CURVE)
    expected = int((FIXTURES / "ecdsa_nonce_reuse.key").read_text().strip(), 16)
    report = sigs.solve(sigs.parse_signatures(text), curve=CURVE, public_point=public)
    assert report.recoveries[0].verified
    assert report.recoveries[0].private_key == expected


def test_the_fixture_snippet_recomputes_the_same_key():
    text = (FIXTURES / "ecdsa_nonce_reuse.txt").read_text()
    report = sigs.solve(sigs.parse_signatures(text), curve=CURVE)
    namespace: dict = {}
    exec(compile(report.python, "<snippet>", "exec"), namespace)  # noqa: S102
    assert namespace["d"] == report.recoveries[0].private_key
