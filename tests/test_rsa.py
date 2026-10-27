"""RSA tests: the maths, the key handling, and one fixture per classic mistake.

Each fixture key has exactly one weakness (see make_fixtures.write_rsa_fixtures)
and hides a flag that names it, so a passing test means the whole path worked:
read the key -> find the weakness -> rebuild the private key -> decrypt.
"""

import math
import subprocess
import sys

import pytest
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, inverse, isPrime

from ctfc.core.budget import Budget
from ctfc.core.rsa import (
    RsaError,
    build_key,
    decrypt_candidates,
    keys_match,
    parse_key,
    small_exponent_candidates,
    solve_rsa,
)
from ctfc.core.rsa_attacks import (
    attack_fermat,
    attack_perfect_square,
    attack_pollard_p_minus_1,
    attack_pollard_rho,
    attack_shared_factor,
    attack_small_primes,
    attack_wiener,
    continued_fraction,
    convergents,
    iroot,
    primes,
    run_attacks,
)


def best(report):
    assert report.candidates, f"no candidate; notes: {report.notes}"
    return report.candidates[0]


# ---------------------------------------------------------------------------
# Integer maths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,degree,expected,exact",
    [
        (27, 3, 3, True),
        (28, 3, 3, False),
        (26, 3, 2, False),
        (10**30, 3, 10**10, True),
        (2**521, 7, 2**74 + 0, False),  # checked below by the invariant, not the value
        (0, 5, 0, True),
        (1, 9, 1, True),
    ],
)
def test_iroot(value, degree, expected, exact):
    root, is_exact = iroot(value, degree)
    assert is_exact == exact
    # The defining property, whatever the machine: root**d <= value < (root+1)**d
    assert root**degree <= value < (root + 1) ** degree
    if exact:
        assert root == expected


def test_iroot_of_a_big_exact_power():
    base = getPrime(200)
    root, exact = iroot(base**5, 5)
    assert exact and root == base


def test_small_prime_sieve():
    found = primes()
    assert found[:5] == [2, 3, 5, 7, 11]
    assert 65537 in found and 99991 in found
    assert all(
        all(candidate % divisor for divisor in range(2, math.isqrt(candidate) + 1))
        for candidate in found[:200]
    )


def test_continued_fraction_and_convergents():
    # 649/200 = [3; 4, 12, 4] is the classic textbook example
    assert continued_fraction(649, 200) == [3, 4, 12, 4]
    assert list(convergents([3, 4, 12, 4]))[-1] == (649, 200)


# ---------------------------------------------------------------------------
# The attacks, each against a key built to be weak in exactly that way
# ---------------------------------------------------------------------------


def test_attack_small_primes():
    q = getPrime(256)
    found = attack_small_primes(65537 * q)
    assert found is not None and found.check(65537 * q)
    assert found.p == 65537


def test_attack_perfect_square():
    p = getPrime(128)
    found = attack_perfect_square(p * p)
    assert found is not None and found.p == found.q == p
    assert attack_perfect_square(p * getPrime(128)) is None


def test_attack_fermat():
    p = getPrime(256)
    q = p + 2
    while not isPrime(q):
        q += 2
    found = attack_fermat(p * q, Budget(max_attempts=10000, max_seconds=10))
    assert found is not None and found.check(p * q)
    assert {found.p, found.q} == {p, q}


def test_attack_fermat_gives_up_on_far_apart_primes():
    """Fermat must respect its budget instead of looping forever."""
    n = getPrime(256) * getPrime(256)
    budget = Budget(max_attempts=500, max_seconds=5)
    assert attack_fermat(n, budget) is None
    assert budget.stopped_reason


def test_attack_shared_factor():
    shared, a, b = getPrime(256), getPrime(256), getPrime(256)
    found = attack_shared_factor(shared * a, [shared * b])
    assert found is not None and found.p == shared
    assert attack_shared_factor(shared * a, [getPrime(256) * b]) is None


def test_attack_wiener():
    """A key with a deliberately tiny d."""
    while True:
        p, q = getPrime(512), getPrime(512)
        phi = (p - 1) * (q - 1)
        d = getPrime(100)
        if math.gcd(d, phi) != 1:
            continue
        e = inverse(d, phi)
        if e.bit_length() > 1000:
            break
    found = attack_wiener(p * q, e)
    assert found is not None and found.d == d


def test_attack_pollard_rho_finds_a_moderate_factor():
    small, big = getPrime(40), getPrime(200)
    found = attack_pollard_rho(small * big, Budget(max_attempts=10**7, max_seconds=20))
    assert found is not None and found.check(small * big)
    assert found.p == small


def test_attack_pollard_p_minus_1():
    """p - 1 smooth: build p = (product of small primes) + 1."""
    product = 1
    for prime in primes()[:40]:
        product *= prime
    p = product + 1
    while not isPrime(p):
        product *= 2
        p = product + 1
    n = p * getPrime(200)
    found = attack_pollard_p_minus_1(n, Budget(max_attempts=10**6, max_seconds=20))
    assert found is not None and found.check(n)


def test_a_strong_key_resists_and_says_so():
    """The honest answer matters more than a never-ending search."""
    n = getPrime(512) * getPrime(512)
    result = run_attacks(n, 65537, budget=Budget(max_attempts=10**7, max_seconds=8))
    assert result.factorisation is None and result.private_exponent is None
    assert any("cannot be factored" in note for note in result.notes)
    assert len(result.tried) >= 6, result.tried


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def test_parse_private_and_public(fixture_bytes):
    private = parse_key(fixture_bytes("rsa_private.pem"))
    public = parse_key(fixture_bytes("rsa_public.pem"))
    assert private.is_private and not public.is_private
    assert private.n == public.n and private.e == public.e == 65537
    assert private.p * private.q == private.n
    assert 1000 <= private.bits <= 1024


def test_parse_rejects_nonsense():
    with pytest.raises(RsaError, match="does not look like an RSA key"):
        parse_key(b"hello, this is not a key")


def test_keys_match(fixture_bytes):
    private = parse_key(fixture_bytes("rsa_private.pem"))
    public = parse_key(fixture_bytes("rsa_public.pem"))
    other = parse_key(fixture_bytes("rsa_fermat.pub.pem"))
    assert keys_match(private, public) == (True, "same modulus n: these two keys are a pair")
    same, why = keys_match(private, other)
    assert not same and "nothing to do with each other" in why


def test_keys_match_warns_about_a_shared_prime(fixture_bytes):
    first = parse_key(fixture_bytes("rsa_shared_a.pub.pem"))
    second = parse_key(fixture_bytes("rsa_shared_b.pub.pem"))
    same, why = keys_match(first, second)
    assert not same and "share a factor" in why


def test_build_key_from_p_q_e():
    p, q = getPrime(256), getPrime(256)
    key = build_key(p=p, q=q, e=65537)
    assert key.n == p * q and key.is_private
    assert (key.d * 65537) % ((p - 1) * (q - 1)) == 1


def test_build_key_from_n_e_d_recovers_p_and_q():
    p, q = getPrime(256), getPrime(256)
    d = inverse(65537, (p - 1) * (q - 1))
    key = build_key(n=p * q, e=65537, d=d)
    assert {key.p, key.q} == {p, q}


def test_build_key_checks_its_inputs():
    with pytest.raises(RsaError, match="n is missing"):
        build_key(e=65537)
    with pytest.raises(RsaError, match="not equal to p"):
        build_key(n=1234, p=getPrime(64), q=getPrime(64))
    with pytest.raises(RsaError, match="not coprime"):
        build_key(p=7, q=13, e=3)  # phi = 72, and gcd(3, 72) = 3


# ---------------------------------------------------------------------------
# Decryption, one fixture per padding scheme
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,flag,label",
    [
        ("rsa_oaep.bin", b"CYBN{fixture_rsa_oaep}", "RSA-OAEP (SHA-1)"),
        ("rsa_pkcs1v15.bin", b"CYBN{fixture_rsa_pkcs1v15}", "RSA PKCS#1 v1.5"),
        ("rsa_textbook.bin", b"CYBN{fixture_rsa_textbook}", "textbook RSA, raw bytes"),
    ],
)
def test_decrypt_each_padding(fixture_bytes, fixture, flag, label):
    key = parse_key(fixture_bytes("rsa_private.pem"))
    candidate = decrypt_candidates(key, fixture_bytes(fixture))[0]
    assert candidate.data == flag
    assert candidate.label == label


def test_decrypt_needs_a_private_key(fixture_bytes):
    public = parse_key(fixture_bytes("rsa_public.pem"))
    with pytest.raises(RsaError, match="no d to decrypt with"):
        decrypt_candidates(public, fixture_bytes("rsa_oaep.bin"))


def test_decrypt_refuses_an_oversized_ciphertext(fixture_bytes):
    key = parse_key(fixture_bytes("rsa_private.pem"))
    with pytest.raises(RsaError, match="larger than n"):
        decrypt_candidates(key, b"\xff" * 256)


def test_small_exponent_needs_no_key(fixture_bytes):
    """e = 3 on a short message: the cube root is the message."""
    key = parse_key(fixture_bytes("rsa_small_e.pub.pem"))
    assert key.e == 3
    candidates = small_exponent_candidates(key.n, key.e, fixture_bytes("rsa_small_e.bin"))
    assert candidates and candidates[0].data == b"CYBN{fixture_rsa_small_e}"
    assert "no key needed" in candidates[0].reasons[0]


def test_small_exponent_ignores_a_normal_exponent():
    assert small_exponent_candidates(12345, 65537, b"\x01\x02") == []


# ---------------------------------------------------------------------------
# End to end: solve_rsa on every weak fixture
# ---------------------------------------------------------------------------


def test_solve_oaep_with_the_private_key(fixture_bytes):
    report = solve_rsa(
        parse_key(fixture_bytes("rsa_private.pem")), ciphertext=fixture_bytes("rsa_oaep.bin")
    )
    assert best(report).data == b"CYBN{fixture_rsa_oaep}"


def test_solve_small_e(fixture_bytes):
    report = solve_rsa(
        parse_key(fixture_bytes("rsa_small_e.pub.pem")),
        ciphertext=fixture_bytes("rsa_small_e.bin"),
    )
    assert best(report).data == b"CYBN{fixture_rsa_small_e}"
    assert any("without the private key" in note for note in report.notes)


def test_solve_fermat(fixture_bytes):
    report = solve_rsa(
        parse_key(fixture_bytes("rsa_fermat.pub.pem")),
        ciphertext=fixture_bytes("rsa_fermat.bin"),
        attack=True,
    )
    assert best(report).data == b"CYBN{fixture_rsa_fermat}"
    assert report.attacks.factorisation.method.startswith("Fermat")
    assert report.key.is_private, "the private key must be rebuilt from p and q"


def test_solve_wiener(fixture_bytes):
    report = solve_rsa(
        parse_key(fixture_bytes("rsa_wiener.pub.pem")),
        ciphertext=fixture_bytes("rsa_wiener.bin"),
        attack=True,
    )
    assert best(report).data == b"CYBN{fixture_rsa_wiener}"
    assert report.attacks.private_exponent.method.startswith("Wiener")


def test_solve_shared_prime(fixture_bytes):
    first = parse_key(fixture_bytes("rsa_shared_a.pub.pem"))
    second = parse_key(fixture_bytes("rsa_shared_b.pub.pem"))
    report = solve_rsa(
        first,
        ciphertext=fixture_bytes("rsa_shared_a.bin"),
        attack=True,
        other_moduli=[second.n],
    )
    assert best(report).data == b"CYBN{fixture_rsa_shared}"
    assert "shared prime" in report.attacks.factorisation.method


def test_solve_without_attack_explains(fixture_bytes):
    """A public key and no --attack: say what to do, do not fail silently."""
    report = solve_rsa(
        parse_key(fixture_bytes("rsa_public.pem")), ciphertext=fixture_bytes("rsa_oaep.bin")
    )
    assert not report.candidates
    assert any("--attack" in note for note in report.notes)


def test_rsa_wrapping_an_aes_key_hands_over_to_blob(fixture_bytes):
    """The layered case: RSA carries the AES key||iv, a second file carries the payload."""
    from ctfc.core.symmetric import solve_symmetric

    report = solve_rsa(
        parse_key(fixture_bytes("rsa_private.pem")),
        ciphertext=fixture_bytes("rsa_wrapped_key.bin"),
    )
    blob = best(report).data
    assert len(blob) == 48
    assert any("ctfc blob" in note for note in report.notes), report.notes
    # Follow our own advice and check it really works.
    result = solve_symmetric(fixture_bytes("rsa_wrapped_payload.bin"), blob=blob)
    assert b"CYBN{fixture_rsa_wrapped_aes}" in result.candidates[0].data


# ---------------------------------------------------------------------------
# Generated code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,flag",
    [
        ("rsa_oaep.bin", b"CYBN{fixture_rsa_oaep}"),
        ("rsa_pkcs1v15.bin", b"CYBN{fixture_rsa_pkcs1v15}"),
        ("rsa_textbook.bin", b"CYBN{fixture_rsa_textbook}"),
    ],
)
def test_generated_snippet_reproduces(tmp_path, fixture_bytes, fixture, flag):
    key = parse_key(fixture_bytes("rsa_private.pem"))
    candidate = decrypt_candidates(key, fixture_bytes(fixture))[0]
    script = tmp_path / "decrypt.py"
    script.write_text(candidate.python)
    (tmp_path / "ct.bin").write_bytes(fixture_bytes(fixture))
    result = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=60
    )
    assert result.returncode == 0, candidate.python + "\n" + result.stderr.decode()
    assert flag in result.stdout


def test_key_facts_point_out_the_weaknesses(fixture_bytes):
    """The report must name the weakness before being asked to attack."""
    fermat = dict(parse_key(fixture_bytes("rsa_fermat.pub.pem")).facts())
    small_e = dict(parse_key(fixture_bytes("rsa_small_e.pub.pem")).facts())
    assert "very small" in small_e["note"]
    # p and q are not in a public key, so the Fermat hint cannot appear there;
    # what must appear is the size and the exponent.
    assert fermat["e"] == "65537" and "1024 bits" in fermat["size"]
    private = dict(parse_key(fixture_bytes("rsa_private.pem")).facts())  # a healthy key: no warning
    assert "warning" not in private


def test_facts_warn_about_a_small_d():
    p, q = getPrime(512), getPrime(512)
    d = getPrime(100)
    while math.gcd(d, (p - 1) * (q - 1)) != 1:
        d = getPrime(100)
    key = build_key(n=p * q, e=inverse(d, (p - 1) * (q - 1)), d=d)
    assert any("Wiener" in value for _, value in key.facts())


def test_an_encrypted_pem_needs_its_passphrase():
    key = RSA.generate(1024)
    protected = key.export_key(passphrase="letmein", pkcs=8)
    with pytest.raises(RsaError):
        parse_key(protected)
    assert parse_key(protected, passphrase="letmein").n == key.n
