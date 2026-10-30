"""RSA attacks that need more than one message.

`rsa_attacks.py` breaks *one* weak key. The attacks here break nothing about the
keys at all - they exploit the fact that the **same message** was sent more than
once, which is a mistake about how RSA was used rather than a bad key:

- **Common modulus**: the same `n`, two different exponents `e1`, `e2` that are
  coprime. Bezout gives `a*e1 + b*e2 = 1`, so `c1^a * c2^b = m^(a*e1+b*e2) = m`
  (mod n). No factoring, no private key - two ciphertexts and some arithmetic.
  This is why two users must never share a modulus.

- **Hastad broadcast**: the same short message sent to `e` recipients, raised to
  the same small `e` under `e` different moduli. The CRT rebuilds `m^e` modulo
  the product of the moduli, which is bigger than `m^e` itself, so the integer
  `e`-th root *is* the message. The fix in practice is padding: with OAEP the
  messages differ, and this falls apart.

- **Franklin-Reiter**: two messages with a known affine relation,
  `m2 = a*m1 + b`, under the same `n` and `e`. Then `m1` is a root of both
  `x^e - c1` and `(a*x + b)^e - c2` modulo `n`, so their polynomial GCD is
  `x - m1`. Works for small `e`, which is where it is ever seen.

Everything is exact integer arithmetic: nothing is brute-forced, so either an
attack applies to the material or it does not, and the report says which.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from math import gcd

from ctfc.core.flags import FlagSet
from ctfc.core.rsa_attacks import iroot
from ctfc.core.scoring import score
from ctfc.core.types import Candidate


class MultiError(ValueError):
    """The material given cannot feed any multi-message attack."""


# Franklin-Reiter does polynomial arithmetic of degree e; above this it is slower
# than it is useful, and e that large is not the case where it is seen anyway.
MAX_RELATION_EXPONENT = 512


@dataclass(frozen=True)
class Message:
    """One ciphertext with the public key it was encrypted under."""

    n: int
    e: int
    ciphertext: bytes
    label: str = ""

    @property
    def value(self) -> int:
        return int.from_bytes(self.ciphertext, "big")


@dataclass
class MultiReport:
    """What was tried, what came out."""

    candidates: list[Candidate] = field(default_factory=list)
    tried: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "tried": list(self.tried),
            "notes": list(self.notes),
        }


def _to_bytes(value: int) -> bytes:
    """An integer back to the bytes it stands for, without leading zeros."""
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def _candidate(label: str, plain: bytes, reasons: list[str], params: dict, code: str, flagset):
    value, why = score(plain, flagset)
    return Candidate(
        label=label,
        data=plain,
        # These attacks are exact: if the maths went through, the result is the
        # message. The score still speaks about the *content*, which is what
        # tells the user whether they are looking at the flag.
        score=min(1.0, value + 0.15),
        reasons=[*reasons, *why],
        params=params,
        python=code,
    )


# --- common modulus ----------------------------------------------------------


def common_modulus(first: Message, second: Message, flagset: FlagSet | None = None) -> Candidate:
    """Recover `m` from two encryptions under the same `n` with coprime exponents."""
    if first.n != second.n:
        raise MultiError("common modulus needs the same n in both keys")
    if gcd(first.e, second.e) != 1:
        raise MultiError(
            f"e1={first.e} and e2={second.e} share a factor "
            f"(gcd = {gcd(first.e, second.e)}): Bezout cannot reach 1, so this attack "
            "does not apply. Only m^gcd can be recovered"
        )
    n = first.n
    # Extended Euclid on the exponents: a*e1 + b*e2 == 1.
    a, b = _bezout(first.e, second.e)
    c1, c2 = first.value % n, second.value % n
    # A negative coefficient means "use the inverse of that ciphertext".
    if a < 0:
        c1, a = pow(c1, -1, n), -a
    if b < 0:
        c2, b = pow(c2, -1, n), -b
    plain = (pow(c1, a, n) * pow(c2, b, n)) % n
    data = _to_bytes(plain)
    return _candidate(
        "common modulus (same n, two exponents)",
        data,
        [
            f"e1={first.e}, e2={second.e} are coprime, so a*e1 + b*e2 = 1",
            "m = c1^a * c2^b mod n: no factoring and no private key needed",
        ],
        {"n_bits": n.bit_length(), "e1": first.e, "e2": second.e, "a": str(a), "b": str(b)},
        _common_modulus_snippet(n, first.e, second.e, first.value, second.value),
        flagset,
    )


def _bezout(first: int, second: int) -> tuple[int, int]:
    """Coefficients (a, b) with a*first + b*second == gcd(first, second)."""
    old_r, r = first, second
    old_a, a = 1, 0
    old_b, b = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_a, a = a, old_a - quotient * a
        old_b, b = b, old_b - quotient * b
    return old_a, old_b


def _common_modulus_snippet(n: int, e1: int, e2: int, c1: int, c2: int) -> str:
    return f'''"""Common modulus: the same n, two coprime exponents, two ciphertexts."""

from math import gcd

n = {n}
e1, e2 = {e1}, {e2}
c1 = {c1}
c2 = {c2}

assert gcd(e1, e2) == 1  # otherwise only m^gcd(e1, e2) comes out


def bezout(a: int, b: int) -> tuple[int, int]:
    """x, y with a*x + b*y == gcd(a, b) - extended Euclid."""
    old_r, r, old_x, x, old_y, y = a, b, 1, 0, 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_x, old_y


a, b = bezout(e1, e2)
if a < 0:
    c1, a = pow(c1, -1, n), -a      # a negative exponent is the inverse
if b < 0:
    c2, b = pow(c2, -1, n), -b
m = (pow(c1, a, n) * pow(c2, b, n)) % n
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
'''


# --- Hastad broadcast --------------------------------------------------------


def hastad(messages: Sequence[Message], flagset: FlagSet | None = None) -> Candidate:
    """Recover `m` from the same message sent to `e` recipients with the same small `e`."""
    exponents = {message.e for message in messages}
    if len(exponents) != 1:
        raise MultiError(f"Hastad needs one shared exponent, got {sorted(exponents)}")
    e = exponents.pop()
    if len(messages) < e:
        raise MultiError(
            f"e = {e} needs {e} ciphertexts under {e} different moduli, "
            f"got {len(messages)}: with fewer, the CRT value stays below m^e and the "
            "root is not exact"
        )
    used = list(messages)[:e]
    for index, first in enumerate(used):
        for second in used[index + 1 :]:
            common = gcd(first.n, second.n)
            if common != 1:
                raise MultiError(
                    "two of the moduli share a factor "
                    f"({common.bit_length()} bits): the CRT needs coprime moduli - but "
                    "that shared factor also factors both keys outright, so use "
                    "`ctfc rsa --key <one> --other <the other> --attack`"
                )
    total, modulus = _crt([(message.value % message.n, message.n) for message in used])
    root, exact = iroot(total, e)
    data = _to_bytes(root)
    reasons = [
        f"{len(used)} ciphertexts, same message, e = {e}: the CRT gives m^{e} mod "
        "(n1*...*nk), which is larger than m^e itself",
        f"the integer root of degree {e} of that value is "
        + ("exact, so it is the message" if exact else "not exact"),
    ]
    if not exact:
        reasons.append(
            "an inexact root means the message was padded (OAEP/PKCS#1) or the "
            "ciphertexts are not of one identical message"
        )
    return _candidate(
        f"Hastad broadcast (e = {e}, {len(used)} recipients)",
        data,
        reasons,
        {"e": e, "moduli": len(used), "exact_root": exact},
        _hastad_snippet([(message.n, message.value) for message in used], e),
        flagset,
    )


def _crt(pairs: Sequence[tuple[int, int]]) -> tuple[int, int]:
    """Chinese remainder theorem over coprime moduli: returns (value, product)."""
    value, modulus = 0, 1
    for residue, current in pairs:
        # Combine (value mod modulus) with (residue mod current).
        difference = (residue - value) % current
        inverse = pow(modulus % current, -1, current)
        value += modulus * ((difference * inverse) % current)
        modulus *= current
    return value % modulus, modulus


def _hastad_snippet(pairs: Sequence[tuple[int, int]], e: int) -> str:
    rows = "\n".join(f"    ({n}, {c})," for n, c in pairs)
    return f'''"""Hastad broadcast: one short message, same small e, several moduli."""

from sympy.ntheory.modular import crt  # or the ten lines below, if sympy is absent

pairs = [
{rows}
]
e = {e}


def crt_pairs(items):
    """Chinese remainder theorem over coprime moduli."""
    value, modulus = 0, 1
    for n, c in items:
        difference = (c - value) % n
        value += modulus * ((difference * pow(modulus % n, -1, n)) % n)
        modulus *= n
    return value % modulus


def iroot(value: int, degree: int) -> int:
    """Integer degree-th root by Newton's method (floats lose precision here)."""
    guess = 1 << ((value.bit_length() + degree - 1) // degree)
    while True:
        better = ((degree - 1) * guess + value // pow(guess, degree - 1)) // degree
        if better >= guess:
            return guess
        guess = better


total = crt_pairs(pairs)
m = iroot(total, e)
assert pow(m, e) == total, "the root is not exact: the message was padded"
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))
'''


# --- Franklin-Reiter ---------------------------------------------------------
#
# Polynomials modulo n, as coefficient lists with the constant term first. Only
# what the GCD needs: subtract, multiply, remainder, make monic.


def _poly_trim(poly: list[int]) -> list[int]:
    while poly and poly[-1] == 0:
        poly.pop()
    return poly


def _poly_mul(left: Sequence[int], right: Sequence[int], n: int) -> list[int]:
    out = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        if not a:
            continue
        for j, b in enumerate(right):
            out[i + j] = (out[i + j] + a * b) % n
    return _poly_trim(out)


def _poly_pow(base: Sequence[int], exponent: int, n: int) -> list[int]:
    result = [1]
    current = list(base)
    while exponent:
        if exponent & 1:
            result = _poly_mul(result, current, n)
        exponent >>= 1
        if exponent:
            current = _poly_mul(current, current, n)
    return result


def _poly_monic(poly: list[int], n: int) -> list[int]:
    """Divide through by the leading coefficient (needs it to be invertible)."""
    poly = _poly_trim(list(poly))
    if not poly:
        return poly
    lead = poly[-1] % n
    if gcd(lead, n) != 1:
        # A non-invertible leading coefficient is a *gift*: it shares a factor
        # with n, which factors the key.
        raise MultiError(
            f"a leading coefficient shares a factor with n (gcd = {gcd(lead, n)}): "
            "that factor breaks the key directly, so factor n instead"
        )
    inverse = pow(lead, -1, n)
    return [(coefficient * inverse) % n for coefficient in poly]


def _poly_mod(left: list[int], right: list[int], n: int) -> list[int]:
    """Remainder of `left` divided by `right`, modulo n."""
    left = _poly_trim(list(left))
    right = _poly_monic(right, n)
    while len(left) >= len(right) and left:
        factor = left[-1]
        shift = len(left) - len(right)
        for index, coefficient in enumerate(right):
            left[shift + index] = (left[shift + index] - factor * coefficient) % n
        _poly_trim(left)
    return left


def _poly_gcd(left: list[int], right: list[int], n: int) -> list[int]:
    while _poly_trim(list(right)):
        left, right = right, _poly_mod(left, right, n)
    return _poly_monic(left, n)


def franklin_reiter(
    first: Message,
    second: Message,
    a: int,
    b: int,
    flagset: FlagSet | None = None,
) -> Candidate:
    """Recover `m1` when `m2 = a*m1 + b` is known, same n and e."""
    if first.n != second.n:
        raise MultiError("Franklin-Reiter needs both messages under the same modulus")
    if first.e != second.e:
        raise MultiError("Franklin-Reiter needs the same exponent for both messages")
    e, n = first.e, first.n
    if e > MAX_RELATION_EXPONENT:
        raise MultiError(
            f"e = {e} is too large for the polynomial GCD (limit "
            f"{MAX_RELATION_EXPONENT}): this attack is for small exponents, which is "
            "also the only place it is ever seen"
        )
    if a % n == 0:
        raise MultiError("the relation m2 = a*m1 + b needs a != 0")

    # f1(x) = x^e - c1 ; f2(x) = (a*x + b)^e - c2. Both have m1 as a root, so
    # their GCD is x - m1 (up to the leading coefficient).
    f1 = [(-first.value) % n] + [0] * (e - 1) + [1]
    f2 = _poly_pow([b % n, a % n], e, n)
    f2[0] = (f2[0] - second.value) % n
    common = _poly_gcd(f1, _poly_trim(f2), n)
    if len(common) != 2:
        raise MultiError(
            f"the polynomial GCD has degree {max(0, len(common) - 1)}, not 1: the "
            "relation given does not hold between these two messages (check a and b, "
            "and that the ciphertexts are in the right order)"
        )
    # common == [constant, 1] == x - m1, so m1 = -constant mod n.
    plain = (-common[0]) % n
    data = _to_bytes(plain)
    return _candidate(
        f"Franklin-Reiter (m2 = {a}*m1 + {b}, e = {e})",
        data,
        [
            "m1 is a root of x^e - c1 and of (a*x + b)^e - c2",
            "their polynomial GCD modulo n is x - m1, so the message falls out",
        ],
        {"e": e, "a": str(a), "b": str(b), "n_bits": n.bit_length()},
        _franklin_snippet(n, e, first.value, second.value, a, b),
        flagset,
    )


def _franklin_snippet(n: int, e: int, c1: int, c2: int, a: int, b: int) -> str:
    return f'''"""Franklin-Reiter: two messages with m2 = a*m1 + b, same n and e.

The polynomial helpers are the ones ctfc uses (ctfc/core/rsa_multi.py) - import
them rather than retyping, or use sympy's gcd over GF(n) if n is prime.
"""

from ctfc.core.rsa_multi import Message, franklin_reiter

n = {n}
e = {e}
c1 = {c1}
c2 = {c2}
a, b = {a}, {b}   # the known relation m2 = a*m1 + b

first = Message(n, e, c1.to_bytes((c1.bit_length() + 7) // 8, "big"))
second = Message(n, e, c2.to_bytes((c2.bit_length() + 7) // 8, "big"))
print(franklin_reiter(first, second, a, b).data)
'''


# --- dispatcher --------------------------------------------------------------


def solve_multi(
    messages: Sequence[Message],
    *,
    relation: tuple[int, int] | None = None,
    flagset: FlagSet | None = None,
) -> MultiReport:
    """Pick the attack the material allows, and run it.

    The shape of the input decides: one modulus and different exponents is a
    common modulus; different moduli and one small exponent is a broadcast; one
    modulus, one exponent and a known relation is Franklin-Reiter.
    """
    report = MultiReport()
    if len(messages) < 2:
        raise MultiError(
            "these attacks need at least two ciphertexts of the same message "
            "(one key and one ciphertext is `ctfc rsa --attack`)"
        )
    moduli = {message.n for message in messages}
    exponents = {message.e for message in messages}

    if relation is not None:
        report.tried.append("Franklin-Reiter (known affine relation)")
        report.candidates.append(
            franklin_reiter(messages[0], messages[1], relation[0], relation[1], flagset)
        )
        return report

    if len(moduli) == 1 and len(exponents) > 1:
        report.tried.append("common modulus (same n, coprime exponents)")
        report.candidates.append(common_modulus(messages[0], messages[1], flagset))
        if len(messages) > 2:
            report.notes.append(
                f"{len(messages)} ciphertexts given; the first two were enough "
                "(any coprime pair is)"
            )
        return report

    if len(moduli) == len(messages) and len(exponents) == 1:
        report.tried.append("Hastad broadcast (same message, same small e)")
        report.candidates.append(hastad(messages, flagset))
        return report

    if len(moduli) == 1 and len(exponents) == 1:
        raise MultiError(
            "same modulus and same exponent: identical keys, so two ciphertexts of "
            "the same message are identical and carry nothing extra. Franklin-Reiter "
            "applies only if you know a relation between the two *messages* "
            "(--relation a,b for m2 = a*m1 + b)"
        )
    raise MultiError(
        f"{len(moduli)} distinct modulus/moduli and {len(exponents)} exponent(s) do "
        "not match any multi-message attack: common modulus wants one n and two "
        "coprime e, a broadcast wants e different moduli with the same e"
    )
