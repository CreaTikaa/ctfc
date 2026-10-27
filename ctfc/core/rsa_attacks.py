"""Offline attacks on *weak* RSA keys, with the reason each one works.

RSA is safe when it is used properly. CTF keys usually are not, and each mistake
has its own shortcut:

| mistake in the key | shortcut |
|---|---|
| p and q too small | trial division by small primes |
| p and q very close | Fermat: n is almost a perfect square |
| p - 1 has only small factors | Pollard p-1 |
| one factor is moderate (< ~2^60) | Pollard rho |
| d chosen too small | Wiener: e/n has d in its continued fraction |
| two keys share a prime | gcd(n1, n2) finds it immediately |
| p == q | n is a perfect square |

Every function here is **pure integer arithmetic**: bytes/ints in, factors out,
no network, no process. `gmpy2` is used when installed (it is an optional extra)
and otherwise the stdlib does the same work, a bit slower.

Factoring a *properly generated* 2048-bit modulus is not possible here, and no
amount of budget will change that: if nothing below fires, the key is not the way
in. Try the ciphertext instead (small `e`, same message under several keys).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ctfc.core.budget import Budget

try:  # optional extra: faster big-integer maths
    from gmpy2 import iroot as _gmpy_iroot
    from gmpy2 import isqrt as _gmpy_isqrt

    HAVE_GMPY2 = True
except ImportError:  # pragma: no cover - depends on the machine
    HAVE_GMPY2 = False

# Primes up to 100000, built once: enough to catch "I used tiny primes" keys.
SMALL_PRIME_LIMIT = 100_000


@dataclass
class Factorisation:
    """Two factors of n, and how they were found."""

    p: int
    q: int
    method: str  # "Fermat (p and q are close)"
    explanation: str  # why that worked, in one or two sentences
    python: str = ""  # a snippet that redoes it

    def check(self, n: int) -> bool:
        return self.p * self.q == n and self.p > 1 and self.q > 1


@dataclass
class PrivateExponent:
    """A private exponent recovered without factoring n."""

    d: int
    method: str
    explanation: str
    python: str = ""


# ---------------------------------------------------------------------------
# Integer helpers
# ---------------------------------------------------------------------------


def isqrt(n: int) -> int:
    """Integer square root (floor)."""
    if HAVE_GMPY2:
        return int(_gmpy_isqrt(n))
    return math.isqrt(n)


def iroot(n: int, degree: int) -> tuple[int, bool]:
    """Integer `degree`-th root of n, and whether it is exact.

    Used by the small-`e` attack: if the message was short, `m**e` never wrapped
    around the modulus, so the plaintext is simply the e-th root of the ciphertext.
    """
    if degree == 1:
        return n, True
    if n < 0:
        raise ValueError("no integer root of a negative number")
    if n in (0, 1):
        return n, True
    if HAVE_GMPY2:
        root, exact = _gmpy_iroot(n, degree)
        return int(root), bool(exact)
    # Newton's method on integers: x <- ((degree-1)*x + n // x**(degree-1)) / degree
    guess = 1 << (n.bit_length() // degree + 1)
    while True:
        power = guess ** (degree - 1)
        better = ((degree - 1) * guess + n // power) // degree
        if better >= guess:
            break
        guess = better
    while guess**degree > n:
        guess -= 1
    while (guess + 1) ** degree <= n:
        guess += 1
    return guess, guess**degree == n


def small_primes(limit: int = SMALL_PRIME_LIMIT) -> list[int]:
    """Primes below `limit` (sieve of Eratosthenes)."""
    sieve = bytearray([1]) * limit
    sieve[0:2] = b"\x00\x00"
    for number in range(2, math.isqrt(limit) + 1):
        if sieve[number]:
            sieve[number * number :: number] = bytearray(len(sieve[number * number :: number]))
    return [number for number in range(limit) if sieve[number]]


_PRIMES: list[int] | None = None


def primes() -> list[int]:
    """The small-prime list, built once per process."""
    global _PRIMES
    if _PRIMES is None:
        _PRIMES = small_primes()
    return _PRIMES


# ---------------------------------------------------------------------------
# The attacks, each one small enough to read
# ---------------------------------------------------------------------------


def attack_small_primes(n: int, budget: Budget | None = None) -> Factorisation | None:
    """Divide by every prime below 100000. Catches "I picked p = 65537"."""
    for prime in primes():
        if budget is not None and not budget.spend():
            return None
        if prime * prime > n:
            break
        if n % prime == 0:
            return Factorisation(
                p=prime,
                q=n // prime,
                method=f"trial division (p = {prime})",
                explanation=(
                    f"n is divisible by the small prime {prime}, so one factor was "
                    "far too small: dividing is enough"
                ),
                python=f"p = {prime}\nq = n // p",
            )
    return None


def attack_perfect_square(n: int) -> Factorisation | None:
    """p == q: then n is a perfect square and phi = p*(p-1)."""
    root = isqrt(n)
    if root * root == n:
        return Factorisation(
            p=root,
            q=root,
            method="n is a perfect square (p == q)",
            explanation=(
                "n is a square, so the same prime was used twice. Careful: with "
                "p == q, phi(n) = p * (p - 1), not (p - 1)**2"
            ),
            python="p = q = math.isqrt(n)",
        )
    return None


def attack_fermat(n: int, budget: Budget | None = None) -> Factorisation | None:
    """Fermat: when p and q are close, n is just under a perfect square.

    Write n = a**2 - b**2 = (a - b)(a + b). Start at a = ceil(sqrt(n)) and walk up
    until a**2 - n is a perfect square. Two primes generated "next to each other"
    (a common mistake) are found in a handful of steps.
    """
    a = isqrt(n)
    if a * a < n:
        a += 1
    while True:
        if budget is not None and not budget.spend():
            return None
        difference = a * a - n
        if difference >= 0:
            b = isqrt(difference)
            if b * b == difference:
                p, q = a - b, a + b
                if p > 1 and q > 1 and p * q == n:
                    return Factorisation(
                        p=p,
                        q=q,
                        method="Fermat (p and q are close)",
                        explanation=(
                            f"n = a^2 - b^2 with a = {a}, b = {b}, found in a few steps "
                            "because p and q are close to each other"
                        ),
                        python=(
                            "a = math.isqrt(n)\n"
                            "while True:\n"
                            "    a += 1\n"
                            "    b2 = a * a - n\n"
                            "    b = math.isqrt(b2)\n"
                            "    if b * b == b2:\n"
                            "        p, q = a - b, a + b\n"
                            "        break"
                        ),
                    )
        a += 1


def attack_pollard_p_minus_1(n: int, budget: Budget | None = None) -> Factorisation | None:
    """Pollard p-1: works when p - 1 has only small prime factors ("smooth").

    By Fermat's little theorem, 2**k = 1 (mod p) as soon as (p-1) divides k. We
    build k = 2*3*4*... step by step and watch gcd(2**k - 1, n).
    """
    base = 2
    for exponent in range(2, 100_000):
        if budget is not None and not budget.spend():
            return None
        base = pow(base, exponent, n)
        factor = math.gcd(base - 1, n)
        if 1 < factor < n:
            return Factorisation(
                p=factor,
                q=n // factor,
                method=f"Pollard p-1 (smooth up to {exponent})",
                explanation=(
                    f"p - 1 has only factors below {exponent}, so 2^k = 1 (mod p) "
                    "happened early and gcd gave p away"
                ),
                python=(
                    "a = 2\n"
                    "for j in range(2, 100000):\n"
                    "    a = pow(a, j, n)\n"
                    "    p = math.gcd(a - 1, n)\n"
                    "    if 1 < p < n:\n"
                    "        q = n // p\n"
                    "        break"
                ),
            )
        if factor == n:
            return None  # went too far: this base cannot work
    return None


def attack_even(n: int) -> Factorisation | None:
    """A modulus that is even is not an RSA modulus at all (and 2 is a factor)."""
    if n % 2 == 0:
        return Factorisation(
            p=2,
            q=n // 2,
            method="n is even",
            explanation="n is even, so 2 is a factor: this is not a proper RSA modulus",
            python="p = 2\nq = n // 2",
        )
    return None


def attack_pollard_rho(n: int, budget: Budget | None = None) -> Factorisation | None:
    """Pollard rho: finds a moderate factor by a random walk.

    Good up to factors of roughly 2^60 in a few seconds. Useless against a real
    2048-bit key, which is the honest answer rather than a never-ending loop. It
    runs **last**, because it is the one attack that cannot say "no" quickly.
    """
    for seed in (2, 3, 5, 7):
        x = y = seed
        c = seed + 1
        factor = 1
        while factor == 1:
            if budget is not None and not budget.spend():
                return None
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            factor = math.gcd(abs(x - y), n)
        if 1 < factor < n:
            return Factorisation(
                p=min(factor, n // factor),
                q=max(factor, n // factor),
                method="Pollard rho",
                explanation=(
                    "a random walk modulo n hit two values with the same remainder "
                    "modulo p, and their difference shares p with n"
                ),
                python=(
                    "# Pollard rho: see ctfc/core/rsa_attacks.py for the full loop\n"
                    "x = y = 2\n"
                    "c, p = 3, 1\n"
                    "while p == 1:\n"
                    "    x = (x * x + c) % n\n"
                    "    y = (y * y + c) % n\n"
                    "    y = (y * y + c) % n\n"
                    "    p = math.gcd(abs(x - y), n)\n"
                    "q = n // p"
                ),
            )
    return None


def attack_shared_factor(n: int, others: list[int]) -> Factorisation | None:
    """Two keys that share a prime: gcd of the two moduli hands it over.

    This happens for real when keys are generated with a poor random source.
    """
    for index, other in enumerate(others):
        if other == n:
            continue
        factor = math.gcd(n, other)
        if 1 < factor < n:
            return Factorisation(
                p=factor,
                q=n // factor,
                method=f"shared prime with key #{index + 1}",
                explanation=(
                    "the two moduli have a common factor, so both keys were built "
                    "with the same prime: gcd(n1, n2) is that prime"
                ),
                python="p = math.gcd(n1, n2)\nq = n1 // p",
            )
    return None


# ---------------------------------------------------------------------------
# Wiener: a private exponent that is too small
# ---------------------------------------------------------------------------


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    """The continued fraction expansion [a0; a1, a2, ...] of numerator/denominator."""
    terms = []
    while denominator:
        quotient = numerator // denominator
        terms.append(quotient)
        numerator, denominator = denominator, numerator - quotient * denominator
    return terms


def convergents(terms: list[int]):
    """Successive fractions k/d approaching the continued fraction."""
    numerator_previous, denominator_previous = 0, 1
    numerator, denominator = 1, 0
    for term in terms:
        numerator_previous, numerator = numerator, term * numerator + numerator_previous
        denominator_previous, denominator = denominator, term * denominator + denominator_previous
        yield numerator, denominator


def attack_wiener(n: int, e: int, budget: Budget | None = None) -> PrivateExponent | None:
    """Wiener: if d < n^0.25 / 3, then d is a denominator of a convergent of e/n.

    Because e*d = 1 + k*phi(n) and phi(n) is close to n, the fraction k/d is a very
    good approximation of e/n - good enough to appear in its continued fraction.
    """
    for k, d in convergents(continued_fraction(e, n)):
        if budget is not None and not budget.spend():
            return None
        if k == 0 or d == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        # p and q are the roots of x^2 - (n - phi + 1)x + n
        total = n - phi + 1
        if total % 2:
            continue
        discriminant = total * total - 4 * n
        if discriminant < 0:
            continue
        root = isqrt(discriminant)
        if root * root != discriminant:
            continue
        return PrivateExponent(
            d=d,
            method="Wiener (d is too small)",
            explanation=(
                f"d = {d} is small enough that k/d shows up in the continued fraction "
                "of e/n, which also gives phi(n) and therefore p and q"
            ),
            python=(
                "# see ctfc/core/rsa_attacks.py: continued fraction of e/n,\n"
                "# then test each convergent k/d against phi = (e*d - 1) // k\n"
                f"d = {d}"
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Running them all
# ---------------------------------------------------------------------------


@dataclass
class AttackResult:
    """What the attacks found, and what was tried."""

    factorisation: Factorisation | None = None
    private_exponent: PrivateExponent | None = None
    tried: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def run_attacks(
    n: int,
    e: int,
    others: list[int] | None = None,
    budget: Budget | None = None,
) -> AttackResult:
    """Try every offline attack and stop at the first success.

    The order is "can say no quickly" first. Each attack gets **its own share of
    the time budget**, so the two that can loop forever (Fermat on far-apart
    primes, Pollard rho on a strong key) cannot starve the others.
    """
    result = AttackResult()
    budget = budget or Budget(max_attempts=50_000_000, max_seconds=20)

    # Instant checks, no budget needed.
    for name, instant in (
        (
            "shared prime (gcd with the other keys given)",
            lambda: attack_shared_factor(n, others or []),
        ),
        ("n even", lambda: attack_even(n)),
        ("perfect square (p == q)", lambda: attack_perfect_square(n)),
    ):
        result.tried.append(name)
        found = instant()
        if found is not None and found.check(n):
            result.factorisation = found
            return result

    # The searching ones, each with its own slice of the budget.
    searches = (
        ("trial division by primes < 100000", attack_small_primes, 0.15),
        ("Wiener (d too small)", attack_wiener, 0.10),
        ("Fermat (p and q close)", attack_fermat, 0.25),
        ("Pollard p-1 (smooth p-1)", attack_pollard_p_minus_1, 0.20),
        ("Pollard rho (moderate factor)", attack_pollard_rho, 0.30),
    )
    for name, attack, share in searches:
        result.tried.append(name)
        if budget.cancel_event.is_set():
            result.notes.append("cancelled")
            return result
        remaining = budget.max_seconds - budget.elapsed()
        if remaining <= 0:
            result.notes.append(f"no time left for {name}: {budget.summary()}")
            break
        slice_budget = Budget(
            max_attempts=max(1000, int(budget.max_attempts * share)),
            max_seconds=min(remaining, budget.max_seconds * share),
            cancel_event=budget.cancel_event,  # a cancel from the UI stops every slice
        )
        if attack is attack_wiener:
            found = attack_wiener(n, e, slice_budget)
        else:
            found = attack(n, slice_budget)
        budget.attempts += slice_budget.attempts
        if isinstance(found, PrivateExponent):
            result.private_exponent = found
            return result
        if found is not None and found.check(n):
            result.factorisation = found
            return result

    result.notes.append(
        "no weakness found offline. A properly generated modulus cannot be factored "
        "here, whatever the budget: look at the ciphertext instead (small e, or the "
        "same message under several keys), or at how the key was stored"
    )
    return result
