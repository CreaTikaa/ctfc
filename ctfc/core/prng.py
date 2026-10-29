"""Clone a non-cryptographic random number generator from its own output.

Two generators cover almost every "guess the token" challenge:

**MT19937** (Python's `random`, PHP's `mt_rand`, most JS polyfills) keeps 624
32-bit words of state. Each call returns one word passed through a *tempering*
function, and every 624 calls the whole array is stirred by a *twist*. Both steps
are invertible:

- tempering is four XOR-with-a-shift operations, so `untemper()` walks them back
  and turns an output back into the state word it came from;
- the twist is a fixed linear recurrence, so 624 consecutive words let us step
  the sequence **forward** (the next tokens) and **backward** (the tokens that
  were handed out before, including the ones derived from the seed).

Nothing is guessed and nothing is brute-forced: 624 consecutive full 32-bit
outputs *are* the state. That is the whole weakness - MT19937 was designed for
simulations, not for secrets.

**java.util.Random** is a 48-bit linear congruential generator with published
constants. `nextInt()` returns the top 32 bits of the state, so one output leaves
only 2^16 possibilities for the bits it dropped; a second output picks the right
one. From there the seed itself comes back by running the recurrence backwards.

Pure functions: numbers in, a report out. No printing, no state.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

# --- MT19937 constants, exactly as in the reference implementation -----------
N = 624  # words of state
M = 397  # how far ahead the recurrence reaches
MATRIX_A = 0x9908B0DF  # the twist constant, mixed in when a bit is set
UPPER_MASK = 0x80000000  # "the top bit of one word"
LOWER_MASK = 0x7FFFFFFF  # "the other 31 bits of the next word"
MASK32 = 0xFFFFFFFF

# --- java.util.Random constants (the JDK documents them) --------------------
JAVA_MULTIPLIER = 0x5DEECE66D
JAVA_ADDEND = 0xB
JAVA_MASK = (1 << 48) - 1
# Inverse of the multiplier modulo 2^48, so the LCG can be run backwards.
JAVA_INVERSE = pow(JAVA_MULTIPLIER, -1, 1 << 48)


class PrngError(ValueError):
    """The numbers given cannot be a run of this generator's output."""


# --- tempering ---------------------------------------------------------------


def temper(word: int) -> int:
    """Turn a state word into the number the generator hands out."""
    y = word & MASK32
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & MASK32


def _unshift_right(value: int, shift: int) -> int:
    """Undo `y ^= y >> shift`.

    The top `shift` bits came through untouched, and each block of `shift` bits
    below is fixed as soon as the block above it is known - so repeating the
    operation converges after 32/shift rounds.
    """
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ (result >> shift)
    return result & MASK32


def _unshift_left(value: int, shift: int, mask: int) -> int:
    """Undo `y ^= (y << shift) & mask`, the same idea from the bottom up."""
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ ((result << shift) & mask)
    return result & MASK32


def untemper(value: int) -> int:
    """Turn a handed-out number back into the state word behind it."""
    y = value & MASK32
    y = _unshift_right(y, 18)
    y = _unshift_left(y, 15, 0xEFC60000)
    y = _unshift_left(y, 7, 0x9D2C5680)
    return _unshift_right(y, 11)


# --- the recurrence, forwards and backwards ---------------------------------
#
# Written over the *sequence* of state words rather than over the 624-slot array,
# which means it does not matter where in a twist cycle the capture started:
#
#     w[k] = w[k-227] ^ (y >> 1) ^ (A if y & 1 else 0)
#     y    = (w[k-624] & UPPER_MASK) | (w[k-623] & LOWER_MASK)
#
# A "window" below is always 624 consecutive state words, oldest first.


def _next_word(window: Sequence[int]) -> int:
    """The state word that follows a window of 624 consecutive words."""
    y = (window[0] & UPPER_MASK) | (window[1] & LOWER_MASK)
    return window[M] ^ (y >> 1) ^ (MATRIX_A if y & 1 else 0)


def _recover_y(mixed: int) -> int:
    """Undo `(y >> 1) ^ (A if y & 1)` and give `y` back.

    `y >> 1` always has a zero top bit while `A` has a one, so the top bit of the
    value says whether `A` was mixed in - which is also the bit of `y` that
    decided it.
    """
    low_bit = (mixed >> 31) & 1
    if low_bit:
        mixed ^= MATRIX_A
    return ((mixed << 1) & MASK32) | low_bit


def _previous_word(window: Sequence[int]) -> tuple[int, bool]:
    """The state word *before* a window of 624 consecutive words.

    Two equations of the recurrence mention the unknown word: the one that
    produced `w[j+624]` carries its top bit, and the one that produced
    `w[j+623]` carries its other 31 bits. Returns the word plus whether the two
    equations agreed about a bit they share, which is a free check that these
    numbers really are MT19937 output.
    """
    top = _recover_y(window[623] ^ window[396])  # y = (w[j] & UPPER) | (w[j+1] & LOWER)
    rest = _recover_y(window[622] ^ window[395])  # y = (w[j-1] & UPPER) | (w[j] & LOWER)
    consistent = (top & LOWER_MASK) == (window[0] & LOWER_MASK)
    return ((top & UPPER_MASK) | (rest & LOWER_MASK)), consistent


# --- reports -----------------------------------------------------------------


@dataclass
class PrngReport:
    """What was recovered, what comes next, and how to redo it by hand."""

    generator: str  # "MT19937" or "java.util.Random"
    used: int  # how many of the given numbers were needed
    next_values: list[int] = field(default_factory=list)
    previous_values: list[int] = field(default_factory=list)
    next_floats: list[float] = field(default_factory=list)
    state: list[int] = field(default_factory=list)  # the 624 untempered words
    seed: int | None = None  # java.util.Random only
    confirmed: int = 0  # extra values the clone predicted correctly
    notes: list[str] = field(default_factory=list)
    python: str = ""

    def to_dict(self) -> dict:
        return {
            "generator": self.generator,
            "used": self.used,
            "next_values": self.next_values,
            "previous_values": self.previous_values,
            "next_floats": self.next_floats,
            "seed": self.seed,
            "confirmed": self.confirmed,
            "notes": self.notes,
            "python": self.python,
        }


# --- MT19937 -----------------------------------------------------------------


def _float_from_words(first: int, second: int) -> float:
    """`random.random()` spends two outputs: 27 bits then 26, over 2**53."""
    return ((first >> 5) * 67108864.0 + (second >> 6)) / 9007199254740992.0


def recover_mt19937(
    values: Sequence[int],
    *,
    forward: int = 10,
    backward: int = 10,
) -> PrngReport:
    """Clone MT19937 from 624 consecutive full 32-bit outputs.

    Uses the *first* 624 numbers and checks the clone against any extra ones,
    which is how the report can say "confirmed against 40 further values".
    """
    if len(values) < N:
        raise PrngError(
            f"{len(values)} values is not enough: cloning MT19937 needs {N} consecutive "
            f"full 32-bit outputs ({N - len(values)} more). getrandbits(32) or "
            "randrange(2**32) give those; see the notes for the truncated cases"
        )
    too_big = [v for v in values if not 0 <= v <= MASK32]
    if too_big:
        raise PrngError(
            f"{len(too_big)} value(s) do not fit in 32 bits (first: {too_big[0]}): "
            "MT19937 outputs do. Were these random.random() floats, or two words joined?"
        )

    window = [untemper(value) for value in values[:N]]
    notes: list[str] = []

    # Step forward from the window, keeping the words so floats can be rebuilt.
    # The first `extra` of them are values the capture already contains, which is
    # what confirms the clone; what the user wants predicted comes after those.
    ahead: list[int] = []
    rolling = list(window)
    extra = len(values) - N
    wanted = extra + 2 * forward + 2
    for _ in range(wanted):
        word = _next_word(rolling)
        ahead.append(word)
        rolling = rolling[1:] + [word]

    # Anything the capture gave us beyond the 624 is a free confirmation.
    confirmed = 0
    for index in range(extra):
        if temper(ahead[index]) != values[N + index]:
            raise PrngError(
                f"value {N + index + 1} of the list is {values[N + index]}, but a cloned "
                f"MT19937 says {temper(ahead[index])}: these numbers are not one "
                "uninterrupted run of MT19937 output (a gap, another generator, or "
                "another consumer of the same generator)"
            )
        confirmed += 1
    if confirmed:
        notes.append(f"the clone reproduced the {confirmed} extra value(s) you gave: confirmed")

    # Step backward. The shared-bit check is what tells us the input was genuine.
    behind: list[int] = []
    rolling = list(window)
    disagreed = False
    for _ in range(backward):
        word, consistent = _previous_word(rolling)
        disagreed = disagreed or not consistent
        behind.append(word)
        rolling = [word] + rolling[:-1]
    if backward and disagreed and not confirmed:
        notes.append(
            "going backwards, two equations disagreed about a bit they share: the "
            "earlier values below are probably wrong, and the input may not be a "
            "single uninterrupted MT19937 run"
        )

    # `ahead` holds *state* words; a float is built from the tempered outputs.
    floats = [
        _float_from_words(temper(ahead[extra + 2 * i]), temper(ahead[extra + 2 * i + 1]))
        for i in range(forward)
    ]
    notes.append("the 624 words are the whole state: untempering them is exact, not a guess")
    notes.append(
        "next_floats is what random.random() would return *instead* of next_values - "
        "each float spends two outputs, so the two lists are different readings of "
        "the same future"
    )
    return PrngReport(
        generator="MT19937",
        used=N + confirmed,
        next_values=[temper(word) for word in ahead[extra : extra + forward]],
        previous_values=[temper(word) for word in behind],
        next_floats=floats,
        state=window,
        confirmed=confirmed,
        notes=notes,
        python=_mt_snippet(window),
    )


def _mt_snippet(state: Sequence[int]) -> str:
    """A standalone script: untemper the outputs, then let `random` do the rest."""
    head = ", ".join(str(word) for word in state[:4])
    return f'''"""Clone Python's random from 624 consecutive getrandbits(32) outputs."""

import random

MASK32 = 0xFFFFFFFF


def unshift_right(value: int, shift: int) -> int:
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ (result >> shift)
    return result & MASK32


def unshift_left(value: int, shift: int, mask: int) -> int:
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ ((result << shift) & mask)
    return result & MASK32


def untemper(value: int) -> int:
    """Undo the four XOR-with-a-shift steps MT19937 applies to each state word."""
    value = unshift_right(value, 18)
    value = unshift_left(value, 15, 0xEFC60000)
    value = unshift_left(value, 7, 0x9D2C5680)
    return unshift_right(value, 11)


outputs = [...]  # the 624 numbers you captured, in order
state = [untemper(value) for value in outputs]
# ctfc recovered: [{head}, ...]

# setstate takes the 624 words plus the index; 624 means "stir before the next one",
# which is exactly where the generator stands after handing out those 624 numbers.
rng = random.Random()
rng.setstate((3, tuple(state) + (624,), None))

print([rng.getrandbits(32) for _ in range(10)])  # the next numbers it will produce
'''


# --- java.util.Random --------------------------------------------------------


def _java_next(seed: int, bits: int) -> tuple[int, int]:
    """One step of the LCG; returns the new seed and the `bits` top bits of it."""
    seed = (seed * JAVA_MULTIPLIER + JAVA_ADDEND) & JAVA_MASK
    return seed, seed >> (48 - bits)


def _signed32(value: int) -> int:
    return value - (1 << 32) if value >= (1 << 31) else value


def recover_java_random(
    values: Sequence[int],
    *,
    forward: int = 10,
) -> PrngReport:
    """Recover a java.util.Random seed from two or more `nextInt()` outputs.

    `nextInt()` is the top 32 bits of a 48-bit state, so the first output leaves
    2^16 candidate states; the second output rules all but one out.
    """
    if len(values) < 2:
        raise PrngError(
            "java.util.Random needs at least two consecutive nextInt() values: one "
            "output leaves 65536 possible states, the second one picks the right state"
        )
    unsigned = [value & MASK32 for value in values]
    for value in values:
        if not -(1 << 31) <= value < (1 << 32):
            raise PrngError(f"{value} does not fit in a Java int (nextInt() returns 32 bits)")

    first, second = unsigned[0], unsigned[1]
    for low in range(1 << 16):
        seed = (first << 16) | low
        candidate, output = _java_next(seed, 32)
        if output != second:
            continue
        # Confirm against everything else the capture gave us.
        rolling, predicted = candidate, []
        ok = True
        for expected in unsigned[2:]:
            rolling, output = _java_next(rolling, 32)
            if output != expected:
                ok = False
                break
            predicted.append(output)
        if not ok:
            continue

        ahead: list[int] = []
        rolling_forward = rolling
        for _ in range(forward):
            rolling_forward, output = _java_next(rolling_forward, 32)
            ahead.append(_signed32(output))
        # Run the LCG backwards to the state before the first output, then unscramble
        # it: `new Random(seed)` stores seed ^ 0x5DEECE66D.
        before = ((seed - JAVA_ADDEND) * JAVA_INVERSE) & JAVA_MASK
        notes = [
            f"state found after {low + 1} tries of the 65536 the first output allows",
            "nextInt() hands out the top 32 bits of a 48-bit state: the 16 bits it "
            "drops are the only secret, and they are cheap to search",
            f"new Random({before ^ JAVA_MULTIPLIER}) reproduces this whole sequence",
        ]
        if len(unsigned) > 2:
            notes.append(f"confirmed against the {len(unsigned) - 2} further value(s) you gave")
        return PrngReport(
            generator="java.util.Random",
            used=len(values),
            next_values=ahead,
            seed=before ^ JAVA_MULTIPLIER,
            confirmed=max(0, len(unsigned) - 2),
            notes=notes,
            python=_java_snippet(before ^ JAVA_MULTIPLIER),
        )
    raise PrngError(
        "no 48-bit state produces these two numbers in a row: they are not "
        "consecutive java.util.Random nextInt() outputs (nextInt(bound), nextLong() "
        "and nextDouble() read the state differently)"
    )


def _java_snippet(seed: int) -> str:
    """Reproduce a java.util.Random sequence in Python, so no JVM is needed."""
    return f'''"""Replay a java.util.Random sequence - the recovered seed is all it takes."""

MULTIPLIER, ADDEND, MASK = 0x5DEECE66D, 0xB, (1 << 48) - 1


class JavaRandom:
    """java.util.Random is a 48-bit LCG; new Random(seed) stores seed ^ MULTIPLIER."""

    def __init__(self, seed: int) -> None:
        self.seed = (seed ^ MULTIPLIER) & MASK

    def next(self, bits: int) -> int:
        self.seed = (self.seed * MULTIPLIER + ADDEND) & MASK
        return self.seed >> (48 - bits)

    def next_int(self) -> int:
        value = self.next(32)
        return value - (1 << 32) if value >= (1 << 31) else value


rng = JavaRandom({seed})
print([rng.next_int() for _ in range(10)])
'''


# --- dispatcher --------------------------------------------------------------


def solve(
    values: Sequence[int],
    *,
    generator: str = "auto",
    forward: int = 10,
    backward: int = 10,
) -> PrngReport:
    """Pick the generator that the numbers can actually belong to, and clone it."""
    if not values:
        raise PrngError("no numbers found in the input")
    if generator == "mt19937":
        return recover_mt19937(values, forward=forward, backward=backward)
    if generator == "java":
        return recover_java_random(values, forward=forward)
    if generator != "auto":
        raise PrngError(f"unknown generator {generator!r} (mt19937, java, or auto)")

    if len(values) >= N:
        return recover_mt19937(values, forward=forward, backward=backward)
    # Too few for MT19937: the LCG is the only thing a short run can pin down.
    try:
        return recover_java_random(values, forward=forward)
    except PrngError as java_error:
        raise PrngError(
            f"{len(values)} values: too few to clone MT19937 (needs {N} consecutive "
            f"full 32-bit outputs, {N - len(values)} more) and not a java.util.Random "
            f"run either - {java_error}"
        ) from java_error


#  A float first, so "0.5" is not read as the two integers 0 and 5.
NUMBER_RE = re.compile(r"-?\d+\.\d+(?:[eE][-+]?\d+)?|-?\d+[eE][-+]?\d+|-?0[xX][0-9a-fA-F]+|-?\d+")


def parse_numbers(text: str) -> tuple[list[int], list[float]]:
    """Pull the numbers out of whatever the challenge printed.

    Accepts one per line, a comma-separated list, a Python/JSON list, or numbers
    buried in a log - and keeps integers and floats apart, because they say
    different things about which generator call produced them.
    """
    integers: list[int] = []
    floats: list[float] = []
    for token in NUMBER_RE.findall(text):
        # Hex first: "0xef" contains an 'e' but is not scientific notation.
        if token.lower().startswith(("0x", "-0x")):
            integers.append(int(token, 16))
        elif "." in token or "e" in token.lower():
            floats.append(float(token))
        else:
            integers.append(int(token))
    return integers, floats


def truncation_notes(values: Sequence[int]) -> list[str]:
    """Explain what to collect when the numbers given are too narrow to untemper.

    Untempering needs all 32 bits of an output. A challenge that prints
    `random.random()`, `mt_rand()` or `randrange(100)` hands over fewer, and no
    amount of those values makes untempering possible - the honest answer is to
    say which call would give the full words.
    """
    notes: list[str] = []
    if not values:
        return notes
    widest = max(values)
    if widest <= MASK32 >> 1:
        bits = max(1, widest.bit_length())
        notes.append(
            f"every value fits in {bits} bits, so these are probably not full 32-bit "
            "outputs: PHP's mt_rand() drops the low bit (31 bits) and "
            "random.getrandbits(k<32) keeps only the top k. Untempering needs all 32 "
            "bits of each word, so look for a call that gives them "
            "(getrandbits(32), randrange(2**32), or two 16-bit halves joined)"
        )
    if widest <= 1 and len(values) > 2:
        notes.append("values of 0/1 look like coin flips: one bit per call cannot be untempered")
    return notes


def float_notes(count: int) -> list[str]:
    """What `random.random()` output does and does not give away."""
    if count <= 0:
        return []
    return [
        f"{count} float(s) read as random.random(): each one spends two state words "
        "but shows only 27 and 26 of their bits, so 11 bits per float are missing and "
        "untempering cannot be applied to them",
        "to clone the generator, get full words instead: getrandbits(32), "
        "randrange(2**32), or a token built from random.randbytes(4)",
    ]
