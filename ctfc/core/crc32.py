"""Work backwards from a CRC32: what file could have produced it?

A ZIP stores the CRC32 of each file's *plaintext*, in clear, even when the file
itself is encrypted. For a short file that is a leak: there is effectively one
sensible string with that checksum, so the content can be recovered with no
password at all. Challenge authors hide one-word flags exactly this way.

Three different questions hide in "invert a CRC32", and they need three
different answers:

1. **What was the file?** Brute force, if the search space is small enough:
   every byte string up to three characters, every word of the right length in
   the embedded word list, or - for four to six characters - a meet-in-the-middle
   search over a plausible alphabet. These give the *real* answer, because they
   only ever propose things a human would have written.

2. **What fits this pattern?** `CYBN{????}` with four unknowns is 95^4 at worst
   and usually far less: the unknown positions are searched directly.

3. **Give me *a* file with this checksum.** That is not a search at all, it is a
   linear system. CRC32 is affine over GF(2): flipping one bit of the message
   flips a fixed set of bits of the checksum, whatever the rest of the message
   is. So with 32 equations and at least 32 free bits - four bytes - a preimage
   can be *solved* in microseconds, and the solution can be constrained to stay
   inside a character class (digits, lowercase, ASCII) by simply not offering
   the solver the bits that would leave it. The result is almost never the
   original text, and the report says so: it is what you want for forging a ZIP
   entry or feeding `bkcrack`, not for reading a flag.

The honest summary of the limit: brute force stops where the search space
explodes, and the solver takes over but stops *answering the same question*.
"""

from __future__ import annotations

import string
import zlib
from dataclasses import dataclass, field

from ctfc.core.budget import Budget
from ctfc.core.datafiles import load_passwords, load_words

# Full brute force is cheap up to two bytes, and bearable over a flag-ish
# alphabet up to three.
FULL_MAX = 2
TEXT_MAX = 3
# Meet in the middle: each half is searched over the alphabet, so the cost is
# 2 * len(alphabet) ** (length // 2) entries in a dictionary.
MITM_MAX = 8
MITM_ENTRIES = 4_000_000  # about 300 MB of dict in CPython: the practical ceiling
PRINTABLE = (string.ascii_letters + string.digits + "_-{}!?.,: @#$%&*+=/\\\n\r\t").encode()
LOWER_WORDS = (string.ascii_lowercase + "_-").encode()
# Alphabets the meet-in-the-middle pass tries, in order of how likely a short
# file is to be written in one. A PIN is digits; a word is lowercase; a token is
# alphanumeric. The last ones are only reachable for short lengths, because the
# cost is len(alphabet) ** (length // 2).
MITM_ALPHABETS: tuple[tuple[str, bytes], ...] = (
    ("digits", string.digits.encode()),
    ("lowercase letters", LOWER_WORDS),
    ("lowercase and digits", (string.ascii_lowercase + string.digits + "_-").encode()),
    ("letters and digits", (string.ascii_letters + string.digits + "_-").encode()),
    ("printable characters", PRINTABLE),
)

# Character classes a solved preimage can be kept inside. Each is an affine
# subspace of the byte: a fixed value plus the bits the solver may flip.
# (name, base byte, mask of free bits)
CLASSES: tuple[tuple[str, int, int], ...] = (
    ("digits 0-7", 0x30, 0x07),
    ("letters a-o", 0x60, 0x0F),
    ("letters A-O", 0x40, 0x0F),
    ("printable p-~", 0x70, 0x0F),
    ("any ASCII byte", 0x00, 0x7F),
    ("any byte", 0x00, 0xFF),
)


@dataclass
class CrcResult:
    """One answer, and how it was found - which decides how much to trust it."""

    data: bytes
    method: str  # "brute force" | "word list" | "pattern" | "meet in the middle" | "solved"
    exact: bool  # True when this is plausibly the *original*, not just a preimage
    note: str = ""


@dataclass
class CrcReport:
    """Everything found for one checksum."""

    target: int
    length: int | None = None
    results: list[CrcResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": f"{self.target:08x}",
            "length": self.length,
            "results": [
                {
                    "text": result.data.decode("utf-8", "replace"),
                    "hex": result.data.hex(),
                    "method": result.method,
                    "exact": result.exact,
                    "note": result.note,
                }
                for result in self.results
            ],
            "notes": list(self.notes),
        }


def crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# 1. Brute force, for the spaces that are small enough to search
# ---------------------------------------------------------------------------


def brute_force(target: int, length: int, budget: Budget | None = None) -> bytes | None:
    """Every string of `length` bytes, over all 256 values or a flag alphabet."""
    if length <= 0 or length > TEXT_MAX:
        return None
    budget = budget or Budget(max_attempts=20_000_000, max_seconds=30)
    alphabet = range(256) if length <= FULL_MAX else PRINTABLE

    def search(prefix: bytes) -> bytes | None:
        if len(prefix) == length:
            return prefix if crc(prefix) == target else None
        for byte in alphabet:
            if not budget.spend():
                return None
            found = search(prefix + bytes([byte]))
            if found is not None:
                return found
        return None

    return search(b"")


def from_word_list(target: int, length: int | None = None) -> list[tuple[bytes, str]]:
    """Words (and the obvious variants) whose CRC32 is the target.

    This is the pass that gives the *real* answer when the file was a word, and
    it costs nothing: the two embedded lists are the 10000 commonest passwords
    and a small EN+FR vocabulary, and each entry is tried bare, capitalised,
    upper-cased, and with a trailing newline - because a file written by `echo`
    has one.
    """
    found: list[tuple[bytes, str]] = []
    candidates = {password.decode("utf-8", "replace") for password in load_passwords()}
    candidates |= set(load_words())
    for word in sorted(candidates):
        for variant, how in (
            (word, "as is"),
            (word.capitalize(), "capitalised"),
            (word.upper(), "upper case"),
            (word + "\n", "with a trailing newline (as `echo` writes it)"),
            (word.capitalize() + "\n", "capitalised, with a newline"),
        ):
            payload = variant.encode()
            if length is not None and len(payload) != length:
                continue
            if crc(payload) == target and all(payload != seen for seen, _ in found):
                found.append((payload, f"word list, {how}"))
    return found


def from_pattern(
    target: int, pattern: bytes, alphabet: bytes = PRINTABLE, budget: Budget | None = None
) -> bytes | None:
    """Fill the `?` positions of a pattern so that the whole thing has this CRC.

    `CYBN{????}` is the shape a flag challenge actually hands you: the format is
    known and only a few characters are not. Four unknowns over the flag
    alphabet is a few million tries, which is seconds.
    """
    holes = [index for index, char in enumerate(pattern) if char == ord("?")]
    if not holes:
        return pattern if crc(pattern) == target else None
    budget = budget or Budget(max_attempts=50_000_000, max_seconds=60)
    body = bytearray(pattern)

    def search(depth: int) -> bytes | None:
        if depth == len(holes):
            return bytes(body) if crc(bytes(body)) == target else None
        for byte in alphabet:
            if not budget.spend():
                return None
            body[holes[depth]] = byte
            found = search(depth + 1)
            if found is not None:
                return found
        return None

    return search(0)


# ---------------------------------------------------------------------------
# 2. Meet in the middle, using CRC32's one useful property for search
# ---------------------------------------------------------------------------


def _crc_table() -> list[int]:
    """The standard reflected CRC32 table, built from the polynomial."""
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        table.append(value)
    return table


TABLE = _crc_table()


def _update(register: int, data: bytes) -> int:
    """Run `data` through the CRC register, with no initial or final inversion."""
    for byte in data:
        register = TABLE[(register ^ byte) & 0xFF] ^ (register >> 8)
    return register


def _undo(register: int, data: bytes) -> int:
    """Run `data` through the register *backwards*, which the table also allows.

    Each step of a CRC consumes one byte and is invertible: the top byte of the
    register after the step identifies which table entry was XORed in, and from
    there both the previous register and the byte follow. That is what makes a
    meet-in-the-middle possible at all - the two halves can be computed
    independently and matched on the register value in between.
    """
    reverse = {value >> 24: index for index, value in enumerate(TABLE)}
    for byte in reversed(data):
        index = reverse[register >> 24]
        register = ((register ^ TABLE[index]) << 8) & 0xFFFFFFFF
        register |= index ^ byte
    return register


def meet_in_the_middle(
    target: int, length: int, alphabet: bytes = LOWER_WORDS, budget: Budget | None = None
) -> bytes | None:
    """Search `length` bytes over `alphabet` in two halves instead of one.

    The register value half-way through the message is computed forwards from
    the start for every first half, and backwards from the end for every second
    half. A collision between the two tables is a message with the right CRC, so
    the cost is twice the square root of the full search.
    """
    if length < 2 or length > MITM_MAX:
        return None
    head = length // 2
    tail = length - head
    if len(alphabet) ** head > MITM_ENTRIES or len(alphabet) ** tail > MITM_ENTRIES:
        return None
    budget = budget or Budget(max_attempts=2 * MITM_ENTRIES, max_seconds=60)

    forwards: dict[int, bytes] = {}
    for prefix in _words(alphabet, head):
        if not budget.spend():
            return None
        forwards[_update(0xFFFFFFFF, prefix)] = prefix
    for suffix in _words(alphabet, tail):
        if not budget.spend():
            return None
        middle = _undo(target ^ 0xFFFFFFFF, suffix)
        prefix = forwards.get(middle)
        if prefix is not None:
            return prefix + suffix
    return None


def _words(alphabet: bytes, length: int):
    """Every byte string of `length` over `alphabet`, as an iterator."""
    if length == 0:
        yield b""
        return
    for byte in alphabet:
        head = bytes([byte])
        for rest in _words(alphabet, length - 1):
            yield head + rest


# ---------------------------------------------------------------------------
# 3. The linear solve: *a* preimage, in microseconds, for any length >= 4
# ---------------------------------------------------------------------------


def solve_linear(columns: list[int], target: int) -> list[int] | None:
    """Which of `columns` XOR together to `target`, over GF(2).

    Plain Gaussian elimination, with each column carried along as a bit mask of
    the original indexes that produced it, so the answer comes back as "these
    columns" rather than only "yes it is possible".
    """
    basis: dict[int, tuple[int, int]] = {}  # pivot bit -> (vector, mask of indexes)
    for index, column in enumerate(columns):
        vector, used = column, 1 << index
        while vector:
            pivot = vector.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (vector, used)
                break
            other, other_used = basis[pivot]
            vector ^= other
            used ^= other_used
    vector, used = target, 0
    while vector:
        pivot = vector.bit_length() - 1
        if pivot not in basis:
            return None  # the target is outside the span: no solution
        other, other_used = basis[pivot]
        vector ^= other
        used ^= other_used
    return [index for index in range(len(columns)) if used >> index & 1]


def solve_preimage(target: int, length: int, base: int = 0x61, free: int = 0x0F) -> bytes | None:
    """Solve for a message of `length` bytes with this CRC, inside a character class.

    `base` is the byte every position starts at and `free` the bits the solver is
    allowed to flip - so (0x60, 0x0F) keeps every byte in `` ` `` to `o`, and
    (0x00, 0xFF) allows anything. CRC32 is affine, so:

        crc(m0 XOR d) = crc(m0) XOR L(d)

    where `L` is linear. Each flippable bit therefore contributes one column
    (the checksum difference flipping it alone causes), and the system
    `L(d) = crc(m0) XOR target` is 32 equations.

    Thirty-two free bits are therefore necessary, but not always sufficient:
    the columns they give may not span GF(2)^32 - the low four bits of eight
    consecutive bytes do not, for instance. There is no need to predict that,
    because an unsolvable system simply has no solution and None comes back;
    the caller moves on to a wider character class.
    """
    if length <= 0:
        return None
    message = bytes([base]) * length
    offset = crc(message) ^ target
    columns: list[int] = []
    places: list[tuple[int, int]] = []
    for position in range(length):
        for bit in range(8):
            if not free >> bit & 1:
                continue
            flipped = bytearray(message)
            flipped[position] ^= 1 << bit
            columns.append(crc(bytes(flipped)) ^ crc(message))
            places.append((position, bit))
    chosen = solve_linear(columns, offset)
    if chosen is None:
        return None
    out = bytearray(message)
    for index in chosen:
        position, bit = places[index]
        out[position] ^= 1 << bit
    return bytes(out) if crc(bytes(out)) == target else None


def collision_estimate(space: int) -> float:
    """How many *other* strings of a search space share one CRC32, on average.

    A CRC32 has 2**32 values, so a space of N candidates puts N / 2**32 of them
    on any given checksum. Below one, a hit is almost certainly the original;
    well above one, a hit is just *a* string that collides - and saying which
    case you are in is the difference between an answer and a coincidence.
    """
    return space / 2**32


# ---------------------------------------------------------------------------
# The entry point: try the answers that are *real* first
# ---------------------------------------------------------------------------


def recover(
    target: int,
    length: int | None = None,
    pattern: bytes | None = None,
    budget: Budget | None = None,
    solve: bool = True,
) -> CrcReport:
    """Everything that can be said about a CRC32, best answer first."""
    report = CrcReport(target=target, length=length)
    budget = budget or Budget(max_attempts=50_000_000, max_seconds=20)

    if pattern is not None:
        filled = from_pattern(target, pattern, budget=budget)
        if filled is not None:
            report.results.append(
                CrcResult(filled, "pattern", True, "the only filling of the pattern found")
            )
            return report
        report.notes.append(
            f"no filling of {pattern.decode('utf-8', 'replace')!r} has this CRC32 over the "
            "flag alphabet: the pattern or the length is wrong"
        )

    for payload, how in from_word_list(target, length):
        report.results.append(CrcResult(payload, "word list", True, how))
    if report.results:
        report.notes.append(
            "a word list hit is almost certainly the real content: a CRC32 collision "
            "with a dictionary word does not happen by accident at these lengths"
        )
        return report

    if length is not None and length <= TEXT_MAX:
        found = brute_force(target, length, budget)
        if found is not None:
            report.results.append(
                CrcResult(found, "brute force", True, f"the only {length}-byte string found")
            )
            return report
        report.notes.append(
            f"no {length}-byte string has this CRC32 "
            + ("(every one was tried)" if length <= FULL_MAX else "over the flag alphabet")
        )

    if length is not None and TEXT_MAX < length <= MITM_MAX:
        tried: list[str] = []
        for name, alphabet in MITM_ALPHABETS:
            half = max(len(alphabet) ** (length // 2), len(alphabet) ** (length - length // 2))
            if half > MITM_ENTRIES:
                continue  # this alphabet is out of reach at this length
            tried.append(name)
            found = meet_in_the_middle(target, length, alphabet, budget)
            if found is None:
                continue
            others = collision_estimate(len(alphabet) ** length)
            report.results.append(
                CrcResult(
                    found,
                    "meet in the middle",
                    others < 1,
                    f"searched the two halves of a {length}-byte string over {name}"
                    + (
                        ", and the space is small enough that nothing else collides: "
                        "this is the content"
                        if others < 1
                        else f" - but about {others:.0f} other strings of this length "
                        "share the checksum, so this is one of them, not necessarily "
                        "the original"
                    ),
                )
            )
            return report
        if tried:
            report.notes.append(f"no {length}-byte string has this CRC32 over " + ", ".join(tried))

    if solve and length is not None and length >= 4:
        for name, base, free in CLASSES:
            if length * bin(free).count("1") < 32:
                continue
            found = solve_preimage(target, length, base, free)
            if found is not None:
                report.results.append(
                    CrcResult(
                        found,
                        "solved",
                        False,
                        f"solved over GF(2), kept inside '{name}' - this is *a* file with "
                        "that CRC32, almost certainly not the original",
                    )
                )
                break
        if not report.results:
            report.notes.append(
                "no preimage could even be solved for, which means the length is wrong: "
                "with four or more free bytes a solution always exists"
            )
        else:
            report.notes.append(
                "the linear solve answers 'give me a file with this checksum', not 'what "
                "was the file': use it to forge an entry or feed bkcrack, not to read a flag"
            )
    return report


# When the length is unknown, several spaces get searched, and every extra
# string searched is another chance of a coincidence. Past this share of the
# 2**32 checksums, a hit is no longer evidence of anything.
SPURIOUS_LIMIT = 0.05


def searchable_spaces() -> list[tuple[int, str, bytes, int]]:
    """Every (length, alphabet) the search can afford, smallest space first.

    Smallest first is the whole point: a 4-digit string lives in a space of
    10000, so a hit there is a fact; an 8-character alphanumeric string lives in
    a space of 2**47, where a hit is a coincidence. Searching in this order means
    the trustworthy answers are found before the search has had a chance to
    produce a spurious one.
    """
    spaces: list[tuple[int, str, bytes, int]] = []
    for length in range(1, MITM_MAX + 1):
        for name, alphabet in MITM_ALPHABETS:
            half = max(len(alphabet) ** (length // 2), len(alphabet) ** (length - length // 2))
            if length > TEXT_MAX and half > MITM_ENTRIES:
                continue
            spaces.append((len(alphabet) ** length, name, alphabet, length))
    spaces.sort()
    return spaces


def recover_any_length(
    target: int, pattern: bytes | None = None, budget: Budget | None = None
) -> CrcReport:
    """The same, when the length is not known - and with the odds spelled out.

    A CRC32 says nothing about how long its input was, so the length is a
    parameter the user usually does not have: a flag is "a short word", not "six
    bytes". Every searchable space is therefore tried, smallest first, and the
    report carries the number that decides what a hit is worth - the share of
    all 2**32 checksums covered by everything searched so far. Below a few per
    cent, a match is the content; above, it may be the content or may be one
    string among many that collide, and the report says which case you are in
    instead of pretending.
    """
    budget = budget or Budget(max_attempts=200_000_000, max_seconds=60)
    report = CrcReport(target=target)
    for word, how in from_word_list(target):
        report.results.append(CrcResult(word, "word list", True, f"{how}, {len(word)} bytes"))
    if report.results:
        report.notes.append(
            "a word list hit is almost certainly the real content: a CRC32 collision "
            "with a dictionary word does not happen by accident at these lengths"
        )
        return report

    searched = 0
    for space, name, alphabet, length in searchable_spaces():
        if budget.stopped_reason:
            report.notes.append(f"the search stopped early: {budget.summary()}")
            break
        found = (
            brute_force(target, length, budget)
            if length <= TEXT_MAX
            else meet_in_the_middle(target, length, alphabet, budget)
        )
        searched += space
        if found is None:
            continue
        odds = collision_estimate(searched)
        report.length = length
        report.results.append(
            CrcResult(
                found,
                "brute force" if length <= TEXT_MAX else "meet in the middle",
                odds < SPURIOUS_LIMIT,
                f"{length} bytes over {name}"
                + (
                    f"; everything searched so far covers {odds:.1%} of all checksums, "
                    "so this is the content"
                    if odds < SPURIOUS_LIMIT
                    else f"; but everything searched so far covers {odds:.0%} of all "
                    "checksums, so a string of this shape turns up for *any* input: "
                    "treat it as a maybe, and check it against what you expect"
                ),
            )
        )
        if odds < SPURIOUS_LIMIT:
            return report
        break
    if not report.results:
        report.notes.append(
            "nothing up to 8 bytes matches, over digits, letters or the flag alphabet. "
            "Either the content is longer, or it is not text: pass a length to solve for "
            "a preimage of that length instead"
        )
    return report
