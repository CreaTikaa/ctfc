"""Classical (pen-and-paper) ciphers: Caesar, affine, Atbash, Vigenère, rail fence.

They only move letters around, so two measurements tell them apart:

- **letter frequencies** (chi-squared against English / French). A *transposition*
  (rail fence) keeps every letter, so the frequencies stay natural: the text has
  the right letters in the wrong order.
- the **index of coincidence** (IoC): the chance that two letters picked at
  random are the same. English is ~0.067, French ~0.078, random letters 0.038.
  A *monoalphabetic* substitution (Caesar, affine, Atbash, any keyword alphabet)
  only renames letters, so the IoC stays high while the frequencies look wrong.
  A *polyalphabetic* one (Vigenère) mixes several alphabets and drags the IoC
  down towards 0.038 - but each column "every L-th letter" is a plain Caesar, so
  the column IoC jumps back up at the right key length L.

Solving is then brute force with scoring (`scoring.py`): 25 Caesar shifts, 311
affine keys, Vigenère column by column, rail fence 2..12 rails with every offset.
A known flag prefix (CYBN{ from the config) is also used as a crib: if a word
of the same length sits in front of a "{", the shift that turns it into the
prefix gives the Caesar shift, or the first letters of the Vigenère key.

Conventions follow CyberChef v11.5.0 (checked in its source), so the CyberChef
recipes give the same result: only ASCII letters change, case is kept, and the
Vigenère key advances on letters only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ctfc.core.budget import Budget
from ctfc.core.codegen import Step, StepCode, chain_cyberchef, chain_snippet
from ctfc.core.flags import FlagSet, default_flagset
from ctfc.core.scoring import ENGLISH_FREQ, FRENCH_FREQ, chi_squared, printable_ratio, score
from ctfc.core.types import Candidate

# Values of `a` with an inverse modulo 26 (a must be coprime to 26).
AFFINE_A = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)
OPERATIONS = ("caesar", "affine", "atbash", "vigenere", "railfence")

IOC_ENGLISH = 0.067
IOC_RANDOM = 0.038
MIN_LETTERS = 6  # below this, nothing classical is worth trying
VIGENERE_MAX_KEY = 20
# Letters per column needed to rank a key length: with fewer, any key "fits"
# (over-fitting). The solver looks further (SOLVER_COLUMN_LETTERS) because it
# checks every candidate key by scoring the whole decryption.
MIN_COLUMN_LETTERS = 12
SOLVER_COLUMN_LETTERS = 8
GOOD_COLUMN_IOC = 0.056  # a column IoC this high already looks like one Caesar alphabet
RAILFENCE_MAX_RAILS = 12
SAMPLE = 4096  # the search runs on this many bytes; the best keys are then applied to all
MIN_SCORE = 0.25  # outputs below this are not reported
# Common flag words used as cribs, besides the prefixes of the config.
EXTRA_CRIBS = ("flag", "FLAG", "Flag")
FLAG_WORD_RE = re.compile(r"([A-Za-z]{2,15})\{")


class ClassicalError(ValueError):
    """A key that cannot work (a not coprime to 26, 1 rail...). The message says why."""


# ---------------------------------------------------------------------------
# The ciphers (decryption direction), on bytes
# ---------------------------------------------------------------------------


def _letter_table(f) -> bytes:
    """bytes.translate table applying f(index 0..25) to every ASCII letter, keeping case."""
    table = bytearray(range(256))
    for index in range(26):
        target = f(index) % 26
        table[65 + index] = 65 + target  # A..Z
        table[97 + index] = 97 + target  # a..z
    return bytes(table)


def caesar_decrypt(data: bytes, shift: int) -> bytes:
    """Undo a Caesar shift: every letter goes `shift` places back (ROT13 is shift 13)."""
    return data.translate(_letter_table(lambda x: x - shift))


def affine_decrypt(data: bytes, a: int, b: int) -> bytes:
    """Undo the affine cipher y = a*x + b (mod 26): x = a^-1 * (y - b)."""
    if a % 26 not in AFFINE_A:
        raise ClassicalError(f"a = {a} has no inverse modulo 26: it must be coprime to 26")
    inverse = pow(a, -1, 26)
    return data.translate(_letter_table(lambda y: inverse * (y - b)))


def atbash(data: bytes) -> bytes:
    """Atbash: A<->Z, B<->Y... (it is its own inverse, and affine with a = b = 25)."""
    return data.translate(_letter_table(lambda x: 25 - x))


def vigenere_decrypt(data: bytes, key: str) -> bytes:
    """Undo Vigenère: shift each letter back by the next key letter.

    The key only advances on letters (spaces and punctuation do not use a key
    letter), which is what CyberChef and dcode do.
    """
    if not key or not key.isascii() or not key.isalpha():
        raise ClassicalError("a Vigenère key is made of letters only (e.g. LEMON)")
    shifts = [ord(char) - 97 for char in key.lower()]
    out = bytearray()
    used = 0
    for byte in data:
        if 65 <= byte <= 90 or 97 <= byte <= 122:
            base = 65 if byte <= 90 else 97
            out.append(base + (byte - base - shifts[used % len(shifts)]) % 26)
            used += 1
        else:
            out.append(byte)
    return bytes(out)


def vigenere_encrypt(data: bytes, key: str) -> bytes:
    """Vigenère forwards (used to check a key against a crib)."""
    inverse = "".join(chr(97 + (26 - (ord(char) - 97)) % 26) for char in key.lower())
    return vigenere_decrypt(data, inverse)


def railfence_decrypt(data: bytes, rails: int, offset: int = 0) -> bytes:
    """Undo the rail fence (zigzag) transposition.

    The text was written in a zigzag over `rails` lines, then read line by line.
    Position p belongs to rail r when (r + p + offset) or (r - p - offset) is a
    multiple of the cycle 2*(rails-1) - CyberChef's own rule, offset included.
    """
    if rails < 2:
        raise ClassicalError("a rail fence needs at least 2 rails")
    if rails > len(data):
        raise ClassicalError(f"{rails} rails is more than the {len(data)} characters")
    if offset < 0:
        raise ClassicalError("the rail fence offset must be 0 or more")
    cycle = 2 * (rails - 1)
    out = bytearray(len(data))
    source = iter(data)
    for rail in range(rails):
        for position in range(len(data)):
            if (rail + position + offset) % cycle == 0 or (rail - position - offset) % cycle == 0:
                out[position] = next(source)
    return bytes(out)


def railfence_encrypt(data: bytes, rails: int, offset: int = 0) -> bytes:
    """Rail fence forwards (for tests and fixtures)."""
    cycle = 2 * (rails - 1)
    lines: list[bytearray] = [bytearray() for _ in range(rails)]
    for position, byte in enumerate(data):
        for rail in range(rails):
            if (rail + position + offset) % cycle == 0 or (rail - position - offset) % cycle == 0:
                lines[rail].append(byte)
                break
    return b"".join(bytes(line) for line in lines)


def apply(data: bytes, name: str, params: dict) -> bytes:
    """Apply one classical operation (a recipe step) with its parameters."""
    try:
        if name == "caesar":
            return caesar_decrypt(data, int(params["shift"]))
        if name == "affine":
            return affine_decrypt(data, int(params["a"]), int(params["b"]))
        if name == "atbash":
            return atbash(data)
        if name == "vigenere":
            return vigenere_decrypt(data, str(params["key"]))
        if name == "railfence":
            rails, offset = int(params["rails"]), int(params.get("offset", 0))
            if params.get("trim"):
                # The final newline was added after encryption: keep it out of the zigzag.
                body = data.rstrip(b"\r\n")
                return railfence_decrypt(body, rails, offset) + data[len(body) :]
            return railfence_decrypt(data, rails, offset)
    except KeyError as exc:
        raise ClassicalError(f"{name} needs the parameter {exc}") from exc
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ClassicalError):
            raise
        raise ClassicalError(f"bad {name} parameter: {exc}") from exc
    raise ClassicalError(f"unknown classical operation {name!r}")


def parse_key(cipher: str, text: str) -> dict:
    """Read a key typed by the user: caesar "3", affine "5,8", vigenere "lemon",
    railfence "3" or "3,1" (rails, offset), atbash none."""
    text = text.strip()
    try:
        if cipher == "caesar":
            return {"shift": int(text) % 26}
        if cipher == "affine":
            a, b = (int(part) for part in text.replace(" ", "").split(","))
            return {"a": a, "b": b}
        if cipher == "vigenere":
            return {"key": text}
        if cipher == "railfence":
            parts = [int(part) for part in text.replace(" ", "").split(",")]
            return {"rails": parts[0], "offset": parts[1] if len(parts) > 1 else 0}
        if cipher == "atbash":
            return {}
    except ValueError as exc:
        raise ClassicalError(
            f"cannot read {text!r} as a {cipher} key: caesar 3, affine 5,8, "
            "vigenere lemon, railfence 3 or 3,1"
        ) from exc
    raise ClassicalError(f"unknown cipher {cipher!r}; known: {', '.join(OPERATIONS)}")


# ---------------------------------------------------------------------------
# Measurements
# ---------------------------------------------------------------------------


def letters_of(data: bytes) -> str:
    """The ASCII letters of the data, lower case, in order."""
    return "".join(chr(b | 0x20) for b in data if 65 <= b <= 90 or 97 <= b <= 122)


def index_of_coincidence(letters: str) -> float:
    """Chance that two letters picked at random are equal (EN ~0.067, random 0.038)."""
    total = len(letters)
    if total < 2:
        return 0.0
    counts = [letters.count(chr(97 + i)) for i in range(26)]
    return sum(n * (n - 1) for n in counts) / (total * (total - 1))


def letter_chi2(letters: str) -> tuple[float, str]:
    """Best chi-squared of the letter counts against English / French, and which one."""
    counts = [letters.count(chr(97 + i)) for i in range(26)]
    english = chi_squared(counts, ENGLISH_FREQ)
    french = chi_squared(counts, FRENCH_FREQ)
    return (english, "English") if english <= french else (french, "French")


@dataclass
class KeyLengthGuess:
    """A Vigenère key length, the average IoC of its columns, and how natural the
    text looks once each column is solved by frequency (chi2, lower is better)."""

    length: int
    ioc: float
    chi2: float = 0.0


def _column_ioc(letters: str, length: int, min_column: int) -> float | None:
    columns = [letters[start::length] for start in range(length)]
    if min(len(column) for column in columns) < min_column:
        return None  # too few letters per column: any key would "fit" them
    return sum(index_of_coincidence(column) for column in columns) / length


def _solved_chi2(letters: str, length: int) -> tuple[float, str]:
    """Solve each column as a Caesar by frequency, then measure the whole result.

    Returns (chi2 of the result, the key found), for the closer of EN / FR.
    """
    best, best_key = float("inf"), ""
    for frequencies in (ENGLISH_FREQ, FRENCH_FREQ):
        shifts = [_best_shift(letters[start::length], frequencies) for start in range(length)]
        plain = "".join(
            chr(97 + (ord(char) - 97 - shifts[i % length]) % 26) for i, char in enumerate(letters)
        )
        counts = [plain.count(chr(97 + i)) for i in range(26)]
        value = chi_squared(counts, frequencies)
        if value < best:
            best, best_key = value, "".join(chr(97 + k) for k in shifts)
    return best, best_key


def key_period(key: str) -> int:
    """The shortest period the key (almost) repeats: "keykeykez" -> 3, "aaaa" -> 1.

    "Almost" = 60% of the letters agree with the repetition, because on a short
    text several columns of a too-long key come out wrong. (A random key agrees
    with a shorter period only ~4% of the time.)
    """
    for period in range(1, len(key)):
        if len(key) % period:
            continue
        agree = sum(key[i] == key[i % period] for i in range(len(key)))
        if agree >= 0.6 * len(key):
            return period
    return len(key)


def vigenere_key_lengths(
    letters: str, max_len: int = VIGENERE_MAX_KEY, min_column: int = MIN_COLUMN_LETTERS
) -> list[KeyLengthGuess]:
    """Rank Vigenère key lengths, the most likely first. Two steps:

    1. the index of coincidence of the columns (every L-th letter): at the right
       length each column is one Caesar alphabet, so its IoC is back near
       English (~0.067). The best few lengths, and their divisors, are kept.
    2. each kept length is *solved* by frequency and the result measured (chi2).
       A wrong length gives gibberish; the right one and its multiples give
       natural letters.
    3. a multiple of the key length is also a "key length", just a noisier one
       that over-fits short texts: when the best key repeats itself
       ("keykeykey"), its period is the answer; so is a divisor whose solved
       text is nearly as natural (chi2 within 1.5x).
    """
    iocs = {}
    for length in range(1, max_len + 1):
        value = _column_ioc(letters, length, min_column)
        if value is None:
            break
        iocs[length] = value
    if not iocs:
        return []
    top = sorted(iocs, key=lambda length: -iocs[length])[:5]
    kept = set(top) | {d for length in top for d in range(1, length) if length % d == 0}
    guesses, keys = [], {}
    for length in sorted(kept):
        chi2, keys[length] = _solved_chi2(letters, length)
        guesses.append(KeyLengthGuess(length, iocs[length], chi2))
    best = min(guesses, key=lambda g: (g.chi2, g.length))
    period = key_period(keys[best.length])
    winner = next((g for g in guesses if g.length == period), best)
    for guess in guesses:  # shortest first
        if guess.length < winner.length and winner.length % guess.length == 0:
            if guess.chi2 <= 1.5 * winner.chi2:
                winner = guess
                break
    others = sorted((g for g in guesses if g is not winner), key=lambda g: (g.chi2, g.length))
    return [winner, *others]


@dataclass
class ClassicalStats:
    """What the letters say about the cipher family (used by detect)."""

    letters: int
    ioc: float
    chi2: float | None
    language: str
    family: str  # "plain", "transposition", "monoalphabetic", "polyalphabetic", ""
    key_lengths: list[KeyLengthGuess] = field(default_factory=list)


def is_text_like(data: bytes) -> bool:
    """Classical ciphers work on text. Base64 / hex blobs must not be mistaken for them.

    Accepted: readable text with spaces, a flag-shaped word ("PLOA{...}": base64
    never contains braces), or a run of letters of a single case (classic
    "LXFOPVEFRNHR" ciphertexts). A mixed-case run without spaces is base64-like
    and refused.
    """
    if not data or printable_ratio(data)[0] < 0.95:
        return False
    text = data.decode("latin-1").strip()
    letters = sum(char.isascii() and char.isalpha() for char in text)
    if letters < MIN_LETTERS:
        return False
    if any(char in " \n\t" for char in text):
        return letters >= 0.5 * len(text.replace(" ", ""))
    if FLAG_WORD_RE.search(text):
        return True
    alpha = "".join(char for char in text if char.isalpha())
    return letters >= 0.9 * len(text) and (alpha.isupper() or alpha.islower())


def stats_notes(stats: ClassicalStats) -> list[str]:
    """The measurements in words, for the CLI / web (the "why" behind the ranking)."""
    if stats.letters < 20:
        return [f"{stats.letters} letters only: too few for statistics, keys are brute-forced"]
    notes = [
        f"{stats.letters} letters, index of coincidence {stats.ioc:.3f} "
        f"(English ~0.067, French ~0.078, random 0.038)",
        f"letter frequencies: chi2 {stats.chi2:.0f} against {stats.language} "
        "(below ~80 = natural letters)",
    ]
    family = {
        "natural": "natural letters: plain text, or a transposition (letters reordered)",
        "monoalphabetic": "high IoC, wrong frequencies: one substituted alphabet "
        "(Caesar, affine, Atbash, keyword)",
        "polyalphabetic": "low IoC: several alphabets (Vigenère)",
    }.get(stats.family)
    if family:
        notes.append(family)
    if stats.key_lengths:
        lengths = ", ".join(f"{g.length} (IoC {g.ioc:.3f})" for g in stats.key_lengths[:3])
        notes.append(f"likely Vigenère key lengths: {lengths}")
    return notes


def analyse(data: bytes) -> ClassicalStats:
    """Measure the letters and name the most likely family. See the module docstring."""
    letters = letters_of(data)
    stats = ClassicalStats(len(letters), index_of_coincidence(letters), None, "", "")
    if len(letters) < 20:
        return stats
    stats.chi2, stats.language = letter_chi2(letters)
    if stats.chi2 < 80:
        # Natural frequencies: either plain text, or the right letters reordered.
        stats.family = "natural"
    elif stats.ioc >= 0.058:
        stats.family = "monoalphabetic"
    elif stats.ioc < 0.054:
        stats.family = "polyalphabetic"
        stats.key_lengths = vigenere_key_lengths(letters)
    return stats


# ---------------------------------------------------------------------------
# Python / CyberChef for a classical step (used by codegen.step_code)
# ---------------------------------------------------------------------------

LETTERS_HELPER = '''
def map_letters(data, f):
    """Apply f(letter index 0..25) to every ASCII letter, keep the case, leave the rest."""
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append(65 + f(b - 65) % 26)
        elif 97 <= b <= 122:
            out.append(97 + f(b - 97) % 26)
        else:
            out.append(b)
    return bytes(out)
'''

VIGENERE_HELPER = '''
def vigenere_decrypt(data, key):
    """Shift each letter back by the next key letter; the key only advances on letters."""
    shifts = [ord(c) - 97 for c in key.lower()]
    out, used = bytearray(), 0
    for b in data:
        if 65 <= b <= 90 or 97 <= b <= 122:
            base = 65 if b <= 90 else 97
            out.append(base + (b - base - shifts[used % len(shifts)]) % 26)
            used += 1
        else:
            out.append(b)
    return bytes(out)
'''

RAILFENCE_HELPER = '''
def rail_fence_decrypt(data, rails, offset=0):
    """Refill the zigzag rail by rail: rail r holds the positions p where
    (r + p + offset) or (r - p - offset) is a multiple of 2 * (rails - 1)."""
    cycle = 2 * (rails - 1)
    out = bytearray(len(data))
    source = iter(data)
    for rail in range(rails):
        for p in range(len(data)):
            if (rail + p + offset) % cycle == 0 or (rail - p - offset) % cycle == 0:
                out[p] = next(source)
    return bytes(out)
'''


def step_code(step: Step) -> StepCode:
    """How to write a classical step in Python and in CyberChef (v11.5.0 argument lists)."""
    params = step.params
    if step.name == "caesar":
        shift = int(params["shift"]) % 26
        return StepCode(
            label=f"caesar(shift={shift})",
            comment=f"Caesar: every letter was moved {shift} places forward, move it back",
            python=f"data = map_letters(data, lambda x: x - {shift})",
            helper=LETTERS_HELPER,
            # ROT13(lower, upper, numbers, amount): rotating forward by 26-shift undoes it.
            cyberchef=f"ROT13(true,true,false,{(26 - shift) % 26})",
        )
    if step.name == "affine":
        a, b = int(params["a"]), int(params["b"])
        return StepCode(
            label=f"affine(a={a}, b={b})",
            comment=f"affine cipher y = {a}*x + {b} (mod 26), undone with x = {a}^-1 * (y - {b})",
            python=f"a_inverse = pow({a}, -1, 26)  # = {pow(a, -1, 26)}\n"
            f"data = map_letters(data, lambda y: a_inverse * (y - {b}))",
            helper=LETTERS_HELPER,
            cyberchef=f"Affine_Cipher_Decode({a},{b})",
        )
    if step.name == "atbash":
        return StepCode(
            label="atbash",
            comment="Atbash: A<->Z, B<->Y, ... (the alphabet reversed)",
            python="data = map_letters(data, lambda x: 25 - x)",
            helper=LETTERS_HELPER,
            cyberchef="Atbash_Cipher()",
        )
    if step.name == "vigenere":
        key = str(params["key"])
        return StepCode(
            label=f"vigenere(key={key!r})",
            comment=f"Vigenère with the key {key!r}",
            python=f'data = vigenere_decrypt(data, "{key}")',
            helper=VIGENERE_HELPER,
            cyberchef=f"Vigenère_Decode('{key}')",
        )
    if step.name == "railfence":
        rails, offset = int(params["rails"]), int(params.get("offset", 0))
        operation = f"Rail_Fence_Cipher_Decode({rails},{offset})"
        python = f"data = rail_fence_decrypt(data, {rails}, {offset})"
        comment = f"rail fence (zigzag) with {rails} rails, offset {offset}"
        if params.get("trim"):
            # A transposition moves every character, so a newline added after the
            # encryption must be kept out (in CyberChef: remove CR/LF first).
            python = (
                'body = data.rstrip(b"\\r\\n")  # the final newline is not part of it\n'
                f"data = rail_fence_decrypt(body, {rails}, {offset}) + data[len(body):]"
            )
            operation = "Remove_whitespace(false,true,true,false,false,false)" + operation
            comment += ", final newline left out"
        return StepCode(
            label=f"railfence(rails={rails}" + (f", offset={offset})" if offset else ")"),
            comment=comment,
            python=python,
            helper=RAILFENCE_HELPER,
            cyberchef=operation,
        )
    raise ClassicalError(f"unknown classical operation {step.name!r}")


# ---------------------------------------------------------------------------
# Solving
# ---------------------------------------------------------------------------


@dataclass
class _Try:
    """One decryption to score: the step, its output, and how the key was found."""

    step: Step
    data: bytes
    how: str


def _best_shift(column: str, frequencies: list[float]) -> int:
    """The Caesar shift that makes this column look most like the language."""
    best_shift, best_chi = 0, float("inf")
    for shift in range(26):
        shifted = "".join(chr(97 + (ord(char) - 97 - shift) % 26) for char in column)
        counts = [shifted.count(chr(97 + i)) for i in range(26)]
        value = chi_squared(counts, frequencies)
        if value < best_chi:
            best_shift, best_chi = shift, value
    return best_shift


def _cribs(flagset: FlagSet | None) -> list[str]:
    """Letter words a flag may start with: the configured prefixes, plus flag/FLAG."""
    flagset = flagset or default_flagset()
    words = []
    for _regex, prefix in flagset.b64_prefixes:
        word = prefix.rstrip("{")
        if word.isascii() and word.isalpha() and word not in words:
            words.append(word)
    words += [word for word in EXTRA_CRIBS if word not in words]
    return words


@dataclass
class Crib:
    """A flag-shaped word that would be a known prefix under some shifts.

    For "PLOA{" and the prefix "CYBN": shifts = [13, 13, 13, 13] (Caesar 13), and
    `position` = how many letters come before it (where the key stands there).
    """

    word: str
    prefix: str
    position: int
    shifts: list[int]

    def key_for(self, length: int, base: list[int] | None = None) -> str | None:
        """The key of this length the crib implies (None if it contradicts itself).

        `base` (a key found by frequency analysis) fills the key letters the crib
        says nothing about, when the key is longer than the prefix.
        """
        key: list[int | None] = list(base) if base else [None] * length
        for i, shift in enumerate(self.shifts):
            slot = (self.position + i) % length
            if base is None and key[slot] is not None and key[slot] != shift:
                return None  # the shifts do not repeat with this period
            key[slot] = shift
        if any(k is None for k in key):
            return None
        return "".join(chr(97 + k) for k in key)  # type: ignore[operator]


def find_cribs(data: bytes, flagset: FlagSet | None = None) -> list[Crib]:
    """Every flag-shaped word ("PLOA{") that has the length of a known prefix."""
    cribs = []
    known = {prefix.lower() for prefix in _cribs(flagset)}
    text = data.decode("latin-1")
    for match in FLAG_WORD_RE.finditer(text):
        word = match.group(1)
        if word.lower() in known:
            continue  # "CYBN{" in clear is a flag, not a shifted "flag{"
        position = len(letters_of(text[: match.start(1)].encode("latin-1")))
        for prefix in _cribs(flagset):
            if len(prefix) != len(word) or prefix.lower() == word.lower():
                continue
            pairs = zip(word.lower(), prefix.lower(), strict=True)
            shifts = [(ord(cipher) - ord(plain)) % 26 for cipher, plain in pairs]
            cribs.append(Crib(word, prefix, position, shifts))
    return cribs


def _caesar_tries(data: bytes) -> list[_Try]:
    return [
        _Try(Step("caesar", {"shift": shift}), caesar_decrypt(data, shift), "all 25 shifts tried")
        for shift in range(1, 26)
    ]


def _affine_tries(data: bytes) -> list[_Try]:
    tries = []
    for a in AFFINE_A:
        for b in range(26):
            if a == 1 or (a, b) == (25, 25):
                continue  # a = 1 is Caesar, (25, 25) is Atbash: tried as such
            step = Step("affine", {"a": a, "b": b})
            tries.append(_Try(step, affine_decrypt(data, a, b), "all 311 keys tried"))
    return tries


def _vigenere_tries(data: bytes, flagset: FlagSet | None) -> list[_Try]:
    """Frequency analysis per likely key length, plus the keys a flag crib gives.

    A crib ("PLOA{" must be "CYBN{") fixes as many key letters as the prefix has.
    A key that short is tried as is; a longer key found by the IoC keeps its
    frequency letters except where the crib knows better.
    """
    letters = letters_of(data)
    tries = []
    seen: set[str] = set()

    def add(key: str | None, how: str) -> None:
        if not key or key in seen or (len(key) > 1 and len(set(key)) == 1):
            return  # "ccc" is just Caesar, tried as such
        seen.add(key)
        tries.append(_Try(Step("vigenere", {"key": key}), vigenere_decrypt(data, key), how))

    frequency_keys: list[tuple[int, list[int], str]] = []
    for guess in vigenere_key_lengths(letters, min_column=SOLVER_COLUMN_LETTERS)[:4]:
        if guess.length < 2:
            continue
        columns = [letters[start :: guess.length] for start in range(guess.length)]
        for language, frequencies in (("English", ENGLISH_FREQ), ("French", FRENCH_FREQ)):
            shifts = [_best_shift(column, frequencies) for column in columns]
            how = f"key length {guess.length} (column IoC {guess.ioc:.3f}), {language} frequencies"
            frequency_keys.append((guess.length, shifts, how))
            add("".join(chr(97 + k) for k in shifts), how)

    for crib in find_cribs(data, flagset):
        why = f"'{crib.word}{{' read as '{crib.prefix}{{'"
        for length in range(2, len(crib.shifts) + 1):
            add(crib.key_for(length), f"{why}: key of {length} letters from the crib")
        for length, shifts, how in frequency_keys:
            if length > len(crib.shifts):
                add(crib.key_for(length, shifts), f"{why} + {how}")
    return tries


def reduce_key(key: str) -> str | None:
    """A key that almost repeats a shorter one ("harbourhadjuur") -> that one.

    On a short text a key twice too long fits a little better, by chance. The
    shorter key (see key_period) takes the majority letter at each position.
    Returns None when the key does not repeat.
    """
    period = key_period(key)
    if period == len(key):
        return None
    chunks = [key[i : i + period] for i in range(0, len(key), period)]
    return "".join(
        max(sorted(set(column)), key=column.count) for column in zip(*chunks, strict=True)
    )


def refine_vigenere(
    data: bytes, key: str, flagset: FlagSet | None, budget: Budget
) -> tuple[str, float]:
    """Improve a Vigenère key letter by letter, keeping what reads best.

    On a short text each column holds only a dozen letters, so frequency
    analysis often gets one key letter wrong. Here every position is tried with
    all 26 letters and scored with the full scorer (common words included): two
    passes fix the stray letter. Returns (key, score).
    """
    best_score, _ = score(vigenere_decrypt(data, key), flagset)
    letters = list(key)
    for _pass in range(2):
        changed = False
        for position in range(len(letters)):
            for candidate in "abcdefghijklmnopqrstuvwxyz":
                if candidate == letters[position] or not budget.spend():
                    continue
                trial = letters.copy()
                trial[position] = candidate
                value, _ = score(vigenere_decrypt(data, "".join(trial)), flagset)
                if value > best_score + 1e-6:
                    best_score, letters, changed = value, trial, True
        if not changed:
            break
    return "".join(letters), best_score


def _railfence_tries(data: bytes) -> list[_Try]:
    """2..12 rails with every offset. A trailing newline (added after encryption,
    by an editor or `echo`) is left out of the zigzag, and also tried in."""
    tries = []
    body = data.rstrip(b"\r\n")
    variants = [(body, True)] if body != data and body else []
    variants.append((data, False))
    for text, trim in variants:
        for rails in range(2, min(RAILFENCE_MAX_RAILS, len(text) - 1) + 1):
            for offset in range(2 * (rails - 1)):
                params = {"rails": rails, "offset": offset, **({"trim": True} if trim else {})}
                output = apply(data, "railfence", params)
                tries.append(_Try(Step("railfence", params), output, "2..12 rails, every offset"))
    return tries


def _candidate(original: bytes, attempt: _Try, value: float, reasons: list[str]) -> Candidate:
    code = step_code(attempt.step)
    return Candidate(
        label=code.label,
        data=attempt.data,
        score=value,
        reasons=[f"{code.comment} ({attempt.how})", *reasons],
        params={
            "cipher": attempt.step.name,
            **attempt.step.params,
            "chain": [attempt.step.to_dict()],
        },
        python=chain_snippet(original, [attempt.step]),
        cyberchef=chain_cyberchef([attempt.step]),
    )


def solve_classical(
    data: bytes,
    flagset: FlagSet | None = None,
    cipher: str | None = None,
    params: dict | None = None,
    budget: Budget | None = None,
    top_n: int = 10,
) -> list[Candidate]:
    """Try the classical ciphers on `data`; return the best decryptions, best first.

    `cipher` limits the search to one of OPERATIONS; with `params` too (e.g.
    {"shift": 3}), that exact decryption is done and scored, nothing is searched.
    Returns [] when the data is not text a classical cipher could have produced.
    """
    budget = budget or Budget(max_attempts=5000, max_seconds=10)
    if cipher is not None and cipher not in OPERATIONS:
        raise ClassicalError(f"unknown cipher {cipher!r}; known: {', '.join(OPERATIONS)}")
    if cipher and params:
        step = Step(cipher, dict(params))
        output = apply(data, cipher, params)
        value, reasons = score(output, flagset)
        return [_candidate(data, _Try(step, output, "key given"), value, reasons)]
    if len(letters_of(data)) < MIN_LETTERS:
        return []

    # A transposition only makes sense on the whole text: the rail fence is
    # searched on texts short enough to be searched whole.
    sample = data[:SAMPLE]
    families = [cipher] if cipher else list(OPERATIONS)
    tries: list[_Try] = []
    if "caesar" in families:
        tries += _caesar_tries(sample)
    if "atbash" in families:
        tries.append(_Try(Step("atbash"), atbash(sample), "no key"))
    if "affine" in families:
        tries += _affine_tries(sample)
    if "vigenere" in families:
        tries += _vigenere_tries(sample, flagset)
    if "railfence" in families and len(data) <= SAMPLE:
        tries += _railfence_tries(data)

    input_score, _ = score(sample, flagset)
    found: dict[bytes, tuple[_Try, float]] = {}
    for attempt in tries:
        if not budget.spend():
            break
        if attempt.data in found or attempt.data == sample:
            continue
        value, _reasons = score(attempt.data, flagset)
        if value >= MIN_SCORE:
            found[attempt.data] = (attempt, value)
    best = sorted(found.values(), key=lambda item: (-item[1], _simplicity(item[0].step)))

    # Polish the two best Vigenère keys (a short text leaves stray key letters),
    # and offer the shorter key a too-long one almost repeats.
    vigenere = [item for item in best if item[0].step.name == "vigenere"][:2]
    known = {item[0].step.params.get("key") for item in best}
    for attempt, value in vigenere:
        key, refined = refine_vigenere(sample, attempt.step.params["key"], flagset, budget)
        shorter = reduce_key(key)
        if shorter and shorter not in known and len(shorter) > 1:  # 1 letter = Caesar
            shorter, short_score = refine_vigenere(sample, shorter, flagset, budget)
            known.add(shorter)
            step = Step("vigenere", {"key": shorter})
            how = attempt.how + f", reduced to the period {len(shorter)} it repeats"
            best.append((_Try(step, vigenere_decrypt(sample, shorter), how), short_score))
        if refined > value and key not in known:
            known.add(key)
            step = Step("vigenere", {"key": key})
            how = attempt.how + ", then refined letter by letter"
            best.append((_Try(step, vigenere_decrypt(sample, key), how), refined))
    # A Vigenère key that (almost) repeats a shorter period is that shorter key
    # over-fitted ("ttttthztttt" is a Caesar shift of 19): the short one is
    # tried anyway, so the long one is dropped.
    best = [
        item
        for item in best
        if item[0].step.name != "vigenere"
        or key_period(item[0].step.params["key"]) == len(item[0].step.params["key"])
    ]
    best.sort(key=_rank)
    if not cipher:
        # Without a cipher named, only report what reads better than the input.
        best = [item for item in best if item[1] > input_score]

    candidates = []
    for attempt, _value in best[:top_n]:
        if len(data) > len(sample):  # apply the key found on the sample to everything
            attempt = _Try(
                attempt.step, apply(data, attempt.step.name, attempt.step.params), attempt.how
            )
        value, reasons = score(attempt.data, flagset)
        candidates.append(_candidate(data, attempt, value, reasons))
    return sorted(candidates, key=lambda c: (-round(c.score, 2), _simplicity(_step_of(c))))


def _rank(item: tuple[_Try, float]) -> tuple[float, int]:
    """Best score first; scores within 0.01 are a tie, won by the simpler cipher."""
    return (-round(item[1], 2), _simplicity(item[0].step))


def _step_of(candidate: Candidate) -> Step:
    return Step(**candidate.params["chain"][0])


def _simplicity(step: Step) -> int:
    """Tie-breaker: on equal scores, the simpler cipher / shorter key is more likely."""
    order = {"caesar": 0, "atbash": 1, "affine": 2, "railfence": 3, "vigenere": 4}
    return order.get(step.name, 9) * 100 + len(str(step.params.get("key", "")))
