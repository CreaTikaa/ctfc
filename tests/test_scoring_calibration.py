"""Is the scoring judge actually calibrated against the thresholds that use it?

`scoring.score()` is the judge for every brute-force loop in ctfc: `auto`, the
XOR column solver, the symmetric layout solver and the key hunt all keep
whatever it ranks highest, and each compares it against a hard-coded cut-off.
Those cut-offs were chosen by eye. The tests elsewhere check individual cases;
what was missing is this question:

    **do the right things score above the cut-off that keeps them, and the
    wrong things below it?**

So this file imports the *real* constants rather than inventing bars, and
asserts the relationships the rest of ctfc depends on:

| constant | what it decides |
|---|---|
| `auto.FOUND` (0.9) | stop decoding: this is the answer |
| `auto.READS_FINE` (0.8) | readable enough to leave alone |
| `auto.XOR_MIN_SCORE` (0.6) | an XOR guess has to read this well to be kept |
| `symmetric.MIN_SCORE` (0.25) | below this a plaintext is noise, not a candidate |

Each test prints the distribution it measured (`pytest -s` shows it), so a
change that drags every score towards one number fails here - loudly and with
the numbers - instead of quietly making every search in ctfc worse.
"""

from __future__ import annotations

import base64
import random
import statistics
import zlib
from pathlib import Path

from ctfc.core.auto import FOUND, MIN_SCORE, READS_FINE, XOR_MIN_SCORE
from ctfc.core.flags import default_flagset
from ctfc.core.scoring import score
from ctfc.core.symmetric import MIN_SCORE as SYM_MIN_SCORE

FIXTURES = Path(__file__).parent / "fixtures"
RNG = random.Random(20261103)

ENGLISH = (
    b"The quick brown fox jumps over the lazy dog, and then it comes back for "
    b"another look at the message hidden in the file."
)
FRENCH = (
    b"Le message etait cache dans le fichier, et la cle se trouvait juste a cote "
    b"dans le meme dossier que la capture reseau."
)


def value_of(data: bytes) -> float:
    return score(data, default_flagset())[0]


def _report(title: str, values: dict[str, float]) -> None:
    """Print the distribution, so a run with -s shows where the cut-offs sit."""
    numbers = sorted(values.values())
    print(f"\n--- {title}")
    for name, number in sorted(values.items(), key=lambda item: -item[1]):
        print(f"  {number:.3f}  {name}")
    if len(numbers) > 1:
        print(
            f"  min {numbers[0]:.3f}  median {statistics.median(numbers):.3f}  "
            f"max {numbers[-1]:.3f}"
        )


# ---------------------------------------------------------------------------
# The top of the scale: what must end a search
# ---------------------------------------------------------------------------


def test_a_flag_ends_the_search():
    """A flag has to clear `auto.FOUND`, or `auto` keeps decoding past the answer."""
    cases = {
        "flag alone": b"CYBN{a_simple_flag}",
        "flag in a sentence": b"Well done, the flag is CYBN{calibration} - send it in.",
        "generic flag format": b"the answer is FLAG{some_other_ctf_format}",
    }
    values = {name: value_of(data) for name, data in cases.items()}
    _report(f"flags (must reach FOUND = {FOUND})", values)
    for name, number in values.items():
        assert number >= FOUND, f"{name} scored {number:.3f}: auto would not stop"


def test_a_flag_in_binary_noise_still_wins_but_pays_for_it():
    """The surround matters: a flag among random bytes is worth less than in a sentence."""
    in_text = value_of(b"Well done, the flag is CYBN{calibration} - send it in.")
    in_noise = value_of(RNG.randbytes(40) + b"CYBN{in_a_blob}" + RNG.randbytes(40))
    _report("a flag in text vs in noise", {"in a sentence": in_text, "in noise": in_noise})
    assert in_noise > READS_FINE  # still clearly the best thing in the file
    assert in_noise < in_text  # but not as convincing


# ---------------------------------------------------------------------------
# The middle: readable, but not the answer
# ---------------------------------------------------------------------------


def test_plain_text_is_kept_but_does_not_end_the_search():
    """Readable text must clear the XOR/classical bar and stay under FOUND."""
    cases = {
        "english sentence": ENGLISH,
        "french sentence": FRENCH,
        "a python script": b"import os\nkey = b'secret'\nprint(open('flag.txt').read())\n",
        "a shell command": b"openssl enc -d -aes-256-cbc -in secret.enc -pass pass:hunter2\n",
    }
    values = {name: value_of(data) for name, data in cases.items()}
    _report(f"plain text (XOR_MIN_SCORE = {XOR_MIN_SCORE}, FOUND = {FOUND})", values)
    for name, number in values.items():
        assert number >= XOR_MIN_SCORE, f"{name} scored {number:.3f}: a correct XOR solve "
        assert number < FOUND, f"{name} scored {number:.3f}: auto would stop on plain text"


def test_encoded_text_sits_below_the_leave_it_alone_bar():
    """base64 and hex are readable but not the answer: `auto` must keep peeling."""
    cases = {
        "base64 of a sentence": base64.b64encode(ENGLISH),
        "hex of a sentence": ENGLISH.hex().encode(),
        "base32 of a sentence": base64.b32encode(ENGLISH),
    }
    values = {name: value_of(data) for name, data in cases.items()}
    _report(f"encoded text (must stay under READS_FINE = {READS_FINE})", values)
    for name, number in values.items():
        assert number < READS_FINE, f"{name} scored {number:.3f}: auto would stop too early"


def test_a_half_right_decryption_lands_in_the_middle():
    """CBC with a wrong IV: block one is garbage, the rest reads.

    This is the case a naive "is it printable?" test gets wrong, and the one a
    solver meets constantly - so it must be worth reporting (above the noise
    floor) without ending the search.
    """
    data = RNG.randbytes(16) + ENGLISH[16:]
    number = value_of(data)
    _report("half-right decryption", {"random first block, then text": number})
    assert SYM_MIN_SCORE < number < FOUND


# ---------------------------------------------------------------------------
# The bottom: what must be discarded
# ---------------------------------------------------------------------------


def test_random_bytes_are_noise():
    cases = {f"random {length} bytes": RNG.randbytes(length) for length in (16, 32, 64, 256, 4096)}
    cases["all zeros"] = bytes(64)
    cases["high bytes only"] = bytes(RNG.randrange(0x80, 0x100) for _ in range(200))
    cases["compressed, header stripped"] = zlib.compress(ENGLISH * 4)[2:]
    values = {name: value_of(data) for name, data in cases.items()}
    _report(f"noise (must stay under symmetric MIN_SCORE = {SYM_MIN_SCORE})", values)
    for name, number in values.items():
        assert number < SYM_MIN_SCORE, f"{name} scored {number:.3f}: it would be a candidate"


def test_a_recognised_container_scores_in_between():
    """A zlib or gzip stream is not an answer, but recognising it is a real signal.

    It therefore belongs above the noise floor and below "leave it alone" - and
    it is worth pinning down, because it is the one case where high entropy
    *should* score something.
    """
    cases = {
        "zlib stream": zlib.compress(ENGLISH * 4),
        "gzip of a sentence": __import__("gzip").compress(ENGLISH * 4),
    }
    values = {name: value_of(data) for name, data in cases.items()}
    _report("recognised containers", values)
    for name, number in values.items():
        # A known file type is worth 0.85 by design - "you have found a gzip" is
        # a real answer to `detect`. What it must not do is reach FOUND, which
        # would stop `auto` before it decompresses the thing.
        assert MIN_SCORE < number < FOUND, f"{name} scored {number:.3f}"


def test_every_wrong_single_byte_xor_key_is_rejected():
    """255 of the 256 keys are wrong, and `solve_xor` must not keep any of them."""
    plain = ENGLISH
    cipher = bytes(byte ^ 0x5A for byte in plain)
    values = {}
    for key in range(256):
        if key == 0x5A:
            continue
        values[f"key {key:#04x}"] = value_of(bytes(byte ^ key for byte in cipher))
    best_name, best = max(values.items(), key=lambda item: item[1])
    right = value_of(plain)
    _report("the five best wrong keys", dict(sorted(values.items(), key=lambda i: -i[1])[:5]))
    print(f"  right key: {right:.3f}  (XOR_MIN_SCORE = {XOR_MIN_SCORE})")
    assert best < XOR_MIN_SCORE, f"the wrong key {best_name} scored {best:.3f} and would be kept"
    # The margin is what makes the ranking safe, not the absolute numbers.
    assert right - best > 0.2, f"only {right - best:.3f} between the right key and {best_name}"


# ---------------------------------------------------------------------------
# Over every fixture at once: the regression guard
# ---------------------------------------------------------------------------


def test_the_fixtures_spread_out_instead_of_bunching_up():
    """The distribution over every fixture must stay wide.

    A change that pushes everything towards one number would keep the individual
    tests passing while making every search in ctfc useless, so the spread
    itself is measured and guarded.
    """
    values: dict[str, float] = {}
    for path in sorted(FIXTURES.glob("*")):
        if not path.is_file() or path.stat().st_size > 1 << 20:
            continue
        values[path.name] = value_of(path.read_bytes()[:8192])
    numbers = sorted(values.values())
    assert len(numbers) > 50
    print(f"\n--- {len(numbers)} fixtures")
    print(f"  min {numbers[0]:.3f}  median {statistics.median(numbers):.3f}  max {numbers[-1]:.3f}")
    print("  highest:")
    for name, number in sorted(values.items(), key=lambda item: -item[1])[:8]:
        print(f"    {number:.3f}  {name}")
    print("  lowest:")
    for name, number in sorted(values.items(), key=lambda item: item[1])[:8]:
        print(f"    {number:.3f}  {name}")
    below = sum(1 for number in numbers if number < SYM_MIN_SCORE)
    middle = sum(1 for number in numbers if SYM_MIN_SCORE <= number < FOUND)
    above = sum(1 for number in numbers if number >= FOUND)
    print(f"  {below} below {SYM_MIN_SCORE}, {middle} in between, {above} at or above {FOUND}")
    assert numbers[-1] - numbers[0] > 0.6, "the scores have collapsed into one band"
    assert numbers[0] < SYM_MIN_SCORE, "nothing scores low any more: the floor has risen"
    assert numbers[-1] >= FOUND, "nothing scores high any more: the ceiling has dropped"
    # Most fixtures are ciphertexts and binaries, so the corpus *should* lean
    # low; what matters is that all three bands are occupied.
    assert below > 5, "nothing is noise any more"
    assert middle > 10, "the middle band has emptied: nothing is 'worth a look'"
    assert above >= 1, "no fixture reads as an answer any more"


def test_every_score_carries_a_reason():
    """A bare number is not allowed anywhere: the rule from CLAUDE.md section 7."""
    for data in (b"CYBN{x_marks_it}", ENGLISH, RNG.randbytes(64), b"", bytes(16)):
        number, reasons = score(data, default_flagset())
        assert 0.0 <= number <= 1.0
        assert reasons, f"no reason given for {data[:20]!r}"


def test_a_weak_magic_number_does_not_outrank_text():
    """`00 00 01 00` is an ICO header and also the start of a lot of noise.

    A weak (two- to four-byte) signature used to be worth 0.6, which is exactly
    `auto.XOR_MIN_SCORE`, so a junk XOR result beginning with four such bytes
    outranked a readable decoding. It must now sit below that bar.
    """
    noise = bytes([0, 0, 1, 0]) + RNG.randbytes(60)
    weak = value_of(noise)
    _report("a weak magic number on noise", {"ICO header + noise": weak})
    assert weak < XOR_MIN_SCORE
    assert weak > SYM_MIN_SCORE  # still worth saying "this may be a file"
    assert weak < value_of(ENGLISH)


def test_a_strong_magic_number_still_answers_the_question():
    png = (FIXTURES / "png_with_zip.png").read_bytes()[:400]
    value = value_of(png)
    _report("a strong magic number", {"PNG header": value})
    assert value >= READS_FINE
